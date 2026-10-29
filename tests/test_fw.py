"""FW regression tests; use Python 3, jq, curl and Bash 4+ (BASH_BIN overrides Bash).

Services/listeners are simulated; downloads use real curl and a local HTTP server.
The scripts' absolute paths are redirected into
each test's temporary directory before loading its functions; no host services
or firewall rules are changed.
"""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("BASH_BIN", shutil.which("bash") or "/bin/bash")
FW_SOURCE = (ROOT / "fw.sh").read_text()
FW_FUNCTIONS = FW_SOURCE.split("# ==================== 入口 ====================")[0]
VT_FUNCTIONS = (ROOT / "vt.sh").read_text().split("# ─────────────────── 入口")[0]
VERSION = re.search(r'^SCRIPT_VERSION="([^"]+)"', FW_SOURCE, re.M)[1]
CORE_VERSION = re.search(r'^REALM_VERSION="([^"]+)"', FW_SOURCE, re.M)[1]
FILE_DOWNLOAD = r'''
curl() {
    while [[ $# -gt 0 ]]; do
        if [[ "$1" == -o ]]; then cp "$TEST_DIR/candidate" "$2"; return; fi
        shift
    done
    return 2
}
'''


def setUpModule():
    major = subprocess.check_output(
        [BASH, "-c", 'echo "${BASH_VERSINFO[0]}"'], text=True
    )
    if int(major) < 4:
        raise RuntimeError("Tests require Bash 4+; set BASH_BIN to a supported Bash")
    if not shutil.which("jq"):
        raise RuntimeError("Tests require jq")
    if not shutil.which("curl"):
        raise RuntimeError("Tests require curl")


def rule(port):
    return {"src_port": port, "dst_ip": "192.0.2.1", "dst_port": 443, "comment": ""}


def sockets(ports, pid=100, address="[::]"):
    return "".join(
        f'{proto} {state} 0 128 {address}:{port} *:* users:(("realm",pid={pid},fd=9))\n'
        for port in ports
        for proto, state in (("tcp", "LISTEN"), ("udp", "UNCONN"))
    )


FW_MOCKS = r'''
CONFIG_DIR="$TEST_DIR/realm"
META_FILE="$CONFIG_DIR/fw.json"
CONFIG_TOML="$CONFIG_DIR/config.toml"
REALM_BIN="$TEST_DIR/bin/realm"
SCRIPT_PATH="$TEST_DIR/bin/fw"
systemctl() {
    printf '%s\n' "$*" >> "$TEST_DIR/service.calls"
    case "$1" in
        is-active) [[ -f "$TEST_DIR/active" ]] ;;
        show)
            [[ ! -f "$TEST_DIR/show.fail" ]] || return 1
            printf '%s\n' "${MOCK_PID-100}"
            ;;
        restart|start)
            [[ ! -f "$TEST_DIR/start.fail" ]] || return 1
            touch "$TEST_DIR/active"
            local n=0
            [[ ! -f "$TEST_DIR/restarts" ]] || n=$(cat "$TEST_DIR/restarts")
            n=$((n + 1))
            echo "$n" > "$TEST_DIR/restarts"
            if [[ "$n" == 1 && -f "$TEST_DIR/sockets.first" ]]; then
                cp "$TEST_DIR/sockets.first" "$TEST_DIR/sockets"
            elif [[ "$n" -ge 2 && -f "$TEST_DIR/sockets.recovered" ]]; then
                cp "$TEST_DIR/sockets.recovered" "$TEST_DIR/sockets"
            fi
            ;;
        stop)
            [[ ! -f "$TEST_DIR/stop.fail" ]] || return 1
            rm -f "$TEST_DIR/active"
            ;;
        disable) [[ ! -f "$TEST_DIR/disable.fail" ]] ;;
        *) return 0 ;;
    esac
}
ss() {
    echo "$*" >> "$TEST_DIR/ss.calls"
    [[ ! -f "$TEST_DIR/ss.fail" ]] || return 1
    if [[ "$*" == *'sport = :'* ]]; then
        local filter=${!#}
        awk -v p="${filter##*:}" '$5 ~ (":" p "$")' "$TEST_DIR/sockets"
    else
        cat "$TEST_DIR/sockets"
    fi
}
sleep() {
    local n=0
    [[ ! -f "$TEST_DIR/ticks" ]] || n=$(cat "$TEST_DIR/ticks")
    n=$((n + 1))
    echo "$n" > "$TEST_DIR/ticks"
    if [[ "$n" == "${READY_AT-0}" && -f "$TEST_DIR/sockets.pending" ]]; then
        cp "$TEST_DIR/sockets.pending" "$TEST_DIR/sockets"
    fi
}
journalctl() { echo 'simulated service log'; }
timeout() { touch "$TEST_DIR/remote.probed"; return 1; }
'''

INSTALL_MOCKS = r'''
SERVICE_FILE="$TEST_DIR/realm.service"
detect_realm_asset() { printf '%s\t%s\n' test-asset "$PACKAGE_SHA"; }
curl() {
    while [[ $# -gt 0 ]]; do
        if [[ "$1" == -o ]]; then cp "$TEST_DIR/archive.tar.gz" "$2"; return; fi
        shift
    done
    return 1
}
if ! command -v sha256sum >/dev/null 2>&1; then
    sha256sum() { shasum -a 256 "$@"; }
fi
'''


class FWTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fw-test-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        (self.path / "realm").mkdir()
        (self.path / "bin").mkdir()
        self.lib = self.path / "functions.sh"
        self.lib.write_text(FW_FUNCTIONS)
        self.write("bin/realm", "#!/bin/bash\nexit 0\n")
        (self.path / "bin/realm").chmod(0o755)
        self.write("active", "")
        self.write("sockets", sockets([44111]))
        self.set_rules([44111])

    def write(self, name, content):
        (self.path / name).write_text(content)

    def set_rules(self, ports):
        self.write("realm/fw.json", json.dumps({"rules": [rule(p) for p in ports]}))

    def run_fw(self, code, input="", **env):
        return subprocess.run(
            [BASH, "-c", 'source "$TEST_LIB"\n' + FW_MOCKS + code],
            env={**os.environ, "TEST_LIB": str(self.lib), "TEST_DIR": str(self.path), **env},
            input=input, text=True, capture_output=True, timeout=10,
        )

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("未预期错误", result.stderr)

    def prepare_install(self):
        binary = f'#!/bin/bash\necho "realm {CORE_VERSION}"\n'.encode()
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as package:
            entry = tarfile.TarInfo("realm")
            entry.size, entry.mode = len(binary), 0o755
            package.addfile(entry, io.BytesIO(binary))
        data = archive.getvalue()
        (self.path / "archive.tar.gz").write_bytes(data)
        self.write("bin/realm", '#!/bin/bash\necho "realm 1.0.0"\n')
        self.write("realm.service", "original unit\n")
        return hashlib.sha256(data).hexdigest(), binary

    def test_signals_during_rule_changes_restore_before_exit(self):
        for operation in ("add", "delete"):
            for signum, rc in (("INT", 130), ("TERM", 143)):
                with self.subTest(operation=operation, signal=signum):
                    original = [44111] if operation == "add" else [44111, 44112]
                    self.set_rules(original)
                    before = (self.path / "realm/fw.json").read_bytes()
                    self.write("restarts", "0")
                    self.write("sockets", sockets(original))
                    self.write("sockets.first", "")
                    self.write("sockets.recovered", sockets(original))
                    command = "add_forward 44112 192.0.2.2 443" if operation == "add" else "delete_forward 44112"
                    result = self.run_fw(
                        'sleep() { kill -"$SIGNAL" "$$"; }\n' + command + '\necho SHOULD_NOT_CONTINUE\n',
                        SIGNAL=signum,
                    )
                    self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
                    self.assertNotIn("SHOULD_NOT_CONTINUE", result.stdout)
                    self.assertEqual((self.path / "realm/fw.json").read_bytes(), before)
                    config = (self.path / "realm/config.toml").read_text()
                    self.assertEqual(":44112" in config, operation == "delete")
                    self.assertTrue((self.path / "active").exists())
                    self.assertEqual((self.path / "restarts").read_text().strip(), "2")
                    self.assertEqual(list((self.path / "realm").glob("fw.json.backup.*")), [])
                    self.assertNotIn("恢复备份已保留", result.stdout + result.stderr)

    def test_interrupt_immediately_after_rule_replace_restores_original(self):
        before = (self.path / "realm/fw.json").read_bytes()
        result = self.run_fw(r'''
mv() {
    command mv "$@" || return
    if [[ "${!#}" == "$META_FILE" ]]; then kill -TERM "$$"; fi
}
add_forward 44112 192.0.2.2 443
echo SHOULD_NOT_CONTINUE
''')
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertEqual((self.path / "realm/fw.json").read_bytes(), before)
        self.assertNotIn(":44112", (self.path / "realm/config.toml").read_text())
        self.assertNotIn("SHOULD_NOT_CONTINUE", result.stdout)

    def test_failed_rule_restore_keeps_backup_after_exit(self):
        for mode in ("copy-failed", "restart-failed"):
            with self.subTest(mode=mode):
                self.set_rules([44111])
                before = (self.path / "realm/fw.json").read_bytes()
                self.write("restarts", "0")
                self.write("sockets", sockets([44111]))
                self.write("sockets.first", "")
                self.write("sockets.recovered", "")
                result = self.run_fw(r'''
cp() {
    if [[ "$MODE" == copy-failed && "$1" == -p && "$2" == "$META_FILE".backup.* ]]; then return 1; fi
    command cp "$@"
}
if add_forward 44112 192.0.2.2 443; then exit 99; fi
''', MODE=mode)
                self.assert_ok(result)
                backups = list((self.path / "realm").glob("fw.json.backup.*"))
                self.assertEqual(len(backups), 1)
                self.assertEqual(backups[0].read_bytes(), before)
                self.assertIn(str(backups[0]), result.stdout)
                self.assertIn("规则回滚未完成", result.stdout)
                if mode == "restart-failed":
                    self.assertEqual((self.path / "realm/fw.json").read_bytes(), before)
                backups[0].unlink()

    def test_delete_rollback_copy_failure_keeps_original_rule_backup(self):
        self.set_rules([44111, 44112])
        before = (self.path / "realm/fw.json").read_bytes()
        self.write("sockets.first", "")
        result = self.run_fw(r'''
cp() {
    if [[ "$1" == -p && "$2" == "$META_FILE".backup.* ]]; then return 1; fi
    command cp "$@"
}
if delete_forward 44112; then exit 99; fi
''')
        self.assert_ok(result)
        backups = list((self.path / "realm").glob("fw.json.backup.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before)
        self.assertIn(str(backups[0]), result.stdout)

    def test_failed_backup_survives_following_successful_operation(self):
        before = (self.path / "realm/fw.json").read_bytes()
        self.write("sockets.first", "")
        self.write("sockets.recovered", sockets([44111]))
        result = self.run_fw(r'''
cp() {
    if [[ "$1" == -p && "$2" == "$META_FILE".backup.* && ! -f "$TEST_DIR/restore.failed" ]]; then
        touch "$TEST_DIR/restore.failed"
        return 1
    fi
    command cp "$@"
}
if add_forward 44112 192.0.2.2 443; then exit 99; fi
delete_forward 44112
''')
        self.assert_ok(result)
        backups = list((self.path / "realm").glob("fw.json.backup.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before)
        self.assertEqual(json.loads((self.path / "realm/fw.json").read_text())["rules"], [rule(44111)])
        self.assertIn(str(backups[0]), result.stdout)

    def test_signal_when_rule_rollback_fails_keeps_backup_and_exits(self):
        before = (self.path / "realm/fw.json").read_bytes()
        result = self.run_fw(r'''
cp() {
    if [[ "$1" == -p && "$2" == "$META_FILE".backup.* ]]; then return 1; fi
    command cp "$@"
}
sleep() { kill -TERM "$$"; }
add_forward 44112 192.0.2.2 443
echo SHOULD_NOT_CONTINUE
''')
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        backups = list((self.path / "realm").glob("fw.json.backup.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before)
        self.assertIn(str(backups[0]), result.stdout + result.stderr)
        self.assertNotIn("SHOULD_NOT_CONTINUE", result.stdout)

    def test_install_signal_restores_old_binary_and_unit(self):
        digest, _ = self.prepare_install()
        before = (self.path / "bin/realm").read_bytes()
        result = self.run_fw(INSTALL_MOCKS + r'''
sleep() { kill -TERM "$$"; }
install_realm
echo SHOULD_NOT_CONTINUE
''', input="y\n", PACKAGE_SHA=digest)
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertEqual((self.path / "bin/realm").read_bytes(), before)
        self.assertEqual((self.path / "realm.service").read_text(), "original unit\n")
        self.assertTrue((self.path / "active").exists())
        self.assertEqual(list((self.path / "realm").glob(".realm-backup.*")), [])
        self.assertNotIn("SHOULD_NOT_CONTINUE", result.stdout)

    def test_install_interrupt_between_binary_and_unit_replace(self):
        digest, _ = self.prepare_install()
        before = (self.path / "bin/realm").read_bytes()
        result = self.run_fw(INSTALL_MOCKS + r'''
mv() {
    command mv "$@" || return
    if [[ "${!#}" == "$REALM_BIN" ]]; then kill -TERM "$$"; fi
}
install_realm
echo SHOULD_NOT_CONTINUE
''', input="y\n", PACKAGE_SHA=digest)
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertEqual((self.path / "bin/realm").read_bytes(), before)
        self.assertEqual((self.path / "realm.service").read_text(), "original unit\n")
        self.assertEqual(list((self.path / "realm").glob(".realm-backup.*")), [])
        self.assertNotIn("SHOULD_NOT_CONTINUE", result.stdout)

    def test_repeated_signals_during_install_rollback_do_not_abort_recovery(self):
        digest, _ = self.prepare_install()
        before = (self.path / "bin/realm").read_bytes()
        self.write("sockets.first", "")
        self.write("sockets.recovered", sockets([44111]))
        result = self.run_fw(INSTALL_MOCKS + r'''
cp() {
    if [[ "$1" == -p && "$2" == */backup.realm ]]; then
        kill -INT "$$"
        kill -TERM "$$"
    fi
    command cp "$@"
}
install_realm
''', input="y\n", PACKAGE_SHA=digest)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual((self.path / "bin/realm").read_bytes(), before)
        self.assertEqual((self.path / "realm.service").read_text(), "original unit\n")
        self.assertIn("已恢复旧版本", result.stdout)
        self.assertNotIn("操作已中断", result.stderr)
        self.assertEqual(list((self.path / "realm").glob(".realm-backup.*")), [])

    def test_install_interruption_before_activation_keeps_existing_install(self):
        digest, _ = self.prepare_install()
        before = (self.path / "bin/realm").read_bytes()
        result = self.run_fw(INSTALL_MOCKS + r'''
curl() { kill -TERM "$$"; }
install_realm
''', input="y\n", PACKAGE_SHA=digest)
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertEqual((self.path / "bin/realm").read_bytes(), before)
        self.assertEqual((self.path / "realm.service").read_text(), "original unit\n")
        self.assertFalse((self.path / "service.calls").exists())
        self.assertEqual(list((self.path / "realm").glob(".realm-backup.*")), [])

    def test_install_rollback_failure_retains_old_binary_and_unit_backup(self):
        for mode in ("copy-failed", "stop-failed", "restart-failed"):
            with self.subTest(mode=mode):
                digest, binary = self.prepare_install()
                before = (self.path / "bin/realm").read_bytes()
                self.write("restarts", "0")
                self.write("active", "")
                self.write("sockets.first", "")
                self.write("sockets.recovered", "")
                if mode == "stop-failed":
                    self.write("stop.fail", "")
                result = self.run_fw(INSTALL_MOCKS + r'''
cp() {
    if [[ "$MODE" == copy-failed && "$1" == -p && "$2" == */backup.realm ]]; then return 1; fi
    command cp "$@"
}
install_realm
''', input="y\n", PACKAGE_SHA=digest, MODE=mode)
                self.assertNotEqual(result.returncode, 0)
                backups = list((self.path / "realm").glob(".realm-backup.*"))
                self.assertEqual(len(backups), 1)
                self.assertEqual((backups[0] / "backup.realm").read_bytes(), before)
                self.assertEqual((backups[0] / "backup.realm.service").read_text(), "original unit\n")
                self.assertIn(str(backups[0]), result.stdout + result.stderr)
                if mode == "stop-failed":
                    self.assertEqual((self.path / "bin/realm").read_bytes(), binary)
                    (self.path / "stop.fail").unlink()
                shutil.rmtree(backups[0])

    def test_install_failed_new_listener_restores_old_and_cleans_backup(self):
        digest, _ = self.prepare_install()
        before = (self.path / "bin/realm").read_bytes()
        self.write("sockets.first", "")
        self.write("sockets.recovered", sockets([44111]))
        result = self.run_fw(INSTALL_MOCKS + "install_realm\n", input="y\n", PACKAGE_SHA=digest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("已恢复旧版本", result.stdout)
        self.assertEqual((self.path / "bin/realm").read_bytes(), before)
        self.assertEqual((self.path / "realm.service").read_text(), "original unit\n")
        self.assertTrue((self.path / "active").exists())
        self.assertEqual(list((self.path / "realm").glob(".realm-backup.*")), [])

    def test_first_install_rollback_delete_failure_is_not_reported_as_restored(self):
        for target in ("bin/realm", "realm.service"):
            with self.subTest(target=target):
                digest, _ = self.prepare_install()
                (self.path / "bin/realm").unlink()
                (self.path / "realm.service").unlink()
                if (self.path / "active").exists():
                    (self.path / "active").unlink()
                self.set_rules([])
                self.write("disable.fail", "")
                result = self.run_fw(INSTALL_MOCKS + r'''
rm() {
    local arg
    for arg in "$@"; do
        if [[ "$arg" == "$BLOCK_REMOVE" ]]; then return 1; fi
    done
    command rm "$@"
}
install_realm
''', PACKAGE_SHA=digest, BLOCK_REMOVE=str(self.path / target))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("自动回滚失败", result.stdout)
                self.assertNotIn("已恢复旧版本", result.stdout)
                self.assertTrue((self.path / target).exists())
                backups = list((self.path / "realm").glob(".realm-backup.*"))
                self.assertEqual(len(backups), 1)
                self.assertIn(str(backups[0]), result.stdout)
                shutil.rmtree(backups[0])

    def test_install_download_progress_and_failure_preserves_existing_files(self):
        binary = f'#!/bin/bash\necho "realm {CORE_VERSION}"\n'.encode()
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as package:
            entry = tarfile.TarInfo("realm")
            entry.size, entry.mode = len(binary), 0o755
            package.addfile(entry, io.BytesIO(binary))
        data = archive.getvalue()
        digest = hashlib.sha256(data).hexdigest()

        for mode in ("ok", "http-error", "bad-hash"):
            with self.subTest(mode=mode):
                class Handler(BaseHTTPRequestHandler):
                    def do_GET(self):
                        self.send_response(404 if mode == "http-error" else 200)
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)

                    def log_message(self, *args):
                        pass

                original = '#!/bin/bash\necho "realm old-version"\n'
                self.write("bin/realm", original)
                self.write("realm.service", "original service")
                with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    try:
                        result = self.run_fw(r'''
SERVICE_FILE="$TEST_DIR/realm.service"
detect_realm_asset() { printf '%s\t%s\n' test-asset "$PACKAGE_SHA"; }
curl() {
    local -a args=("$@")
    args[${#args[@]}-1]="$DOWNLOAD_URL"
    command curl --noproxy '*' "${args[@]}"
}
if ! command -v sha256sum >/dev/null 2>&1; then
    sha256sum() { shasum -a 256 "$@"; }
fi
install_realm
''', input="y\n", PACKAGE_SHA="0" * 64 if mode == "bad-hash" else digest,
                            DOWNLOAD_URL=f"http://127.0.0.1:{server.server_port}/realm.tar.gz")
                    finally:
                        server.shutdown()
                        thread.join()
                if mode == "ok":
                    self.assert_ok(result)
                    self.assertRegex(result.stderr, r"100(?:\.0)?%")
                    stages = ("正在下载 Realm", "下载完成，正在校验安装包", "安装包校验通过，正在解压", "正在安装 Realm 并检查服务", "已安装完成")
                    positions = [result.stdout.index(stage) for stage in stages]
                    self.assertEqual(positions, sorted(positions))
                    self.assertEqual((self.path / "bin/realm").read_bytes(), binary)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual((self.path / "bin/realm").read_text(), original)
                    self.assertEqual((self.path / "realm.service").read_text(), "original service")
                    self.assertNotIn("正在安装 Realm", result.stdout)
                    if mode == "http-error":
                        self.assertIn("下载失败", result.stdout)
                        self.assertNotIn("下载完成", result.stdout)
                    else:
                        self.assertIn("SHA256 校验失败", result.stdout)
                        self.assertNotIn("正在解压", result.stdout)

    def test_cli_update_success_and_unchanged(self):
        for suffix in ("# changed\n", ""):
            with self.subTest(suffix=suffix):
                candidate = f'#!/bin/bash\nSCRIPT_VERSION="{VERSION}"\n' + suffix
                self.write("candidate", candidate)
                self.write("bin/fw", candidate if not suffix else candidate + "# old\n")
                result = self.run_fw(FILE_DOWNLOAD + 'update_script cli\n')
                self.assert_ok(result)
                self.assertEqual((self.path / "bin/fw").read_text(), candidate)

    def test_update_rejects_invalid_download_and_downgrade(self):
        for candidate, failure in (
            ('#!/bin/bash\nSCRIPT_VERSION="0.0.1"\n', False),
            ('#!/bin/bash\nSCRIPT_VERSION="999.0"\nif\n', False),
            ("not a script", False), ("", True),
        ):
            with self.subTest(candidate=candidate, failure=failure):
                self.write("bin/fw", "original")
                self.write("candidate", candidate)
                download = 'curl() { return 22; }\n' if failure else FILE_DOWNLOAD
                result = self.run_fw(download + 'update_script cli\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.path / "bin/fw").read_text(), "original")

    def test_menu_update_executes_updated_script(self):
        self.write("bin/fw", "original")
        self.write("candidate", f'#!/bin/bash\nSCRIPT_VERSION="{VERSION}"\necho menu-restarted\n')
        result = self.run_fw(FILE_DOWNLOAD + 'update_script menu\n')
        self.assert_ok(result)
        self.assertIn("menu-restarted", result.stdout)

    def test_add_menu_retries_only_invalid_field_and_keeps_previous_values(self):
        self.write("sockets", sockets([44111]) + sockets([44113], pid=999))
        self.write("sockets.first", sockets([44111, 44112]))
        result = self.run_fw("menu_add\n", input="\n".join((
            "bad-port", "44111", "44113", "00044112",
            "bad-ip", "256.1.1.1", "192.0.2.9",
            "-1", "9" * 200, "0443", "Hong Kong", "maybe", "Y", "n", "",
        )))
        self.assert_ok(result)
        saved = json.loads((self.path / "realm/fw.json").read_text())["rules"]
        self.assertEqual(saved, [rule(44111), {
            "src_port": 44112, "dst_ip": "192.0.2.9", "dst_port": 443,
            "comment": "Hong Kong",
        }])
        for message in ("已存在", "已被其他进程占用", "无效 IP", "无效目标端口", "请输入 y 或 n"):
            self.assertIn(message, result.stdout)
        self.assertIn(":44112 → 192.0.2.9:443（TCP/UDP）", result.stdout)
        self.assertIn("备注: Hong Kong", result.stdout)
        self.assertIn("现有 1 条规则的连接会短暂中断", result.stdout)
        self.assertLess(result.stdout.index("备注: Hong Kong"), result.stdout.index("转发已添加"))

    def test_add_menu_defaults_and_first_rule_start_message(self):
        self.set_rules([])
        (self.path / "active").unlink()
        self.write("sockets", "")
        self.write("sockets.first", sockets([44112]))
        result = self.run_fw("menu_add\n", input="44112\n192.0.2.2\n\n\n\nn\n")
        self.assert_ok(result)
        saved = json.loads((self.path / "realm/fw.json").read_text())["rules"]
        self.assertEqual(saved, [{
            "src_port": 44112, "dst_ip": "192.0.2.2", "dst_port": 44112, "comment": "",
        }])
        self.assertIn("备注: 无", result.stdout)
        self.assertIn("添加后将启动 Realm", result.stdout)
        self.assertNotIn("现有 0 条", result.stdout)

    def test_add_menu_cancellation_or_eof_never_changes_rules_or_service(self):
        for value in (
            "0\n", "00\n", "44112\n0\n", "44112\n192.0.2.2\n0\n",
            "44112\n192.0.2.2\n443\nnote\n0\n",
            "44112\n192.0.2.2\n443\nnote\nn\n",
            "44112\n192.0.2.2\n443\nnote\nwrong\n0\n",
            "", "44112\n", "44112\n192.0.2.2\n", "44112\n192.0.2.2\n443\n",
            "44112\n192.0.2.2\n443\nnote\n", "bad\n",
        ):
            with self.subTest(input=value):
                before = (self.path / "realm/fw.json").read_bytes()
                result = self.run_fw("menu_add\n", input=value)
                self.assert_ok(result)
                self.assertEqual((self.path / "realm/fw.json").read_bytes(), before)
                self.assertFalse((self.path / "realm/config.toml").exists())
                self.assertFalse((self.path / "service.calls").exists())

    def test_port_overflow_is_rejected_before_next_input(self):
        self.write("sockets.first", sockets([44111, 44112]))
        result = self.run_fw("menu_add\n", input=(
            f"{2**64 + 44112}\n44112\n192.0.2.2\n{2**64 + 443}\n443\n0\ny\nn\n"
        ))
        self.assert_ok(result)
        self.assertIn("无效本机监听端口", result.stdout)
        self.assertIn("无效目标端口", result.stdout)
        saved = json.loads((self.path / "realm/fw.json").read_text())["rules"][-1]
        self.assertEqual((saved["src_port"], saved["dst_port"], saved["comment"]), (44112, 443, "0"))

    def test_delete_menu_retries_then_previews_selected_rule_before_deletion(self):
        selected = {**rule(44102), "dst_ip": "192.0.2.99", "dst_port": 8443, "comment": "Tokyo"}
        self.write("realm/fw.json", json.dumps({"rules": [rule(44101), selected, rule(44103)]}))
        self.write("sockets.first", sockets([44101, 44103]))
        result = self.run_fw("menu_delete\n", input="bad\n99999999999999999999\n4\n02\nwrong\ny\n")
        self.assert_ok(result)
        saved = json.loads((self.path / "realm/fw.json").read_text())["rules"]
        self.assertEqual(saved, [rule(44101), rule(44103)])
        self.assertIn(":44102 → 192.0.2.99:8443（TCP/UDP）", result.stdout)
        self.assertIn("备注: Tokyo", result.stdout)
        self.assertIn("全部 3 条规则的现有连接会中断", result.stdout)
        self.assertLess(result.stdout.index("备注: Tokyo"), result.stdout.index("转发已删除"))

    def test_delete_last_rule_preview_and_cancel_defaults(self):
        for confirmation in ("", "0", "n", "wrong\n0"):
            with self.subTest(confirmation=confirmation):
                before = (self.path / "realm/fw.json").read_bytes()
                result = self.run_fw("menu_delete\n", input=f"1\n{confirmation}\n")
                self.assert_ok(result)
                self.assertIn(":44111 → 192.0.2.1:443（TCP/UDP）", result.stdout)
                self.assertIn("备注: 无", result.stdout)
                self.assertIn("删除后将停止 Realm", result.stdout)
                self.assertEqual((self.path / "realm/fw.json").read_bytes(), before)
                self.assertFalse((self.path / "service.calls").exists())
        self.assert_ok(self.run_fw("menu_delete\n", input="1\ny\n"))
        self.assertEqual(json.loads((self.path / "realm/fw.json").read_text())["rules"], [])
        self.assertFalse((self.path / "active").exists())

    def test_rule_test_selection_retries_and_handles_decimal(self):
        self.set_rules(range(44101, 44113))
        before = (self.path / "realm/fw.json").read_bytes()
        result = self.run_fw("test_forward_rule\n", input="wrong\n13\n08\n")
        self.assert_ok(result)
        self.assertIn("检测: :44108 → 192.0.2.1:443", result.stdout)
        self.assertEqual((self.path / "realm/fw.json").read_bytes(), before)
        self.assertNotIn("restart", (self.path / "service.calls").read_text())

    def test_rule_test_selection_zero_and_eof_return_without_probe(self):
        for value in ("0\n", "00\n", "wrong\n0\n", "", "wrong\n"):
            with self.subTest(input=value):
                result = self.run_fw("test_forward_rule\n", input=value)
                self.assert_ok(result)
                self.assertFalse((self.path / "remote.probed").exists())
                self.assertFalse((self.path / "service.calls").exists())

    def test_main_menu_cancellation_returns_without_extra_pause(self):
        for choice, following in (("2", "0\n"), ("3", "0\n"), ("5", "0\n"), ("5", "1\n0\n")):
            with self.subTest(choice=choice, following=following):
                self.write("prompts", "")
                result = self.run_fw(r'''
clear() { :; }
read() { printf '%s\n' "$*" >> "$TEST_DIR/prompts"; builtin read "$@"; }
menu
''', input=choice + "\n" + following)
                self.assert_ok(result)
                self.assertNotIn("按回车返回", (self.path / "prompts").read_text())
                self.assertEqual(json.loads((self.path / "realm/fw.json").read_text())["rules"], [rule(44111)])
                self.assertNotRegex((self.path / "service.calls").read_text(), r"(?m)^(start|restart|stop) ")

    def test_main_menu_completed_add_and_test_pause_once(self):
        self.write("sockets.first", sockets([44111, 44112]))
        result = self.run_fw(r'''
clear() { :; }
read() { printf '%s\n' "$*" >> "$TEST_DIR/prompts"; builtin read "$@"; }
menu
''', input="2\n44112\n192.0.2.2\n443\nnote\ny\ny\n\n")
        self.assert_ok(result)
        self.assertIn("检测: :44112", result.stdout)
        self.assertEqual((self.path / "prompts").read_text().count("按回车返回"), 1)
        self.assertEqual(len(json.loads((self.path / "realm/fw.json").read_text())["rules"]), 2)

    def test_delete_selection_cancellation_and_invalid_input(self):
        self.set_rules(range(44101, 44113))
        for value in ("0", "00", "0" * 200, "", "-1", "1a", "13", "99", "9" * 200):
            with self.subTest(value=value):
                result = self.run_fw(
                    'delete_forward() { echo "DELETED:$1"; }\nmenu_delete\n',
                    input=value + "\ny\n",
                )
                self.assert_ok(result)
                self.assertNotIn("DELETED:", result.stdout)

    def test_delete_selection_is_decimal_and_requires_confirmation(self):
        self.set_rules(range(44101, 44113))
        for value, confirmation, port in (
            ("08", "y", 44108), ("09", "Y", 44109),
            ("00012", "y", 44112), ("0" * 200 + "1", "y", 44101),
            ("1", "n", None), ("1", "", None),
        ):
            with self.subTest(value=value, confirmation=confirmation):
                result = self.run_fw(
                    'delete_forward() { echo "DELETED:$1"; }\nmenu_delete\n',
                    input=f"{value}\n{confirmation}\n",
                )
                self.assert_ok(result)
                if port:
                    self.assertIn(f"DELETED:{port}", result.stdout)
                else:
                    self.assertNotIn("DELETED:", result.stdout)
        for value in ("", "1\n"):
            result = self.run_fw('delete_forward() { echo DELETED; }\nmenu_delete\n', input=value)
            self.assert_ok(result)
            self.assertNotIn("DELETED", result.stdout)

    def test_listener_checks_all_ports_protocols_and_main_pid(self):
        healthy = sockets([44111, 44112])
        for data, good in (
            (healthy, True), (sockets([44111, 44112], address="0.0.0.0"), True),
            (healthy.replace('("realm",', '("other-name",'), True),
            (healthy.replace("pid=100,", "pid=1000,"), False),
            (sockets([44111]), False),
            ("".join(line + "\n" for line in healthy.splitlines() if not line.startswith("udp")), False),
            ("".join(line + "\n" for line in healthy.splitlines() if not line.startswith("tcp")), False),
            (sockets([144111, 144112]), False), ("", False),
        ):
            with self.subTest(data=data, good=good):
                self.write("sockets", data)
                result = self.run_fw("check_realm_listeners $'44111\\n44112'\n")
                self.assertEqual(result.returncode == 0, good, result.stdout + result.stderr)

    def test_listener_query_failures_are_not_success(self):
        for marker in ("show.fail", "ss.fail"):
            with self.subTest(marker=marker):
                self.write(marker, "")
                result = self.run_fw("check_realm_listeners 44111\n")
                self.assertNotEqual(result.returncode, 0)
                (self.path / marker).unlink()
        for pid in ("0", "", "invalid"):
            with self.subTest(pid=pid):
                self.assertNotEqual(self.run_fw("check_realm_listeners 44111\n", MOCK_PID=pid).returncode, 0)
        (self.path / "active").unlink()
        self.assertNotEqual(self.run_fw("check_realm_listeners 44111\n").returncode, 0)

    def test_reload_waits_for_listeners_without_probing_remote(self):
        self.write("sockets", "")
        self.write("sockets.pending", sockets([44111]))
        result = self.run_fw("reload_realm\n", READY_AT="3")
        self.assert_ok(result)
        self.assertEqual((self.path / "ticks").read_text().strip(), "3")
        self.assertFalse((self.path / "remote.probed").exists())

    def test_reload_rejects_partial_listeners_after_five_attempts(self):
        self.set_rules([44111, 44112])
        result = self.run_fw("reload_realm\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.path / "ticks").read_text().strip(), "5")
        self.assertIn("44112", result.stderr)
        self.assertIn("simulated service log", result.stderr)
        self.assertNotIn("realm 已重载", result.stdout)

    def test_failed_start_does_not_report_success(self):
        self.write("start.fail", "")
        result = self.run_fw("reload_realm\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.path / "ticks").exists())
        self.assertNotIn("realm 已重载", result.stdout)

    def test_add_and_delete_success(self):
        self.write("sockets.first", sockets([44111, 44112]))
        self.assert_ok(self.run_fw("add_forward 44112 192.0.2.1 443 example\n"))
        self.assertEqual(len(json.loads((self.path / "realm/fw.json").read_text())["rules"]), 2)
        self.assert_ok(self.run_fw("delete_forward 44112\n"))
        self.assertEqual(json.loads((self.path / "realm/fw.json").read_text())["rules"], [rule(44111)])

    def test_add_listener_failure_rolls_back_metadata_and_config(self):
        result = self.run_fw("if add_forward 44112 192.0.2.1 443 example; then exit 99; fi\n")
        self.assert_ok(result)
        self.assertIn("新增规则已回滚", result.stdout)
        self.assertNotIn("恢复启动失败", result.stdout)
        self.assertEqual(json.loads((self.path / "realm/fw.json").read_text())["rules"], [rule(44111)])
        self.assertNotIn(":44112", (self.path / "realm/config.toml").read_text())
        self.assertEqual((self.path / "restarts").read_text().strip(), "2")

    def test_delete_listener_failure_rolls_back_metadata_and_config(self):
        self.set_rules([44111, 44112])
        self.write("sockets", sockets([44111, 44112]))
        self.write("sockets.first", "")
        self.write("sockets.recovered", sockets([44111, 44112]))
        result = self.run_fw("if delete_forward 44112; then exit 99; fi\n")
        self.assert_ok(result)
        self.assertIn("删除操作已回滚", result.stdout)
        self.assertNotIn("恢复启动失败", result.stdout)
        self.assertEqual(len(json.loads((self.path / "realm/fw.json").read_text())["rules"]), 2)
        self.assertIn(":44112", (self.path / "realm/config.toml").read_text())

    def test_deleting_last_rule_stops_service_without_listener_check(self):
        self.assert_ok(self.run_fw("delete_forward 44111\n"))
        calls = (self.path / "service.calls").read_text()
        self.assertIn("stop realm", calls)
        self.assertIn("disable realm", calls)
        self.assertFalse((self.path / "ss.calls").exists())
        self.assertFalse((self.path / "active").exists())


class VTUninstallTests(unittest.TestCase):
    def test_uninstall_preserves_firewall_and_keeps_files_if_stop_fails(self):
        for mode in (
            "stopped", "stop-failed", "still-active", "already-stopped",
            "not-installed", "partial-install", "state-query-failed", "missing-unit-active",
            "unknown-active-state",
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="vt-test-") as tmp:
                root = Path(tmp)
                source = re.sub(
                    r"/(?:etc|usr/local|var|run|tmp)/",
                    lambda match: str(root) + match[0], VT_FUNCTIONS,
                )
                lib = root / "functions.sh"
                lib.write_text(source)
                files = [root / name for name in (
                    "etc/realm/fw.json", "etc/realm/config.toml",
                    "etc/systemd/system/realm.service", "usr/local/bin/realm", "usr/local/bin/fw",
                )]
                for path in files:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('{"rules":[{"src_port":44111}]}')
                    path.chmod(0o755)
                if mode in ("not-installed", "partial-install", "missing-unit-active", "unknown-active-state"):
                    (root / "etc/systemd/system/realm.service").unlink()
                if mode == "not-installed":
                    (root / "usr/local/bin/realm").unlink()
                initially_present = {path for path in files if path.exists()}
                mocks = r'''
source "$TEST_LIB"
systemctl() {
    echo "$*" >> "$TEST_DIR/service.calls"
    case "$1" in
        stop)
            case "$MODE" in
                stopped|still-active|already-stopped) return 0 ;;
                *) return 5 ;;
            esac
            ;;
        show)
            case "$MODE" in
                not-installed|partial-install) printf 'LoadState=not-found\nActiveState=inactive\n' ;;
                missing-unit-active) printf 'LoadState=not-found\nActiveState=active\n' ;;
                unknown-active-state) printf 'LoadState=not-found\nActiveState=unknown\n' ;;
                state-query-failed) return 1 ;;
                *) printf 'LoadState=loaded\nActiveState=inactive\n' ;;
            esac
            ;;
        is-active) [[ "$MODE" == still-active ]] ;;
        *) return 0 ;;
    esac
}
close_port() { echo "$*" >> "$TEST_DIR/firewall.calls"; }
nuke_all
'''
                result = subprocess.run(
                    [BASH, "-c", mocks], input="yes\nn\n", text=True,
                    env={**os.environ, "TEST_LIB": str(lib), "TEST_DIR": tmp, "MODE": mode},
                    capture_output=True, timeout=10,
                )
                preserve = mode in ("stop-failed", "still-active", "state-query-failed", "missing-unit-active", "unknown-active-state")
                self.assertEqual(result.returncode, 1 if preserve else 0, result.stdout + result.stderr)
                self.assertFalse((root / "firewall.calls").exists())
                for path in files:
                    self.assertEqual(path.exists(), preserve and path in initially_present, str(path))
                calls = (root / "service.calls").read_text()
                if preserve:
                    self.assertNotIn("disable realm", calls)
                    self.assertNotIn("全部清除完成", result.stdout)
                    self.assertIn("已保留 FW 文件和配置", result.stderr)
                else:
                    if mode in ("not-installed", "partial-install"):
                        self.assertNotIn("disable realm", calls)
                    else:
                        self.assertIn("disable realm", calls)
                    self.assertIn("未修改防火墙", result.stdout)


if __name__ == "__main__":
    unittest.main()

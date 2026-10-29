"""VT uninstall faults. All system paths and commands use per-test fixtures."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("BASH_BIN", shutil.which("bash") or "/bin/bash")
SOURCE, MARKER, _ = (ROOT / "vt.sh").read_text().partition("# ─────────────────── 入口")
assert MARKER, "Refuse to load VT without its entry marker"


def setUpModule():
    major = subprocess.check_output([BASH, "-c", 'echo "${BASH_VERSINFO[0]}"'], text=True)
    if int(major) < 4:
        raise RuntimeError("Tests require Bash 4+; set BASH_BIN to a supported Bash")


MOCKS = r'''
source "$TEST_LIB"
systemctl() {
    echo "$*" >> "$TEST_DIR/service.calls"
    local unit port=""
    for unit in "$@"; do
        [[ "$unit" != snell@* ]] || port=${unit#snell@}
    done
    case "$1" in
        list-units)
            [[ "$MODE" != list-failed ]] || return 1
            cat "$TEST_DIR/units" 2>/dev/null; return 0 ;;
        show)
            [[ "$MODE" != show-failed ]] || return 1
            if [[ -f "$TEST_DIR/missing-unit" ]]; then echo LoadState=not-found; else echo LoadState=loaded; fi
            if [[ -f "$TEST_DIR/active.$port" ]]; then echo ActiveState=active; else echo ActiveState=inactive; fi ;;
        stop)
            if [[ "$MODE" == interrupted ]]; then kill -TERM "$BASHPID"; return 1; fi
            [[ "$MODE" != stop-failed || "$port" != 45001 ]] || return 1
            [[ "$MODE" != missing-unit ]] || return 5
            [[ "$MODE" == still-active ]] || command rm -f "$TEST_DIR/active.$port" ;;
        start)
            if [[ "$MODE" == repeated-signal ]]; then kill -TERM "$BASHPID"; fi
            [[ "$MODE" != restore-failed ]] || return 1
            touch "$TEST_DIR/active.$port" ;;
        is-enabled) [[ -f "$TEST_DIR/enabled.$port" ]] ;;
        disable)
            [[ "$MODE" != disable-failed && "$MODE" != restore-failed && "$MODE" != repeated-signal ]] || return 1
            command rm -f "$TEST_DIR/enabled.$port" "$TEST_DIR/etc/systemd/system/multi-user.target.wants/snell@$port.service" ;;
        enable) touch "$TEST_DIR/enabled.$port" ;;
        *) return 0 ;;
    esac
}
id() {
    case "$*" in
        '-u snell') [[ -f "$TEST_DIR/account-user" ]] ;;
        '-un') echo root ;;
        *) command id "$@" ;;
    esac
}
getent() { [[ -f "$TEST_DIR/account-group" ]]; }
userdel() {
    echo "$*" >> "$TEST_DIR/userdel.calls"
    [[ "$MODE" != userdel-failed ]] || return 1
    command rm -f "$TEST_DIR/account-user"
}
groupdel() {
    echo "$*" >> "$TEST_DIR/groupdel.calls"
    [[ "$MODE" != groupdel-failed ]] || return 1
    command rm -f "$TEST_DIR/account-group"
}
close_port() {
    echo "$*" >> "$TEST_DIR/closed"
    [[ "$MODE" != firewall-failed ]] || return 1
}
open_port() { echo "$*" >> "$TEST_DIR/opened"; }
flock() { echo "$*" >> "$TEST_DIR/flock.calls"; [[ "$MODE" != lock-failed ]]; }
crontab() {
    echo "$*" >> "$TEST_DIR/cron.calls"
    if [[ "$1" == -l ]]; then
        case "$MODE" in
            cron-read-failed) echo '* partial output'; echo 'read failed' >&2; return 1 ;;
            cron-read-empty-failed) echo 'permission denied' >&2; return 1 ;;
            cron-read-diagnostic) cat "$TEST_DIR/crontab"; echo 'I/O error' >&2; return 0 ;;
            no-crontab) echo 'no crontab for root' >&2; return 1 ;;
        esac
        cat "$TEST_DIR/crontab"
    else
        [[ "$MODE" != cron-write-failed ]] || return 1
        [[ "$MODE" != cron-write-noop ]] || return 0
        cp "$1" "$TEST_DIR/crontab"
        touch "$TEST_DIR/cron-written"
    fi
}
nft() {
    echo "$*" >> "$TEST_DIR/nft.calls"
    if [[ "$1" == -j ]]; then
        [[ "$MODE" != nft-query-failed ]] || return 1
        if [[ "$MODE" == nft-malformed ]]; then echo '{}'; return 0; fi
        if [[ -f "$TEST_DIR/nft-table" ]]; then
            echo '{"nftables":[{"table":{"family":"inet","name":"port_monitor"}}]}'
        else
            echo '{"nftables":[]}'
        fi
    else
        [[ "$MODE" != nft-delete-failed && "$MODE" != nft-tc-delete-failed ]] || return 1
        command rm -f "$TEST_DIR/nft-table"
    fi
}
tc() {
    echo "$*" >> "$TEST_DIR/tc.calls"
    if [[ "$2" == show ]]; then
        [[ "$MODE" != tc-query-failed ]] || return 1
        if [[ -f "$TEST_DIR/tc-root" ]]; then cat "$TEST_DIR/tc-root"; fi
    else
        [[ "$MODE" != tc-delete-failed && "$MODE" != nft-tc-delete-failed ]] || return 1
        command rm -f "$TEST_DIR/tc-root"
    fi
}
rm() {
    if [[ "$MODE" == file-delete-failed && "$*" == *'/usr/local/bin/'* ]]; then return 1; fi
    command rm "$@"
}
'''


class VTCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vt-cleanup-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ("run/systemd/system", "etc/systemd/system", "usr/local/bin", "var/run", "tmp"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.put("library.sh", re.sub(r"/(?:etc|usr/local|var|run|tmp)/", lambda m: str(self.root) + m[0], SOURCE))
        self.put("usr/local/bin/vt", "keep toolbox")

    def put(self, name, data="fixture"):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data)
        return target

    def run_cleanup(self, mode="ok", action="nuke_all", data="yes\nn\n"):
        result = subprocess.run(
            [BASH, "-c", MOCKS + action + "\n"], input=data, text=True,
            env={**os.environ, "MODE": mode, "TEST_DIR": str(self.root),
                 "TEST_LIB": str(self.root / "library.sh"), "TMPDIR": str(self.root / "tmp")},
            capture_output=True, timeout=6,
        )
        return result

    def snell(self, owned=True):
        for name in ("userdel.calls", "groupdel.calls", "opened", "closed"):
            (self.root / name).unlink(missing_ok=True)
        for name in ("etc/snell/45000.conf", "etc/snell/45001.conf", "usr/local/bin/snell-server",
                     "usr/local/bin/snell", "etc/systemd/system/snell@.service", "account-user", "account-group"):
            self.put(name)
        if owned:
            self.put("etc/snell/.user-created-by-snell-script", "")
        for port in (45000, 45001):
            self.put(f"active.{port}")
            self.put(f"enabled.{port}")
        self.put("units", "snell@45000.service loaded active running\nsnell@45001.service loaded active running\n")

    def pm(self, owned=True):
        self.put("etc/port_monitor/config.json", '{"ports":{}}')
        self.put("usr/local/bin/pm")
        self.put("var/log/port_monitor.log")
        self.put("nft-table")
        if owned:
            self.put("etc/port_monitor/tc_root_owned", "ens4\n")
            self.put("tc-root", "qdisc htb 1: root refcnt 2 default 0x0\n")
        self.cron_original = (
            f"* * * * * {self.root}/usr/local/bin/pm --monitor\n"
            f"* * * * * {self.root}/usr/local/bin/pm --monitor >> {self.root}/var/log/port_monitor.log 2>&1\n"
            "0 0 * * * echo keep-other-job\n"
        )
        self.put("crontab", self.cron_original)

    def assert_failed(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("全部清除完成", result.stdout)
        self.assertTrue((self.root / "usr/local/bin/vt").exists())

    def test_snell_service_faults_preserve_files_and_restore_original_state(self):
        for mode in ("stop-failed", "disable-failed", "firewall-failed", "interrupted", "repeated-signal"):
            with self.subTest(mode=mode):
                self.snell()
                result = self.run_cleanup(mode)
                self.assert_failed(result)
                for name in ("etc/snell/45000.conf", "etc/snell/45001.conf", "usr/local/bin/snell-server",
                             "usr/local/bin/snell", "etc/systemd/system/snell@.service", "account-user", "account-group"):
                    self.assertTrue((self.root / name).exists(), name)
                for port in (45000, 45001):
                    self.assertTrue((self.root / f"active.{port}").exists())
                    self.assertTrue((self.root / f"enabled.{port}").exists())
                self.assertFalse((self.root / "userdel.calls").exists())
                if mode == "firewall-failed":
                    self.assertEqual((self.root / "opened").read_text().splitlines(), ["45000", "45001"])

    def test_snell_failed_state_restore_is_reported_and_retry_succeeds(self):
        self.snell()
        result = self.run_cleanup("restore-failed")
        self.assert_failed(result)
        self.assertIn("原状态恢复失败", result.stderr)
        self.assertTrue((self.root / "etc/snell/45000.conf").exists())
        retry = self.run_cleanup()
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertFalse((self.root / "etc/snell").exists())

    def test_snell_uncertain_or_still_running_state_prevents_deletion(self):
        for mode in ("list-failed", "show-failed", "still-active"):
            with self.subTest(mode=mode):
                self.snell()
                result = self.run_cleanup(mode)
                self.assert_failed(result)
                self.assertTrue((self.root / "etc/snell/45000.conf").exists())
                self.assertTrue((self.root / "usr/local/bin/snell-server").exists())

    def test_snell_success_removes_owned_account_and_group(self):
        self.snell()
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in ("etc/snell", "usr/local/bin/snell-server", "usr/local/bin/snell",
                     "etc/systemd/system/snell@.service", "account-user", "account-group"):
            self.assertFalse((self.root / name).exists(), name)
        self.assertEqual((self.root / "closed").read_text().splitlines(), ["45000", "45001"])

    def test_snell_unowned_account_and_symlink_marker_are_preserved(self):
        for marker in ("absent", "symlink"):
            with self.subTest(marker=marker):
                self.snell(owned=False)
                if marker == "symlink":
                    (self.root / "etc/snell/.user-created-by-snell-script").symlink_to(self.put("foreign-marker"))
                result = self.run_cleanup()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((self.root / "account-user").exists())
                self.assertTrue((self.root / "account-group").exists())
                self.assertFalse((self.root / "userdel.calls").exists())

    def test_snell_account_or_file_failure_retains_configuration_for_retry(self):
        for mode in ("userdel-failed", "groupdel-failed", "file-delete-failed"):
            with self.subTest(mode=mode):
                self.snell()
                result = self.run_cleanup(mode)
                self.assert_failed(result)
                self.assertTrue((self.root / "etc/snell/.user-created-by-snell-script").exists())
                self.assertTrue((self.root / "etc/snell/45000.conf").exists())
                retry = self.run_cleanup()
                self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)

    def test_snell_partial_install_and_orphan_instances_are_cleaned(self):
        self.snell()
        for name in ("etc/snell/45000.conf", "etc/snell/45001.conf", "active.45000", "active.45001"):
            (self.root / name).unlink()
        self.put("units", "")
        self.put("missing-unit")
        result = self.run_cleanup("missing-unit")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "etc/snell").exists())
        self.snell()
        for name in ("etc/snell/45000.conf", "etc/snell/45001.conf", "missing-unit"):
            (self.root / name).unlink()
        link = self.root / "etc/systemd/system/multi-user.target.wants/snell@45002.service"
        link.parent.mkdir(parents=True)
        link.symlink_to("../snell@.service")
        self.put("enabled.45002")
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(link.is_symlink())
        self.assertIn("stop snell@45002", (self.root / "service.calls").read_text())

    def test_pm_cron_faults_leave_other_jobs_files_and_kernel_state_untouched(self):
        for mode in ("cron-read-failed", "cron-read-empty-failed", "cron-read-diagnostic",
                     "cron-write-failed", "cron-write-noop", "lock-failed"):
            with self.subTest(mode=mode):
                self.pm()
                result = self.run_cleanup(mode)
                self.assert_failed(result)
                self.assertEqual((self.root / "crontab").read_text(), self.cron_original)
                for name in ("etc/port_monitor/config.json", "etc/port_monitor/tc_root_owned", "usr/local/bin/pm", "nft-table", "tc-root"):
                    self.assertTrue((self.root / name).exists(), name)
                self.assertFalse((self.root / "nft.calls").exists())
                self.assertFalse((self.root / "tc.calls").exists())

    def test_pm_kernel_failures_keep_config_log_and_owner_then_allow_retry(self):
        for mode in ("nft-query-failed", "nft-malformed", "nft-delete-failed", "tc-query-failed",
                     "tc-delete-failed", "nft-tc-delete-failed"):
            with self.subTest(mode=mode):
                self.pm()
                result = self.run_cleanup(mode)
                self.assert_failed(result)
                for name in ("etc/port_monitor/config.json", "etc/port_monitor/tc_root_owned", "usr/local/bin/pm", "var/log/port_monitor.log"):
                    self.assertTrue((self.root / name).exists(), name)
                self.assertEqual((self.root / "crontab").read_text(), "0 0 * * * echo keep-other-job\n")
                retry = self.run_cleanup()
                self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
                self.assertFalse((self.root / "etc/port_monitor").exists())

    def test_pm_success_uses_recorded_interface_and_preserves_other_cron_jobs(self):
        self.pm()
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "crontab").read_text(), "0 0 * * * echo keep-other-job\n")
        self.assertEqual((self.root / "tc.calls").read_text().splitlines(), ["qdisc show dev ens4", "qdisc del dev ens4 root"])
        self.assertFalse((self.root / "nft-table").exists())
        self.assertFalse((self.root / "tc-root").exists())
        self.assertFalse((self.root / "etc/port_monitor").exists())
        self.assertTrue((self.root / "var/run/pm_cron.lock").exists())
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_pm_unowned_or_replaced_tc_queue_is_not_deleted(self):
        self.pm(owned=False)
        self.put("tc-root", "qdisc fq_codel 0: root\n")
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "tc.calls").exists())
        self.assertTrue((self.root / "tc-root").exists())
        self.pm()
        self.put("tc-root", "qdisc fq_codel 0: root\n")
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("qdisc del", (self.root / "tc.calls").read_text())
        self.assertTrue((self.root / "tc-root").exists())

    def test_pm_missing_rules_and_no_crontab_are_safe(self):
        self.pm(owned=False)
        (self.root / "nft-table").unlink()
        result = self.run_cleanup("no-crontab")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("delete", (self.root / "nft.calls").read_text())
        self.assertFalse((self.root / "cron-written").exists())

    def test_pm_file_failure_does_not_discard_config(self):
        self.pm()
        result = self.run_cleanup("file-delete-failed")
        self.assert_failed(result)
        self.assertTrue((self.root / "etc/port_monitor/config.json").exists())
        self.assertTrue((self.root / "etc/port_monitor/tc_root_owned").exists())

    def test_symlink_configuration_paths_are_rejected(self):
        for name in ("etc/snell", "etc/port_monitor"):
            with self.subTest(name=name):
                foreign = self.root / "foreign-config"
                foreign.mkdir(exist_ok=True)
                (foreign / "data").write_text("keep")
                (self.root / name).symlink_to(foreign)
                result = self.run_cleanup()
                self.assert_failed(result)
                self.assertEqual((foreign / "data").read_text(), "keep")
                (self.root / name).unlink()

    def test_one_module_failure_does_not_block_other_module_cleanup(self):
        self.snell()
        self.pm()
        result = self.run_cleanup("stop-failed")
        self.assert_failed(result)
        self.assertTrue((self.root / "etc/snell/45000.conf").exists())
        self.assertFalse((self.root / "etc/port_monitor").exists())

    def test_real_firewall_helpers_propagate_backend_query_and_delete_failures(self):
        code = r'''
# Reload VT's actual port helpers; backend commands remain isolated below.
source "$TEST_LIB"
command() {
    if [[ "$1" == -v ]]; then
        case "$2" in
            ufw|firewall-cmd|iptables|iptables-save)
                case "$MODE:$2" in
                    ufw*:ufw|firewalld*:firewall-cmd|iptables*:iptables|iptables*:iptables-save) return 0 ;;
                    *) return 1 ;;
                esac ;;
        esac
    fi
    builtin command "$@"
}
ufw() { echo "$*" >> "$TEST_DIR/backend.calls"; [[ "$MODE" != ufw-failed ]]; }
firewall-cmd() { echo "$*" >> "$TEST_DIR/backend.calls"; [[ "$MODE" != firewalld-failed ]]; }
iptables() {
    echo "$*" >> "$TEST_DIR/backend.calls"
    case "$1" in
        -C)
            case "$MODE" in
                iptables-query-failed) return 4 ;;
                iptables-absent) return 1 ;;
            esac ;;
        -D) [[ "$MODE" != iptables-delete-failed ]] || return 1 ;;
    esac
}
iptables-save() { [[ "$MODE" != iptables-save-failed ]] || return 1; echo rules; }
nuke_all
'''
        (self.root / "etc/iptables").mkdir()
        for mode in ("ufw-failed", "firewalld-failed", "iptables-query-failed",
                     "iptables-delete-failed", "iptables-save-failed", "iptables-absent", "iptables-ok"):
            with self.subTest(mode=mode):
                self.snell()
                (self.root / "backend.calls").unlink(missing_ok=True)
                result = self.run_cleanup(mode, action=code)
                failed = mode.endswith("failed")
                if failed:
                    self.assert_failed(result)
                    self.assertTrue((self.root / "etc/snell/45000.conf").exists())
                    self.assertTrue((self.root / "account-user").exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse((self.root / "etc/snell").exists())
                calls = (self.root / "backend.calls").read_text()
                if mode.startswith("iptables"):
                    self.assertIn("-p tcp", calls)
                    self.assertIn("-p udp", calls)
                if mode == "iptables-query-failed":
                    self.assertNotIn("-D INPUT", calls)
                    self.assertNotIn("-I INPUT", calls)

    def test_cancel_or_eof_never_deletes_files(self):
        self.snell()
        self.pm()
        for data in ("", "no\n", "\n"):
            result = self.run_cleanup(data=data)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((self.root / "etc/snell/45000.conf").exists())
            self.assertTrue((self.root / "etc/port_monitor/config.json").exists())
            self.assertFalse((self.root / "service.calls").exists())


if __name__ == "__main__":
    unittest.main()

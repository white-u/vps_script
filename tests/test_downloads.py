"""Exercise actual download/update functions with real curl and local HTTP only."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("BASH_BIN", shutil.which("bash") or "/bin/bash")


def function(source, name):
    match = re.search(r"(?ms)^" + name + r"\(\) \{.*?^\}", source)
    if not match:
        raise AssertionError(f"Missing function: {name}")
    return match[0] + "\n"


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vt-download-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def run_http(self, code, body, status=200, **env):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                return subprocess.run(
                    [BASH, "-c", code], text=True, capture_output=True, timeout=6,
                    env={**os.environ, "TEST_DIR": str(self.root),
                         "HTTP_URL": f"http://127.0.0.1:{server.server_port}/asset", **env},
                )
            finally:
                server.shutdown()
                thread.join()

    def wrapper(self):
        return r'''
_CLEANUP_FILES=()
trap 'for item in "${_CLEANUP_FILES[@]}"; do rm -rf "$item"; done' EXIT
curl() {
    printf '%s\n' "$@" >> "$TEST_DIR/curl.args"
    local arg args=()
    for arg in "$@"; do
        case "$arg" in https://*) args+=("$HTTP_URL") ;; *) args+=("$arg") ;; esac
    done
    command curl --noproxy '*' "${args[@]}"
}
sleep() { :; }
fresh_script_url() { echo 'https://example.invalid/update'; }
fresh_url() { echo 'https://example.invalid/update'; }
info() { echo "$*"; }
warn() { echo "$*" >&2; }
err() { echo "$*" >&2; exit 1; }
stop_edit_lock() { echo released > "$TEST_DIR/edit-lock-released"; }
mktemp() {
    local arg args=()
    for arg in "$@"; do
        case "$arg" in /tmp/*) args+=("$TEST_DIR/${arg##*/}") ;; *) args+=("$arg") ;; esac
    done
    command mktemp "${args[@]}"
}
SCRIPT_PATH="$TEST_DIR/installed"
INSTALL_PATH="$SCRIPT_PATH"
VT_INSTALL_PATH="$SCRIPT_PATH"
SCRIPT_URL='https://example.invalid/update'
VT_URL="$SCRIPT_URL"
'''

    def test_manual_updates_show_progress_validate_and_preserve_existing_on_failure(self):
        for module in ("vt", "snell", "sb", "pm", "fw"):
            source = (ROOT / f"{module}.sh").read_text()
            key = "VT_VERSION" if module == "vt" else "SCRIPT_VERSION"
            version = re.search(r'^' + key + r'="([^"]+)"', source, re.M)[1]
            update = "update_self" if module == "vt" else "update_script"
            validate = "validate_script_file" if module == "vt" else "validate_script_candidate"
            code = self.wrapper() + f'{key}="{version}"\n'
            code += function(source, validate) + function(source, "version_is_older") + function(source, update)
            code += update + (" cli\n" if module == "fw" else "\n")
            for mode in ("ok", "http-error", "invalid", "downgrade", "unchanged"):
                with self.subTest(module=module, mode=mode):
                    (self.root / "curl.args").unlink(missing_ok=True)
                    payload = f'#!/bin/bash\n{key}="{version}"\necho UPDATED\n' + "# padding\n" * 15000
                    original = payload if mode == "unchanged" else "original script\n"
                    (self.root / "installed").write_text(original)
                    if mode == "invalid": payload = "not a script\n"
                    if mode == "downgrade": payload = f'#!/bin/bash\n{key}="0.0.1"\n'
                    result = self.run_http(code, payload.encode(), 503 if mode == "http-error" else 200)
                    args = (self.root / "curl.args").read_text().splitlines()
                    self.assertIn("--progress-bar", args)
                    self.assertIn("--connect-timeout", args)
                    self.assertNotIn("-s", args)
                    if mode in ("ok", "unchanged"):
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertRegex(result.stderr, r"100(?:\.0)?%")
                        self.assertEqual((self.root / "installed").read_text(), payload)
                        if mode == "unchanged":
                            self.assertIn("已是最新版本", result.stdout)
                            self.assertNotIn("\nUPDATED\n", result.stdout)
                        elif module != "fw":
                            self.assertIn("\nUPDATED\n", result.stdout)
                    else:
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual((self.root / "installed").read_text(), original)
                        self.assertNotIn("\nUPDATED\n", result.stdout)

    def test_snell_core_download_has_progress_and_keeps_existing_files_on_failure(self):
        source = (ROOT / "snell.sh").read_text()
        code = self.wrapper() + r'''
SNELL_VERSION=5.0.1
SNELL_BIN="$TEST_DIR/core"
SNELL_CONF_DIR="$TEST_DIR/config"
SERVICE_FILE="$TEST_DIR/service"
DL_BASE='https://example.invalid'
get_stable_asset_info() { printf 'amd64\t%s\t%s\n' "$ZERO_SHA" "$ZERO_SHA"; }
get_installed_full_ver() { echo 5.0.0; }
write_service_candidate() { echo candidate > "$1"; }
if ! command -v sha256sum >/dev/null 2>&1; then sha256sum() { shasum -a 256 "$@"; }; fi
'''
        code += function(source, "version_is_older") + function(source, "install_core") + "install_core\n"
        for mode in ("http-error", "bad-hash"):
            with self.subTest(mode=mode):
                (self.root / "core").write_text("old core")
                (self.root / "service").write_text("old unit")
                result = self.run_http(code, b"incorrect archive" * 10000,
                                       503 if mode == "http-error" else 200, ZERO_SHA="0" * 64)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((self.root / "core").read_text(), "old core")
                self.assertEqual((self.root / "service").read_text(), "old unit")
                self.assertNotIn("正在解压", result.stdout)
                if mode == "http-error":
                    self.assertNotIn("下载完成", result.stdout)
                else:
                    self.assertRegex(result.stderr, r"100(?:\.0)?%")
                    self.assertIn("下载完成，正在校验", result.stdout)
                    self.assertIn("SHA256 校验失败", result.stderr)

    def test_vt_dispatch_validates_download_and_returns_child_failure(self):
        source = (ROOT / "vt.sh").read_text()
        code = self.wrapper() + function(source, "validate_script_file") + function(source, "report_child_exit")
        code += function(source, "dispatch").replace('/usr/local/bin/', str(self.root) + '/')
        code += 'dispatch test-child child https://example.invalid/child\n'
        for mode in ("ok", "http-error", "invalid", "child-error"):
            with self.subTest(mode=mode):
                (self.root / "child").unlink(missing_ok=True)
                payload = '#!/bin/bash\nSCRIPT_VERSION="1.0"\necho CHILD_RAN\n' + "# pad\n" * 20000
                if mode == "invalid": payload = "bad script\n"
                if mode == "child-error": payload += "exit 42\n"
                result = self.run_http(code, payload.encode(), 503 if mode == "http-error" else 200)
                self.assertEqual(result.returncode, 0 if mode == "ok" else 42 if mode == "child-error" else 1,
                                 result.stdout + result.stderr)
                if mode in ("ok", "child-error"):
                    self.assertIn("CHILD_RAN", result.stdout)
                    self.assertRegex(result.stderr, r"100(?:\.0)?%")
                    # Repeat through the installed-command path (no download).
                    installed = self.run_http(code, b"unused", 503)
                    self.assertEqual(installed.returncode, result.returncode)
                    self.assertIn("CHILD_RAN", installed.stdout)
                    if mode == "child-error": self.assertIn("退出码 42", result.stderr)
                else:
                    self.assertFalse((self.root / "child").exists())
                    self.assertNotIn("CHILD_RAN", result.stdout)

    def test_singbox_both_download_attempts_keep_meter_timeout_and_failure_message(self):
        source = (ROOT / "sb.sh").read_text()
        code = self.wrapper() + r'''
SB_BIN="$TEST_DIR/core"
PINNED_SB_VERSION=1.14.0
init_meta_if_missing() { :; }
init_config_if_missing() { :; }
map_arch_sb() { echo amd64; }
get_current_sb_ver() { echo 1.13.0; }
get_release_asset_name() { echo sing-box-1.14.0-linux-amd64-musl.tar.gz; }
'''
        code += function(source, "version_is_older") + function(source, "install_singbox") + "install_singbox\n"
        (self.root / "core").write_text("old core")
        result = self.run_http(code, b"error", 404)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "core").read_text(), "old core")
        self.assertIn("尝试旧版通用静态构建", result.stdout)
        self.assertIn("下载失败", result.stdout)
        args = (self.root / "curl.args").read_text().splitlines()
        self.assertEqual(args.count("--connect-timeout"), 2)
        self.assertEqual(args.count("--max-time"), 2)
        self.assertNotIn("-s", args)
        self.assertNotIn("--silent", args)


if __name__ == "__main__":
    unittest.main()

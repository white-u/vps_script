"""VT menu input regression tests; no host services or installed scripts are used."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("BASH_BIN", shutil.which("bash") or "/bin/bash")


class VTMenuInputTests(unittest.TestCase):
    def run_menu(self, data, close_stdin=False, setup=""):
        functions, marker, _ = (ROOT / "vt.sh").read_text().partition("# ─────────────────── 入口")
        self.assertTrue(marker, "VT entry marker missing; refuse to execute installation")
        with tempfile.TemporaryDirectory(prefix="vt-input-test-") as tmp:
            library = Path(tmp) / "vt-functions.sh"
            library.write_text(functions)
            code = r'''
source "$TEST_LIB"
renders=0
clear() {
    renders=$((renders + 1))
    if [[ "$renders" -gt 4 ]]; then echo REPEATED_MENU >&2; exit 97; fi
}
sys_info() { :; }
status_line() { :; }
snell_version() { :; }
sb_version() { :; }
pm_version() { :; }
fw_version() { :; }
dispatch() { echo "DISPATCH:$2"; }
nuke_all() { echo UNEXPECTED_UNINSTALL; }
update_self() { echo UNEXPECTED_UPDATE; }
'''
            code += setup
            if close_stdin:
                code += "exec 0<&-\n"
            result = subprocess.run(
                [BASH, "-c", code + "main_menu\n"], input=data, text=True,
                env={**os.environ, "TEST_LIB": str(library)},
                capture_output=True, timeout=3,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("REPEATED_MENU", result.stderr)
        self.assertNotIn("UNEXPECTED_", result.stdout)
        return result

    def test_eof_exits_without_repeating_menu(self):
        result = self.run_menu("")
        self.assertEqual(result.stdout.count("VPS 工具箱"), 1)
        self.assertIn("输入已结束", result.stdout)
        self.assertNotIn("DISPATCH:", result.stdout)

    def test_blank_or_invalid_choice_then_eof_exits(self):
        for data in ("\n", "99\n"):
            with self.subTest(data=data):
                result = self.run_menu(data)
                self.assertEqual(result.stdout.count("VPS 工具箱"), 2)
                self.assertIn("输入已结束", result.stdout)
                self.assertNotIn("DISPATCH:", result.stdout)

    def test_dispatch_then_eof_does_not_repeat_action(self):
        result = self.run_menu("1\n")
        self.assertEqual(result.stdout.count("DISPATCH:snell"), 1)
        self.assertEqual(result.stdout.count("VPS 工具箱"), 2)
        self.assertIn("输入已结束", result.stdout)

    def test_zero_still_exits_normally(self):
        result = self.run_menu("0\n")
        self.assertEqual(result.stdout.count("VPS 工具箱"), 1)
        self.assertNotIn("输入已结束", result.stdout)

    def test_closed_stdin_exits_without_refresh_loop(self):
        result = self.run_menu("", close_stdin=True)
        self.assertEqual(result.stdout.count("VPS 工具箱"), 1)
        self.assertIn("输入已结束", result.stdout)

    def test_failed_child_or_uninstall_keeps_result_until_enter(self):
        for choice in ("1", "2", "3", "4", "8"):
            with self.subTest(choice=choice):
                result = self.run_menu(choice + "\n\n0\n", setup=r'''
dispatch() { echo ACTION_FAILED; return 1; }
nuke_all() { echo ACTION_FAILED; return 1; }
read() { printf '[PROMPT:%s]\n' "$*"; builtin read "$@"; }
''')
                self.assertEqual(result.stdout.count("ACTION_FAILED"), 1)
                self.assertEqual(result.stdout.count("按回车返回"), 1)
                self.assertEqual(result.stdout.count("VPS 工具箱"), 2)


if __name__ == "__main__":
    unittest.main()

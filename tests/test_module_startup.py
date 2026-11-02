"""Interactive core bootstrap, with real entry logic and mocked system operations."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_downloads import BASH, ROOT, function


class ModuleStartupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='module-startup-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)

    def run_module(self, module, *, installed=False, install_status=0, args=(), via_vt=False,
                   dependency_failure=False, executable=True, fail_install_temp=False):
        core = self.path / (module + '.core')
        if installed:
            core.write_text('existing core')
            core.chmod(0o755 if executable else 0o644)
        elif core.exists():
            core.unlink()
        source = (ROOT / (module + '.sh')).read_text()
        if module == 'sb':
            entry = source.rsplit('\ncheck_root\n', 1)[1]
            entry = 'check_root\n' + entry
            entry = function(source, 'main_menu') + entry
            installer = 'install_singbox'
        else:
            entry = source.split('# ==================== 入口 ====================', 1)[1]
            installer = 'install_core' if module == 'snell' else 'install_realm'
        setup = r'''
set -Eeuo pipefail
BLUE=""; GREEN=""; YELLOW=""; RED=""; PLAIN=""
SNELL_BIN="$CORE"; SB_BIN="$CORE"
info() { echo "$*"; }
warn() { echo "$*" >&2; }
check_root() { echo CHECK_ROOT; }
check_platform() { echo CHECK_PLATFORM; }
check_deps() { echo CHECK_DEPS; [[ "$DEPS_FAIL" != 1 ]] || exit 23; }
require_service_manager() { echo CHECK_SERVICE_MANAGER; }
sync_script() { echo SYNC_SCRIPT; }
init_meta() { echo INIT_META; }
init_meta_if_missing() { echo INIT_META; }
init_config_if_missing() { echo INIT_CONFIG; }
migrate_config_if_needed() { echo MIGRATE; }
realm_installed() { [[ -x "$CORE" ]]; }
show_help() { echo HELP; }
show_all_configs() { echo LIST; }
show_service_status() { echo STATUS; }
menu_status() { echo STATUS; }
update_script() { echo UPDATE; }
uninstall_all() { echo UNINSTALL; }
menu() {
    echo MENU
    if read -r reply; then printf 'NEXT:%s\n' "$reply"; fi
    exit 0
}
clear() { menu; }
'''
        setup += installer + r'''() {
    echo INSTALL
    [[ "$INSTALL_STATUS" != cancelled ]] || return 0
    [[ "$INSTALL_STATUS" == 0 ]] || return "$INSTALL_STATUS"
    printf 'new core' > "$CORE"
    chmod 755 "$CORE"
}
'''
        if fail_install_temp:
            self.assertEqual(module, 'fw')
            setup += function(source, 'install_realm') + r'''
REALM_VERSION=2.9.6
_CLEANUP_FILES=()
detect_realm_asset() { printf 'test-asset\ttest-hash\n'; }
mktemp() { echo 'injected temporary directory failure' >&2; return 1; }
curl() { echo UNEXPECTED_DOWNLOAD; return 1; }
'''
        target = self.path / module
        target.write_text('#!' + BASH + '\n' + setup + entry)
        target.chmod(0o755)
        env = {**os.environ, 'CORE': str(core), 'INSTALL_STATUS': str(install_status),
               'DEPS_FAIL': '1' if dependency_failure else '0'}
        if via_vt:
            vt = (ROOT / 'vt.sh').read_text()
            code = 'RED=""; PLAIN=""\n' + function(vt, 'report_child_exit')
            code += function(vt, 'dispatch').replace('/usr/local/bin/', str(self.path) + '/')
            code += f'\ndispatch {module} {module} https://example.invalid/unused\n'
            command = [BASH, '-c', code]
        else:
            command = [BASH, str(target), *args]
        return subprocess.run(command, input='next-answer\n', text=True, capture_output=True,
                              timeout=5, env=env)

    def test_missing_core_installs_before_menu_without_consuming_input(self):
        for module in ('snell', 'sb', 'fw'):
            for via_vt in (False, True):
                with self.subTest(module=module, via_vt=via_vt):
                    result = self.run_module(module, via_vt=via_vt)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    lines = result.stdout.splitlines()
                    self.assertEqual(lines.count('INSTALL'), 1)
                    self.assertLess(lines.index('CHECK_DEPS'), lines.index('INSTALL'))
                    self.assertLess(lines.index('INSTALL'), lines.index('MENU'))
                    self.assertIn('NEXT:next-answer', lines)
                    self.assertTrue(os.access(self.path / (module + '.core'), os.X_OK))

    def test_installed_core_opens_menu_without_reinstalling_or_changing_binary(self):
        for module in ('snell', 'sb', 'fw'):
            with self.subTest(module=module):
                result = self.run_module(module, installed=True, via_vt=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('INSTALL', result.stdout.splitlines())
                self.assertIn('MENU', result.stdout.splitlines())
                self.assertEqual((self.path / (module + '.core')).read_text(), 'existing core')

    def test_failed_install_stops_before_menu_and_next_selection_retries(self):
        for module in ('snell', 'sb', 'fw'):
            with self.subTest(module=module):
                result = self.run_module(module, install_status=42, via_vt=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('INSTALL', result.stdout.splitlines())
                self.assertNotIn('MENU', result.stdout.splitlines())
                self.assertIn('退出码', result.stdout + result.stderr)
                retry = self.run_module(module, via_vt=True)
                self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
                self.assertIn('MENU', retry.stdout.splitlines())

    def test_nonexecutable_core_is_installed_and_dependency_failure_stops_install(self):
        for module in ('snell', 'sb', 'fw'):
            with self.subTest(module=module):
                result = self.run_module(module, installed=True, executable=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('INSTALL', result.stdout.splitlines())
                result = self.run_module(module, dependency_failure=True)
                self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
                self.assertNotIn('INSTALL', result.stdout.splitlines())
                self.assertNotIn('MENU', result.stdout.splitlines())

    def test_noninteractive_commands_do_not_trigger_bootstrap(self):
        for module in ('snell', 'fw'):
            for command in ('list', 'status', 'update', 'uninstall', 'help', 'install'):
                with self.subTest(module=module, command=command):
                    result = self.run_module(module, args=(command,))
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout.splitlines().count('INSTALL'),
                                     1 if command == 'install' else 0)
                    self.assertNotIn('MENU', result.stdout.splitlines())

    def test_snell_cancelled_install_without_core_does_not_open_menu(self):
        result = self.run_module('snell', install_status='cancelled', via_vt=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('INSTALL', result.stdout.splitlines())
        self.assertNotIn('MENU', result.stdout.splitlines())
        self.assertIn('核心尚未安装', result.stderr)

    def test_fw_temporary_directory_failure_stops_real_installer_before_download(self):
        result = self.run_module('fw', fail_install_temp=True, via_vt=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('injected temporary directory failure', result.stderr)
        self.assertNotIn('UNEXPECTED_DOWNLOAD', result.stdout)
        self.assertNotIn('MENU', result.stdout.splitlines())


if __name__ == '__main__':
    unittest.main()

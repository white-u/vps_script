"""SB signal recovery with real file replacement and a simulated service manager."""

import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from test_downloads import BASH, ROOT


@unittest.skipUnless(shutil.which('jq'), 'requires jq')
class SBInterruptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sb-interrupt-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.lib = self.path / 'library.sh'
        source = (ROOT / 'sb.sh').read_text().rsplit('\ncheck_root\n', 1)[0]
        self.lib.write_text(source)
        self.original = {
            'core': self.core('1.14.1'),
            'config.json': '{"inbounds":[],"route":{"rules":[]}}\n',
            'service': 'original service definition\n',
            'manager': 'original shortcut\n',
        }
        for name, value in self.original.items():
            (self.path / name).write_text(value)
        (self.path / 'core').chmod(0o755)
        (self.path / 'active').touch()
        (self.path / 'enabled').touch()
        (self.path / 'candidate.json').write_text('{"inbounds":[],"route":{"rules":[]},"log":{"level":"debug"}}\n')
        candidate = self.path / 'candidate-core'
        candidate.write_text(self.core('1.14.2'))
        candidate.chmod(0o755)
        with tarfile.open(self.path / 'candidate.tar.gz', 'w:gz') as archive:
            archive.add(candidate, arcname='release/sing-box')

    @staticmethod
    def core(version):
        return f'#!/bin/bash\nif [[ "$1" == version ]]; then echo "sing-box version {version}"; fi\n'

    def run_sb(self, action, *, signal='', mode=''):
        setup = r'''
source "$TEST_DIR/library.sh"
SB_BIN="$TEST_DIR/core"; SB_CONF_DIR="$TEST_DIR"; SB_CONF_FILE="$TEST_DIR/config.json"
SYSTEMD_FILE="$TEST_DIR/service"; OPENRC_FILE="$TEST_DIR/openrc"
INSTALL_PATH="$TEST_DIR/manager"; WORK_DIR="$TEST_DIR"
PINNED_SB_VERSION=1.14.2
detect_service_manager() { echo systemd; }
sleep() { :; }
journalctl() { :; }
init_meta_if_missing() { :; }
init_config_if_missing() { :; }
install_shortcut_cmd() { :; }
migrate_config_if_needed() { :; }
get_release_asset_digest() { return 1; }
curl() {
    while [[ "$1" != -o ]]; do shift; done
    cp "$TEST_DIR/candidate.tar.gz" "$2"
}
systemctl() {
    case "$1" in
        show)
            echo LoadState=loaded
            if [[ -e "$TEST_DIR/active" ]]; then echo ActiveState=active; else echo ActiveState=inactive; fi ;;
        is-active) [[ -e "$TEST_DIR/active" ]] ;;
        is-enabled)
            if [[ -e "$TEST_DIR/enabled" ]]; then echo enabled; else echo disabled; return 1; fi ;;
        enable) touch "$TEST_DIR/enabled" ;;
        disable) rm -f "$TEST_DIR/enabled" ;;
        stop)
            [[ "$MODE" != stop-failed ]] || return 1
            rm -f "$TEST_DIR/active"
            # A repeated signal during recovery must not interrupt the restore.
            if [[ -e "$TEST_DIR/signaled" ]]; then kill -TERM "$$"; fi ;;
        restart)
            if [[ ! -e "$TEST_DIR/restart-attempted" ]]; then
                touch "$TEST_DIR/restart-attempted"
                if [[ -n "$TEST_SIGNAL" ]]; then
                    touch "$TEST_DIR/signaled"
                    kill -"$TEST_SIGNAL" "$$"
                fi
                [[ "$MODE" != restart-failed ]] || return 1
            fi
            [[ "$MODE" != restore-failed ]] || return 1
            touch "$TEST_DIR/active" ;;
    esac
}
'''
        return subprocess.run([BASH, '-c', setup + action], text=True, capture_output=True, timeout=12,
                              env={**os.environ, 'TEST_DIR': str(self.path), 'TEST_SIGNAL': signal, 'MODE': mode})

    def assert_restored(self, result, status, *, active=True, enabled=True):
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        self.assertIn('已恢复 sing-box 原文件和服务状态', result.stderr)
        for name, content in self.original.items():
            self.assertEqual((self.path / name).read_text(), content, name)
        self.assertEqual((self.path / 'active').exists(), active)
        self.assertEqual((self.path / 'enabled').exists(), enabled)
        self.assertEqual(list(self.path.glob('.sb-recovery.*')), [])

    def test_ctrl_c_during_config_restart_restores_config_and_exits(self):
        result = self.run_sb('safe_save_config "$TEST_DIR/candidate.json"\necho UNEXPECTED_CONTINUE', signal='INT')
        self.assert_restored(result, 130)
        self.assertNotIn('UNEXPECTED_CONTINUE', result.stdout)

    def test_term_during_core_upgrade_restores_binary_service_and_config(self):
        result = self.run_sb('install_singbox\necho UNEXPECTED_CONTINUE', signal='TERM')
        self.assert_restored(result, 143)
        self.assertNotIn('UNEXPECTED_CONTINUE', result.stdout)

    def test_interrupted_upgrade_preserves_previously_stopped_disabled_service(self):
        (self.path / 'active').unlink()
        (self.path / 'enabled').unlink()
        self.assert_restored(self.run_sb('install_singbox', signal='TERM'), 143, active=False, enabled=False)

    def test_hup_after_upgrade_migrates_config_restores_both_original_files(self):
        result = self.run_sb(r'''
migrate_config_if_needed() {
    safe_save_config "$TEST_DIR/candidate.json" || return 1
    kill -HUP "$$"
}
install_singbox
''')
        self.assert_restored(result, 129)

    def test_restart_failure_uses_same_rollback(self):
        result = self.run_sb('safe_save_config "$TEST_DIR/candidate.json"', mode='restart-failed')
        self.assert_restored(result, 1)

    def test_failed_recovery_keeps_original_backup_and_reports_path(self):
        result = self.run_sb('safe_save_config "$TEST_DIR/candidate.json"', signal='TERM', mode='restore-failed')
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        backups = list(self.path.glob('.sb-recovery.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / '0').read_text(), self.original['config.json'])
        self.assertIn(str(backups[0]), result.stderr)
        self.assertIn('回滚未完成', result.stderr)

    def test_failed_stop_preserves_live_candidate_and_backup(self):
        result = self.run_sb('install_singbox', signal='TERM', mode='stop-failed')
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn('无法停止 sing-box', result.stderr)
        self.assertTrue((self.path / 'active').exists())
        self.assertTrue((self.path / 'service').is_file())
        self.assertEqual((self.path / 'core').read_text(), self.core('1.14.2'))
        backups = list(self.path.glob('.sb-recovery.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / '1').read_text(), self.original['core'])
        self.assertIn(str(self.path / 'core'), (backups[0] / 'paths.tsv').read_text())


if __name__ == '__main__':
    unittest.main()

"""Snell release discovery, configuration migration, install and rollback behavior."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from test_downloads import BASH, ROOT, function

SOURCE = (ROOT / 'snell.sh').read_text()


class SnellTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='snell-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def run_shell(self, names, code, stdin=''):
        setup = r'''
set -Eeuo pipefail
_CLEANUP_FILES=()
trap 'rc=$?; for item in "${_CLEANUP_FILES[@]+"${_CLEANUP_FILES[@]}"}"; do rm -rf "$item"; done; exit "$rc"' EXIT
BLUE=""; PLAIN=""
SNELL_CONF_DIR="$TEST_DIR/config"
SNELL_BIN="$TEST_DIR/core"
SYSTEMD_DIR="$TEST_DIR/systemd"
SERVICE_FILE="$SYSTEMD_DIR/service"
USER_MARKER="$SNELL_CONF_DIR/marker"
DL_BASE=https://dl.nssurge.com/snell
RELEASE_URL=https://example.invalid/releases
info() { echo "$*"; }
warn() { echo "$*" >&2; }
uname() { echo "${ARCH:-x86_64}"; }
mktemp() {
    local arg args=()
    for arg in "$@"; do
        case "$arg" in /tmp/snell_service.*|/tmp/snell_install.*) args+=("$TEST_DIR/${arg##*/}") ;; *) args+=("$arg") ;; esac
    done
    command mktemp "${args[@]}"
}
if ! command -v sha256sum >/dev/null 2>&1; then sha256sum() { shasum -a 256 "$@"; }; fi
'''
        script = setup + ''.join(function(SOURCE, n) for n in names) + code
        return subprocess.run([BASH, '-c', script], input=stdin, text=True,
                              capture_output=True, timeout=15,
                              env={**os.environ, 'TEST_DIR': str(self.root)})

    def test_discovery_uses_highest_numeric_official_asset_for_architecture(self):
        result = self.run_shell(['version_is_older', 'get_stable_asset_info', 'resolve_latest_release'], r'''
SNELL_VERSION=""
curl() { cat <<'EOF'
https://dl.nssurge.com/snell/snell-server-v5.0.1-linux-amd64.zip
https://dl.nssurge.com/snell/snell-server-v6.2.0-linux-amd64.zip
https://dl.nssurge.com/snell/snell-server-v6.10.0-linux-amd64.zip
https://dl.nssurge.com/snell/snell-server-v6.11.0b1-linux-amd64.zip
https://evil.invalid/snell/snell-server-v6.99.0-linux-amd64.zip
https://dl.nssurge.com/snell/snell-server-v6.99.0-linux-aarch64.zip
EOF
}
resolve_latest_release
[[ "$SNELL_VERSION" == 6.10.0 ]]
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_discovery_failure_and_unsupported_major_do_not_fall_back(self):
        for payload in ('', 'https://evil.invalid/v6.0.0.zip',
                        'https://dl.nssurge.com/snell/snell-server-v5.0.1-linux-amd64.zip',
                        'https://dl.nssurge.com/snell/snell-server-v7.0.0-linux-amd64.zip'):
            with self.subTest(payload=payload):
                result = self.run_shell(['version_is_older', 'get_stable_asset_info', 'resolve_latest_release'],
                                        'SNELL_VERSION=""\ncurl() { printf "%s" ' + repr(payload) + '; }\nresolve_latest_release\n')
                self.assertNotEqual(result.returncode, 0)
        result = self.run_shell(['get_stable_asset_info', 'resolve_latest_release'],
                                'SNELL_VERSION=""\ncurl() { return 22; }\nresolve_latest_release\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('无法读取', result.stderr)

    def test_v6_known_hashes_and_new_release_unpinned_marker(self):
        result = self.run_shell(['get_stable_asset_info'], r'''
SNELL_VERSION=6.0.0
get_stable_asset_info
ARCH=arm64 get_stable_asset_info
SNELL_VERSION=6.1.0
get_stable_asset_info
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split('\t') for line in result.stdout.splitlines()]
        self.assertEqual([r[0] for r in rows], ['amd64', 'aarch64', 'amd64'])
        self.assertEqual(len(rows[0][1]), 64)
        self.assertEqual(len(rows[1][2]), 64)
        self.assertEqual(rows[2][1:], ['-', '-'])

    def prepare_install(self, version='6.1.0', reported=None):
        conf = self.root / 'config'
        conf.mkdir()
        (self.root / 'systemd').mkdir()
        (conf / '.version').write_text('5.0.1\n')
        (conf / '100.conf').write_text('[snell-server]\nlisten = ::0:100\npsk = KEEP\nobfs = http\nobfs-host = example.com\ndns = 1.1.1.1\n')
        (conf / '200.conf').write_text('[snell-server]\nlisten = ::0:200\npsk = STOPPED\nobfs = off\n')
        (self.root / 'core').write_text('old core')
        (self.root / 'core').chmod(0o755)
        (self.root / 'systemd/service').write_text('old service')
        (self.root / 'active.100').touch()
        candidate = f'#!/bin/bash\necho "2026-10-29 17:59:37.379545 [server_main] <NOTIFY> snell-server v{reported or version} (test)"\n'
        with zipfile.ZipFile(self.root / 'asset.zip', 'w') as archive:
            archive.writestr('snell-server', candidate)
        return candidate

    def install(self, extra='', stdin='y\n', version='6.1.0'):
        names = ['version_is_older', 'get_installed_full_ver', 'strip_cr', 'read_config_value',
                 'core_configs_need_migration', 'rollback_core_install', 'preserve_core_backup',
                 'interrupt_core_install', 'install_core']
        return self.run_shell(names, f'SNELL_VERSION={version}\n' + r'''
resolve_latest_release() { :; }
get_stable_asset_info() { printf 'amd64\t-\t-\n'; }
curl() { cp "$TEST_DIR/asset.zip" "$TEST_DIR/download.zip"; local prev="" arg; for arg in "$@"; do
    if [[ "$prev" == -o ]]; then cp "$TEST_DIR/asset.zip" "$arg"; fi
    prev=$arg
 done; }
write_service_candidate() { echo 'new service' > "$1"; }
ensure_snell_user() { :; }
secure_config_permissions() { :; }
id() { return 0; }
timeout() { shift; "$@"; }
sleep() { :; }
journalctl() { :; }
systemctl() {
    echo "$*" >> "$TEST_DIR/service.calls"
    local op=$1 port=${2:-}
    port=${port#snell@}
    case "$op" in
        is-active) port=${3#snell@}; [[ -f "$TEST_DIR/active.$port" ]] ;;
        stop) rm -f "$TEST_DIR/active.$port" ;;
        start)
            [[ "${FAIL_ALL_START:-false}" != true ]] || return 1
            if [[ -f "$TEST_DIR/fail-start" ]]; then rm "$TEST_DIR/fail-start"; return 1; fi
            touch "$TEST_DIR/active.$port" ;;
        daemon-reload) : ;;
        *) return 1 ;;
    esac
}
''' + extra + '\ninstall_core\n', stdin)

    def test_upgrade_migrates_all_configs_preserves_psk_and_stopped_instances(self):
        candidate = self.prepare_install()
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        conf = self.root / 'config'
        for port, key in ((100, 'KEEP'), (200, 'STOPPED')):
            text = (conf / f'{port}.conf').read_text()
            self.assertIn(f'psk = {key}', text)
            self.assertIn('mode = default', text)
            self.assertNotIn('obfs', text)
        self.assertTrue((self.root / 'active.100').exists())
        self.assertFalse((self.root / 'active.200').exists())
        self.assertEqual((conf / '.version').read_text().splitlines(),
                         ['6.1.0', hashlib.sha256(candidate.encode()).hexdigest()])
        again = self.install(stdin='')
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertIn('无需更新', again.stdout)
        self.assertEqual((self.root / 'service.calls').read_text().count('stop '), 1)

    def test_failed_restart_restores_core_metadata_and_all_configs(self):
        self.prepare_install()
        originals = {p: p.read_bytes() for p in (self.root / 'config').iterdir()}
        (self.root / 'fail-start').touch()
        result = self.install()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('已恢复旧核心', result.stderr)
        for p, data in originals.items():
            self.assertEqual(p.read_bytes(), data)
        self.assertEqual((self.root / 'core').read_text(), 'old core')
        self.assertEqual((self.root / 'systemd/service').read_text(), 'old service')
        self.assertTrue((self.root / 'active.100').exists())
        self.assertFalse((self.root / 'active.200').exists())

    def test_declined_major_upgrade_does_not_download_or_stop(self):
        self.prepare_install()
        result = self.install(stdin='n\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'download.zip').exists())
        self.assertFalse((self.root / 'service.calls').exists())

    def test_wrong_reported_version_or_invalid_zip_keeps_installation(self):
        self.prepare_install(reported='6.0.0')
        for corrupt in (False, True):
            if corrupt:
                (self.root / 'asset.zip').write_text('not a zip')
            result = self.install()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((self.root / 'core').read_text(), 'old core')
            self.assertEqual((self.root / 'config/.version').read_text(), '5.0.1\n')
            self.assertFalse((self.root / 'service.calls').exists())

    def test_new_instance_uses_v6_defaults_and_exports_matching_client(self):
        conf = self.root / 'config'; conf.mkdir()
        (self.root / 'systemd').mkdir()
        (self.root / 'systemd/service').touch()
        (self.root / 'core').touch(); (self.root / 'core').chmod(0o755)
        result = self.run_shell(['strip_cr', 'read_config_value', 'format_client_config', 'add_instance'], r'''
FIREWALL_BACKEND=""
ensure_snell_user() { :; }
secure_config_permissions() { :; }
get_installed_major_ver() { echo 6; }
ss() { :; }
chown() { :; }
systemctl() { return 0; }
sleep() { :; }
open_port() { :; }
show_single_config() { format_client_config "$1" 1.2.3.4; }
add_instance
''', '12345\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        content = (conf / '12345.conf').read_text()
        self.assertIn('listen = 0.0.0.0:12345,[::]:12345', content)
        self.assertIn('mode = default', content)
        self.assertIn('dns-ip-preference = default', content)
        self.assertNotIn('obfs', content)
        self.assertIn('version=6', result.stdout)
        self.assertIn('mode=default', result.stdout)

    def test_modified_local_binary_is_repaired(self):
        self.prepare_install()
        first = self.install()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        (self.root / 'core').write_text('modified core')
        repaired = self.install(stdin='')
        self.assertEqual(repaired.returncode, 0, repaired.stdout + repaired.stderr)
        self.assertNotIn('无需更新', repaired.stdout)
        self.assertIn('snell-server v6.1.0', (self.root / 'core').read_text())

    def test_config_replacement_is_staged_on_target_filesystem(self):
        self.prepare_install()
        result = self.install(extra=r'''
mv() {
    if [[ "$1" == -f && "$3" == "$SNELL_CONF_DIR/"*.conf ]]; then
        [[ "$2" == "$SNELL_CONF_DIR/.core-configs."*/* ]] || return 1
        echo checked >> "$TEST_DIR/config-moves"
    fi
    command mv "$@"
}
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / 'config-moves').read_text().splitlines(), ['checked', 'checked'])

    def test_interruption_after_config_replacement_restores_old_install(self):
        self.prepare_install()
        originals = {p: p.read_bytes() for p in (self.root / 'config').iterdir()}
        result = self.install(extra=r'''
mv() {
    command mv "$@" || return
    if [[ "$3" == "$SNELL_CONF_DIR/"*.conf && ! -f "$TEST_DIR/interrupted" ]]; then
        touch "$TEST_DIR/interrupted"
        kill -TERM "$$"
    fi
}
''')
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        for p, data in originals.items():
            self.assertEqual(p.read_bytes(), data)
        self.assertEqual((self.root / 'core').read_text(), 'old core')
        self.assertTrue((self.root / 'active.100').exists())
        self.assertFalse((self.root / 'active.200').exists())
        self.assertFalse(list((self.root / 'config').glob('.core-configs.*')))

    def test_failed_rollback_retains_backup_for_manual_recovery(self):
        self.prepare_install()
        result = self.install(extra=r'''
cp() {
    if [[ "$1" == -a && "$2" == */backup/snell-server ]]; then return 1; fi
    command cp "$@"
}
# Force both the update and rollback restart to fail.
FAIL_ALL_START=true
''')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('恢复备份已保留在', result.stderr)
        backups = list(self.root.glob('snell_install.*/backup/snell-server'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), 'old core')

    def test_client_export_modes_and_legacy_obfs(self):
        conf = self.root / 'config'; conf.mkdir()
        for version, settings, expected in (
            (6, '', ', mode=default'), (6, 'mode = unshaped', ', mode=unshaped'),
            (6, 'mode = unsafe-raw', ', mode=unsafe-raw'), (6, 'mode = bad', None),
            (6, 'obfs = http', None), (5, 'obfs = http', ', obfs=http')):
            with self.subTest(version=version, settings=settings):
                (conf / '100.conf').write_text('psk = SECRET\n' + settings + '\n')
                result = self.run_shell(['read_config_value', 'format_client_config'],
                                        f'get_installed_major_ver() {{ echo {version}; }}\nformat_client_config 100 1.2.3.4\n')
                if expected is None:
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f'version={version}', result.stdout)
                    self.assertIn(expected, result.stdout)


if __name__ == '__main__':
    unittest.main()

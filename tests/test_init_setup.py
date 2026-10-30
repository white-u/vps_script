"""Initialization failure paths, using temporary files and mocked system services."""

import shutil
import unittest

import test_init_network_security as security
from test_downloads import function

INIT = security.INIT
KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILriFq6rHMsegrs53OICXUTSvwd0QTdxJAZA4xr68I9h os@netcatty'


def functions(*names):
    return ''.join(function(INIT, n) for n in names)


HELPERS = functions('fail', 'warn', 'read_prompt') + next(
    line for line in INIT.splitlines() if line.startswith('strip_cr()')) + '\n'


class BaseToolsTests(security.ShellCase):
    def code(self):
        return HELPERS + functions('install_base_tools') + r'''
dpkg-query() {
    [[ "$MODE" != query-failure ]] || return 2
    if [[ "$MODE" == installed ]]; then printf 'install ok installed'; return 0; fi
    return 1
}
debconf-set-selections() {
    cat > "$TEST_DIR/debconf.selection"
    [[ "$MODE" != seed-failure ]]
}
apt() {
    printf '%s\n' "$DEBIAN_FRONTEND" "$@" > "$TEST_DIR/apt.args"
    [[ "$MODE" != apt-failure ]]
}
install_base_tools
'''

    def test_new_install_seeds_no_daemon_and_uses_noninteractive_package_setup(self):
        self.assert_ok(self.shell(self.code(), MODE='new'))
        self.assertEqual((self.path / 'debconf.selection').read_text(),
                         'iperf3 iperf3/start_daemon boolean false\n')
        args = (self.path / 'apt.args').read_text().splitlines()
        self.assertEqual(args[:3], ['noninteractive', 'install', '-y'])
        for package in ('iperf3', 'curl', 'ca-certificates', 'tzdata', 'python3'):
            self.assertIn(package, args)

    def test_existing_install_keeps_administrator_daemon_setting(self):
        self.assert_ok(self.shell(self.code(), MODE='installed'))
        self.assertFalse((self.path / 'debconf.selection').exists())
        self.assertTrue((self.path / 'apt.args').exists())

    def test_setup_failures_stop_instead_of_reporting_success(self):
        for mode in ('query-failure', 'seed-failure', 'apt-failure'):
            with self.subTest(mode=mode):
                result = self.shell(self.code(), MODE=mode)
                self.assertNotEqual(result.returncode, 0)
                if mode != 'apt-failure':
                    self.assertFalse((self.path / 'apt.args').exists())


class PortInputTests(security.ShellCase):
    def test_ports_are_decimal_and_reject_default_out_of_range_and_oversized_values(self):
        block = INIT.split('# --- 修改端口 ---\n', 1)[1].split('echo -e "${YELLOW}切换 SSH 端口前', 1)[0]
        code = HELPERS + block + '\nprintf "PORT=%s\\n" "$SSH_PORT"'
        result = self.shell(code, stdin='00022\n00000\n65536\n999999999999999999999\n00080\n')
        self.assert_ok(result)
        self.assertIn('不允许使用默认端口 22', result.stdout)
        self.assertIn('PORT=80', result.stdout)
        self.assertEqual(result.stdout.count('无效端口'), 3)


@unittest.skipUnless(shutil.which('ssh-keygen'), 'requires ssh-keygen')
class PublicKeyTests(security.ShellCase):
    def code(self):
        return HELPERS + functions('valid_public_key', 'import_public_key')

    def test_rejects_empty_malformed_multiline_and_private_keys_without_writing(self):
        for value in ('', 'not-a-public-key', 'ssh-ed25519 broken', KEY + '\n' + KEY,
                      '-----BEGIN OPENSSH PRIVATE KEY-----'):
            with self.subTest(value=value):
                result = self.shell(self.code() + '\nimport_public_key "$KEY" "$TEST_DIR/.ssh/authorized_keys"', KEY=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.path / '.ssh').exists())
                self.assertNotIn('公钥已导入', result.stdout)

    def test_valid_ed25519_rsa_and_ecdsa(self):
        import subprocess
        for kind in ('ed25519', 'rsa', 'ecdsa'):
            with self.subTest(kind=kind):
                keyfile = self.path / kind
                generated = subprocess.run(['ssh-keygen', '-q', '-t', kind, '-N', '', '-f', str(keyfile)],
                                           text=True, capture_output=True)
                self.assert_ok(generated)
                self.assert_ok(self.shell(self.code() + '\nvalid_public_key "$KEY"', KEY=keyfile.with_suffix('.pub').read_text().strip()))

    def test_preserves_existing_key_without_newline_and_is_idempotent(self):
        directory = self.path / '.ssh'
        directory.mkdir()
        target = directory / 'authorized_keys'
        target.write_text(KEY + ' old')
        code = self.code() + '\nimport_public_key "$KEY" "$TEST_DIR/.ssh/authorized_keys"'
        self.assert_ok(self.shell(code, KEY=KEY))
        self.assert_ok(self.shell(code, KEY=KEY))
        self.assertEqual(target.read_text().splitlines(), [KEY + ' old', KEY])
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_write_failure_or_nonregular_target_never_reports_imported(self):
        code = self.code() + r'''
mv() { return 1; }
import_public_key "$KEY" "$TEST_DIR/.ssh/authorized_keys"
'''
        result = self.shell(code, KEY=KEY)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('公钥已导入', result.stdout)
        self.assertEqual(list((self.path / '.ssh').iterdir()), [])
        (self.path / '.ssh/authorized_keys').mkdir()
        result = self.shell(self.code() + '\nimport_public_key "$KEY" "$TEST_DIR/.ssh/authorized_keys"', KEY=KEY)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('公钥已导入', result.stdout)

    def test_disable_password_requires_separate_login_confirmation(self):
        target = self.path / 'authorized_keys'
        target.write_text(KEY + '\n')
        block = INIT.split('# --- 禁用密码登录 (独立判断) ---', 1)[1].split('# 应用 SSH 配置', 1)[0]
        apply = INIT.split('# 应用 SSH 配置\n', 1)[1].split('# ==============================', 1)[0]
        code = HELPERS + '''
SSH_PORT=12345
SSH_KEY_FILE="$TEST_DIR/authorized_keys"
sshd_set() { echo WRITE; printf 'ARG:%s\\n' "$@"; }
''' + block + apply
        for answer, disabled in (('y\nyes\n', True), ('y\nno\n', False), ('n\n', False)):
            with self.subTest(answer=answer):
                result = self.shell(code, stdin=answer)
                self.assert_ok(result)
                self.assertEqual('ARG:PasswordAuthentication\nARG:no' in result.stdout, disabled)
                self.assertEqual(result.stdout.count('WRITE'), 1)
        target.write_text('invalid\n')
        result = self.shell(code, stdin='y\nyes\n')
        self.assert_ok(result)
        self.assertNotIn('ARG:PasswordAuthentication', result.stdout)


class SSHTransactionTests(security.ShellCase):
    def setUp(self):
        super().setUp()
        (self.path / 'etc/ssh').mkdir(parents=True)
        self.config = self.path / 'etc/ssh/sshd_config'
        self.original = 'Port 33212\nPasswordAuthentication yes\n'
        self.config.write_text(self.original)
        (self.path / 'home/.ssh').mkdir(parents=True)
        self.keyfile = self.path / 'home/.ssh/authorized_keys'
        self.keyfile.write_text('# original keys\n')

    def code(self):
        code = HELPERS + functions('begin_ssh_transaction', 'sshd_set', 'rollback_ssh_transaction',
                                  'ssh_transaction_exit', 'activate_ssh_settings')
        code = code.replace('/etc/ssh', str(self.path / 'etc/ssh'))
        return code + r'''
getent() { printf 'root:x:0:0:root:%s/home:/bin/bash\n' "$TEST_DIR"; }
command() {
    if [[ "$1" == -v ]]; then return 0; fi
    builtin command "$@"
}
sshd() { return 0; }
systemctl() { echo "$*" >> "$TEST_DIR/systemctl.log"; return 0; }
sleep() { :; }
ss() { echo 'LISTEN 0 128 0.0.0.0:12345 0.0.0.0:* users:(("sshd",pid=42,fd=3))'; }
SSH_SERVICE=ssh
SSH_PORT=12345
begin_ssh_transaction
'''

    def assert_restored(self):
        self.assertEqual(self.config.read_text(), self.original)
        self.assertEqual(self.keyfile.read_text(), '# original keys\n')

    def test_failure_after_first_write_restores_config_and_keys(self):
        code = self.code() + r'''
SSH_KEY_CHANGED=1
echo changed > "$SSH_KEY_FILE"
sshd_set PasswordAuthentication no
mv() { [[ "$2" != *sshd_config.new.* ]] || return 1; command mv "$@"; }
sshd_set Port 12345
'''
        result = self.shell(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('原配置及公钥已恢复', result.stderr)
        self.assert_restored()

    def test_signal_and_eof_restore_pending_configuration(self):
        for stop in ('kill -TERM $$', 'kill -INT $$', 'kill -HUP $$', 'read_prompt reply'):
            with self.subTest(stop=stop):
                result = self.shell(self.code() + '\nsshd_set PasswordAuthentication no\n' + stop)
                self.assertNotEqual(result.returncode, 0)
                self.assert_restored()

    def test_declined_confirmation_or_unrelated_listener_rolls_back_and_reloads(self):
        for override, answer in (('', 'no\n'), ('ss() { echo "LISTEN 0 128 0.0.0.0:12345 0.0.0.0:* users:((nginx,pid=1))"; }', 'yes\n')):
            with self.subTest(override=override):
                result = self.shell(self.code() + '\nsshd_set Port 12345\n' + override + '\nactivate_ssh_settings', stdin=answer)
                self.assertNotEqual(result.returncode, 0)
                self.assert_restored()
                self.assertGreaterEqual((self.path / 'systemctl.log').read_text().count('reload ssh'), 2)

    def test_confirmed_change_commits(self):
        result = self.shell(self.code() + '\nsshd_set Port 12345\nactivate_ssh_settings', stdin='yes\n')
        self.assert_ok(result)
        self.assertIn('Port 12345', self.config.read_text())

    def test_failed_restore_is_reported_with_backup_location(self):
        code = self.code() + '\ncp() { return 1; }\nfail "injected failure"'
        result = self.shell(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SSH 回滚失败', result.stderr)
        self.assertIn('init-backup.', result.stderr)
        self.assertNotIn('原配置及公钥已恢复', result.stderr)

    def test_key_restore_failure_does_not_skip_restoring_running_service(self):
        code = self.code() + r'''
SSH_KEY_CHANGED=1
SSH_RELOAD_ATTEMPTED=1
echo changed > "$SSH_KEY_FILE"
sshd_set Port 12345
mktemp() { [[ "$1" != *authorized_keys.restore.* ]] || return 1; command mktemp "$@"; }
fail "injected failure"
'''
        result = self.shell(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_text(), self.original)
        self.assertIn('reload ssh', (self.path / 'systemctl.log').read_text())
        self.assertIn('SSH 回滚失败', result.stderr)


class NetworkSetupTests(security.ShellCase):
    def timezone_code(self):
        (self.path / 'timezone').write_text('UTC\n')
        return HELPERS + functions('configure_timezone') + r'''
timedatectl() {
    case "$1" in
        show) cat "$TEST_DIR/timezone" ;;
        list-timezones) printf 'UTC\nAsia/Shanghai\nAsia/Singapore\n' ;;
        set-timezone) [[ "$MODE" != apply-failure ]] || return 1; echo "$2" > "$TEST_DIR/timezone" ;;
    esac
}
curl() {
    printf '%s\n' "$@" > "$TEST_DIR/curl.args"
    [[ "$MODE" != network-failure ]] || return 22
    if [[ "$MODE" == primary-failure ]]; then
        [[ "${@: -1}" != https://ipapi.co/timezone/ ]] || return 22
        printf '{"success": true, "timezone": {"id": "Asia/Singapore"}}'
        return
    fi
    printf '%s' "$GUESS"
}
configure_timezone
'''

    def test_geoip_default_manual_override_and_keep(self):
        for answer, expected in (('\n', 'Asia/Shanghai'), ('Asia/Singapore\n', 'Asia/Singapore'), ('keep\n', 'UTC'), ('Bad/Zone\nUTC\n', 'UTC')):
            with self.subTest(answer=answer):
                result = self.shell(self.timezone_code(), stdin=answer, GUESS='Asia/Shanghai')
                self.assert_ok(result)
                self.assertEqual((self.path / 'timezone').read_text().strip(), expected)
                args = (self.path / 'curl.args').read_text()
                self.assertIn('--max-time\n10', args)
                self.assertIn('--proto\n=https', args)

    def test_geoip_failure_keeps_timezone_and_explains_failure(self):
        for mode, guess in (('network-failure', ''), ('bad-response', '$(touch unwanted)'), ('bad-response', '<html>error</html>')):
            with self.subTest(mode=mode, guess=guess):
                result = self.shell(self.timezone_code(), stdin='\n', GUESS=guess, MODE=mode)
                self.assert_ok(result)
                self.assertIn('默认保留 UTC', result.stderr)
                self.assertEqual((self.path / 'timezone').read_text(), 'UTC\n')
        result = self.shell(self.timezone_code(), stdin='\n', GUESS='Asia/Shanghai', MODE='apply-failure')
        self.assertNotEqual(result.returncode, 0)

    def test_geoip_secondary_service_handles_primary_rate_limit(self):
        result = self.shell(self.timezone_code(), stdin='\n', MODE='primary-failure')
        self.assert_ok(result)
        self.assertEqual((self.path / 'timezone').read_text(), 'Asia/Singapore\n')
        self.assertIn('尝试备用服务', result.stderr)

    def ip_code(self):
        return HELPERS + functions('configure_ip_preference').replace('/etc/gai.conf', str(self.path / 'gai.conf')) + '\nconfigure_ip_preference\n'

    def test_default_v4_switch_v6_and_repeated_runs(self):
        target = self.path / 'gai.conf'
        target.write_text('# custom\nlabel fc00::/7 6\nprecedence ::ffff:0:0/96 99\n')
        for answer, value in (('\n', '100'), ('6\n', '10'), ('6\n', '10')):
            result = self.shell(self.ip_code(), stdin=answer)
            self.assert_ok(result)
            text = target.read_text()
            self.assertIn('label fc00::/7 6', text)
            self.assertIn('precedence ::ffff:0:0/96 ' + value, text)
            self.assertEqual(sum(line.startswith('precedence ') for line in text.splitlines()), 5)
            self.assertEqual(text.count('# BEGIN vps-init precedence'), 1)

    def test_keep_and_write_failure_preserve_original(self):
        target = self.path / 'gai.conf'
        original = '# unchanged\n'
        target.write_text(original)
        self.assert_ok(self.shell(self.ip_code(), stdin='keep\n'))
        self.assertEqual(target.read_text(), original)
        result = self.shell('mv() { return 1; }\n' + self.ip_code(), stdin='4\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), original)


if __name__ == '__main__':
    unittest.main()

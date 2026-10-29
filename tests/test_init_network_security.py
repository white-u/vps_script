"""Security regressions; temporary files and mocked installers, no host changes."""

import ipaddress
import os
from pathlib import Path
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from test_downloads import BASH, ROOT, function

INIT = (ROOT / 'init.sh').read_text()
NETWORK = (ROOT / 'network_audit.sh').read_text()
HAS_TIMEOUT = shutil.which('timeout') is not None
IP_FUNCTIONS = ''.join(function(NETWORK, name) for name in
                       ('valid_ipv4', 'valid_ip', 'get_public_ip', 'print_return_command'))


class ShellCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='init-network-security-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)

    def shell(self, code, stdin='', **extra):
        return subprocess.run([BASH, '-c', code], input=stdin, text=True,
                              capture_output=True, timeout=15,
                              env={**os.environ, 'TEST_DIR': str(self.path),
                                   'TMPDIR': str(self.path), **extra})

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class SecurityTests(ShellCase):
    def test_nexttrace_complete_download_only_and_reports_installer_failure(self):
        code = function(INIT, 'install_nexttrace') + r'''
warn() { echo "$*" >&2; }
curl() {
    printf '%s\n' "$@" > "$TEST_DIR/curl.args"
    while [[ "$1" != -o ]]; do shift; done
    local destination=$2
    case "$MODE" in
        empty) : > "$destination" ;;
        syntax) printf 'if then\n' > "$destination" ;;
        *) printf 'touch "$TEST_DIR/executed"\n' > "$destination" ;;
    esac
    [[ "$MODE" != installer-failure ]] || echo 'exit 7' >> "$destination"
    [[ "$MODE" != partial ]] || return 18
}
install_nexttrace
'''
        for mode in ('success', 'partial', 'empty', 'syntax', 'installer-failure'):
            with self.subTest(mode=mode):
                (self.path / 'executed').unlink(missing_ok=True)
                result = self.shell(code, MODE=mode)
                self.assertEqual(result.returncode == 0, mode == 'success', result.stderr)
                self.assertEqual((self.path / 'executed').exists(),
                                 mode in ('success', 'installer-failure'))
                args = (self.path / 'curl.args').read_text().splitlines()
                self.assertEqual(args[0], '-q')
                for key in ('--proto', '--proto-redir'):
                    self.assertEqual(args[args.index(key) + 1], '=https')
                self.assertEqual(args[-1], 'https://nxtrace.org/nt')
                self.assertEqual(sorted(p.name for p in self.path.iterdir()),
                                 ['curl.args', 'executed'] if mode in ('success', 'installer-failure')
                                 else ['curl.args'])

    def test_real_curl_refuses_http_even_if_download_url_is_replaced(self):
        code = function(INIT, 'install_nexttrace') + r'''
warn() { echo "$*" >&2; }
curl() {
    local arg args=()
    for arg in "$@"; do
        [[ "$arg" != https://nxtrace.org/nt ]] || arg=http://127.0.0.1:9/nt
        args+=("$arg")
    done
    command curl "${args[@]}"
}
install_nexttrace
'''
        result = self.shell(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr.lower(), 'protocol|disabled')
        self.assertEqual(list(self.path.iterdir()), [])

    def test_ip_validation_matches_standard_parser_and_rejects_shell_syntax(self):
        values = ['0.0.0.0', '255.255.255.255', '::', '::1', '2001:db8::1',
                  '::ffff:192.0.2.1', '1:2:3:4:5:6:7:8', '', '256.1.1.1',
                  '01.2.3.4', '1.2.3', '1::2::3', '1:2:3:4:5:6:7:8::',
                  ':::1', ':1:2:3:4:5:6:7', '::ffff:999.1.1.1',
                  '1.2.3.4; touch /tmp/unwanted', '$(id)', '-help',
                  '2001:db8::1%eth0', '1.2.3.4\ncommand']
        rng = random.Random(2)
        values += [str(ipaddress.IPv6Address(rng.getrandbits(128))) for _ in range(60)]
        values += [str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(40)]
        for value in values:
            with self.subTest(value=value):
                try:
                    ipaddress.ip_address(value)
                    expected = '%' not in value
                except ValueError:
                    expected = False
                result = self.shell(IP_FUNCTIONS + '\nvalid_ip "$VALUE"', VALUE=value)
                self.assertEqual(result.returncode == 0, expected, result.stderr)

    def test_invalid_endpoint_response_falls_back_and_checks_https(self):
        code = IP_FUNCTIONS + r'''
curl() {
    printf '%s\n' "$@" >> "$TEST_DIR/curl.args"
    case "${@: -1}" in
        https://ipconfig.io) printf '%s' '1.2.3.4; echo injected' ;;
        https://ifconfig.me) printf '%s' "$FALLBACK" ;;
        *) return 1 ;;
    esac
}
get_public_ip
'''
        result = self.shell(code, FALLBACK='2001:db8::1')
        self.assert_ok(result)
        self.assertEqual(result.stdout.strip(), '2001:db8::1')
        args = (self.path / 'curl.args').read_text().splitlines()
        self.assertEqual(args.count('--proto'), 2)
        self.assertEqual(args.count('--proto-redir'), 2)
        self.assertEqual(args.count('=https'), 4)
        result = self.shell(code, FALLBACK='<html>error</html>')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_manual_ip_input_is_validated_before_continuing(self):
        block = NETWORK.split('# 自动获取本机公网 IP\n', 1)[1].split('# 用户输入目标', 1)[0]
        code = IP_FUNCTIONS + '\nget_public_ip() { return 1; }\n' + block + '\necho ACCEPTED'
        for value in ('203.0.113.1', '2001:db8::1', '1.2.3.4; id', '', '1.2.3.999'):
            with self.subTest(value=value):
                result = self.shell(code, stdin=value + '\n')
                self.assertEqual(result.returncode == 0, value in ('203.0.113.1', '2001:db8::1'))
                self.assertEqual('ACCEPTED' in result.stdout, result.returncode == 0)

    def test_return_command_rejects_injection_and_stops_on_failed_download(self):
        bad = self.shell(IP_FUNCTIONS + '\nprint_return_command "$IP"', IP='1.2.3.4; echo injected')
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, '')
        generated = self.shell(IP_FUNCTIONS + '\nprint_return_command "$IP"', IP='2001:db8::1')
        self.assert_ok(generated)
        mocks = r'''
curl() {
    printf '%s\n' "$@" > "$TEST_DIR/curl.args"
    while [[ "$1" != -o ]]; do shift; done
    if [[ "$MODE" == syntax ]]; then
        printf 'if then\n' > "$2"
    else
        printf 'touch "$TEST_DIR/installed"\n' > "$2"
    fi
    [[ "$MODE" != partial ]] || return 18
}
nexttrace() { printf '%s\n' "$@" > "$TEST_DIR/trace.args"; }
'''
        for mode in ('success', 'partial', 'syntax'):
            with self.subTest(mode=mode):
                for file in self.path.iterdir():
                    file.unlink()
                result = self.shell(mocks + generated.stdout, MODE=mode)
                self.assertEqual(result.returncode == 0, mode == 'success', result.stderr)
                self.assertEqual((self.path / 'installed').exists(), mode == 'success')
                self.assertEqual((self.path / 'trace.args').exists(), mode == 'success')
                if mode == 'success':
                    self.assertEqual((self.path / 'trace.args').read_text().splitlines(),
                                     ['-g', 'cn', '2001:db8::1'])
                self.assertFalse(any(p.name.startswith('tmp.') for p in self.path.iterdir()))


class SSHSecurityTests(ShellCase):
    def setUp(self):
        super().setUp()
        self.sshd = shutil.which('sshd') or '/usr/sbin/sshd'
        if not Path(self.sshd).exists() or not shutil.which('ssh-keygen'):
            self.skipTest('SSH effective-configuration tests require sshd and ssh-keygen')
        result = subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                                 '-f', str(self.path / 'hostkey')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.config = self.path / 'sshd_config'
        self.config.write_text(f'HostKey {self.path}/hostkey\n')
        self.config.chmod(0o600)

    def ssh_code(self):
        functions = ''.join(function(INIT, n) for n in
                            ('sshd_set', 'resolve_ssh_client_host', 'validate_sshd_settings'))
        functions = functions.replace('/etc/ssh/sshd_config', str(self.config))
        return functions + r'''
fail() { echo "$*" >&2; exit 1; }
warn() { echo "$*" >&2; }
sshd() { "$SSHD_BIN" -f "$TEST_DIR/sshd_config" "$@"; }
SSH_PORT=12345
DISABLE_PWD=y
SSH_CONNECTION='198.51.100.3 20000 192.0.2.1 22'
'''

    def dns_environment(self, mode='success', address='198.51.100.3'):
        # Mock only NSS/DNS calls in the helper's Python subprocess, leaving the
        # real sshd parser and the actual forward/reverse validation code intact.
        (self.path / 'dns_driver.py').write_text('''
import os
import runpy
import socket
import sys
mock = runpy.run_path(os.path.join(os.environ['TEST_DIR'], 'socket.py'))
socket.getnameinfo = mock['getnameinfo']
socket.getaddrinfo = mock['getaddrinfo']
sys.argv = ['-', sys.argv[-1]]
exec(compile(sys.stdin.read(), '<ssh-dns-helper>', 'exec'))
''')
        bin_dir = self.path / 'bin'
        bin_dir.mkdir(exist_ok=True)
        shim = bin_dir / 'python3'
        shim.write_text('#!/bin/bash\nexec ' + shlex.quote(sys.executable) +
                        ' -I "$DNS_DRIVER" "$@"\n')
        shim.chmod(0o700)
        (self.path / 'socket.py').write_text('''
import os
AF_INET = 2
AF_INET6 = 10
SOCK_STREAM = 1
NI_NAMEREQD = 8
AI_NUMERICHOST = 4
from socket import gaierror
def getnameinfo(peer, flags):
    mode = os.environ['DNS_MODE']
    if mode == 'reverse-failure':
        raise gaierror('No PTR record')
    if mode == 'resolver-error':
        raise TimeoutError('Resolver error')
    if mode == 'native-block':
        import ctypes
        with open(os.environ['DNS_PID_FILE'], 'w') as file:
            file.write(str(os.getpid()))
        ctypes.CDLL(os.environ['DNS_STALL_LIB']).stall(12)
    if mode == 'invalid-host':
        return ('client.example.org,addr=1.2.3.4', '0')
    if mode == 'numeric':
        return (peer[0], '0')
    return ('Client.Example.Org', '0')
def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    mode = os.environ['DNS_MODE']
    if flags == AI_NUMERICHOST:
        if mode != 'numeric':
            raise gaierror('Not a numeric address')
    elif mode == 'forward-failure':
        raise gaierror('No forward record')
    address = '198.51.100.99' if mode == 'mismatch' else os.environ['DNS_ADDRESS']
    return [(family, SOCK_STREAM, 6, '', (address, 0))]
''')
        return {'DNS_DRIVER': str(self.path / 'dns_driver.py'),
                'PATH': str(bin_dir) + os.pathsep + os.environ.get('PATH', ''),
                'DNS_MODE': mode, 'DNS_ADDRESS': address, 'SSHD_BIN': self.sshd}

    def validation_block(self):
        return INIT.split('# 验证配置语法 (防止重启失败导致失联)\n', 1)[1].split(
            'SSH_SERVICE="sshd"', 1)[0].replace('/etc/ssh/sshd_config', str(self.config))

    def apply_settings(self):
        return '''
sshd_set PasswordAuthentication no
sshd_set ChallengeResponseAuthentication no
sshd_set Port "$SSH_PORT"
sshd_set PermitRootLogin yes
sshd_set PubkeyAuthentication yes
'''

    def test_include_precedence_root_login_and_repeated_application(self):
        cloud = self.path / 'cloud.conf'
        cloud.write_text('PasswordAuthentication yes\nKbdInteractiveAuthentication yes\nPermitRootLogin no\n')
        with self.config.open('a') as f:
            f.write(f'Include {cloud}\nPasswordAuthentication yes\n')
        code = self.ssh_code() + self.apply_settings() + self.apply_settings()
        code += '\nsshd -t && validate_sshd_settings && sshd -T'
        result = self.shell(code, SSHD_BIN=self.sshd)
        self.assert_ok(result)
        self.assertIn('permitrootlogin yes', result.stdout)
        self.assertIn('passwordauthentication no', result.stdout)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.config.read_text().count('PasswordAuthentication no'), 1)

    def test_match_override_is_preserved_but_rejected_and_rolled_back(self):
        with self.config.open('a') as f:
            f.write('Match User root\n    PasswordAuthentication yes\n')
        original = self.config.read_bytes()
        backup = self.path / 'backup'
        backup.write_bytes(original)
        validation = INIT.split('# 验证配置语法 (防止重启失败导致失联)\n', 1)[1].split('SSH_SERVICE="sshd"', 1)[0]
        validation = validation.replace('/etc/ssh/sshd_config', str(self.config))
        code = self.ssh_code() + f'\nSSHD_BACKUP="{backup}"\n' + self.apply_settings()
        code += validation + '\necho RELOAD_REACHED'
        result = self.shell(code, SSHD_BIN=self.sshd)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('root', result.stderr)
        self.assertNotIn('RELOAD_REACHED', result.stdout)
        self.assertEqual(self.config.read_bytes(), original)

    def test_password_login_can_be_retained_when_not_disabled(self):
        code = self.ssh_code() + '''
DISABLE_PWD=n
sshd_set Port "$SSH_PORT"
sshd_set PermitRootLogin yes
sshd_set PubkeyAuthentication yes
sshd_set PasswordAuthentication yes
validate_sshd_settings
'''
        self.assert_ok(self.shell(code, SSHD_BIN=self.sshd))

    @unittest.skipUnless(HAS_TIMEOUT, 'DNS verification requires GNU timeout')
    def test_dns_match_authentication_conflicts_restore_original_config(self):
        for setting in ('PasswordAuthentication yes', 'KbdInteractiveAuthentication yes',
                        'PermitRootLogin no', 'PubkeyAuthentication no'):
            with self.subTest(setting=setting):
                self.config.write_text(f'HostKey {self.path}/hostkey\nUseDNS yes\n'
                                       f'Match User root Host *.example.org\n {setting}\n')
                original = self.config.read_bytes()
                (self.path / 'backup').write_bytes(original)
                code = self.ssh_code() + '\nSSHD_BACKUP="$TEST_DIR/backup"\n'
                code += self.apply_settings() + self.validation_block() + '\necho RELOAD_REACHED'
                result = self.shell(code, **self.dns_environment())
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('root-dns', result.stderr)
                self.assertNotIn('RELOAD_REACHED', result.stdout)
                self.assertEqual(self.config.read_bytes(), original)

    @unittest.skipUnless(HAS_TIMEOUT, 'DNS verification requires GNU timeout')
    def test_safe_dns_match_allows_root_keys_and_preserves_usedns(self):
        with self.config.open('a') as config:
            config.write('UseDNS yes\nMatch User root Host client.example.org\n'
                         ' PasswordAuthentication no\n PermitRootLogin yes\n')
        code = self.ssh_code() + self.apply_settings() + '\nvalidate_sshd_settings && sshd -T'
        result = self.shell(code, **self.dns_environment())
        self.assert_ok(result)
        self.assertIn('usedns yes', result.stdout)
        self.assertIn('permitrootlogin yes', result.stdout)

    @unittest.skipUnless(HAS_TIMEOUT, 'DNS verification requires GNU timeout')
    def test_unverifiable_dns_restores_original_without_reload(self):
        for mode in ('reverse-failure', 'forward-failure', 'mismatch', 'resolver-error',
                     'numeric', 'invalid-host'):
            with self.subTest(mode=mode):
                self.config.write_text(f'HostKey {self.path}/hostkey\nUseDNS yes\n')
                original = self.config.read_bytes()
                (self.path / 'backup').write_bytes(original)
                code = self.ssh_code() + '\nSSHD_BACKUP="$TEST_DIR/backup"\n'
                code += self.apply_settings() + self.validation_block() + '\necho RELOAD_REACHED'
                result = self.shell(code, **self.dns_environment(mode))
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('域名验证失败', result.stderr)
                self.assertNotIn('RELOAD_REACHED', result.stdout)
                self.assertEqual(self.config.read_bytes(), original)

    def test_dns_disabled_does_not_invoke_resolver(self):
        with self.config.open('a') as config:
            config.write('UseDNS no\nMatch Host client.example.org\n PasswordAuthentication yes\n')
        code = self.ssh_code() + self.apply_settings() + '''
python3() { echo UNEXPECTED_DNS_LOOKUP >&2; return 1; }
validate_sshd_settings
'''
        result = self.shell(code, SSHD_BIN=self.sshd)
        self.assert_ok(result)
        self.assertNotIn('UNEXPECTED_DNS_LOOKUP', result.stderr)

    def test_dns_enabled_without_connection_stops_before_lookup(self):
        with self.config.open('a') as config:
            config.write('UseDNS yes\n')
        code = self.ssh_code() + self.apply_settings() + '\nunset SSH_CONNECTION\nvalidate_sshd_settings'
        result = self.shell(code, SSHD_BIN=self.sshd)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SSH_CONNECTION', result.stderr)

    def test_missing_dns_verification_dependency_restores_original(self):
        with self.config.open('a') as config:
            config.write('UseDNS yes\n')
        original = self.config.read_bytes()
        (self.path / 'backup').write_bytes(original)
        code = self.ssh_code() + '\nSSHD_BACKUP="$TEST_DIR/backup"\n' + self.apply_settings()
        code += '''
command() {
    if [[ "$1" == -v && "$2" == python3 ]]; then return 1; fi
    builtin command "$@"
}
'''
        code += self.validation_block() + '\necho RELOAD_REACHED'
        result = self.shell(code, SSHD_BIN=self.sshd)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Python 3', result.stderr)
        self.assertNotIn('RELOAD_REACHED', result.stdout)
        self.assertEqual(self.config.read_bytes(), original)

    def test_missing_timeout_restores_original_config(self):
        with self.config.open('a') as config:
            config.write('UseDNS yes\n')
        original = self.config.read_bytes()
        (self.path / 'backup').write_bytes(original)
        code = self.ssh_code() + '\nSSHD_BACKUP="$TEST_DIR/backup"\n' + self.apply_settings()
        code += '''
command() {
    if [[ "$1" == -v && "$2" == timeout ]]; then return 1; fi
    builtin command "$@"
}
'''
        result = self.shell(code + self.validation_block() + '\necho RELOAD_REACHED',
                            SSHD_BIN=self.sshd)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('GNU timeout', result.stderr)
        self.assertNotIn('RELOAD_REACHED', result.stdout)
        self.assertEqual(self.config.read_bytes(), original)

    @unittest.skipUnless(HAS_TIMEOUT and shutil.which('cc'),
                         'Native resolver timeout test requires GNU timeout and a C compiler')
    def test_native_resolver_block_is_killed_and_configuration_rolled_back(self):
        native = self.path / 'stall.c'
        library = self.path / ('stall.dylib' if sys.platform == 'darwin' else 'stall.so')
        native.write_text('''#include <time.h>
void stall(int seconds) {
    struct timespec start, now, pause = {0, 50000000};
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        nanosleep(&pause, 0);
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while ((now.tv_sec-start.tv_sec) + (now.tv_nsec-start.tv_nsec)/1000000000.0 < seconds);
}
''')
        compiled = subprocess.run(['cc', '-dynamiclib' if sys.platform == 'darwin' else '-shared',
                                   '-fPIC', str(native), '-o', str(library)],
                                  capture_output=True, text=True, timeout=15)
        self.assert_ok(compiled)
        with self.config.open('a') as config:
            config.write('UseDNS yes\n')
        original = self.config.read_bytes()
        (self.path / 'backup').write_bytes(original)
        code = self.ssh_code() + '\nSSHD_BACKUP="$TEST_DIR/backup"\n' + self.apply_settings()
        code += self.validation_block() + '\necho RELOAD_REACHED'
        pid_file = self.path / 'dns.pid'
        started = time.monotonic()
        result = self.shell(code, DNS_STALL_LIB=str(library), DNS_PID_FILE=str(pid_file),
                            **self.dns_environment('native-block'))
        elapsed = time.monotonic() - started
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DNS 查询超时', result.stderr)
        self.assertNotIn('RELOAD_REACHED', result.stdout)
        self.assertGreaterEqual(elapsed, 9.0, f'Resolver terminated before its deadline: {elapsed:.2f}s')
        self.assertLess(elapsed, 11.5, f'Native resolver escaped deadline: {elapsed:.2f}s')
        self.assertEqual(self.config.read_bytes(), original)
        # timeout must reap the helper; a timed-out resolver may not linger.
        pid = int(pid_file.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_equals_syntax_replaces_all_old_global_ports(self):
        for directive in ('Port=22', 'Port =22', 'Port= 22', '\tPoRt\t=\t22', 'Port 22'):
            with self.subTest(directive=directive):
                self.config.write_text(f'HostKey {self.path}/hostkey\n{directive}\n')
                code = self.ssh_code() + self.apply_settings() + '\nvalidate_sshd_settings && sshd -T'
                result = self.shell(code, SSHD_BIN=self.sshd)
                self.assert_ok(result)
                ports = [line.split()[1] for line in result.stdout.splitlines() if line.startswith('port ')]
                self.assertEqual(ports, ['12345'])

    def test_equals_match_syntax_preserves_conditional_settings(self):
        match = 'MaTcH=User nobody\n    PubkeyAuthentication no\n'
        with self.config.open('a') as config:
            config.write(match)
        code = self.ssh_code() + self.apply_settings() + '''
validate_sshd_settings && sshd -T -C user=nobody,host=198.51.100.3,addr=198.51.100.3
'''
        result = self.shell(code, SSHD_BIN=self.sshd)
        self.assert_ok(result)
        self.assertIn(match, self.config.read_text())
        self.assertIn('pubkeyauthentication no', result.stdout)

    def test_extra_port_from_include_is_rejected_and_rolled_back(self):
        cloud = self.path / 'cloud.conf'
        cloud.write_text('Port=22\n')
        with self.config.open('a') as config:
            config.write(f'Include {cloud}\n')
        original = self.config.read_bytes()
        (self.path / 'backup').write_bytes(original)
        code = self.ssh_code() + '\nSSHD_BACKUP="$TEST_DIR/backup"\n' + self.apply_settings()
        result = self.shell(code + self.validation_block() + '\necho RELOAD_REACHED',
                            SSHD_BIN=self.sshd)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('RELOAD_REACHED', result.stdout)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(cloud.read_text(), 'Port=22\n')

    @unittest.skipUnless(HAS_TIMEOUT, 'DNS verification requires GNU timeout')
    def test_domain_resolution_normalizes_ipv4_ipv6_and_mapped_ipv4(self):
        cases = [('198.51.100.3', '198.51.100.3'),
                 ('2001:db8::3', '2001:0db8:0:0:0:0:0:3'),
                 ('::ffff:198.51.100.3', '198.51.100.3')]
        for peer, forward in cases:
            with self.subTest(peer=peer):
                result = self.shell(self.ssh_code() + '\nresolve_ssh_client_host "$PEER"',
                                    PEER=peer, **self.dns_environment(address=forward))
                self.assert_ok(result)
                self.assertEqual(result.stdout.strip(), 'client.example.org')

    def test_auth_summary_reflects_effective_policy_instead_of_prompt_answer(self):
        for password, interactive in (('no', 'no'), ('yes', 'no'), ('no', 'yes')):
            with self.subTest(password=password, interactive=interactive):
                code = self.ssh_code() + '\nDISABLE_PWD=n\n' + self.apply_settings()
                code += f'\nsshd_set PasswordAuthentication {password}\n'
                code += f'sshd_set ChallengeResponseAuthentication {interactive}\n'
                code += 'validate_sshd_settings && printf "%s\\n" "$SSH_AUTH_SUMMARY"'
                result = self.shell(code, SSHD_BIN=self.sshd)
                self.assert_ok(result)
                self.assertIn('密码已启用' if password == 'yes' else '密码已禁用', result.stdout)
                self.assertIn('交互式认证已启用' if interactive == 'yes' else '交互式认证已禁用', result.stdout)

    def test_parser_failure_restores_backup_without_reload(self):
        original = self.config.read_bytes()
        (self.path / 'backup').write_bytes(original)
        validation = INIT.split('# 验证配置语法 (防止重启失败导致失联)\n', 1)[1].split('SSH_SERVICE="sshd"', 1)[0]
        validation = validation.replace('/etc/ssh/sshd_config', str(self.config))
        code = self.ssh_code() + '\nSSHD_BACKUP="$TEST_DIR/backup"\n'
        code += 'echo InvalidDirective yes >> "$TEST_DIR/sshd_config"\n' + validation
        code += '\necho RELOAD_REACHED'
        result = self.shell(code, SSHD_BIN=self.sshd)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('RELOAD_REACHED', result.stdout)
        self.assertEqual(self.config.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()

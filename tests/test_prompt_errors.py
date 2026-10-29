"""Prompt/status fault regressions. All writes and service commands are isolated."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from test_downloads import BASH, ROOT

SOURCES = {name: (ROOT / (name + '.sh')).read_text() for name in
           ('vt', 'x-sb', 'sb', 'snell', 'fw', 'pm', 'init', 'network_audit')}


BASH4 = int(subprocess.check_output([BASH, '-c', 'echo ${BASH_VERSINFO[0]}'])) >= 4


def functions(module, *names):
    result = ''
    for name in names:
        first = next(line for line in SOURCES[module].splitlines() if line.startswith(name + '()'))
        if first.rstrip().endswith('}'):
            result += first + '\n'
        else:
            result += re.search(r'(?ms)^' + re.escape(name) + r'\(\) \{.*?^\}', SOURCES[module])[0] + '\n'
    return result


COMMON = r'''
RED=''; GREEN=''; BLUE=''; YELLOW=''; PLAIN=''; DIM=''; NC=''
SCRIPT_VERSION=1.0.0; VT_VERSION=1.0.0
_CLEANUP_FILES=()
sleep() { :; }
journalctl() { :; }
truncate() { :; }
systemctl() {
    printf '%s\n' "$*" >> "$TEST_DIR/service.calls"
    case "$1" in
        stop) [[ "$MODE" != stop-failed ]] || return 1; command rm -f "$TEST_DIR/active" ;;
        is-active) [[ -f "$TEST_DIR/active" ]] ;;
        disable) [[ "$MODE" != disable-failed ]] ;;
        show) printf 'LoadState=loaded\nActiveState=active\n' ;;
        restart)
            restarts=$((restarts+1))
            [[ "$MODE" != restart-failed || "$restarts" -gt 1 ]] || return 1
            [[ "$MODE" != restart-always-failed ]] || return 1
            touch "$TEST_DIR/active"
            ;;
    esac
}
rm() {
    local arg
    for arg in "$@"; do
        case "$arg" in -*|'') ;; "$TEST_DIR"/*) ;; *) echo "UNSAFE_PATH:$arg" >&2; return 99;; esac
        case "$MODE:$arg" in
            unit-failed:*service|remove-failed:*) echo REMOVE_FAILED >&2; return 1 ;;
        esac
    done
    command rm "$@"
}
mktemp() {
    local arg args=()
    for arg in "$@"; do
        case "$arg" in "$TEST_DIR"/*) args+=("$arg");; /tmp/*) args+=("$TEST_DIR/${arg##*/}");; *) args+=("$arg");; esac
    done
    command mktemp "${args[@]}"
}
MODE=success; restarts=0
'''


class ShellCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='prompt-regression-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def write(self, name, content):
        path = self.path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def run_shell(self, code, stdin='', **env):
        result = subprocess.run([BASH, '-c', COMMON + code.replace('@TEST_DIR@', str(self.path))],
                                input=stdin, text=True, capture_output=True, timeout=10,
                                env={**os.environ, 'TEST_DIR': str(self.path), 'TMPDIR': str(self.path), **env})
        self.assertNotIn('UNSAFE_PATH', result.stderr)
        return result

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipUnless(BASH4, 'Xray manager requires Bash 4+')
class XrayFailureTests(ShellCase):
    def setUp(self):
        super().setUp()
        self.config = self.write('config/config.json', '{"old":true}')
        self.write('candidate.json', '{"new":true}')
        self.write('active', '')
        self.write('xray.service', 'service')
        self.write('core', '#!/bin/bash\nexit 0\n').chmod(0o755)
        self.write('manager', 'manager')
        self.setup = r'''
XRAY_CONF_FILE="$TEST_DIR/config/config.json"; XRAY_CONF_DIR="$TEST_DIR/config"
XRAY_BIN="$TEST_DIR/core"; DAT_DIR="$TEST_DIR/data"; SYSTEMD_FILE="$TEST_DIR/xray.service"
INSTALL_PATH="$TEST_DIR/manager"
'''

    def save_code(self):
        return self.setup + functions('x-sb', 'replace_xray_config', 'safe_save_config')

    def test_write_and_backup_failures_do_not_restart_or_report_success(self):
        for mode in ('backup', 'copy', 'chmod', 'move'):
            with self.subTest(mode=mode):
                self.config.write_text('{"old":true}')
                (self.path / 'service.calls').unlink(missing_ok=True)
                code = self.save_code() + r'''
cp() {
    if [[ "$FAILURE" == backup && "$1" == -p ]] ||
       [[ "$FAILURE" == copy && "$1" == "$TEST_DIR/candidate.json" ]]; then return 1; fi
    command cp "$@"
}
chmod() { [[ "$FAILURE" != chmod ]] || return 1; command chmod "$@"; }
mv() { [[ "$FAILURE" != move ]] || return 1; command mv "$@"; }
safe_save_config "$TEST_DIR/candidate.json"
'''
                result = self.run_shell(code, FAILURE=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('配置已应用', result.stdout)
                self.assertEqual(self.config.read_text(), '{"old":true}')
                self.assertFalse((self.path / 'service.calls').exists())

    def test_failed_restart_restores_config_even_if_old_process_is_active(self):
        result = self.run_shell(self.save_code() + '\nMODE=restart-failed\nsafe_save_config "$TEST_DIR/candidate.json"')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('配置已应用', result.stdout)
        self.assertIn('服务已恢复', result.stderr)
        self.assertEqual(self.config.read_text(), '{"old":true}')

    def test_failed_recovery_keeps_backup_and_reports_failure(self):
        result = self.run_shell(self.save_code() + '\nMODE=restart-always-failed\nsafe_save_config "$TEST_DIR/candidate.json"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('备份已保留', result.stderr)
        backups = list(self.config.parent.glob('config.json.bak.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), '{"old":true}')

    def test_success_applies_config_and_cleans_backup(self):
        result = self.run_shell(self.save_code() + '\nsafe_save_config "$TEST_DIR/candidate.json"')
        self.assert_ok(result)
        self.assertEqual(self.config.read_text(), '{"new":true}')
        self.assertIn('配置已应用', result.stdout)
        self.assertEqual(list(self.config.parent.glob('config.json.bak.*')), [])

    def test_uninstall_success_removes_owned_files(self):
        self.config.write_text('{"inbounds":[]}')
        code = self.setup + functions('x-sb', 'read_prompt', 'strip_cr', 'uninstall_script').replace(
            '/var/log/xray', '@TEST_DIR@/xray-log') + '\nuninstall_script'
        result = self.run_shell(code, stdin='yes\n')
        self.assert_ok(result)
        self.assertIn('卸载完成', result.stdout)
        for name in ('config', 'core', 'manager', 'xray.service'):
            self.assertFalse((self.path / name).exists())

    def test_recovery_write_failure_retains_backup(self):
        code = self.save_code() + r'''
cp() {
    if [[ "$1" == *.bak.* ]]; then return 1; fi
    command cp "$@"
}
MODE=restart-failed
safe_save_config "$TEST_DIR/candidate.json"
'''
        result = self.run_shell(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('配置恢复失败', result.stderr)
        backups = list(self.config.parent.glob('config.json.bak.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), '{"old":true}')

    def test_chain_prompt_eof_cannot_be_mistaken_for_yes(self):
        self.config.write_text('{"outbounds":[{"tag":"chain_proxy"}]}')
        code = self.setup + functions('x-sb', 'strip_cr', 'ask_chain_proxy') + '\nask_chain_proxy'
        result = self.run_shell(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('未创建节点', result.stderr)
        for answer, expected in (('n\n', ''), ('y\n', 'yes')):
            result = self.run_shell(code, stdin=answer)
            self.assert_ok(result)
            self.assertEqual(result.stdout.strip(), expected)

    def test_uninstall_failures_preserve_retry_files_and_report_failure(self):
        uninstall = functions('x-sb', 'read_prompt', 'strip_cr', 'uninstall_script').replace(
            '/var/log/xray', '@TEST_DIR@/xray-log')
        self.config.write_text('{"inbounds":[]}')
        for mode in ('stop-failed', 'disable-failed', 'unit-failed', 'remove-failed'):
            with self.subTest(mode=mode):
                self.write('active', '')
                result = self.run_shell(self.setup + uninstall + '\nMODE="$FAILURE"\nuninstall_script',
                                        stdin='yes\n', FAILURE=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('卸载完成', result.stdout)
                self.assertTrue(self.config.exists())
                self.assertTrue((self.path / 'core').exists())
                self.assertTrue((self.path / 'manager').exists())

    def test_delete_propagates_save_failure_without_closing_port(self):
        self.config.write_text('{"inbounds":[{"tag":"ss_443","port":443}],"routing":{"rules":[]}}')
        code = self.setup + functions('x-sb', 'read_prompt', 'strip_cr', 'delete_node') + r'''
list_nodes() { _NODE_COUNT=1; }
get_node_tag_by_id() { echo ss_443; }
safe_save_config() { echo SAVE_FAILED >&2; return 1; }
close_port() { echo CLOSED_UNEXPECTEDLY; }
delete_node
'''
        result = self.run_shell(code, stdin='1\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SAVE_FAILED', result.stderr)
        self.assertNotIn('CLOSED_UNEXPECTEDLY', result.stdout)
        self.assertIn('ss_443', self.config.read_text())


@unittest.skipUnless(BASH4, 'Cleanup managers require Bash 4+')
class CleanupFailureTests(ShellCase):
    def test_sb_cleanup_failure_does_not_report_completion(self):
        self.write('core', 'core')
        self.write('config/config.json', '{"inbounds":[]}')
        code = functions('sb', 'strip_cr', 'uninstall_all') + r'''
SB_CONF_FILE="$TEST_DIR/config/config.json"; SB_CONF_DIR="$TEST_DIR/config"; WORK_DIR="$TEST_DIR/work"
SB_BIN="$TEST_DIR/core"; OPENRC_LOG_FILE="$TEST_DIR/log"; INSTALL_PATH="$TEST_DIR/manager"
service_stop() { return 0; }; remove_service_definition() { return 0; }
MODE=remove-failed
uninstall_all
'''
        result = self.run_shell(code, stdin='yes\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('卸载完成', result.stdout)
        self.assertTrue((self.path / 'core').exists())

    def test_vt_failed_service_removal_preserves_configuration_and_toolbox(self):
        code = functions('vt', 'strip_cr', 'cleanup_warn', 'nuke_all')
        code = re.sub(r'(?<![A-Za-z0-9_])/(?:usr/local|etc|var|run)(?=/|\b)',
                      lambda m: '@TEST_DIR@' + m[0], code)
        code += r'''
cleanup_snell() { :; }; cleanup_pm() { :; }; close_port() { :; }
sb_installed() { [[ -f "$TEST_DIR/usr/local/bin/sing-box" ]]; }
fw_installed() { [[ -f "$TEST_DIR/usr/local/bin/realm" ]]; }
MODE=unit-failed
nuke_all
'''
        for component in ('sing-box', 'realm'):
            with self.subTest(component=component):
                if component == 'sing-box':
                    self.write('usr/local/bin/sing-box', 'core')
                    config = self.write('usr/local/etc/sing-box/config.json', '{"inbounds":[]}')
                else:
                    self.write('usr/local/bin/realm', 'core')
                    config = self.write('etc/realm/config.toml', 'config')
                self.write('etc/systemd/system/' + component + '.service', 'unit')
                self.write('run/systemd/system/marker', '')
                result = self.run_shell(code, stdin='yes\nn\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('全部清除完成', result.stdout)
                self.assertTrue(config.exists())


class FirewallErrorTests(ShellCase):
    def test_failed_rule_query_is_not_treated_as_successful_cleanup(self):
        for module in ('x-sb', 'sb', 'vt'):
            with self.subTest(module=module):
                code = functions(module, 'close_port') + r'''
command() {
    if [[ "$1" == -v ]]; then [[ "$2" == iptables ]]; else builtin command "$@"; fi
}
iptables() { printf '%s\n' "$*" >> "$TEST_DIR/iptables.calls"; return 2; }
close_port 443
'''
                result = self.run_shell(code)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('-D', (self.path / 'iptables.calls').read_text())
    def test_sb_tcp_cleanup_does_not_remove_udp_firewalld_rule(self):
        code = functions('sb', 'close_port') + r'''
command() {
    if [[ "$1" == -v ]]; then [[ "$2" == firewall-cmd ]]; else builtin command "$@"; fi
}
firewall-cmd() { printf '%s\n' "$*" >> "$TEST_DIR/firewalld.calls"; }
close_port 443 tcp
'''
        result = self.run_shell(code)
        self.assert_ok(result)
        calls = (self.path / 'firewalld.calls').read_text()
        self.assertIn('--remove-port=443/tcp', calls)
        self.assertNotIn('udp', calls)



class MenuFailureTests(ShellCase):
    def menu(self, module, data):
        names = ['read_prompt', 'strip_cr']
        names += ['show_main_menu'] if module == 'pm' else ['main_menu'] if module == 'x-sb' else ['menu']
        if module == 'fw':
            names += ['pause_to_menu']
        code = functions(module, *names) + r'''
renders=0
clear() { renders=$((renders+1)); [[ "$renders" -lt 4 ]] || { echo REPEATED_MENU; exit 97; }; }
check_deps() { :; }; get_realm_status() { echo absent; }; realm_installed() { return 1; }; rule_count() { echo 0; }
start_edit_lock() { :; }; stop_edit_lock() { :; }
telegram_status_text() { echo disabled; }; push_status_text() { echo disabled; }; warn() { echo "$*"; }
SNELL_BIN="$TEST_DIR/no-core"; SNELL_CONF_DIR="$TEST_DIR"; XRAY_BIN="$TEST_DIR/no-core"
XRAY_CONF_FILE="$TEST_DIR/config.json"; CONFIG_FILE="$TEST_DIR/config.json"
'''
        self.write('config.json', '{"ports":{}}')
        if module in ('snell', 'fw'):
            code += 'set -Eeuo pipefail\ntrap \'echo UNEXPECTED_ERROR >&2\' ERR\nwhile true; do menu; done\n'
        elif module == 'pm':
            code += 'while true; do show_main_menu; done\n'
        else:
            code += 'main_menu\n'
        return self.run_shell(code, stdin=data)

    def test_eof_exits_managers_normally(self):
        for module in ('snell', 'fw', 'x-sb', 'pm'):
            if module == 'pm' and int(subprocess.check_output([BASH, '-c', 'echo ${BASH_VERSINFO[0]}'])) < 4:
                continue  # PM is separately exercised on the Linux target.
            with self.subTest(module=module):
                result = self.menu(module, '')
                self.assert_ok(result)
                self.assertIn('输入已结束', result.stdout)
                self.assertNotIn('REPEATED_MENU', result.stdout)
                self.assertNotIn('UNEXPECTED_ERROR', result.stderr)

    def test_invalid_choices_are_reported_and_wait_for_confirmation(self):
        for module in ('fw', 'x-sb', 'pm'):
            if module == 'pm' and int(subprocess.check_output([BASH, '-c', 'echo ${BASH_VERSINFO[0]}'])) < 4:
                continue
            with self.subTest(module=module):
                result = self.menu(module, '99\n\n0\n')
                self.assert_ok(result)
                self.assertIn('无效选项', result.stdout)
                self.assertNotIn('REPEATED_MENU', result.stdout)

    def test_xray_update_error_is_followed_by_pause(self):
        code = functions('x-sb', 'read_prompt', 'strip_cr', 'run_menu_action', 'main_menu') + r'''
check_deps() { :; }; clear() { :; }; XRAY_BIN="$TEST_DIR/no-core"; XRAY_CONF_FILE="$TEST_DIR/config"
update_script() { echo UPDATE_FAILURE >&2; return 1; }
read() { printf 'PROMPT:%s\n' "$*"; builtin read "$@"; }
main_menu
'''
        result = self.run_shell(code, stdin='7\n\n0\n')
        self.assert_ok(result)
        self.assertIn('UPDATE_FAILURE', result.stderr)
        self.assertIn('按回车继续', result.stdout)

    def test_read_programming_errors_are_not_reported_as_normal_eof(self):
        for module in ('init', 'snell', 'fw', 'x-sb', 'pm'):
            with self.subTest(module=module):
                result = self.run_shell(functions(module, 'read_prompt') + '\nread_prompt --invalid-option reply')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('读取输入失败', result.stderr)
                self.assertNotIn('输入已结束', result.stdout)

    def test_xray_advanced_save_failure_waits_before_clearing(self):
        self.write('config.json', '{"outbounds":[],"routing":{"rules":[]}}')
        code = functions('x-sb', 'read_prompt', 'strip_cr', 'configure_advanced') + r'''
XRAY_CONF_FILE="$TEST_DIR/config.json"
clear() { echo CLEARED; }
safe_save_config() { echo SAVE_FAILED; return 1; }
read() { printf 'PROMPT:%s\n' "$*"; builtin read "$@"; }
configure_advanced
'''
        result = self.run_shell(code, stdin='2\n\n0\n')
        self.assert_ok(result)
        after_failure = result.stdout.split('SAVE_FAILED', 1)[1]
        self.assertLess(after_failure.index('配置未应用，按回车继续'), after_failure.index('CLEARED'))

    def test_init_port_eof_exits_without_loop(self):
        block = SOURCES['init'].split('# --- 修改端口 ---\n', 1)[1].split('echo -e "${YELLOW}切换 SSH 端口前', 1)[0]
        result = self.run_shell(functions('init', 'read_prompt', 'strip_cr') + block)
        self.assert_ok(result)
        self.assertIn('输入已结束', result.stdout)
        self.assertNotIn('无效端口', result.stdout)


class StatusTests(ShellCase):
    def test_version_and_uptime_failures_use_unknown(self):
        for helper, binary in (('sb_version', '/usr/local/bin/sing-box'), ('fw_version', '/usr/local/bin/realm')):
            with self.subTest(helper=helper):
                code = functions('vt', helper).replace(binary, 'core_stub')
                for body in ('return 1', 'echo unrecognized', 'echo "2.9.6"; return 1'):
                    result = self.run_shell('core_stub() { ' + body + '; }\n' + code + helper)
                    self.assert_ok(result)
                    self.assertEqual(result.stdout.strip(), '?')
        self.write('os-release', 'PRETTY_NAME="Fixture Linux"\n')
        code = functions('vt', 'sys_info').replace('/etc/os-release', '@TEST_DIR@/os-release')
        result = self.run_shell(code + '\nuptime() { return 1; }; sys_info')
        self.assert_ok(result)
        self.assertIn('运行 ?', result.stdout)

    def test_ping_timeout_arguments_use_platform_units(self):
        for platform, expected in (('Linux', ['-c', '1', '-W', '3', '-w', '3', '192.0.2.1']),
                                   ('Darwin', ['-c', '1', '-W', '3000', '-t', '3', '192.0.2.1'])):
            with self.subTest(platform=platform):
                code = functions('network_audit', 'ping_check') + r'''
uname() { echo "$PLATFORM"; }
ping() { printf '%s\n' "$@" > "$TEST_DIR/ping.args"; }
ping_check 192.0.2.1
'''
                self.assert_ok(self.run_shell(code, PLATFORM=platform))
                self.assertEqual((self.path / 'ping.args').read_text().splitlines(), expected)

    def test_incomplete_qos_measurements_are_not_reported_as_healthy(self):
        code = functions('network_audit', 'analyze_qos') + '\nSUMMARY_LOSS="0%"; S_AVG=10; L_AVG="$VALUE"\nanalyze_qos\necho "$SUMMARY_RATIO|$SUMMARY_QOS_CONCLUSION"'
        for value in ('', '0', 'N/A', 'invalid'):
            with self.subTest(value=value):
                result = self.run_shell(code, VALUE=value)
                self.assert_ok(result)
                self.assertIn('N/A|', result.stdout)
                self.assertIn('无法评估', result.stdout)
                self.assertNotIn('链路透明', result.stdout)
        result = self.run_shell(code, VALUE='20')
        self.assert_ok(result)
        self.assertIn('2.00|', result.stdout)
        self.assertIn('疑似', result.stdout)

    def test_large_ping_failure_reaches_unknown_qos(self):
        source = SOURCES['network_audit']
        start = source.index('echo -n "正在发送大包')
        end = source.index('# --- 2. 路由分析', start)
        code = functions('network_audit', 'analyze_qos') + '\nS_AVG=10; SUMMARY_LOSS="0%"; ping() { return 1; }\n'
        result = self.run_shell(code + source[start:end] + '\necho "RESULT:$SUMMARY_LATENCY_LARGE|$SUMMARY_RATIO"')
        self.assert_ok(result)
        self.assertIn('RESULT:测试失败|N/A', result.stdout)
        self.assertNotIn('链路透明', result.stdout)


class BBRTests(ShellCase):
    def bbr_code(self):
        return functions('init', 'configure_bbr').replace('/etc/sysctl.conf', '@TEST_DIR@/sysctl.conf') + r'''
fail() { echo "$*" >&2; exit 1; }
sysctl() {
    if [[ "$1" == -w ]]; then
        echo called > "$TEST_DIR/applied"
        [[ "$FAILURE" != apply ]] || return 1
        [[ "$FAILURE" == ineffective ]] || echo bbr > "$TEST_DIR/controller"
        return 0
    fi
    case "$2" in
        net.ipv4.tcp_congestion_control) cat "$TEST_DIR/controller" ;;
        net.core.default_qdisc) echo fq ;;
    esac
}
mv() { [[ "$FAILURE" != persist ]] || return 1; command mv "$@"; }
configure_bbr
'''

    def test_commented_or_stale_config_does_not_fake_runtime_success(self):
        self.write('controller', 'cubic\n')
        self.write('sysctl.conf', '# net.ipv4.tcp_congestion_control = bbr\nnet.ipv4.tcp_congestion_control = cubic\n')
        result = self.run_shell(self.bbr_code(), FAILURE='none')
        self.assert_ok(result)
        self.assertTrue((self.path / 'applied').exists())
        self.assertEqual((self.path / 'controller').read_text().strip(), 'bbr')
        lines = [line for line in (self.path / 'sysctl.conf').read_text().splitlines() if not line.startswith('#')]
        self.assertIn('net.ipv4.tcp_congestion_control = bbr', lines)
        self.assertNotIn('net.ipv4.tcp_congestion_control = cubic', lines)

    def test_apply_verification_or_persistence_failure_never_reports_enabled(self):
        for failure in ('apply', 'ineffective', 'persist'):
            with self.subTest(failure=failure):
                self.write('controller', 'cubic\n')
                self.write('sysctl.conf', '# original\n')
                result = self.run_shell(self.bbr_code(), FAILURE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('BBR 已开启', result.stdout)
                self.assertEqual((self.path / 'sysctl.conf').read_text(), '# original\n')




@unittest.skipUnless(BASH4, 'PM UI requires Bash 4+')
class PMStatusTests(ShellCase):
    def test_unknown_unblocked_and_blocked_states_are_distinct(self):
        self.write('config.json', '{"ports":{"443":{"quota_mode":"in_out","quota_gb":100}}}')
        code = functions('pm', 'read_prompt', 'strip_cr', 'show_main_menu') + r'''
CONFIG_FILE="$TEST_DIR/config.json"; NFT_TABLE='inet port_monitor'
clear() { :; }; start_edit_lock() { :; }; stop_edit_lock() { :; }
telegram_status_text() { echo disabled; }; push_status_text() { echo disabled; }
_load_port_state() { s_acc_in=0; s_acc_out=0; s_is_punished=false; return 0; }
fmt_bytes() { echo '0 B'; }; pm_error() { echo "$*" >> "$TEST_DIR/errors"; }
nft() { [[ "$QUERY" != failure ]] || return 1; printf '%s' "$QUERY"; }
show_main_menu
'''
        scenarios = [('failure', '封禁状态未知'), ('invalid', '封禁状态未知'),
                     ('{"nftables":[]}', '封禁状态未知'),
                     ('{"nftables":[{"set":{"name":"blocked_ports"}}]}', '0 B / 100 GB'),
                     ('{"nftables":[{"set":{"name":"blocked_ports","elem":[443]}}]}', '已阻断')]
        for query, expected in scenarios:
            with self.subTest(query=query):
                result = self.run_shell(code, stdin='0\n', QUERY=query)
                self.assert_ok(result)
                self.assertIn(expected, result.stdout)


if __name__ == '__main__':
    unittest.main()

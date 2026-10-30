"""User input -> saved configuration regressions, with no real system changes.

The real menu functions, JSON generation, validation and file commits run here.
Service/core/firewall boundaries use deterministic fakes inside a temporary tree.
"""

import json
import shutil
import unittest

from test_pm import SOURCE as PM_SOURCE
from test_prompt_errors import BASH4, ShellCase, functions


@unittest.skipUnless(BASH4 and shutil.which('jq'), 'Requires Bash 4+ and jq')
class PMUserFlowTests(ShellCase):
    def setUp(self):
        super().setUp()
        self.write('pm-library.sh', PM_SOURCE)
        self.config = self.path / 'config/config.json'
        self.setup = r'''
source "$TEST_DIR/pm-library.sh"
CONFIG_DIR="$TEST_DIR/config"; CONFIG_FILE="$CONFIG_DIR/config.json"
STATE_DIR="$CONFIG_DIR/state"; LOG_FILE="$TEST_DIR/pm.log"
LOCK_FILE="$TEST_DIR/write.lock"; CRON_LOCK_FILE="$TEST_DIR/cron.lock"
USER_EDIT_LOCK="$TEST_DIR/edit.lock"
RED=''; GREEN=''; YELLOW=''; BLUE=''; PLAIN=''
hostname() { echo test-node; }
get_iface() { echo test0; }
flock() { :; }
clear() { :; }
mktemp() {
    if [[ "$#" -eq 0 ]]; then command mktemp "$TEST_DIR/pm.XXXXXX";
    else command mktemp "$@"; fi
}
scan_active_services() { printf '443 tcp web-server\n8443 tcp/udp proxy\n'; }
apply_port_rules() { echo "apply:$1" >> "$TEST_DIR/rules.calls"; }
reload_all_rules() { echo reload >> "$TEST_DIR/rules.calls"; }
nft() { echo UNSAFE_SYSTEM:nft >&2; return 99; }
tc() { echo UNSAFE_SYSTEM:tc >&2; return 99; }
init_config || exit 1
'''

    def run_pm(self, code, stdin=''):
        result = self.run_shell(self.setup + code, stdin=stdin)
        self.assertNotIn('UNSAFE_SYSTEM', result.stderr)
        return result

    def read_config(self):
        return json.loads(self.config.read_text())

    def seed_ports(self):
        self.assert_ok(self.run_pm(''))
        config = self.read_config()
        for port, group, quota, reset in (
                ('443', 'family', 100, 15), ('8443', 'family', 100, 15),
                ('9443', '', 25, 0)):
            config['ports'][port] = {
                'quota_gb': quota, 'quota_mode': 'in_out', 'reset_day': reset,
                'comment': 'original', 'expiry_date': '', 'group_id': group,
                'dyn_limit': {'enable': False},
                'ip_limit': {'enable': True, 'max_ips': 3, 'action': 'alert',
                             'cooldown_min': 30, 'whitelist': []},
            }
            self.write(f'config/state/{port}.txt', 'existing-usage\n')
        self.config.write_text(json.dumps(config))

    def test_manual_add_defaults_create_state_and_monitoring(self):
        result = self.run_pm('_run_edit_action add_port_flow', 'M\n0443\n100\n\n\n\nAlice "home"\\room\n\n')
        self.assert_ok(result)
        ports = self.read_config()['ports']
        self.assertEqual(list(ports), ['443'])
        self.assertEqual(ports['443'], {
            'quota_gb': 100, 'quota_mode': 'in_out', 'reset_day': 0,
            'comment': 'Alice "home"\\room', 'expiry_date': '', 'group_id': '',
            'dyn_limit': {'enable': False},
            'ip_limit': {'enable': True, 'max_ips': 3, 'action': 'alert',
                         'cooldown_min': 30, 'whitelist': []},
        })
        state = self.path / 'config/state/443.txt'
        self.assertIn('s_acc_out=0\n', state.read_text())
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.path / 'rules.calls').read_text(), 'apply:443\n')
        self.assertIn('添加成功', result.stdout)
        self.assertFalse((self.path / 'edit.lock').exists())

    def test_scanned_service_selection_and_crlf_input_keep_selected_port(self):
        result = self.run_pm('_run_edit_action add_port_flow', '2\r\n50\r\n2\r\ny\r\n31\r\nProxy\r\n\r\n')
        self.assert_ok(result)
        port = self.read_config()['ports']['8443']
        self.assertEqual(port['quota_mode'], 'out_only')
        self.assertEqual(port['reset_day'], 31)
        self.assertTrue(port['dyn_limit']['enable'])
        self.assertEqual(port['comment'], 'Proxy')

    def test_duplicate_port_with_leading_zero_preserves_configuration_and_usage(self):
        self.seed_ports()
        before = self.config.read_bytes()
        result = self.run_pm('_run_edit_action add_port_flow', 'M\n0443\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('已在监控列表', result.stdout)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual((self.path / 'config/state/443.txt').read_text(), 'existing-usage\n')
        self.assertFalse((self.path / 'rules.calls').exists())

    def test_add_cancel_invalid_fields_and_eof_leave_existing_ports_untouched(self):
        self.seed_ports()
        before = self.config.read_bytes()
        inputs = ('0\n', 'M\n0\n', 'M\n65536\n', 'M\n9000\n0\n',
                  'M\n9000\n20\n3\n', 'M\n9000\n20\n1\nn\n32\n',
                  'M\n9000\n20\n1\nn\n0\nNew\n2026-02-30\n',
                  '', 'M\n9000\n20\n1\nn\n0\nNew\n')
        for answer in inputs:
            with self.subTest(input=answer):
                result = self.run_pm('_run_edit_action add_port_flow', answer)
                self.assert_ok(result)
                self.assertEqual(self.config.read_bytes(), before)
                self.assertFalse((self.path / 'config/state/9000.txt').exists())
                self.assertFalse((self.path / 'rules.calls').exists())
                self.assertFalse((self.path / 'edit.lock').exists())

    def test_failed_rule_creation_rolls_back_new_port_and_keeps_existing_usage(self):
        self.seed_ports()
        before = self.read_config()
        result = self.run_pm('apply_port_rules() { return 1; }; _run_edit_action add_port_flow',
                             'M\n9000\n20\n1\nn\n0\nNew\n\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read_config(), before)
        self.assertFalse((self.path / 'config/state/9000.txt').exists())
        self.assertEqual((self.path / 'config/state/443.txt').read_text(), 'existing-usage\n')
        self.assertEqual((self.path / 'rules.calls').read_text(), 'reload\n')
        self.assertNotIn('添加成功', result.stdout)

    def test_group_quota_edit_updates_group_members_only_without_resetting_usage(self):
        self.seed_ports()
        result = self.run_pm('config_port_menu 443 8443 9443', '1\n1\n250\n0\n')
        self.assert_ok(result)
        ports = self.read_config()['ports']
        self.assertEqual([ports[p]['quota_gb'] for p in ('443', '8443', '9443')], [250, 250, 25])
        self.assertIn('已同步配额到组', result.stdout)
        for port in ports:
            self.assertEqual((self.path / f'config/state/{port}.txt').read_text(), 'existing-usage\n')

    def test_join_existing_group_synchronizes_quota_and_reset_day(self):
        self.seed_ports()
        result = self.run_pm('config_port_menu 443 8443 9443', '3\n7\n1\n0\n')
        self.assert_ok(result)
        port = self.read_config()['ports']['9443']
        self.assertEqual((port['group_id'], port['quota_gb'], port['reset_day']), ('family', 100, 15))
        self.assertEqual(port['comment'], 'original')

    def test_edit_mode_cancel_and_clear_user_have_distinct_meanings(self):
        self.seed_ports()
        result = self.run_pm('config_port_menu 443 8443 9443', '1\n2\n\n4\n\n0\n')
        self.assert_ok(result)
        ports = self.read_config()['ports']
        self.assertEqual(ports['443']['quota_mode'], 'in_out')
        self.assertEqual(ports['443']['comment'], '')
        self.assertEqual(ports['8443']['comment'], 'original')
        self.assertFalse((self.path / 'edit.lock').exists())

    def test_delete_selection_cancel_and_default_no_preserve_config_and_usage(self):
        self.seed_ports()
        before = self.config.read_bytes()
        for answer in ('0\n', '1\n\n', '1\nn\n', '4\n', 'bad\n', ''):
            with self.subTest(input=answer):
                self.run_pm('delete_port_flow 443 8443 9443', answer)
                self.assertEqual(self.config.read_bytes(), before)
                self.assertTrue((self.path / 'config/state/443.txt').exists())
                self.assertFalse((self.path / 'rules.calls').exists())

    def test_confirmed_delete_removes_selected_state_and_preserves_other_ports(self):
        self.seed_ports()
        before = self.read_config()
        result = self.run_pm('delete_port_flow 443 8443 9443', '2\ny\n')
        self.assert_ok(result)
        del before['ports']['8443']
        self.assertEqual(self.read_config(), before)
        self.assertFalse((self.path / 'config/state/8443.txt').exists())
        self.assertTrue((self.path / 'config/state/443.txt').exists())
        self.assertEqual((self.path / 'rules.calls').read_text(), 'reload\n')
        self.assertIn('已删除', result.stdout)

    def test_failed_delete_rule_cleanup_restores_configuration_and_usage(self):
        self.seed_ports()
        before = self.read_config()
        result = self.run_pm(r'''
reloads=0
reload_all_rules() { reloads=$((reloads+1)); [[ "$reloads" -gt 1 ]]; }
delete_port_flow 443 8443 9443
''', '1\ny\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read_config(), before)
        self.assertEqual((self.path / 'config/state/443.txt').read_text(), 'existing-usage\n')
        self.assertIn('原配置与规则已恢复', result.stdout)
        self.assertNotIn('已删除', result.stdout)


@unittest.skipUnless(BASH4 and shutil.which('jq'), 'Requires Bash 4+ and jq')
class ProxyNodeUserFlowTests(ShellCase):
    def setup_manager(self, module):
        self.config = self.write('config/config.json', json.dumps({
            'inbounds': [], 'outbounds': [{'tag': 'direct'}],
            'route' if module == 'sb' else 'routing': {'rules': []},
        }))
        core = self.write('core', '#!/bin/sh\nif [ "$1" = generate ]; then echo test-key; fi\nexit 0\n')
        core.chmod(0o755)
        common = r'''
get_random_port() { echo 23456; }
ss() { :; }
openssl() { echo test-key; }
open_port() { echo "open:$*" >> "$TEST_DIR/firewall.calls"; }
close_port() { echo "close:$*" >> "$TEST_DIR/firewall.calls"; }
show_node_info() { echo "share:$1"; }
'''
        if module == 'sb':
            return functions('sb', 'strip_cr', 'is_port_available', 'prompt_node_port',
                             'ensure_private_reject_rule', 'atomic_replace_file', 'safe_save_config',
                             'add_ss2022', 'list_nodes', 'get_node_tag_by_id', 'delete_node',
                             'network_mode_for_type') + r'''
SB_CONF_FILE="$TEST_DIR/config/config.json"; SB_BIN="$TEST_DIR/core"
SS2022_METHOD=2022-blake3-aes-128-gcm; SS2022_KEY_BYTES=16
restart_singbox_checked() { systemctl restart sing-box && systemctl is-active --quiet sing-box; }
service_log_hint() { echo test-log; }
meta_del_tag() { echo "$1" >> "$TEST_DIR/meta.calls"; }
''' + common
        return functions('x-sb', 'strip_cr', 'read_prompt', 'is_port_available',
                         'replace_xray_config', 'safe_save_config', 'ask_chain_proxy',
                         'add_ss2022', 'list_nodes', 'get_node_tag_by_id', 'delete_node') + r'''
XRAY_CONF_FILE="$TEST_DIR/config/config.json"; XRAY_BIN="$TEST_DIR/core"
''' + common

    def test_ss2022_add_default_port_saves_node_before_opening_firewall(self):
        for module in ('sb', 'x-sb'):
            with self.subTest(manager=module):
                setup = self.setup_manager(module)
                (self.path / 'firewall.calls').unlink(missing_ok=True)
                result = self.run_shell(setup + '\nadd_ss2022', stdin='\n')
                self.assert_ok(result)
                config = json.loads(self.config.read_text())
                self.assertEqual(len(config['inbounds']), 1)
                node = config['inbounds'][0]
                self.assertEqual(node['tag'], 'ss_23456')
                self.assertEqual(node.get('listen_port', node.get('port')), 23456)
                settings = node if module == 'sb' else node['settings']
                self.assertEqual(settings['method'], '2022-blake3-aes-128-gcm')
                self.assertEqual(settings['password'], 'test-key')
                self.assertEqual(settings.get('network', 'tcp,udp'), 'tcp,udp')
                expected = 'open:23456 both\n' if module == 'sb' else 'open:23456\n'
                self.assertEqual((self.path / 'firewall.calls').read_text(), expected)
                self.assertIn('share:ss_23456', result.stdout)
                self.assertEqual(config['outbounds'], [{'tag': 'direct'}])
                self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)

    def test_sing_box_add_retries_invalid_and_occupied_ports_and_supports_cancel(self):
        setup = self.setup_manager('sb')
        result = self.run_shell(setup + r'''
ss() { echo 'LISTEN 0 128 *:443 '; }
add_ss2022
''', stdin='bad\n65536\n443\n09000\n')
        self.assert_ok(result)
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][0]['listen_port'], 9000)
        self.assertIn('已被系统占用', result.stderr)
        for answer in ('0\n', ''):
            with self.subTest(input=answer):
                setup = self.setup_manager('sb')
                (self.path / 'firewall.calls').unlink(missing_ok=True)
                before = self.config.read_bytes()
                result = self.run_shell(setup + '\nadd_ss2022', stdin=answer)
                self.assert_ok(result)
                self.assertEqual(self.config.read_bytes(), before)
                self.assertFalse((self.path / 'firewall.calls').exists())

    def seed_nodes(self, module):
        port_field, type_field = ('listen_port', 'type') if module == 'sb' else ('port', 'protocol')
        rules_key, inbound_key = ('route', 'inbound') if module == 'sb' else ('routing', 'inboundTag')
        config = json.loads(self.config.read_text())
        config['inbounds'] = [
            {'tag': 'internal', port_field: 10000, type_field: 'mixed'},
            {'tag': 'reality_443', port_field: 443, type_field: 'vless'},
            {'tag': 'ss_8443', port_field: 8443, type_field: 'shadowsocks'},
        ]
        config[rules_key]['rules'] = [
            {inbound_key: ['reality_443'], 'outbound': 'direct'},
            {inbound_key: ['ss_8443'], 'outbound': 'direct'},
            {'domain': ['example.com'], 'outbound': 'direct'},
        ]
        self.config.write_text(json.dumps(config))
        return config, rules_key

    def test_delete_uses_displayed_node_id_and_preserves_unrelated_nodes_and_routes(self):
        for module in ('sb', 'x-sb'):
            with self.subTest(manager=module):
                setup = self.setup_manager(module)
                before, rules_key = self.seed_nodes(module)
                (self.path / 'firewall.calls').unlink(missing_ok=True)
                result = self.run_shell(setup + '\ndelete_node', stdin='2\n')
                self.assert_ok(result)
                after = json.loads(self.config.read_text())
                self.assertEqual(after['inbounds'], before['inbounds'][:2])
                self.assertEqual(after[rules_key]['rules'], [before[rules_key]['rules'][0], before[rules_key]['rules'][2]])
                expected = 'close:8443 both\n' if module == 'sb' else 'close:8443\n'
                self.assertEqual((self.path / 'firewall.calls').read_text(), expected)

    def test_delete_cancel_invalid_id_and_eof_never_save_or_close_port(self):
        for module in ('sb', 'x-sb'):
            setup = self.setup_manager(module)
            self.seed_nodes(module)
            before = self.config.read_bytes()
            for answer in ('0\n', '3\n', 'bad\n', ''):
                with self.subTest(manager=module, input=answer):
                    (self.path / 'firewall.calls').unlink(missing_ok=True)
                    (self.path / 'service.calls').unlink(missing_ok=True)
                    self.run_shell(setup + '\ndelete_node', stdin=answer)
                    self.assertEqual(self.config.read_bytes(), before)
                    self.assertFalse((self.path / 'firewall.calls').exists())
                    self.assertFalse((self.path / 'service.calls').exists())

    def test_sing_box_failed_delete_is_visible_in_menu_and_preserves_user_data(self):
        setup = self.setup_manager('sb') + functions('sb', 'run_menu_action')
        self.seed_nodes('sb')
        self.write('metadata.json', '{"ss_8443":"existing-metadata"}')
        before = self.config.read_bytes()
        result = self.run_shell(setup + r'''
meta_del_tag() { rm -f "$TEST_DIR/metadata.json"; echo "$1" >> "$TEST_DIR/meta.calls"; }
safe_save_config() { echo SAVE_FAILED >&2; return 1; }
run_menu_action "删除节点" delete_node
''', stdin='2\n')
        self.assert_ok(result)
        self.assertIn('删除节点未完成', result.stderr)
        self.assertIn('SAVE_FAILED', result.stderr)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual((self.path / 'metadata.json').read_text(), '{"ss_8443":"existing-metadata"}')
        self.assertFalse((self.path / 'meta.calls').exists())
        self.assertFalse((self.path / 'firewall.calls').exists())
        self.assertFalse((self.path / 'service.calls').exists())
        self.assertNotIn('删除完成', result.stdout)


if __name__ == '__main__':
    unittest.main()

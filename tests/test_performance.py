"""Small-install performance regressions, with isolated files and command fixtures."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import subprocess
import unittest

from test_prompt_errors import BASH4, ShellCase, functions
from test_pm import SOURCE


@unittest.skipUnless(BASH4, 'PM requires Bash 4+')
class PMPerformanceTests(ShellCase):
    def setup_pm(self, count=10):
        config = {'config_version': 6, 'node_id': 'test', 'interface': 'synthetic0',
                  'telegram': {'enable': False}, 'push': {'enable': False},
                  'ports': {str(20000+i): {'quota_gb': 1, 'quota_mode': 'in_out',
                            'group_id': '', 'comment': '', 'dyn_limit': {'enable': False},
                            'ip_limit': {'enable': False}} for i in range(count)}}
        self.write('config.json', json.dumps(config))
        return config

    def run_pm(self, code, stdin='', **env):
        setup = r'''
CONFIG_DIR="$TEST_DIR"; CONFIG_FILE="$TEST_DIR/config.json"; STATE_DIR="$TEST_DIR/state"
CRON_LOCK_FILE="$TEST_DIR/cron.lock"; USER_EDIT_LOCK="$TEST_DIR/edit.lock"
TC_OWNER_FILE="$TEST_DIR/tc-owner"; LOG_FILE="$TEST_DIR/pm.log"
clear() { :; }
curl() { echo UNEXPECTED_NETWORK >&2; return 99; }
systemctl() { echo UNEXPECTED_SERVICE >&2; return 99; }
nft() { echo UNEXPECTED_NFT >&2; return 99; }
'''
        self.write('pm-library.sh', SOURCE)
        result = self.run_shell('source "$TEST_DIR/pm-library.sh"\n' + setup + code, stdin=stdin, **env)
        self.assertNotIn('UNEXPECTED_', result.stderr)
        return result

    def test_ten_port_menu_reads_config_and_blocked_set_in_batches(self):
        config = self.setup_pm()
        config['ports']['20000']['comment'] = 'user \\ name\tline\nnext\x1fend'
        for port in ('20000', '20001'):
            config['ports'][port]['group_id'] = 'shared \\ group'
        config['ports']['20001']['quota_mode'] = 'out_only'
        self.write('config.json', json.dumps(config))
        code = r'''
jq() { echo jq >> "$TEST_DIR/jq.calls"; command jq "$@"; }
nft() { echo nft >> "$TEST_DIR/nft.calls"; echo '{"nftables":[{"set":{"name":"blocked_ports","elem":[20009]}}]}'; }
_load_port_state() { s_acc_in=10; s_acc_out=20; s_is_punished=false; }
fmt_bytes() { printf '%s B\n' "$1"; }
show_main_menu
'''
        result = self.run_pm(code, stdin='0\n')
        self.assert_ok(result)
        self.assertEqual((self.path/'jq.calls').read_text().splitlines(), ['jq']*4)
        self.assertEqual((self.path/'nft.calls').read_text().splitlines(), ['nft'])
        self.assertEqual(result.stdout.count('50 B / 1 GB'), 2)
        self.assertIn(config['ports']['20000']['comment'], result.stdout)
        self.assertIn('[已阻断]', result.stdout)
        self.assertLess(result.stdout.index('20000'), result.stdout.index('20009'))
        self.assertFalse((self.path/'edit.lock').exists())

    def test_unknown_set_and_invalid_group_state_still_display_errors(self):
        config = self.setup_pm(2)
        for item in config['ports'].values(): item['group_id'] = 'g'
        self.write('config.json', json.dumps(config))
        result = self.run_pm(r'''
nft() { return 1; }
_load_port_state() { s_acc_in=10; s_acc_out=20; s_is_punished=false; [[ "$1" != 20001 ]]; }
show_main_menu
''', stdin='0\n')
        self.assert_ok(result)
        self.assertEqual(result.stdout.count('[状态异常，查看日志]'), 2)
        self.assertIn('无法读取封禁状态', (self.path/'pm.log').read_text())

    def test_menu_matches_leading_zero_port_keys_to_numeric_kernel_ports(self):
        config = self.setup_pm(1)
        config['ports']['020000'] = config['ports'].pop('20000')
        self.write('config.json', json.dumps(config))
        result = self.run_pm(r'''
nft() { echo '{"nftables":[{"set":{"name":"blocked_ports","elem":[20000]}}]}'; }
_load_port_state() { s_acc_in=0; s_acc_out=0; s_is_punished=false; }
show_main_menu
''', stdin='0\n')
        self.assert_ok(result)
        self.assertIn('020000', result.stdout)
        self.assertIn('[已阻断]', result.stdout)

    def cron_setup(self):
        return r'''
mkdir -p "$STATE_DIR"
for port in $(jq -r '.ports | keys[]' "$CONFIG_FILE"); do
    _init_port_state_defaults
    _save_port_state "$port" || exit 1
done
nft_table_healthy() { return 0; }
read_kernel_counters() {
    jq -r '.ports | keys[] | "cnt_in_\(.)\t2000000000\ncnt_out_\(.)\t0"' "$CONFIG_FILE"
}
nft() {
    if [[ "$1" == -j ]]; then echo '{"nftables":[{"set":{"name":"blocked_ports"}}]}'; return 0; fi
    [[ "$1 $2" == 'add element' ]] || return 99
    echo "block:${@: -2:1}" >> "$TEST_DIR/events"
}
'''

    def test_all_ports_are_blocked_before_notifications_and_success_is_saved(self):
        config = self.setup_pm(2)
        config['telegram'] = {'enable': True, 'bot_token': 'test-token', 'chat_id': 'test-chat'}
        self.write('config.json', json.dumps(config))
        result = self.run_pm(self.cron_setup()+r'''
_tg_send_chunk() { echo send >> "$TEST_DIR/events"; return 0; }
cron_task
for port in 20000 20001; do _load_port_state "$port"; echo "${port}:${s_quota_level}"; done
''')
        self.assert_ok(result)
        self.assertEqual((self.path/'events').read_text().splitlines(),
                         ['block:20000', 'block:20001', 'send', 'send', 'send', 'send'])
        self.assertIn('20000:100', result.stdout)
        self.assertIn('20001:100', result.stdout)

    def test_failed_notification_preserves_retry_state_and_does_not_prevent_blocks(self):
        config = self.setup_pm(2)
        config['telegram'] = {'enable': True, 'bot_token': 'test-token', 'chat_id': 'test-chat'}
        self.write('config.json', json.dumps(config))
        result = self.run_pm(self.cron_setup()+r'''
_tg_send_chunk() {
    echo send >> "$TEST_DIR/events"
    _TG_LAST_FAILURE_SCOPE=service; _TG_LAST_FAILURE_DETAIL=injected
    return 1
}
cron_task; rc=$?
for port in 20000 20001; do _load_port_state "$port"; echo "${port}:${s_quota_level}"; done
exit "$rc"
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.path/'events').read_text().splitlines(), ['block:20000', 'block:20001', 'send'])
        self.assertIn('20000:0', result.stdout)
        self.assertIn('20001:0', result.stdout)

    def test_notification_budget_starts_only_complete_messages_with_full_request_timeout(self):
        config = self.setup_pm(1)
        config['telegram'] = {'enable':True,'bot_token':'token','chat_id':'chat'}
        self.write('config.json',json.dumps(config))
        code = r'''
curl() { echo REQUEST >> "$TEST_DIR/curl.calls"; printf '%s\n' "$*" > "$TEST_DIR/curl.args"; printf '{"ok":true}\n200'; }
SECONDS=20
_NOTIFY_DEADLINE=$((SECONDS + 2))
_tg_send_now text || exit 1
_NOTIFY_DEADLINE=$((SECONDS - 1))
_tg_send_now text
'''
        result = self.run_pm(code)
        self.assertNotEqual(result.returncode, 0)
        calls = (self.path/'curl.calls').read_text().splitlines()
        self.assertEqual(len(calls), 1)
        self.assertIn('--max-time 10 ', (self.path/'curl.args').read_text())

    def test_started_multipart_message_can_finish_after_budget_boundary(self):
        config = self.setup_pm(1)
        config['telegram'] = {'enable':True,'bot_token':'token','chat_id':'chat'}
        self.write('config.json',json.dumps(config))
        result=self.run_pm(r'''
SECONDS=20; _NOTIFY_DEADLINE=35
_tg_send_chunk() { echo chunk >> "$TEST_DIR/chunks"; SECONDS=$((SECONDS+8)); return 0; }
printf -v message '%08000d' 0
_tg_send_now "$message"
''')
        self.assert_ok(result)
        self.assertEqual((self.path/'chunks').read_text().splitlines(),['chunk']*3)

    def test_quota_warning_progress_survives_round_and_only_missing_message_is_retried(self):
        config=self.setup_pm(1)
        config['telegram']={'enable':True,'bot_token':'token','chat_id':'chat'}
        self.write('config.json',json.dumps(config))
        result=self.run_pm(self.cron_setup()+r'''
nft() {
    if [[ "$1" == -j ]]; then echo '{"nftables":[{"set":{"name":"blocked_ports","elem":[20000]}}]}'; return 0; fi
    return 99
}
_tg_send_chunk() {
    if [[ "$4" == *流量预警* ]]; then echo warning; else echo exhausted; fi >> "$TEST_DIR/notices"
    SECONDS=$((SECONDS+16)); return 0
}
SECONDS=20
cron_task; first_rc=$?
_load_port_state 20000; echo "first:$first_rc:$s_quota_level:$s_quota_warned_level"
_TG_SYNC_FAILED=false; SECONDS=20
cron_task; second_rc=$?
_load_port_state 20000; echo "second:$second_rc:$s_quota_level:$s_quota_warned_level"
exit "$second_rc"
''')
        self.assert_ok(result)
        self.assertIn('first:1:0:100',result.stdout)
        self.assertIn('second:0:100:0',result.stdout)
        self.assertEqual((self.path/'notices').read_text().splitlines(),['warning','exhausted'])

    def test_incomplete_warning_checkpoint_is_cleared_when_usage_is_within_quota(self):
        self.setup_pm(1)
        result=self.run_pm(self.cron_setup()+r'''
_load_port_state 20000; s_quota_warned_level=100; _save_port_state 20000 || exit 1
read_kernel_counters() { printf 'cnt_in_20000\t0\ncnt_out_20000\t0\n'; }
cron_task || exit 1
_load_port_state 20000; echo "checkpoint:$s_quota_warned_level"
''')
        self.assert_ok(result)
        self.assertIn('checkpoint:0',result.stdout)

    def test_warning_checkpoint_write_failure_never_advances_level_or_sends_second_message(self):
        config=self.setup_pm(1)
        config['telegram']={'enable':True,'bot_token':'token','chat_id':'chat'}
        self.write('config.json',json.dumps(config))
        result=self.run_pm(self.cron_setup()+r'''
eval "$(declare -f _save_port_state | sed 's/_save_port_state ()/_save_real ()/')"
_save_port_state() { [[ "$s_quota_warned_level" == 0 ]] || return 1; _save_real "$@"; }
_tg_send_chunk() { echo send >> "$TEST_DIR/notices"; return 0; }
cron_task; rc=$?
_load_port_state 20000; echo "state:$s_quota_level:$s_quota_warned_level"
exit "$rc"
''')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('state:0:0',result.stdout)
        self.assertEqual((self.path/'notices').read_text().splitlines(),['send'])

    def test_valid_port_recovery_notice_is_independent_of_invalid_shared_group_peer(self):
        config=self.setup_pm(2)
        for item in config['ports'].values(): item.update(group_id='shared',quota_gb=1000)
        config['ports']['20000']['dyn_limit']['enable']=True
        config['telegram']={'enable':True,'bot_token':'token','chat_id':'chat'}
        self.write('config.json',json.dumps(config))
        result=self.run_pm(self.cron_setup()+r'''
_load_port_state 20000; s_is_punished=true; s_punish_end_ts=1; _save_port_state 20000 || exit 1
printf bad > "$STATE_DIR/20001.txt"
read_kernel_counters() { printf 'cnt_in_20000\t0\ncnt_out_20000\t0\ncnt_in_20001\t0\ncnt_out_20001\t0\n'; }
apply_port_rules() { echo restored > "$TEST_DIR/rules"; }
_tg_send_chunk() { echo "$4" > "$TEST_DIR/notice"; return 0; }
cron_task; rc=$?
_load_port_state 20000; echo "state:$s_is_punished:$s_pending_qos_notice:$s_recover_notified"
exit "$rc"
''')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('state:false::true',result.stdout)
        self.assertTrue((self.path/'rules').exists())
        self.assertIn('限速已恢复',(self.path/'notice').read_text())
        self.assertEqual((self.path/'state/20001.txt').read_text(),'bad')

    def test_service_failure_skips_geo_but_keeps_sentinel_disconnect(self):
        config = self.setup_pm(1)
        config['ports']['20000']['ip_limit'] = {'enable': True, 'max_ips': 1, 'action': 'block'}
        config['telegram'] = {'enable': True, 'bot_token': 'test-token', 'chat_id': 'test-chat'}
        self.write('config.json', json.dumps(config))
        self.write('connections', '20000\t11.1.1.1\n20000\t11.1.1.2\n')
        result = self.run_pm(r'''
mkdir -p "$STATE_DIR"; _init_port_state_defaults; _save_port_state 20000 || exit 1
_UNIQUE_CONNECTION_SNAPSHOT_FILE="$TEST_DIR/connections"; _CONNECTION_SNAPSHOT_FILE="$TEST_DIR/connections"
_CONNECTION_SNAPSHOT_TS=$(date +%s)
_TG_SYNC_FAILED=true
ss() { echo "$*" > "$TEST_DIR/disconnect.calls"; }
check_ip_sentinel "$_CONNECTION_SNAPSHOT_TS"
''')
        self.assert_ok(result)
        self.assertIn('-K dst', (self.path/'disconnect.calls').read_text())

    def test_quota_boundary_group_sum_out_only_and_unblock_are_unchanged(self):
        config = self.setup_pm(5)
        config['ports']['20001']['quota_mode'] = 'out_only'
        for port in ('20002', '20003'): config['ports'][port]['group_id'] = 'shared'
        self.write('config.json', json.dumps(config))
        counters = []
        for port, incoming in zip(config['ports'], [1073741824,2000000000,600000000,600000000,2000000000]):
            counters.extend([f'cnt_in_{port}\t{incoming}', f'cnt_out_{port}\t0'])
        self.write('counters', '\n'.join(counters)+'\n')
        result = self.run_pm(self.cron_setup()+r'''
read_kernel_counters() { cat "$TEST_DIR/counters"; }
nft() {
    if [[ "$1" == -j ]]; then echo '{"nftables":[{"set":{"name":"blocked_ports","elem":[20001]}}]}'; return 0; fi
    printf '%s:%s\n' "$1" "${@: -2:1}" >> "$TEST_DIR/quota.events"
}
cron_task
_load_port_state 20000; echo "boundary:$s_acc_in:$s_quota_level"
''')
        self.assert_ok(result)
        self.assertEqual((self.path/'quota.events').read_text().splitlines(),
                         ['delete:20001','add:20002','add:20003','add:20004'])
        self.assertIn('boundary:1073741824:0', result.stdout)

    def test_burst_trigger_and_recovery_keep_pending_notices_when_telegram_disabled(self):
        config = self.setup_pm(2)
        for item in config['ports'].values():
            item['quota_gb'] = 1000
            item['dyn_limit']['enable'] = True
        self.write('config.json', json.dumps(config))
        result = self.run_pm(self.cron_setup()+r'''
now=$(date +%s)
_load_port_state 20000; s_high_seconds=1140; s_last_sample_ts=$((now-60)); _save_port_state 20000
_load_port_state 20001; s_is_punished=true; s_punish_end_ts=$((now-1)); _save_port_state 20001
read_kernel_counters() {
    printf 'cnt_in_20000\t0\ncnt_out_20000\t3000000000\ncnt_in_20001\t0\ncnt_out_20001\t0\n'
}
apply_port_rules() { echo "$1:$s_is_punished" >> "$TEST_DIR/burst.events"; }
cron_task
for port in 20000 20001; do
    _load_port_state "$port"; echo "$port:$s_is_punished:$s_pending_qos_notice:$s_rules_dirty"
done
''')
        self.assert_ok(result)
        self.assertEqual((self.path/'burst.events').read_text().splitlines(), ['20000:true','20001:false'])
        self.assertIn('20000:true:punish:false', result.stdout)
        self.assertIn('20001:false:recover:false', result.stdout)

    def test_monthly_shared_reset_keeps_counter_baselines_and_unblocks_before_notifications(self):
        config = self.setup_pm(2)
        for item in config['ports'].values(): item.update(group_id='shared',reset_day=1)
        config['telegram'] = {'enable': True, 'bot_token': 'test-token', 'chat_id': 'test-chat'}
        self.write('config.json', json.dumps(config))
        result = self.run_pm(self.cron_setup()+r'''
for port in 20000 20001; do
    _load_port_state "$port"; s_acc_in=9999999999; s_last_reset_ts=1; s_quota_level=100; s_quota_warned_level=100
    _save_port_state "$port" || exit 1
done
nft() {
    if [[ "$1" == -j ]]; then echo '{"nftables":[{"set":{"name":"blocked_ports","elem":[20000,20001]}}]}'; return 0; fi
    printf '%s:%s\n' "$1" "${@: -2:1}" >> "$TEST_DIR/reset.events"
}
cron_task
for port in 20000 20001; do
    _load_port_state "$port"; echo "$port:$s_acc_in:$s_acc_out:$s_last_k_in:$s_quota_level:$s_quota_warned_level"
done
''')
        self.assert_ok(result)
        self.assertEqual((self.path/'reset.events').read_text().splitlines(), ['delete:20000','delete:20001'])
        for port in ('20000','20001'): self.assertIn(port+':0:0:2000000000:0:0', result.stdout)

    def test_expiry_confirmation_is_saved_only_after_success(self):
        config = self.setup_pm(1)
        expiry = (datetime.now(timezone.utc)+timedelta(days=2)).date().isoformat()
        config['ports']['20000'].update(quota_gb=100, expiry_date=expiry)
        config['telegram'] = {'enable': True, 'bot_token': 'test-token', 'chat_id': 'test-chat'}
        self.write('config.json', json.dumps(config))
        for failed in ('yes','no'):
            with self.subTest(failed=failed):
                result = self.run_pm(self.cron_setup()+r'''
_tg_send_chunk() {
    if [[ "$SEND_FAILED" == yes ]]; then _TG_LAST_FAILURE_SCOPE=service; return 1; fi
    return 0
}
cron_task; rc=$?
_load_port_state 20000; printf 'expiry:%s\n' "$s_expiry_notified_date"
exit "$rc"
''', SEND_FAILED=failed)
                self.assertEqual(result.returncode, 1 if failed=='yes' else 0, result.stdout+result.stderr)
                self.assertIn('expiry:'+('' if failed=='yes' else expiry)+'\n', result.stdout)

    def test_invalid_state_preserves_shared_group_policy_and_skips_notifications(self):
        config = self.setup_pm(2)
        for item in config['ports'].values(): item['group_id'] = 'shared'
        self.write('config.json', json.dumps(config))
        result = self.run_pm(self.cron_setup()+r'''
printf bad > "$STATE_DIR/20001.txt"
cron_task
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.path/'events').exists())
        self.assertEqual((self.path/'state/20001.txt').read_text(), 'bad')


class XrayRequestTests(ShellCase):
    def test_version_lookup_has_bounded_connection_and_total_time(self):
        result = self.run_shell(functions('x-sb','install_xray')+r'''
XRAY_CONF_DIR="$TEST_DIR/config"; DAT_DIR="$TEST_DIR/data"; XRAY_BIN="$TEST_DIR/missing"
map_arch() { echo 64; }
curl() { printf '%s\n' "$*" > "$TEST_DIR/curl.args"; return 28; }
install_xray
''')
        self.assertNotEqual(result.returncode, 0)
        args = (self.path/'curl.args').read_text()
        self.assertIn('--connect-timeout 8', args)
        self.assertIn('--max-time 15', args)
        self.assertIn('无法获取 Xray 最新版本', result.stdout)


class WorkerPerformanceTests(unittest.TestCase):
    def test_worker_budgets_backoff_cached_reports_and_callback_timeouts(self):
        node = shutil.which('node')
        self.assertIsNotNone(node)
        result = subprocess.run([node, str(Path(__file__).with_name('worker_performance.mjs'))],
                                text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()

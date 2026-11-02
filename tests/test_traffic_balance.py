"""Traffic balance accounting and real local curl flows; never contacts public sources."""
import contextlib
import copy
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('traffic_balance', Path(__file__).resolve().parents[1] / 'traffic_balance.py')
b = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(b)
REAL_PREFLIGHT = b.preflight
NOW = int(dt.datetime(2026, 11, 2, 12, tzinfo=dt.timezone.utc).timestamp())
SETTINGS = dict(UseUTC=1, SaveInterval=5)


def config(**kw):
    return dict(dict(b.DEFAULT, interface='eth0', bandwidth_mbps=20), **kw)


def fixture(rx=100*b.MIB, tx=840*b.MIB, updated=NOW):
    return dict(jsonversion='2', vnstatversion='2.13', interfaces=[dict(
        name='eth0', created=dict(timestamp=NOW-2*86400), updated=dict(timestamp=updated),
        traffic=dict(total=dict(rx=rx+1000, tx=tx+1000), day=[dict(
            date=dict(year=2026, month=11, day=2), rx=rx, tx=tx)]))])


def sample():
    return b.parse_stats(json.dumps(fixture()), 'eth0', SETTINGS, NOW)


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.c = config()
        self.s = b.initial_state()
        self.day, self.v = sample()
        b.observe(self.s, self.day, self.v)
        b.STOP.clear()
        preflight = patch.object(b, 'preflight', return_value=SimpleNamespace(received=0))
        preflight.start()
        self.addCleanup(preflight.stop)
        network = patch.object(b, 'detect_interface', return_value='eth0')
        network.start()
        self.addCleanup(network.stop)

    def test_config_units_and_invalid_values(self):
        self.assertEqual(b.amount_input('0.5 GiB'), 512)
        for value in ('500', '500 MB', '-1 MiB', 'NaN MiB'):
            with self.assertRaises(b.Error):
                b.amount_input(value)
        for key, value in [('speed_mbps', float('nan')), ('daily_mib', True),
                           ('ratio', 1.9), ('ratio', 5.1), ('bandwidth_mbps', 0), ('interval_max', 1), ('max_attempts', 1.1),
                           ('interface', '../eth0')]:
            with self.subTest(key=key), self.assertRaises(b.Error):
                b.validate_config(dict(self.c, **{key: value}))
        self.assertEqual(b.validate_config(dict(self.c, speed_mbps=.25))['speed_mbps'], .25)

    def test_gap_bounds_daily_and_attempt_limits(self):
        self.assertEqual(b.plan(self.c, self.s, self.v)[0], 300*b.MIB)
        v = dict(self.v, rx=359*b.MIB, tx=840*b.MIB)
        self.assertEqual(b.plan(dict(self.c, round_mib=100), self.s, v)[0], 41*b.MIB)
        for v in (dict(self.v, rx=400*b.MIB), dict(self.v, rx=500*b.MIB),
                  dict(self.v, tx=199*b.MIB), dict(self.v, tx=0)):
            self.assertEqual(b.plan(self.c, self.s, v)[0], 0)
        self.s['used'] = 10239*b.MIB
        self.assertEqual(b.plan(self.c, self.s, self.v)[0], b.MIB)
        self.s['attempts'] = 100
        self.assertEqual(b.plan(self.c, self.s, self.v)[0], 0)

    def test_outbound_inbound_direction_decimals_and_last_byte(self):
        # 2.1 GiB out / 1 GiB in is already enough; 1:1 needs no download.
        for rx, tx in ((10*b.MIB, 21*b.MIB), (5*1024*b.MIB, 5*1024*b.MIB)):
            self.assertTrue(b.target_reached(self.c, rx, tx))
            self.assertEqual(b.plan(dict(self.c, min_tx_mib=0), self.s,
                                    dict(self.v, rx=rx, tx=tx))[0], 0)
        c = dict(self.c, min_tx_mib=0)
        v = dict(self.v, rx=95, tx=201)
        self.assertEqual(b.plan(c, self.s, v)[0], 1)
        self.assertFalse(b.target_reached(c, 95, 201))
        self.assertTrue(b.target_reached(c, 96, 201))
        self.assertGreater(b.plan(self.c, self.s, dict(self.v, rx=0))[0], 0)

    def test_large_daily_budget_still_stops_after_real_gap_is_filled(self):
        s = b.initial_state()
        c = dict(self.c, ratio=2)
        v = dict(self.v, rx=1024*b.MIB, tx=4096*b.MIB,
                 total_rx=2048*b.MIB, total_tx=8192*b.MIB)
        b.observe(s, self.day, v)
        # Only 1 GiB is needed for a 2:1 target, even though the budget is 10 GiB.
        for _ in range(2):
            amount, _ = b.plan(c, s, v)
            self.assertEqual(amount, 512*b.MIB)
            with patch.object(b.time, 'time', return_value=v['updated']):
                b.reserve(s, amount, v)
                b.settle(s, amount)
            v = dict(v, rx=v['rx']+amount, total_rx=v['total_rx']+amount,
                     updated=v['updated']+1)
            b.observe(s, self.day, v)
        amount, reason = b.plan(c, s, v)
        self.assertEqual(amount, 0)
        self.assertIn('无需补量', reason)
        self.assertEqual((s['used'], s['attempts']), (1024*b.MIB, 2))

    def test_multiple_rounds_stop_at_target_without_using_entire_daily_budget(self):
        s = b.initial_state()
        c = dict(self.c, ratio=2)
        v = dict(self.v, rx=5*1024*b.MIB, tx=18*1024*b.MIB,
                 total_rx=6*1024*b.MIB, total_tx=20*1024*b.MIB)
        b.observe(s, self.day, v)
        for _ in range(8):
            amount, _ = b.plan(c, s, v)
            self.assertEqual(amount, 512*b.MIB)
            with patch.object(b.time, 'time', return_value=v['updated']):
                b.reserve(s, amount, v)
                b.settle(s, amount)
            v = dict(v, rx=v['rx']+amount, total_rx=v['total_rx']+amount,
                     updated=v['updated']+1)
            b.observe(s, self.day, v)
        self.assertEqual(b.plan(c, s, v)[0], 0)
        self.assertEqual((s['used'], s['attempts']), (4*1024*b.MIB, 8))
        self.assertEqual(v['rx']*2, v['tx'])

    def test_large_gap_is_capped_per_round_but_small_gap_is_not_padded(self):
        large = dict(self.v, rx=1024*b.MIB, tx=10*1024*b.MIB)
        self.assertEqual(b.plan(self.c, self.s, large)[0], 512*b.MIB)
        near = dict(self.v, rx=1790*b.MIB, tx=4200*b.MIB)
        self.assertEqual(b.plan(self.c, self.s, near)[0], 210*b.MIB)
        # Reaching the single outbound/inbound target stops future rounds.
        self.assertEqual(b.plan(self.c, self.s, dict(near, rx=2000*b.MIB))[0], 0)

    def test_in_range_daemon_does_not_request_a_download_or_spend_budget(self):
        s = copy.deepcopy(self.s)
        s['mode'] = 'running'
        v = dict(self.v, rx=400*b.MIB, total_rx=self.v['total_rx']+300*b.MIB)
        def scheduled(_c, state, reason=None):
            state['next_check'] = 0
            if reason: state['reason'] = reason
        with patch.object(b, 'locked', contextlib.nullcontext), \
             patch.object(b, 'load_json', side_effect=[self.c, s]), patch.object(b, 'atomic_json'), \
             patch.object(b, 'vn_settings', return_value=SETTINGS), patch.object(b, 'stats', return_value=(self.day, v)), \
             patch.object(b, 'wait_fresh_stats', return_value=(self.day, v)), \
             patch.object(b, 'schedule', side_effect=scheduled), patch.object(b.STOP, 'wait', side_effect=[False, True]), \
             patch.object(b, 'download') as dl:
            b.daemon()
        dl.assert_not_called()
        self.assertEqual((s['used'], s['attempts']), (0, 0))

    def test_daemon_changed_exit_never_reads_mixed_stats_or_spends_budget(self):
        s = dict(copy.deepcopy(self.s), mode='running')
        def scheduled(_c, state, reason=None):
            state['next_check'] = 0
            if reason: state['reason'] = reason
        with patch.object(b, 'locked', contextlib.nullcontext), \
             patch.object(b, 'load_json', side_effect=[self.c, s]), patch.object(b, 'atomic_json'), \
             patch.object(b, 'detect_interface', return_value='ens9'), \
             patch.object(b, 'schedule', side_effect=scheduled), patch.object(b.STOP, 'wait', side_effect=[False, True]), \
             patch.object(b, 'stats') as stats, patch.object(b, 'round_download') as download:
            b.daemon()
        stats.assert_not_called()
        download.assert_not_called()
        self.assertIn('网卡不一致', s['reason'])
        self.assertEqual((s['used'], s['attempts']), (0, 0))

    def test_large_round_uses_large_static_files_and_requests_only_its_budget(self):
        for source in b.SOURCES:
            cmd = b.curl_command(self.c, source, 512*b.MIB, 300)
            self.assertEqual(cmd[cmd.index('--range')+1], '0-536870911')
            self.assertEqual(cmd[cmd.index('--max-filesize')+1], '536870912')
            self.assertIn({'ovh': '/1Gb.dat', 'hetzner': '/1GB.bin',
                           'cloudflare': 'bytes=536870912'}[source], cmd[-1])

    def test_reserve_partial_settle_and_coverage_barrier(self):
        with patch.object(b.time, 'time', return_value=NOW):
            b.reserve(self.s, 20*b.MIB, self.v)
            self.assertEqual(self.s['used'], 20*b.MIB)
            self.assertEqual(self.s['attempts'], 1)
            b.settle(self.s, 3*b.MIB)
        self.assertEqual(self.s['used'], 3*b.MIB)
        self.assertEqual(b.plan(self.c, self.s, self.v)[0], 0)
        # Even a higher count doesn't cover a sample taken before completion.
        v = dict(self.v, total_rx=self.v['total_rx']+3*b.MIB)
        b.observe(self.s, self.day, v)
        self.assertIsNotNone(self.s['barrier'])
        v['updated'] += 1
        b.observe(self.s, self.day, v)
        self.assertIsNone(self.s['barrier'])

    def test_crash_keeps_reserved_budget_and_count(self):
        with patch.object(b.time, 'time', return_value=NOW):
            b.reserve(self.s, 20*b.MIB, self.v)
        persisted = json.loads(json.dumps(self.s))
        b.recover(persisted)
        self.assertEqual(persisted['used'], 20*b.MIB)
        self.assertEqual(persisted['attempts'], 1)
        self.assertIsNone(persisted['pending'])
        self.assertIsNotNone(persisted['barrier'])
        b.recover(persisted)
        self.assertEqual(persisted['used'], 20*b.MIB)

    def test_day_rollover_not_clock_rollback_or_db_reset(self):
        self.s.update(used=1234, attempts=3, mode='paused')
        b.observe(self.s, '2026-11-03', dict(self.v, updated=NOW+86400, rx=0, tx=0))
        self.assertEqual((self.s['used'], self.s['attempts'], self.s['mode']), (0, 0, 'paused'))
        with self.assertRaises(b.Error):
            b.observe(self.s, self.day, self.v)
        for key in ('created', 'updated', 'total_rx', 'total_tx'):
            s = b.initial_state()
            b.observe(s, self.day, self.v)
            with self.subTest(key=key), self.assertRaises(b.Error):
                b.observe(s, self.day, dict(self.v, **{key: self.v[key]-1}))

    def test_statistics_reject_missing_stale_future_incomplete_and_negative(self):
        for change in ('missing', 'stale', 'future', 'new', 'negative', 'old_api'):
            f = fixture()
            i = f['interfaces'][0]
            if change == 'missing': i['traffic']['day'] = []
            if change == 'stale': i['updated']['timestamp'] -= 421
            if change == 'future': i['updated']['timestamp'] += 1
            if change == 'new': i['created']['timestamp'] = NOW-10
            if change == 'negative': i['traffic']['day'][0]['rx'] = -1
            if change == 'old_api': f['jsonversion'] = '1'
            with self.subTest(change=change), self.assertRaises(b.Error):
                b.parse_stats(json.dumps(f), 'eth0', SETTINGS, NOW)

    def test_reported_new_database_waits_without_claiming_source_download_failure(self):
        stamp = 1793627020
        f = fixture(rx=16682581, tx=15284164, updated=stamp)
        f['interfaces'][0].update(name='ens5', created=dict(timestamp=1793626701))
        for missing in (False, True):
            current = copy.deepcopy(f)
            if missing:
                current['interfaces'][0]['traffic']['day'] = []
            with self.subTest(missing=missing), self.assertRaises(b.StatsNotReady) as raised:
                b.parse_stats(json.dumps(current), 'ens5', SETTINGS, stamp+1)
            self.assertIn('首日统计尚未完整', str(raised.exception))
            self.assertIn('无需操作', str(raised.exception))
            self.assertNotIn('统计异常', str(raised.exception))

    def test_first_day_does_not_hide_stale_future_or_negative_statistics(self):
        for change in ('stale', 'future', 'negative'):
            f = fixture()
            i = f['interfaces'][0]
            i['created'] = dict(timestamp=NOW-10)
            if change == 'stale': i['updated']['timestamp'] = NOW-421
            if change == 'future': i['updated']['timestamp'] = NOW+1
            if change == 'negative': i['traffic']['day'][0]['rx'] = -1
            with self.subTest(change=change), self.assertRaises(b.Error) as raised:
                b.parse_stats(json.dumps(f), 'eth0', SETTINGS, NOW)
            self.assertNotIsInstance(raised.exception, b.StatsNotReady)

    def test_invalid_history_date_or_counter_is_not_normal_waiting(self):
        for field, value in (('month', 13), ('day', 32), ('rx', -1)):
            f = fixture()
            row = f['interfaces'][0]['traffic']['day'][0]
            if field == 'rx':
                row[field] = value
                row['date']['day'] = 1
            else:
                row['date'][field] = value
            with self.subTest(field=field), self.assertRaises(b.Error) as raised:
                b.parse_stats(json.dumps(f), 'eth0', SETTINGS, NOW)
            self.assertNotIsInstance(raised.exception, b.StatsNotReady)

    def test_normal_initial_statistics_wait_is_logged_as_info_and_spends_nothing(self):
        s = dict(copy.deepcopy(self.s), mode='running')
        with patch.object(b, 'locked', contextlib.nullcontext), \
             patch.object(b, 'load_json', side_effect=[self.c, s]), patch.object(b, 'atomic_json'), \
             patch.object(b, 'vn_settings', return_value=SETTINGS), \
             patch.object(b, 'stats', side_effect=b.StatsNotReady('首日统计等待，无需操作')), \
             patch.object(b.STOP, 'wait', return_value=True), patch.object(b, 'download') as download, \
             self.assertLogs(b.logger, level='INFO') as logs:
            b.daemon()
        self.assertTrue(all(record.levelno == b.logging.INFO for record in logs.records))
        self.assertEqual((s['used'], s['attempts']), (self.s['used'], self.s['attempts']))
        download.assert_not_called()

    def test_utc_date_and_local_date(self):
        self.assertEqual(b.date_now(SETTINGS, NOW), '2026-11-02')
        stamp = NOW-13*3600
        self.assertEqual(b.date_now(SETTINGS, stamp), '2026-11-01')
        with patch.object(b.dt, 'datetime') as mocked:
            mocked.fromtimestamp.return_value.date.return_value.isoformat.return_value = 'local-day'
            self.assertEqual(b.date_now(dict(UseUTC=0), stamp), 'local-day')
            mocked.fromtimestamp.assert_called_with(stamp)

    def test_atomic_state_and_corruption_does_not_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'state.json'
            b.atomic_json(p, self.s)
            self.assertEqual(b.validate_state(b.load_json(p)), self.s)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            before = p.read_bytes()
            with patch.object(b.os, 'replace', side_effect=OSError('disk full')):
                with self.assertRaises(b.Error): b.atomic_json(p, b.initial_state())
            self.assertEqual(p.read_bytes(), before)
            p.write_text('{broken')
            with self.assertRaises(b.Error): b.load_json(p)
            self.assertEqual(p.read_text(), '{broken')
            with self.assertRaises(b.Error): b.validate_state(dict(self.s, pending={}))
            with self.assertRaises(b.Error): b.validate_state(dict(self.s, date=None))

    def test_retry_after_seconds_dates_and_invalid(self):
        self.assertEqual(b.retry_after('HTTP/1.1 429\r\nRetry-After: 123\r\n', NOW), NOW+123)
        self.assertEqual(b.retry_after('Retry-After: Mon, 02 Nov 2026 12:10:00 GMT\r\n', NOW), NOW+600)
        self.assertEqual(b.retry_after('Retry-After: nope\r\n', NOW), 0)

    def test_round_partial_fallback_counts_every_attempt_and_preserves_barrier(self):
        saved = []
        def save(_, s): saved.append(copy.deepcopy(s))
        results = [(3*b.MIB, False, 0, '下载失败'), (17*b.MIB, True, 0, '下载成功')]
        with patch.object(b, 'Guard'), patch.object(b, 'download', side_effect=results) as dl:
            b.round_download(self.c, self.s, 20*b.MIB, SETTINGS, b.date_now(SETTINGS), save)
        self.assertEqual(dl.call_count, 2)
        self.assertEqual(self.s['used'], 20*b.MIB)
        self.assertEqual(self.s['attempts'], 2)
        self.assertEqual(saved[0]['pending']['amount'], 20*b.MIB)
        self.assertEqual(saved[2]['pending']['amount'], 17*b.MIB)
        self.assertEqual(self.s['barrier']['total_rx'], self.v['total_rx']+20*b.MIB)

    def test_reservation_write_failure_never_starts_download(self):
        with patch.object(b, 'Guard'), patch.object(b, 'download') as dl:
            def fail(*_): raise b.Error('保存失败')
            with self.assertRaises(b.Error):
                b.round_download(self.c, self.s, b.MIB, SETTINGS, b.date_now(SETTINGS), fail)
            dl.assert_not_called()

    def test_known_pre_start_failure_refunds_only_the_new_reservation(self):
        prior = dict(after=NOW, total_rx=self.v['total_rx']+3*b.MIB)
        self.s.update(used=3*b.MIB, attempts=1, barrier=prior.copy())
        with patch.object(b, 'Guard'), patch.object(b, 'download', side_effect=b.DownloadNotStarted('curl missing')):
            b.round_download(self.c, self.s, 20*b.MIB, SETTINGS, b.date_now(SETTINGS), lambda *_: None)
        self.assertEqual((self.s['used'], self.s['attempts']), (3*b.MIB, 1))
        self.assertIsNone(self.s['pending'])
        self.assertEqual(self.s['barrier'], prior)

    def test_header_setup_failure_is_known_not_started(self):
        with patch.object(b, 'Guard'), patch.object(b.tempfile, 'NamedTemporaryFile', side_effect=OSError('full /run')), \
             patch.object(b.subprocess, 'Popen') as process:
            with self.assertRaises(b.DownloadNotStarted):
                b.download(self.c, 'cloudflare', b.MIB, SETTINGS, self.day, time.monotonic()+10)
        process.assert_not_called()

    def test_curl_exec_failure_is_known_not_started(self):
        with tempfile.TemporaryDirectory() as headers_dir:
            with patch.object(b, 'Guard'), patch.object(b, 'HEADER_DIR', headers_dir), \
                 patch.object(b.subprocess, 'Popen', side_effect=FileNotFoundError('curl missing')):
                with self.assertRaises(b.DownloadNotStarted):
                    b.download(self.c, 'cloudflare', b.MIB, SETTINGS, self.day, time.monotonic()+10)
            self.assertEqual(list(Path(headers_dir).iterdir()), [])

    def test_rate_limit_ends_round_and_persists_cooldown(self):
        with patch.object(b, 'Guard'), patch.object(b, 'download', return_value=(0, False, NOW+600, '限流')) as dl:
            b.round_download(self.c, self.s, b.MIB, SETTINGS, b.date_now(SETTINGS), lambda *_: None)
        self.assertEqual(dl.call_count, 1)
        self.assertEqual(self.s['cooldown'], NOW+600)
        self.assertEqual(self.s['attempts'], 1)

    def test_three_failures_stop_and_attempt_limit_caps_fallback(self):
        for attempts, expected in ((0, 3), (99, 1)):
            s = copy.deepcopy(self.s)
            s['attempts'] = attempts
            with patch.object(b, 'Guard'), patch.object(b, 'download', return_value=(0, False, 0, '下载失败')) as dl:
                b.round_download(self.c, s, b.MIB, SETTINGS, b.date_now(SETTINGS), lambda *_: None)
            self.assertEqual(dl.call_count, expected)

    def test_sources_rotate_as_a_shuffled_deck(self):
        first = [b.source_candidates(self.s)[0] for _ in range(3)]
        self.assertEqual(sorted(first), sorted(b.SOURCES))

    def test_paused_and_stopped_daemon_never_queries_or_downloads(self):
        for mode in ('paused', 'stopped'):
            s = dict(self.s, mode=mode, reason='手动状态')
            with patch.object(b, 'locked', contextlib.nullcontext), patch.object(b, 'load_json', side_effect=[self.c, s]), \
                 patch.object(b, 'atomic_json'), patch.object(b, 'stats') as st, patch.object(b, 'download') as dl:
                b.daemon()
            st.assert_not_called()
            dl.assert_not_called()
            self.assertEqual(s['reason'], '手动状态')

    def test_exclusive_lock_prevents_duplicate_instance(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'lock'
            with b.locked(p):
                with self.assertRaises(b.Error):
                    with b.locked(p): pass

    def test_guard_terminates_on_first_busy_sample(self):
        with patch.object(b, 'counters', side_effect=[(0,0), (10**7,0), (20*10**6,0), (30*10**6,0)]), \
             patch.object(b.os, 'getloadavg', return_value=(0,0,0)), patch.object(b.time, 'monotonic', side_effect=[0,5,10,15]), \
             patch.object(b, 'cpu_times', side_effect=[(100,100),(200,200),(300,300),(400,400)]):
            g = b.Guard(dict(self.c, bandwidth_mbps=10))
            self.assertTrue(g.check())

    def test_showconfig_accepts_commented_effective_defaults(self):
        with patch.object(b, 'run', return_value=';UseUTC 0\n;SaveInterval 5\n'):
            self.assertEqual(b.vn_settings(), dict(UseUTC=0, SaveInterval=5))
        with patch.object(b, 'run', return_value='SaveInterval 5\n'):
            self.assertEqual(b.vn_settings(), dict(UseUTC=0, SaveInterval=5))
        with patch.object(b, 'run', return_value='UseUTC 1\n'):
            with self.assertRaises(b.Error): b.vn_settings()

    def test_old_vnstat_calendar_fields_are_supported_conservatively(self):
        f = fixture()
        f['vnstatversion'] = '2.6'
        i = f['interfaces'][0]
        i['created'] = dict(date=dict(year=2026, month=10, day=31))
        i['updated'] = dict(date=dict(year=2026, month=11, day=2), time=dict(hour=12, minute=0))
        day, v = b.parse_stats(json.dumps(f), 'eth0', SETTINGS, NOW+30)
        self.assertEqual(day, '2026-11-02')
        self.assertEqual(v['updated'], NOW)
        s = b.initial_state()
        b.observe(s, day, v)
        s['barrier'] = dict(after=NOW+10, total_rx=v['total_rx'])
        b.observe(s, day, v)
        self.assertIsNotNone(s['barrier'])
        b.observe(s, day, dict(v, updated=NOW+60))
        self.assertIsNone(s['barrier'])
        i['updated']['time']['minute'] = 60
        with self.assertRaises(b.Error):
            b.parse_stats(json.dumps(f), 'eth0', SETTINGS, NOW+30)

    def test_stop_and_pause_work_even_with_corrupted_json(self):
        for mode in ('paused', 'stopped'):
            with patch.object(b, 'run', return_value='') as run, patch.object(b, 'locked', contextlib.nullcontext), \
                 patch.object(b, 'load_json', side_effect=b.Error('损坏')):
                with self.assertRaises(b.Error): b.control(mode)
            self.assertEqual(run.call_args_list, [unittest.mock.call('systemctl', 'stop', b.SERVICE),
                                                 unittest.mock.call('systemctl', 'disable', b.SERVICE)])

    def test_stop_save_failure_leaves_service_disabled(self):
        with patch.object(b, 'run', return_value='') as run, patch.object(b, 'locked', contextlib.nullcontext), \
             patch.object(b, 'load_json', return_value=self.s), patch.object(b, 'atomic_json', side_effect=b.PersistenceError('disk full')):
            with self.assertRaises(b.PersistenceError): b.control('paused')
        self.assertFalse(any('enable' in c.args or 'start' in c.args for c in run.call_args_list))

    def test_resume_keeps_daily_ledger_and_duplicate_start_is_blocked(self):
        s = dict(self.s, mode='paused', used=1234, attempts=3)
        with patch.object(b, 'run', return_value='inactive') as run, patch.object(b, 'locked', contextlib.nullcontext), \
             patch.object(b, 'load_json', side_effect=[self.c, s, s]), patch.object(b, 'atomic_json'):
            b.control('running')
        self.assertEqual((s['used'], s['attempts'], s['mode']), (1234, 3, 'running'))
        self.assertIn(unittest.mock.call('systemctl', 'start', b.SERVICE), run.call_args_list)
        with patch.object(b, 'run', return_value='active') as run, \
             patch.object(b, 'load_json', side_effect=[self.c, s]):
            with self.assertRaises(b.Error): b.control('running')
        self.assertFalse(any('start' in c.args for c in run.call_args_list))

    def test_midnight_boundary_does_not_start_download(self):
        stamp = int(dt.datetime(2026, 11, 2, 23, 59, tzinfo=dt.timezone.utc).timestamp())
        with patch.object(b.time, 'time', return_value=stamp), patch.object(b, 'download') as dl:
            b.round_download(self.c, self.s, b.MIB, SETTINGS, self.day, lambda *_: None)
        dl.assert_not_called()
        self.assertEqual(self.s['attempts'], 0)

    def test_interface_registration_works_with_old_json_api(self):
        with patch.object(b, 'run', return_value=json.dumps(fixture())) as run:
            b.ensure_interface('eth0')
        self.assertEqual(run.call_count, 1)
        with patch.object(b, 'run', side_effect=[json.dumps(fixture()), '', '']) as run:
            b.ensure_interface('eth1')
        self.assertEqual(run.call_args_list[1], unittest.mock.call('vnstat', '--add', '-i', 'eth1'))
        with patch.object(b, 'run', side_effect=[b.Error('no database'), '', '']) as run:
            b.ensure_interface('eth0')
        self.assertEqual(run.call_count, 3)
        with patch.object(b, 'run', return_value='broken') as run:
            with self.assertRaises(b.Error): b.ensure_interface('eth0')
        self.assertEqual(run.call_count, 1)

    def test_boot_checks_stats_and_waits_before_first_download(self):
        s = dict(self.s, mode='running')
        with patch.object(b, 'locked', contextlib.nullcontext), \
             patch.object(b, 'load_json', side_effect=[self.c, s]), patch.object(b, 'atomic_json') as save, \
             patch.object(b, 'vn_settings', return_value=SETTINGS), patch.object(b, 'stats', return_value=(self.day, self.v)) as stats, \
             patch.object(b.STOP, 'wait', side_effect=[False, True]), patch.object(b, 'download') as dl:
            before = time.time()
            b.daemon()
        stats.assert_called_once()
        dl.assert_not_called()
        self.assertGreaterEqual(s['next_check'], int(before)+20*60)
        self.assertLessEqual(s['next_check'], int(time.time())+60*60)

    def test_busy_preflight_never_reserves_or_starts_download(self):
        with patch.object(b, 'preflight', side_effect=b.Error('业务繁忙')), patch.object(b, 'download') as dl:
            with self.assertRaises(b.Error):
                b.round_download(self.c, self.s, b.MIB, SETTINGS, b.date_now(SETTINGS), lambda *_: None)
        dl.assert_not_called()
        self.assertEqual((self.s['used'], self.s['attempts']), (0, 0))

    def test_preflight_incoming_traffic_only_reduces_original_plan(self):
        for incoming, expected in ((8*b.MIB, 12*b.MIB), (21*b.MIB, 0)):
            s = copy.deepcopy(self.s)
            with patch.object(b, 'preflight', return_value=SimpleNamespace(received=incoming)), \
                 patch.object(b, 'download', return_value=(expected, True, 0, '下载成功')) as dl:
                b.round_download(self.c, s, 20*b.MIB, SETTINGS, b.date_now(SETTINGS), lambda *_: None)
            self.assertEqual(s['used'], expected)
            if expected:
                self.assertEqual(dl.call_args.args[2], expected)
            else:
                dl.assert_not_called()
                self.assertEqual(s['attempts'], 0)

    def test_preflight_stops_if_business_rx_already_reaches_lower_bound(self):
        self.s['last'] = dict(self.v, rx=399*b.MIB)
        with patch.object(b, 'preflight', return_value=SimpleNamespace(received=2*b.MIB)), \
             patch.object(b, 'download') as dl:
            b.round_download(self.c, self.s, 41*b.MIB, SETTINGS, b.date_now(SETTINGS), lambda *_: None)
        dl.assert_not_called()
        self.assertEqual((self.s['used'], self.s['attempts']), (0, 0))
        self.assertIn('比例达标', self.s['reason'])

    def test_partial_failed_download_does_not_switch_sources_after_recovery(self):
        self.s['last'] = dict(self.v, rx=399*b.MIB)
        with patch.object(b, 'download', return_value=(2*b.MIB, False, 0, '下载失败')) as dl:
            b.round_download(self.c, self.s, 41*b.MIB, SETTINGS, b.date_now(SETTINGS), lambda *_: None)
        self.assertEqual(dl.call_count, 1)
        self.assertEqual((self.s['used'], self.s['attempts']), (2*b.MIB, 1))
        self.assertIn('比例达标', self.s['reason'])

    def test_round_budget_is_not_reduced_by_old_240_second_prediction(self):
        c = dict(self.c, bandwidth_mbps=30)
        def completed(_c, _source, amount, *_args, **_kw):
            return amount, True, 0, '下载成功'
        with patch.object(b, 'download', side_effect=completed) as dl:
            b.round_download(c, self.s, 512*b.MIB, SETTINGS, b.date_now(SETTINGS), lambda *_: None)
        self.assertEqual(dl.call_args.args[2], 512*b.MIB)
        self.assertEqual(self.s['used'], 512*b.MIB)
        self.assertEqual(self.s['attempts'], 1)

    def test_user_limit_is_never_raised_by_server_bandwidth_share(self):
        self.assertEqual(b.effective_speed(dict(self.c, speed_mbps=.5)), .5)
        self.assertEqual(b.effective_speed(dict(self.c, speed_mbps=.5, bandwidth_mbps=30)), .5)
        self.assertEqual(b.effective_speed(dict(self.c, bandwidth_mbps=30)), 12)
        self.assertEqual(b.effective_speed(self.c), 8)

    def test_cpu_spike_stops_without_waiting_for_one_minute_load(self):
        with patch.object(b, 'counters', return_value=(0, 0)), \
             patch.object(b.os, 'getloadavg', return_value=(0, 0, 0)), \
             patch.object(b, 'cpu_times', side_effect=[(100, 90), (200, 95)]), \
             patch.object(b.time, 'monotonic', side_effect=[0, 1]):
            guard = b.Guard(self.c)
            self.assertTrue(guard.check())

    def test_preflight_leaves_room_for_planned_download_before_network_line(self):
        for before, expected in ((True, True), (False, False)):
            with patch.object(b, 'counters', side_effect=[(0, 0), (1500000, 0)]), \
                 patch.object(b.os, 'getloadavg', return_value=(0, 0, 0)), \
                 patch.object(b, 'cpu_times', side_effect=[(100, 100), (200, 200)]), \
                 patch.object(b.time, 'monotonic', side_effect=[0, 1]):
                guard = b.Guard(dict(self.c, bandwidth_mbps=30))
                self.assertEqual(guard.check(before_download=before), expected)

    def test_stop_during_preflight_does_not_wait_or_check_more(self):
        fake = SimpleNamespace(check=unittest.mock.Mock())
        with patch.object(b, 'Guard', return_value=fake), patch.object(b.STOP, 'wait', return_value=True):
            with self.assertRaises(b.Error): REAL_PREFLIGHT(self.c)
        fake.check.assert_not_called()

    def test_wait_fresh_stats_requires_newer_vnstat_timestamp(self):
        fresh = dict(self.v, updated=NOW+1)
        with patch.object(b.time, 'time', return_value=NOW), \
             patch.object(b.time, 'monotonic', side_effect=[0, 1, 1, 2]), \
             patch.object(b, 'stats', side_effect=[(self.day, self.v), (self.day, fresh)]) as stats, \
             patch.object(b, 'atomic_json'), patch.object(b.STOP, 'wait', return_value=False):
            day, v = b.wait_fresh_stats(self.c, self.s, dict(SETTINGS, SaveInterval=1))
        self.assertEqual(stats.call_count, 2)
        self.assertEqual(v['updated'], NOW+1)
        self.assertEqual(day, self.day)

    def test_stats_that_never_update_timeout_without_using_stale_data(self):
        with patch.object(b.time, 'time', return_value=NOW), \
             patch.object(b.time, 'monotonic', side_effect=[0, 181]), \
             patch.object(b, 'stats', return_value=(self.day, self.v)), patch.object(b, 'atomic_json'):
            with self.assertRaisesRegex(b.Error, '超时'):
                b.wait_fresh_stats(self.c, self.s, dict(SETTINGS, SaveInterval=1))
        self.assertEqual((self.s['used'], self.s['attempts']), (0, 0))

    def test_stop_while_waiting_for_fresh_stats_is_interruptible(self):
        def stop(_):
            b.STOP.set()
            return True
        try:
            with patch.object(b.time, 'time', return_value=NOW), \
                 patch.object(b.time, 'monotonic', side_effect=[0, 1, 1]), \
                 patch.object(b, 'stats', return_value=(self.day, self.v)), patch.object(b, 'atomic_json'), \
                 patch.object(b.STOP, 'wait', side_effect=stop):
                with self.assertRaisesRegex(b.Error, '暂停或停止'):
                    b.wait_fresh_stats(self.c, self.s, SETTINGS)
        finally:
            b.STOP.clear()
        self.assertEqual((self.s['used'], self.s['attempts']), (0, 0))

    def test_command_failure_keeps_stdout_diagnostics(self):
        failed = b.subprocess.CompletedProcess(['vnstat'], 1, stdout='Database cannot be opened', stderr='')
        with patch.object(b.subprocess, 'run', return_value=failed):
            with self.assertRaisesRegex(b.Error, 'Database cannot be opened'):
                b.run('vnstat', '--json')

    def test_fixed_rate_decimal_mbps_conversion(self):
        default_cmd = b.curl_command(self.c, 'cloudflare', 1024, 30)
        self.assertEqual(default_cmd[default_cmd.index('--limit-rate')+1], '1000000')
        capped = b.curl_command(dict(self.c, bandwidth_mbps=30), 'cloudflare', 1024, 30)
        self.assertEqual(capped[capped.index('--limit-rate')+1], '1500000')
        self.assertEqual(self.c['min_tx_mib'], 200)
        cmd = b.curl_command(dict(self.c, speed_mbps=.5), 'cloudflare', 1024, 30)
        self.assertEqual(cmd[cmd.index('--limit-rate')+1], '62500')
        self.assertIn('--noproxy', cmd)
        self.assertIn('0-1023', cmd)
        self.assertNotIn('--retry', cmd)
        self.assertEqual(cmd[cmd.index('--connect-timeout')+1], '5')
        self.assertEqual(cmd[cmd.index('--speed-time')+1], '5')

    def test_bandwidth_share_is_configurable_without_overriding_user_speed(self):
        self.assertEqual(b.effective_speed(config(bandwidth_mbps=200)), 80)
        self.assertEqual(b.effective_speed(config(bandwidth_mbps=30)), 12)
        self.assertEqual(b.effective_speed(config(bandwidth_mbps=200, download_percent=10)), 20)
        for value in (0, 101, float('nan'), True):
            with self.subTest(value=value), self.assertRaises(b.Error):
                b.validate_config(config(download_percent=value))

    def test_time_limit_partial_download_is_settled_without_fallback_or_success(self):
        with patch.object(b, 'download', return_value=(3*b.MIB, False, 0, '单轮总时长已达 300 秒')) as dl:
            b.round_download(self.c, self.s, 512*b.MIB, SETTINGS, b.date_now(SETTINGS), lambda *_: None)
        dl.assert_called_once()
        self.assertEqual((self.s['used'], self.s['attempts']), (3*b.MIB, 1))
        self.assertIsNone(self.s['pending'])
        self.assertEqual(self.s['barrier']['total_rx'], self.v['total_rx']+3*b.MIB)

    def test_preflight_cannot_start_new_request_after_shared_round_deadline(self):
        clock = [0]
        def preflight(_c, **_):
            clock[0] = 301
            return SimpleNamespace(received=0)
        with patch.object(b.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(b, 'preflight', side_effect=preflight), patch.object(b, 'download') as dl:
            b.round_download(self.c, self.s, b.MIB, SETTINGS, b.date_now(SETTINGS), lambda *_: None)
        dl.assert_not_called()
        self.assertEqual((self.s['used'], self.s['attempts']), (0, 0))

    def test_preflight_wait_is_bounded_by_remaining_shared_round_time(self):
        guard = SimpleNamespace(check=unittest.mock.Mock())
        clock = [299.5]
        def wait(seconds):
            clock[0] += seconds
            return False
        with patch.object(b, 'Guard', return_value=guard), \
             patch.object(b.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(b.STOP, 'wait', side_effect=wait) as sleep:
            with self.assertRaisesRegex(b.Error, '单轮总时长'):
                REAL_PREFLIGHT(self.c, deadline=300)
        sleep.assert_called_once_with(.5)
        guard.check.assert_not_called()


class InterfaceDetectionTests(unittest.TestCase):
    def detect(self, *, ipv4='ens3', ipv6=None, second=None, kind=None,
               flags=('UP', 'LOWER_UP'), multipath=False):
        def route(*args, **kwargs):
            parts = args[2:]
            if 'route' in parts:
                name = ipv4 if parts[0] == '-4' else ipv6
                if 'show' in parts:
                    rows = [] if name is None else [dict(dev=name, dst='default')]
                    if rows and multipath:
                        rows[0]['nexthops'] = [dict(dev=name), dict(dev='ens9')]
                else:
                    name = second if second and parts[-1] == '8.8.8.8' else name
                    rows = [dict(dev=name, prefsrc='172.31.7.71')]
            else:
                rows = [dict(ifname=parts[-1], link_type='ether', flags=flags,
                             linkinfo=dict(info_kind=kind) if kind else {})]
            return json.dumps(rows)
        with patch.object(b, 'run', side_effect=route) as run, patch.object(b, 'counters') as count:
            result = b.detect_interface()
        count.assert_called_once_with(result)
        return result, run.call_args_list

    def test_nat_server_is_detected_without_input_or_public_packets(self):
        with patch('builtins.input', side_effect=AssertionError('must not ask')):
            name, calls = self.detect()
        self.assertEqual(name, 'ens3')
        self.assertTrue(all(call.args[0] == 'ip' for call in calls))

    def test_ipv6_only_and_same_interface_dual_stack(self):
        self.assertEqual(self.detect(ipv4=None, ipv6='ens3')[0], 'ens3')
        self.assertEqual(self.detect(ipv6='ens3')[0], 'ens3')

    def test_ambiguous_missing_tunnel_and_down_interfaces_are_refused(self):
        for values in (dict(ipv6='ens4'), dict(second='ens4'), dict(ipv4=None),
                       dict(kind='tun'), dict(kind='bridge'), dict(flags=('UP',)),
                       dict(multipath=True)):
            with self.subTest(values=values), self.assertRaises(b.Error):
                self.detect(**values)

    def test_missing_tool_and_malformed_route_do_not_fall_back_to_a_guess(self):
        for result in ('{bad', '{}', '[null]', '[{"dev":null}]'):
            with patch.object(b, 'run', return_value=result), self.assertRaises(b.Error):
                b.detect_interface()
        with patch.object(b, 'run', side_effect=b.Error('ip missing')), self.assertRaisesRegex(b.Error, 'iproute2'):
            b.detect_interface()
        with patch.object(b.subprocess, 'run', side_effect=FileNotFoundError('ip')), \
             self.assertRaisesRegex(b.Error, 'sudo apt-get install -y iproute2'):
            b.detect_interface()

    def test_changed_interface_is_not_silently_switched(self):
        with patch.object(b, 'detect_interface', return_value='ens9'), self.assertRaisesRegex(b.Error, '不自动换网卡'):
            b.verify_interface(config())


class ProtectionLogTests(unittest.TestCase):
    def checked(self, *, rx=0, tx=0, idle=100, load1=0, before=False, **settings):
        c = dict(config(), bandwidth_mbps=30, **settings)
        with patch.object(b, 'counters', side_effect=[(0, 0), (rx, tx)]), \
             patch.object(b, 'cpu_times', side_effect=[(1000, 900), (1100, 900+idle)]), \
             patch.object(b.os, 'getloadavg', side_effect=[(0, 0, 0), (load1, 0, 0)]), \
             patch.object(b.os, 'cpu_count', return_value=2), \
             patch.object(b.time, 'monotonic', side_effect=[10, 11]):
            guard = b.Guard(c)
            return guard, guard.check(before_download=before)

    def test_cpu_cause_contains_actual_value_and_threshold(self):
        guard, busy = self.checked(idle=5)
        self.assertTrue(busy)
        self.assertIn('CPU 95% > 70%', guard.reason)
        self.assertIn('[下载保护]', guard.reason)
        self.assertNotIn('eth0', guard.reason)
        self.assertNotIn('1s', guard.reason)
        self.assertNotIn('负载', guard.reason)
        self.assertNotIn('带宽', guard.reason)

    def test_load_cause_displays_only_normalized_value_and_threshold(self):
        guard, busy = self.checked(load1=2.4)
        self.assertTrue(busy)
        self.assertIn('每核负载 1.2 > 0.8', guard.reason)
        self.assertNotIn('原', guard.reason)
        self.assertNotIn('CPU', guard.reason)

    def test_bandwidth_cause_displays_maximum_rate_and_threshold(self):
        guard, busy = self.checked(rx=3250000, tx=125000)
        self.assertTrue(busy)
        self.assertIn('带宽 26 > 24 Mbps', guard.reason)
        self.assertNotIn('收', guard.reason)
        self.assertNotIn('eth0', guard.reason)

    def test_preflight_start_gate_uses_current_occupancy_without_reserves(self):
        guard, busy = self.checked(rx=1500000, before=True)
        self.assertTrue(busy)
        self.assertEqual(guard.reason, '[预检保护] 当前占用 12 >= 12 Mbps')
        self.assertNotIn('预留', guard.reason)

    def test_full_duplex_projection_adds_download_to_rx_only(self):
        # 30 Mbps server, RX=1/TX=10, download=18: max(1+18,10)=19, not 28.
        guard, busy = self.checked(rx=125000, tx=1250000, before=True, download_percent=60)
        self.assertFalse(busy)
        self.assertEqual(guard.reason, '')
        # RX=10/TX=1, download=18 gives 28 > the fixed 24 Mbps line.
        guard, busy = self.checked(rx=1250000, tx=125000, before=True, download_percent=60)
        self.assertTrue(busy)
        self.assertEqual(guard.reason, '[预检保护] 预计带宽 28 > 24 Mbps')

    def test_runtime_bandwidth_uses_higher_direction_not_the_sum(self):
        guard, busy = self.checked(rx=2500000, tx=2500000)  # 20 in and 20 out
        self.assertFalse(busy)

    def test_cpu_70_percent_and_start_40_percent_boundaries(self):
        self.assertFalse(self.checked(idle=30)[1])
        self.assertTrue(self.checked(idle=29)[1])
        self.assertFalse(self.checked(tx=1499999, before=True)[1])
        self.assertTrue(self.checked(tx=1500000, before=True)[1])

    def test_equal_projected_80_percent_is_allowed_without_extra_margin(self):
        guard, busy = self.checked(before=True, download_percent=80)
        self.assertFalse(busy)
        self.assertEqual(guard.reason, '')

    def test_simultaneous_causes_are_not_lost_to_short_circuiting(self):
        guard, busy = self.checked(rx=3250000, idle=5, load1=2.4)
        self.assertTrue(busy)
        self.assertEqual(guard.reason,
                         '[下载保护] CPU 95% > 70%；每核负载 1.2 > 0.8；带宽 26 > 24 Mbps')

    def test_compact_numbers_preserve_readability_and_tiny_overruns(self):
        self.assertEqual(b.over_limit('CPU', 95.0, 70, '%'), 'CPU 95% > 70%')
        self.assertEqual(b.over_limit('带宽', 26.12345, 24.0, 'Mbps'), '带宽 26.12 > 24 Mbps')
        tiny = b.over_limit('CPU', 85.0000001, 85, '%')
        self.assertEqual(tiny, 'CPU 85.0000001% > 85%')

    def test_exact_thresholds_still_do_not_trigger(self):
        guard, busy = self.checked(rx=3000000, idle=30, load1=1.6)
        self.assertFalse(busy)
        self.assertEqual(guard.reason, '')
        guard, busy = self.checked(rx=1499999, before=True)
        self.assertFalse(busy)
        self.assertEqual(guard.reason, '')

    def test_initial_high_load_reports_stage_value_and_threshold(self):
        with patch.object(b, 'counters', return_value=(0, 0)), patch.object(b, 'cpu_times', return_value=(1000, 900)), \
             patch.object(b.os, 'getloadavg', return_value=(2.4, 0, 0)), patch.object(b.os, 'cpu_count', return_value=2):
            with self.assertRaises(b.Error) as raised:
                b.Guard(config())
        self.assertIn('[启动保护]', str(raised.exception))
        self.assertIn('每核负载 1.2 > 0.8', str(raised.exception))

    def test_recovered_sample_clears_the_previous_cause(self):
        with patch.object(b, 'counters', return_value=(0, 0)), \
             patch.object(b, 'cpu_times', side_effect=[(1000, 900), (1100, 905), (1200, 1005)]), \
             patch.object(b.os, 'getloadavg', return_value=(0, 0, 0)), patch.object(b.os, 'cpu_count', return_value=2), \
             patch.object(b.time, 'monotonic', side_effect=[10, 11, 12]):
            guard = b.Guard(config())
            self.assertTrue(guard.check())
            self.assertFalse(guard.check())
            self.assertEqual(guard.reason, '')

    def test_preflight_propagates_diagnostic_without_losing_detail(self):
        message = '[预检保护] CPU 95% > 70%'
        fake = SimpleNamespace(check=lambda **_: True, reason=message)
        with patch.object(b, 'Guard', return_value=fake), patch.object(b.STOP, 'wait', return_value=False):
            with self.assertRaises(b.Error) as raised:
                REAL_PREFLIGHT(config())
        self.assertIn(message, str(raised.exception))
        self.assertIn('→ 跳过本轮', str(raised.exception))


class UserInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        for name in ('CONFIG', 'STATE', 'UNIT', 'LOG', 'SCRIPT', 'SHORTCUT'):
            patcher = patch.object(b, name, self.base/name)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.out = io.StringIO()
        redirect = contextlib.redirect_stdout(self.out)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def test_input_retry_and_familiar_units(self):
        with patch('builtins.input', side_effect=['bad', '512']):
            self.assertEqual(b.ask_amount('每日额度', 500, 1, 1048576), 512)
        with patch('builtins.input', side_effect=['0.5 GiB']):
            self.assertEqual(b.ask_amount('每日额度', 500, 1, 1048576), 512)
        with patch('builtins.input', side_effect=['4 MB/s', '0.5 Mbps']):
            self.assertEqual(b.ask_number('速度 Mbps', 4, .001, 10000, suffix='Mbps'), .5)
        for text in ('20-60', '20～60', '20 60'):
            with patch('builtins.input', side_effect=[text]):
                self.assertEqual(b.ask_interval(b.DEFAULT), (20, 60))
        with patch('builtins.input', side_effect=['60-20', '1-10']):
            self.assertEqual(b.ask_interval(b.DEFAULT), (1, 10))
        self.assertIn('重新输入这一项', self.out.getvalue())

    def test_ratio_accepts_decimal_and_full_notation_with_safe_bounds(self):
        for text in ('', '2.1', '2.1:1', '2.1 ： 1', '2', '5'):
            with patch('builtins.input', return_value=text):
                self.assertEqual(b.ask_ratio(2.1), float(text) if text in ('2', '5') else 2.1)
        for text in ('1.9', '5.1', 'NaN', '1:2.1', '2.1:2'):
            with patch('builtins.input', side_effect=[text, '2.1']):
                self.assertEqual(b.ask_ratio(2.1), 2.1)

    def test_bandwidth_is_required_and_zero_cannot_disable_protection(self):
        with patch('builtins.input', side_effect=['', '0', '-1', '30 Mbps']):
            self.assertEqual(b.ask_number('服务器带宽 Mbps（必填）', None, .001, 1000000,
                                          suffix='Mbps'), 30)
        with self.assertRaises(b.Error):
            b.validate_config(config(bandwidth_mbps=0))

    def legacy_config(self, bandwidth=30):
        c = config(bandwidth_mbps=bandwidth)
        c.pop('ratio')
        c.pop('download_percent')
        c['bandwidth_percent'] = 70
        c.update(version=1, ratio_low=1.8, ratio_high=2.2)
        return c

    def test_legacy_ratio_is_only_converted_after_confirmation_and_keeps_accounting(self):
        b.atomic_json(b.CONFIG, self.legacy_config())
        s = b.initial_state()
        day, v = sample()
        b.observe(s, day, v)
        s.update(used=1234, attempts=3)
        b.atomic_json(b.STATE, s)
        b.UNIT.write_text('existing service')
        with self.assertRaisesRegex(b.Error, '旧版配置'):
            b.validate_config(b.load_json(b.CONFIG))
        with patch.object(b, 'detect_interface', return_value='eth0'), patch.object(b, 'run'), \
             patch.object(b, 'ensure_interface'), patch.object(b, 'locked', contextlib.nullcontext), \
             patch('builtins.input', side_effect=['']*7):
            b.configure()
        c = b.validate_config(b.load_json(b.CONFIG))
        self.assertEqual((c['version'], c['ratio'], c['bandwidth_mbps']), (3, 2.1, 30))
        saved = b.load_json(b.STATE)
        self.assertEqual((saved['used'], saved['attempts'], saved['date']), (1234, 3, '2026-11-02'))
        self.assertNotIn('ratio_low', c)

    def test_legacy_unset_bandwidth_and_cancel_leave_original_files(self):
        b.atomic_json(b.CONFIG, self.legacy_config(bandwidth=0))
        b.atomic_json(b.STATE, b.initial_state())
        before = (b.CONFIG.read_bytes(), b.STATE.read_bytes())
        with patch.object(b, 'detect_interface', return_value='eth0'), patch.object(b, 'run') as run, \
             patch('builtins.input', side_effect=['', '', '0', 'q']):
            with self.assertRaises(b.Cancelled):
                b.configure()
        self.assertEqual((b.CONFIG.read_bytes(), b.STATE.read_bytes()), before)
        run.assert_not_called()

    def test_detection_failure_never_installs_or_stops_existing_task(self):
        with patch.object(b, 'detect_interface', side_effect=b.Error('没有唯一出口')), \
             patch.object(b, 'run') as run, patch.object(b, 'install') as install, \
             patch('builtins.input') as prompt:
            with self.assertRaises(b.Error):
                b.configure()
        run.assert_not_called()
        install.assert_not_called()
        prompt.assert_not_called()

    def test_auto_detected_new_interface_cannot_replace_existing_accounting(self):
        b.atomic_json(b.CONFIG, config())
        s = b.initial_state()
        day, v = sample()
        b.observe(s, day, v)
        s.update(used=1234, attempts=3)
        b.atomic_json(b.STATE, s)
        b.UNIT.write_text('existing service')
        before = (b.CONFIG.read_bytes(), b.STATE.read_bytes())
        with patch.object(b, 'detect_interface', return_value='ens9'), patch.object(b, 'run'), \
             patch.object(b, 'ensure_interface') as register, patch.object(b, 'locked', contextlib.nullcontext), \
             patch('builtins.input', side_effect=['']*7), self.assertRaisesRegex(b.Error, '不能直接换网卡'):
            b.configure()
        register.assert_not_called()
        self.assertEqual((b.CONFIG.read_bytes(), b.STATE.read_bytes()), before)

    def test_corrupt_legacy_config_cannot_be_migrated_using_defaults(self):
        old = self.legacy_config()
        old.pop('daily_mib')
        b.atomic_json(b.CONFIG, old)
        with self.assertRaises(b.Error):
            b.config_for_edit()

    def test_missing_config_with_existing_accounting_cannot_switch_interface(self):
        s = b.initial_state()
        day, v = sample()
        b.observe(s, day, v)
        b.atomic_json(b.STATE, s)
        before = b.STATE.read_bytes()
        with patch.object(b, 'detect_interface') as detect, patch.object(b, 'run') as run:
            with self.assertRaisesRegex(b.Error, '配置文件丢失但已有流量账本'):
                b.configure()
        detect.assert_not_called()
        run.assert_not_called()
        self.assertEqual(b.STATE.read_bytes(), before)
        self.assertFalse(b.CONFIG.exists())
        b.atomic_json(b.STATE, b.initial_state())
        self.assertEqual(b.config_for_edit(), b.DEFAULT)

    def test_first_setup_retries_only_invalid_fields_then_saves(self):
        def install():
            b.atomic_json(b.STATE, b.initial_state())
        entries = ['junk', '1.9', '2.1', '', '0', '30 Mbps', 'bad', '512', '', '.5 Mbps', '', '']
        with patch.object(b, 'detect_interface', return_value='eth0'), patch.object(b, 'counters'), \
             patch.object(b, 'install', side_effect=install), patch.object(b, 'ensure_interface'), \
             patch.object(b, 'locked', contextlib.nullcontext), patch('builtins.input', side_effect=entries):
            b.configure()
        c = b.validate_config(b.load_json(b.CONFIG))
        self.assertEqual((c['ratio'], c['bandwidth_mbps'], c['daily_mib'], c['speed_mbps']), (2.1, 30, 512, .5))
        self.assertEqual(b.load_json(b.STATE)['mode'], 'stopped')
        self.assertEqual(b.SCRIPT.read_text(), Path(b.__file__).read_text())
        self.assertIn('选择 2', self.out.getvalue())

    def test_advanced_settings_save_bandwidth_share_without_fixed_protection_inputs(self):
        def install():
            b.atomic_json(b.STATE, b.initial_state())
        entries = ['', '30', '', '', '', 'y', '25', '50', '128', '300', '.5', '']
        with patch.object(b, 'detect_interface', return_value='eth0'), \
             patch.object(b, 'install', side_effect=install), patch.object(b, 'ensure_interface'), \
             patch.object(b, 'locked', contextlib.nullcontext), patch('builtins.input', side_effect=entries):
            b.configure()
        c = b.validate_config(b.load_json(b.CONFIG))
        self.assertEqual((c['download_percent'], c['max_attempts'], c['round_mib'],
                          c['min_tx_mib'], c['load_per_cpu']), (25, 50, 128, 300, .5))
        self.assertNotIn('bandwidth_percent', c)
        self.assertEqual(b.effective_speed(c), 7.5)

    def test_configuring_from_new_source_refreshes_existing_installed_copy(self):
        b.atomic_json(b.CONFIG, config())
        b.atomic_json(b.STATE, b.initial_state())
        b.UNIT.write_text('existing service')
        b.SCRIPT.write_text('old script')
        with patch.object(b, 'detect_interface', return_value='eth0'), patch.object(b, 'counters'), \
             patch.object(b, 'run', return_value=''), patch.object(b, 'ensure_interface'), \
             patch.object(b, 'locked', contextlib.nullcontext), patch('builtins.input', side_effect=['']*7):
            b.configure()
        self.assertEqual(b.SCRIPT.read_text(), Path(b.__file__).read_text())
        self.assertEqual(b.SCRIPT.stat().st_mode & 0o777, 0o755)

    def test_summary_warns_when_download_itself_can_trigger_protection(self):
        b.config_summary(config(bandwidth_mbps=100, speed_mbps=100, download_percent=90))
        self.assertIn('当前设置会跳过下载', self.out.getvalue())

    def test_cancelling_summary_keeps_running_task_and_files_untouched(self):
        b.atomic_json(b.CONFIG, config())
        s = b.initial_state()
        day, v = sample()
        b.observe(s, day, v)
        s.update(mode='running', used=1234, attempts=3)
        b.atomic_json(b.STATE, s)
        before = (b.CONFIG.read_bytes(), b.STATE.read_bytes())
        with patch.object(b, 'detect_interface', return_value='eth0'), patch.object(b, 'run') as run, \
             patch.object(b, 'install') as install, patch('builtins.input', side_effect=['', '', '', '', '', '', 'n']):
            b.configure()
        run.assert_not_called()
        install.assert_not_called()
        self.assertEqual((b.CONFIG.read_bytes(), b.STATE.read_bytes()), before)
        self.assertIn('原任务保持不变', self.out.getvalue())

    def test_q_cancels_before_installing_or_stopping_task(self):
        with patch.object(b, 'detect_interface', return_value='eth0'), patch.object(b, 'run') as run, \
             patch.object(b, 'install') as install, patch('builtins.input', side_effect=['q']):
            with self.assertRaises(b.Cancelled): b.configure()
        run.assert_not_called()
        install.assert_not_called()
        self.assertFalse(b.CONFIG.exists())

    def test_status_shows_actual_stopped_service_and_explains_ratio(self):
        b.atomic_json(b.CONFIG, config())
        s = b.initial_state()
        day, v = sample()
        b.observe(s, day, v)
        s.update(mode='running', used=20*b.MIB, attempts=1)
        b.atomic_json(b.STATE, s)
        with patch.object(b, 'run', return_value='inactive'), patch.object(b, 'vn_settings', return_value=SETTINGS), \
             patch.object(b, 'stats', return_value=(day, v)):
            b.status()
        text = self.out.getvalue()
        self.assertIn('后台尚未运行', text)
        self.assertIn('超过目标', text)
        self.assertIn('剩余 9.98 GiB', text)
        self.assertIn('下次检查：—', text)
        self.assertNotIn('ActiveState=', text)

    def test_compact_status_does_not_repeat_initial_wait_or_dump_logs(self):
        b.atomic_json(b.CONFIG, config())
        b.atomic_json(b.STATE, dict(b.initial_state(), mode='running', reason='旧的首日等待原因'))
        with patch.object(b, 'run', return_value='active'), patch.object(b, 'vn_settings', return_value=SETTINGS), \
             patch.object(b, 'stats', side_effect=b.StatsNotReady('详细的首日等待原因', '首日统计不完整，暂不补量')), \
             patch.object(b, 'recent_logs') as logs:
            b.status()
        text = self.out.getvalue()
        self.assertEqual(text.count('首日'), 1)
        self.assertNotIn('旧的', text)
        self.assertLessEqual(len(text.strip().splitlines()), 6)
        logs.assert_not_called()

    def test_zero_and_legacy_seven_exit_without_changing_task(self):
        for value in ('0', '7'):
            with patch('builtins.input', return_value=value) as prompt, patch.object(b, 'control') as control:
                b.menu()
            self.assertIn('0 退出', prompt.call_args.args[0])
            control.assert_not_called()

    def test_logs_and_details_are_explicit_choices_after_status(self):
        b.atomic_json(b.STATE, b.initial_state())
        for choice in ('', '1', '2'):
            with patch('builtins.input', side_effect=['5', choice, '0']), patch.object(b, 'status'), \
                 patch.object(b, 'recent_logs') as logs, patch.object(b, 'diagnostics') as diagnostics:
                b.menu()
            self.assertEqual(logs.call_count, int(choice == '1'))
            self.assertEqual(diagnostics.call_count, int(choice == '2'))

    def test_status_and_diagnostics_remain_available_for_corrupt_state(self):
        b.atomic_json(b.CONFIG, config())
        b.STATE.write_text('{broken')
        b.LOG.write_text('状态保存失败\n')
        with patch.object(b, 'run', return_value='active'):
            b.status()
            b.diagnostics()
        text = self.out.getvalue()
        self.assertIn('配置或记录暂不可用', text)
        self.assertIn('停止任务', text)
        self.assertIn('状态保存失败', text)
        self.assertEqual(b.STATE.read_text(), '{broken')

    def test_first_use_menu_opens_save_and_start_wizard(self):
        with patch.object(b, 'configure', return_value=False) as configure, patch.object(b, 'run') as run, \
             patch('builtins.input', side_effect=['2', '7']):
            b.menu()
        configure.assert_called_once_with(start_after=True)
        run.assert_not_called()

    def test_direct_start_saves_configuration_then_starts_once(self):
        def install():
            b.atomic_json(b.STATE, b.initial_state())
        def start(mode):
            self.assertEqual(mode, 'running')
            self.assertEqual(b.validate_config(b.load_json(b.CONFIG))['bandwidth_mbps'], 30)
        with patch.object(b, 'detect_interface', return_value='eth0'), patch.object(b, 'install', side_effect=install), \
             patch.object(b, 'ensure_interface'), patch.object(b, 'locked', contextlib.nullcontext), \
             patch.object(b, 'control', side_effect=start) as control, \
             patch('builtins.input', side_effect=['', '30', '', '', '', '', '']):
            b.start_task()
        control.assert_called_once_with('running')
        self.assertIn('保存后将启动任务', self.out.getvalue())

    def test_direct_start_cancel_or_q_never_installs_or_starts(self):
        for inputs in (['q'], ['', '30', '', '', '', '', 'n']):
            with patch.object(b, 'detect_interface', return_value='eth0'), patch.object(b, 'install') as install, \
                 patch.object(b, 'control') as control, patch('builtins.input', side_effect=inputs):
                if inputs == ['q']:
                    with self.assertRaises(b.Cancelled):
                        b.start_task()
                else:
                    b.start_task()
            install.assert_not_called()
            control.assert_not_called()
            self.assertFalse(b.CONFIG.exists())
            self.assertFalse(b.STATE.exists())

    def test_direct_start_existing_valid_config_does_not_reconfigure(self):
        b.atomic_json(b.CONFIG, config())
        with patch.object(b, 'control') as control, patch.object(b, 'configure') as configure:
            b.start_task()
        control.assert_called_once_with('running')
        configure.assert_not_called()

    def test_repeat_start_of_current_task_does_not_stop_or_restart_service(self):
        b.atomic_json(b.CONFIG, config())
        b.atomic_json(b.STATE, dict(b.initial_state(), mode='running'))
        with patch.object(b, 'run', return_value='active') as run:
            with self.assertRaisesRegex(b.Error, '任务已运行'):
                b.start_task()
        self.assertEqual(run.call_args_list,
                         [unittest.mock.call('systemctl', 'show', b.SERVICE, '-p', 'ActiveState', '--value')])

    def test_direct_start_corrupt_config_or_state_never_uses_defaults(self):
        for target in (b.CONFIG, b.STATE):
            target.write_text('{broken')
            with patch.object(b, 'configure') as configure, patch.object(b, 'control') as control:
                with self.assertRaises(b.Error):
                    b.start_task()
            configure.assert_not_called()
            control.assert_not_called()
            target.unlink()

    def test_version_two_conversion_preserves_ratio_and_other_user_settings(self):
        old = config(ratio=3.4, daily_mib=2048)
        old.pop('download_percent')
        old.update(version=2, bandwidth_percent=60)
        b.atomic_json(b.CONFIG, old)
        converted = b.config_for_edit()
        self.assertEqual((converted['ratio'], converted['daily_mib'], converted['download_percent']), (3.4, 2048, 40))
        self.assertNotIn('bandwidth_percent', converted)
        self.assertEqual(b.load_json(b.CONFIG), old)

    def test_already_running_legacy_task_never_reconfigures_on_repeat_start(self):
        b.atomic_json(b.CONFIG, self.legacy_config())
        b.atomic_json(b.STATE, dict(b.initial_state(), mode='running'))
        with patch.object(b, 'run', return_value='active'), patch.object(b, 'configure') as configure:
            with self.assertRaisesRegex(b.Error, '任务已运行'):
                b.start_task()
        configure.assert_not_called()


class InstallationFeedbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        paths = dict(BASE=root/'data', CONFIG=root/'data'/'config.json', STATE=root/'data'/'state.json',
                     SCRIPT=root/'program', UNIT=root/'task.service')
        for key, value in paths.items():
            patcher = patch.object(b, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(b, 'locked', contextlib.nullcontext)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_ready_dependencies_skip_apt_and_still_show_installation_stage(self):
        with patch.object(b, 'missing_packages', return_value=[]), patch.object(b, 'run') as run, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            b.install()
        self.assertFalse(any(call.args[0] == 'apt-get' for call in run.call_args_list))
        self.assertIn('跳过 APT 下载', output.getvalue())
        self.assertIn('正在启用 vnStat', output.getvalue())
        self.assertTrue(b.SCRIPT.exists())

    def test_missing_packages_install_with_live_output(self):
        with patch.object(b, 'missing_packages', return_value=['vnstat']), patch.object(b, 'run') as run, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            b.install()
        self.assertIn(unittest.mock.call('apt-get', 'update', timeout=300, live=True), run.call_args_list)
        self.assertIn(unittest.mock.call('apt-get', 'install', '-y', 'vnstat', timeout=300, live=True), run.call_args_list)
        self.assertIn('下面显示实时进度', output.getvalue())

    def test_dependency_failure_does_not_save_or_start_task(self):
        with patch.object(b, 'missing_packages', return_value=['vnstat']), \
             patch.object(b, 'run', side_effect=b.Error('APT timeout')), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(b.Error):
                b.install()
        self.assertFalse(b.STATE.exists())
        self.assertFalse(b.SCRIPT.exists())
        self.assertFalse(b.CONFIG.exists())

    def test_live_command_output_is_not_captured_and_failure_is_not_hidden(self):
        failed = b.subprocess.CompletedProcess(['apt-get'], 1, stdout=None, stderr=None)
        with patch.object(b.subprocess, 'run', return_value=failed) as run:
            with self.assertRaisesRegex(b.Error, '请查看上方命令输出'):
                b.run('apt-get', 'update', live=True)
        self.assertIsNone(run.call_args.kwargs['stdout'])
        self.assertIsNone(run.call_args.kwargs['stderr'])
        self.assertEqual(run.call_args.kwargs['env']['DEBIAN_FRONTEND'], 'noninteractive')


class ShortcutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root/'data'
        self.base.mkdir()
        binary = self.root/'bin'
        binary.mkdir()
        paths = dict(BASE=self.base, CONFIG=self.base/'config.json', STATE=self.base/'state.json',
                     SCRIPT=binary/'traffic-balance', SHORTCUT=binary/'tb',
                     LOG=self.root/'task.log', UNIT=self.root/'task.service')
        for key, value in paths.items():
            patcher = patch.object(b, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        b.SCRIPT.write_text('owned script')

    def test_owned_shortcut_is_created_and_is_idempotent(self):
        b.ensure_shortcut()
        self.assertTrue(b.SHORTCUT.is_symlink())
        self.assertEqual(b.SHORTCUT.resolve(), b.SCRIPT.resolve())
        b.ensure_shortcut()
        self.assertEqual(b.SHORTCUT.read_text(), 'owned script')

    def test_foreign_file_and_symlink_are_never_overwritten(self):
        foreign = self.root/'other-command'
        foreign.write_text('other app')
        for symlink in (False, True):
            if symlink:
                b.SHORTCUT.symlink_to(foreign)
            else:
                b.SHORTCUT.write_text('other app')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                b.ensure_shortcut()
            self.assertEqual(b.SHORTCUT.read_text(), 'other app')
            self.assertIn('已被其他程序使用', output.getvalue())
            b.SHORTCUT.unlink()

    def test_uninstall_removes_only_owned_shortcut(self):
        for owned in (True, False):
            self.base.mkdir(exist_ok=True)
            b.SCRIPT.write_text('owned script')
            other = self.root/'other-command'
            other.write_text('other app')
            b.SHORTCUT.symlink_to(b.SCRIPT if owned else other)
            with patch.object(b, 'ask', return_value='DELETE'), patch.object(b, 'run'), \
                 patch.object(b, 'locked', contextlib.nullcontext), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(b.uninstall())
            self.assertFalse(b.SCRIPT.exists())
            if owned:
                self.assertFalse(b.SHORTCUT.is_symlink())
            else:
                self.assertEqual(b.SHORTCUT.read_text(), 'other app')
                b.SHORTCUT.unlink()

    def test_cyclic_foreign_shortcut_does_not_break_configuration_or_uninstall(self):
        b.SHORTCUT.symlink_to(b.SHORTCUT)
        with patch.object(Path, 'resolve', side_effect=RuntimeError('Symlink loop')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            b.ensure_shortcut()
            self.assertIn('已被其他程序使用', output.getvalue())
            with patch.object(b, 'ask', return_value='DELETE'), patch.object(b, 'run'), \
                 patch.object(b, 'locked', contextlib.nullcontext):
                self.assertTrue(b.uninstall())
        self.assertTrue(b.SHORTCUT.is_symlink())
        self.assertEqual(b.os.readlink(b.SHORTCUT), str(b.SHORTCUT))


@unittest.skipUnless(shutil.which('curl'), 'requires curl')
class LocalCurlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                if self.path in ('/trailers', '/chunked', '/chunked-overrun'):
                    self.send_response(200)
                    self.send_header('Transfer-Encoding', 'chunked')
                    self.send_header('Trailer', 'X-Trailer')
                    self.end_headers()
                    try:
                        body = b'10000\r\n' + b'x'*65536 + b'\r\n' if self.path == '/chunked-overrun' else b'4\r\ntest\r\n'
                        self.wfile.write(body)
                        self.wfile.flush()
                        if self.path == '/chunked':
                            time.sleep(1)
                        self.wfile.write(b'0\r\nX-Trailer: yes\r\n\r\n')
                    except (BrokenPipeError, ConnectionResetError): pass
                    return
                if self.path == '/ignored-range':
                    self.send_response(200)
                    self.send_header('Content-Length', '1000000')
                    self.end_headers()
                    return
                if self.path == '/limited':
                    self.send_response(429)
                    self.send_header('Retry-After', '3600')
                    self.end_headers()
                    return
                self.send_response(206)
                self.send_header('Content-Length', '65536')
                self.end_headers()
                try:
                    self.wfile.write(b'x'*(4096 if self.path in ('/partial', '/slow', '/guarded') else 65536))
                    self.wfile.flush()
                    if self.path in ('/slow', '/guarded'):
                        time.sleep(5 if self.path == '/guarded' else 1)
                        self.wfile.write(b'x'*61440)
                except (BrokenPipeError, ConnectionResetError): pass
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def download(self, route, amount=65536, old_curl=False, guard=None, duration=10):
        b.STOP.clear()
        cmd = b.curl_command(config(), 'cloudflare', amount, 10)
        if old_curl:
            i = cmd.index('--max-filesize')
            del cmd[i:i+2]
        cmd[cmd.index('--proto')+1] = '=http'
        del cmd[cmd.index('--interface'):cmd.index('--interface')+2]
        cmd[-1] = f'http://127.0.0.1:{self.server.server_port}/{route}'
        with tempfile.TemporaryDirectory() as headers_dir:
            with patch.object(b, 'curl_command', return_value=cmd), patch.object(b, 'Guard', return_value=guard or SimpleNamespace(check=lambda: False)), \
                 patch.object(b, 'HEADER_DIR', headers_dir):
                result = b.download(config(), 'cloudflare', amount, SETTINGS,
                                    b.date_now(SETTINGS), time.monotonic()+duration)
            self.assertEqual(list(Path(headers_dir).iterdir()), [])
            return result

    def test_success_counts_body_and_does_not_write_file(self):
        actual, ok, until, _ = self.download('ok')
        self.assertEqual(actual, 65536)
        self.assertTrue(ok)
        self.assertEqual(until, 0)

    def test_connection_failure_retains_partial_body(self):
        actual, ok, _, reason = self.download('partial')
        self.assertEqual(actual, 4096)
        self.assertFalse(ok)
        self.assertIn('下载失败', reason)

    def test_stop_signal_terminates_active_curl_and_counts_partial_body(self):
        timer = threading.Timer(.1, b.STOP.set)
        timer.start()
        try:
            started = time.monotonic()
            actual, ok, _, reason = self.download('slow')
            self.assertLess(time.monotonic()-started, 2)
            self.assertEqual(actual, 4096)
            self.assertFalse(ok)
            self.assertIn('停止信号', reason)
        finally:
            timer.join()
            b.STOP.clear()

    def test_total_deadline_ends_real_partial_download_without_reporting_success(self):
        started = time.monotonic()
        actual, ok, _, reason = self.download('slow', duration=.25)
        self.assertLess(time.monotonic()-started, 1)
        self.assertEqual(actual, 4096)
        self.assertFalse(ok)
        self.assertIn('单轮总时长', reason)

    def test_active_download_logs_trigger_immediately_and_still_settles_partial(self):
        message = '[下载保护] CPU 95% > 70%'
        guard = SimpleNamespace(check=lambda: True, reason=message)
        with self.assertLogs(b.logger, level='WARNING') as logs:
            actual, ok, _, reason = self.download('guarded', guard=guard)
        self.assertEqual(actual, 4096)
        self.assertFalse(ok)
        self.assertIn(message, reason)
        self.assertIn(message, '\n'.join(logs.output))
        self.assertNotIn('source=', '\n'.join(logs.output))
        self.assertIn('→ 停止本轮', '\n'.join(logs.output))

    def test_chunked_trailers_are_metadata_not_billable_body(self):
        actual, ok, until, _ = self.download('trailers', amount=4)
        self.assertEqual(actual, 4)
        self.assertTrue(ok)
        self.assertEqual(until, 0)

    def test_unknown_size_body_stops_at_budget_with_old_curl_capability(self):
        # Removing max-filesize models the documented <8.4 unknown-size behavior.
        started = time.monotonic()
        actual, ok, _, reason = self.download('chunked', amount=4, old_curl=True)
        self.assertLess(time.monotonic()-started, .8)
        self.assertEqual(actual, 4)
        self.assertTrue(ok)
        self.assertIn('预算', reason)

    def test_bytes_already_received_beyond_budget_are_not_hidden(self):
        actual, ok, _, reason = self.download('chunked-overrun', amount=4, old_curl=True)
        self.assertGreater(actual, 4)
        self.assertFalse(ok)
        self.assertIn('超过请求', reason)

    def test_ignored_range_with_large_content_length_is_rejected(self):
        actual, ok, _, reason = self.download('ignored-range', amount=4)
        self.assertEqual(actual, 0)
        self.assertFalse(ok)
        self.assertIn('下载失败', reason)

    def test_429_honors_retry_after(self):
        actual, ok, until, reason = self.download('limited')
        self.assertEqual(actual, 0)
        self.assertFalse(ok)
        self.assertGreaterEqual(until, int(time.time())+3599)
        self.assertIn('限流', reason)


if __name__ == '__main__':
    unittest.main()

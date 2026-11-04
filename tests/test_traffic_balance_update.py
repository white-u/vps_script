"""Online update transactions and complete-file rounds; isolated local fixtures."""
import copy
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('balance_update', Path(__file__).resolve().parents[1]/'traffic_balance.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for key in ('CONFIG', 'STATE', 'SCRIPT', 'UNIT', 'LOCK', 'UPDATE_LOCK'):
            p = patch.object(b, key, root/key)
            p.start()
            self.addCleanup(p.stop)
        self.c = dict(b.DEFAULT, interface='eth0', bandwidth_mbps=200)
        self.s = b.initial_state()
        self.s.update(date='2026-11-04', used=123456, attempts=3, mode='running',
                      last=dict(updated=1, rx=1, tx=1, total_rx=1, total_tx=1, created=1))
        b.atomic_json(b.CONFIG, self.c)
        b.atomic_json(b.STATE, self.s)
        b.SCRIPT.write_text('# old script\n')
        b.UNIT.write_text('old unit\n')
        self.calls = []
        def command(*args, **kwargs):
            self.calls.append(args)
            return ('active' if len([x for x in self.calls if 'show' in x]) == 1 else 'inactive') if 'show' in args else ''
        patch.object(b, 'wait_updated_service', return_value=None).start()
        self.run = patch.object(b, 'run', side_effect=command).start()
        self.addCleanup(patch.stopall)

    def test_running_update_keeps_config_and_quota_and_restarts(self):
        before = b.CONFIG.read_bytes()
        b.apply_update()
        self.assertEqual(b.CONFIG.read_bytes(), before)
        state = b.load_json(b.STATE)
        self.assertEqual((state['used'], state['attempts'], state['mode']), (123456, 3, 'running'))
        self.assertEqual(b.SCRIPT.read_text(), Path(b.__file__).read_text())
        self.assertLess(self.calls.index(('systemctl', 'stop', b.SERVICE)), self.calls.index(('systemctl', 'start', b.SERVICE)))

    def test_stopped_and_paused_remain_stopped(self):
        for mode in ('stopped', 'paused'):
            self.calls.clear()
            b.atomic_json(b.STATE, dict(self.s, mode=mode))
            b.apply_update()
            self.assertEqual(b.load_json(b.STATE)['mode'], mode)
            self.assertFalse(any('start' in x or 'enable' in x for x in self.calls))

    def test_pending_reservation_is_not_refunded_on_update(self):
        self.s['pending'] = dict(amount=123456, started=1, total_rx=1)
        b.atomic_json(b.STATE, self.s)
        b.apply_update()
        state = b.load_json(b.STATE)
        self.assertEqual(state['used'], 123456)
        self.assertIsNone(state['pending'])
        self.assertEqual(state['barrier']['total_rx'], 1)

    def test_corrupted_state_does_not_stop_or_replace(self):
        b.STATE.write_text('{broken')
        with self.assertRaises(b.Error):
            b.apply_update()
        self.assertEqual(self.calls, [])
        self.assertEqual(b.SCRIPT.read_text(), '# old script\n')

    def test_failed_new_start_rolls_back_code_but_not_ledger(self):
        def command(*args, **kwargs):
            self.calls.append(args)
            if 'start' in args:
                raise b.Error('start failed')
            return ('active' if len([x for x in self.calls if 'show' in x]) == 1 else 'inactive') if 'show' in args else ''
        self.run.side_effect = command
        with self.assertRaisesRegex(b.Error, '已恢复旧程序'):
            b.apply_update()
        self.assertEqual(b.SCRIPT.read_text(), '# old script\n')
        self.assertEqual(b.UNIT.read_text(), 'old unit\n')
        self.assertEqual(b.load_json(b.STATE)['used'], 123456)
        self.assertEqual(sum('start' in x for x in self.calls), 1)

    def test_busy_management_lock_prevents_stop(self):
        with b.locked(b.UPDATE_LOCK):
            with self.assertRaises(b.Error):
                b.apply_update()
        self.assertEqual(self.calls, [])

    def test_interrupted_write_rolls_back_and_disables(self):
        original = b.atomic_write
        interrupted = [False]
        def write(path, text, mode):
            original(path, text, mode)
            if path == b.SCRIPT and not interrupted[0]:
                interrupted[0] = True
                raise KeyboardInterrupt()
        with patch.object(b, 'atomic_write', side_effect=write):
            with self.assertRaisesRegex(b.Error, '已恢复旧程序'):
                b.apply_update()
        self.assertEqual(b.SCRIPT.read_text(), '# old script\n')
        self.assertEqual(b.load_json(b.STATE)['mode'], 'stopped')
        self.assertIn(('systemctl', 'disable', b.SERVICE), self.calls)

    def test_parent_interrupt_waits_for_child_rollback(self):
        root = Path(self.tmp.name)
        child = root/'child.py'
        ready, finished = root/'ready', root/'finished'
        child.write_text('import signal,time,pathlib,sys\n'
                         'def stop(*args):\n'
                         ' time.sleep(.4)\n'
                         f' pathlib.Path({str(finished)!r}).touch()\n'
                         ' sys.exit(1)\n'
                         'signal.signal(signal.SIGTERM,stop)\n'
                         f'pathlib.Path({str(ready)!r}).touch()\n'
                         'time.sleep(10)\n')
        code = (f'import runpy; b=runpy.run_path({b.__file__!r}); '
                f'b["run_update_candidate"]({str(child)!r})')
        parent = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic()+5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(ready.exists())
            parent.send_signal(signal.SIGINT)
            parent.communicate(timeout=5)
            self.assertTrue(finished.exists(), 'parent must not kill child during rollback')
            self.assertNotEqual(parent.returncode, 0)
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.communicate()

    def test_bad_digest_never_stops_or_executes_payload(self):
        def command(*args, **kwargs):
            self.calls.append(args)
            dest = Path(args[args.index('--output')+1])
            dest.write_text("SOURCE_REF='stable'\nSOURCE_SHA256='"+'0'*64+"'\n" if dest.name == 'tb.sh' else 'print("bad")')
            return ''
        self.run.side_effect = command
        with self.assertRaisesRegex(b.Error, '原任务未停止'):
            b.online_update()
        self.assertTrue(all(x[0] == 'curl' for x in self.calls))

    def test_verified_payload_is_checked_before_apply(self):
        payload = 'print("candidate")\n'
        digest = hashlib.sha256(payload.encode()).hexdigest()
        def command(*args, **kwargs):
            self.calls.append(args)
            if args[0] == 'curl':
                dest = Path(args[args.index('--output')+1])
                dest.write_text("SOURCE_REF='stable'\nSOURCE_SHA256='"+digest+"'\n" if dest.name == 'tb.sh' else payload)
            return ''
        self.run.side_effect = command
        with patch.object(b, 'run_update_candidate') as apply:
            b.online_update()
        self.assertEqual(self.calls[-1][-1], '--check-update')
        apply.assert_called_once()


class CompleteRoundsTests(unittest.TestCase):
    def setUp(self):
        b.STOP.clear()
        self.c = dict(b.DEFAULT, interface='eth0', bandwidth_mbps=200)
        self.s = b.initial_state()
        self.s.update(date='2026-11-04', last=dict(rx=0, tx=10000*b.MIB, total_rx=0, total_tx=0, updated=1, created=1))
        for name, kw in [('preflight', dict(return_value=SimpleNamespace(received=0))),
                         ('file_pause', dict(return_value=False)),
                         ('date_now', dict(return_value='2026-11-04'))]:
            p = patch.object(b, name, **kw); p.start(); self.addCleanup(p.stop)
        self.saved = []

    def invoke(self, gap):
        b.round_download(self.c, self.s, gap, {}, '2026-11-04', lambda _, state: self.saved.append(copy.deepcopy(state)))

    def test_continues_complete_files_then_smallest_overshoot(self):
        sizes = dict(wechat=303*b.MIB, firefox=82*b.MIB, blender=344*b.MIB)
        def complete(c, source, amount, *a, **kw):
            self.assertTrue(kw['full_file'])
            self.assertEqual(amount, sizes[source])
            return amount, True, 0, '下载成功'
        with patch.object(b, 'source_candidates', return_value=list(sizes)), \
             patch.object(b, 'source_size', side_effect=lambda c, x, d: (sizes[x], 0)), \
             patch.object(b, 'download', side_effect=complete) as dl:
            self.invoke(400*b.MIB)
        # Last smallest file can repeat rather than causing a larger overshoot.
        self.assertEqual([x.args[2] for x in dl.call_args_list], [303*b.MIB, 82*b.MIB, 82*b.MIB])
        self.assertEqual(self.s['used'], 467*b.MIB)
        self.assertEqual(self.s['barrier']['total_rx'], 467*b.MIB)

    def test_final_preflight_reselects_smallest_after_gap_reduces(self):
        with patch.object(b, 'source_candidates', return_value=['wechat', 'firefox']), \
             patch.object(b, 'source_size', side_effect=[(180, 0), (50, 0)]), \
             patch.object(b, 'preflight', side_effect=[SimpleNamespace(received=0), SimpleNamespace(received=175)]), \
             patch.object(b, 'download', return_value=(50, True, 0, '下载成功')) as dl:
            self.invoke(200)
        self.assertEqual(dl.call_args.args[1:3], ('firefox', 50))

    def test_quota_cannot_fit_whole_file_never_starts(self):
        self.s['used'] = int(self.c['daily_mib']*b.MIB)-50*b.MIB
        with patch.object(b, 'source_size', return_value=(82*b.MIB, 0)), patch.object(b, 'download') as dl:
            self.invoke(400*b.MIB)
        dl.assert_not_called()
        self.assertIn('每日剩余额度不足', self.s['reason'])

    def test_metadata_rate_limit_ends_round_without_attempt(self):
        with patch.object(b, 'source_size', return_value=(None, 9999999999)), patch.object(b, 'download') as dl:
            self.invoke(400*b.MIB)
        dl.assert_not_called()
        self.assertEqual(self.s['attempts'], 0)
        self.assertEqual(self.s['cooldown'], 9999999999)

    def test_download_failure_counts_bytes_and_excludes_source(self):
        with patch.object(b, 'source_candidates', return_value=['wechat', 'firefox']), \
             patch.object(b, 'source_size', return_value=(82*b.MIB, 0)), \
             patch.object(b, 'download', side_effect=[(5*b.MIB, False, 0, '下载失败'), (82*b.MIB, True, 0, '下载成功')]) as dl:
            self.invoke(80*b.MIB)
        self.assertEqual(self.s['used'], 87*b.MIB)
        self.assertEqual(self.s['attempts'], 2)
        self.assertEqual([x.args[1] for x in dl.call_args_list], ['wechat', 'firefox'])

    def test_non_utf8_header_is_a_source_error_not_daemon_crash(self):
        error = UnicodeDecodeError('utf-8', b'\xe9', 0, 1, 'invalid start byte')
        with patch.object(b.subprocess, 'run', side_effect=error):
            with self.assertRaises(b.Error):
                b.source_size(self.c, 'firefox', b.time.monotonic()+5)

    def test_date_change_after_reservation_never_starts_curl(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(b, 'HEADER_DIR', tmp), \
             patch.object(b, 'date_now', return_value='2026-11-05'), \
             patch.object(b.subprocess, 'Popen') as process:
            with self.assertRaises(b.DownloadNotStarted):
                b.download(self.c, 'firefox', 50, {}, '2026-11-04',
                           b.time.monotonic()+300, guard=SimpleNamespace(), full_file=True)
        process.assert_not_called()

    def test_head_size_and_rate_limit_validation(self):
        for text, expected in [('HTTP/1.1 200 OK\r\nContent-Length: 85933992\r\n', 85933992),
                               ('HTTP/1.1 200 OK\r\nContent-Length: 1073741825\r\n', None),
                               ('HTTP/1.1 403 Forbidden\r\n', None)]:
            with patch.object(b, 'run', return_value=text):
                if expected:
                    self.assertEqual(b.source_size(self.c, 'firefox', b.time.monotonic()+5), (expected, 0))
                else:
                    with self.assertRaises(b.Error): b.source_size(self.c, 'firefox', b.time.monotonic()+5)


if __name__ == '__main__':
    unittest.main()

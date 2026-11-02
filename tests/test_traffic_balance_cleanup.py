"""Failure-path checks for the opt-in balance integration's resource ownership."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('balance_it_cleanup', Path(__file__).with_name('integration_traffic_balance.py'))
it = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(it)


class IntegrationCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.unit = self.root/'owned.service'
        self.unit.write_text('ExecStart='+str(self.root/'task'))

    def test_refuses_changed_unit_ownership(self):
        self.unit.write_text('ExecStart=/different/task')
        with patch.object(it.b, 'run') as run:
            with self.assertRaisesRegex(AssertionError, 'ownership'):
                it.clean_unit('owned.service', self.unit, self.root)
        run.assert_not_called()
        self.assertTrue(self.unit.exists())

    def test_failed_stop_or_unknown_state_preserves_unit_and_resources(self):
        for state in ('active', 'unknown'):
            with patch.object(it.b, 'run', return_value=state) as run:
                with self.assertRaisesRegex(AssertionError, 'did not stop'):
                    it.clean_unit('owned.service', self.unit, self.root)
            self.assertTrue(self.unit.exists())
            self.assertFalse(any('disable' in c.args for c in run.call_args_list))

    def test_disable_failure_preserves_unit(self):
        def command(*args):
            if args[1] == 'disable':
                raise it.b.Error('disable failed')
            return 'inactive'
        with patch.object(it.b, 'run', side_effect=command):
            with self.assertRaises(it.b.Error):
                it.clean_unit('owned.service', self.unit, self.root)
        self.assertTrue(self.unit.exists())

    def test_success_stops_disables_and_removes_only_owned_unit(self):
        other = self.root/'other.service'
        other.write_text('unrelated')
        with patch.object(it.b, 'run', return_value='inactive') as run, patch.object(it.subprocess, 'run'):
            it.clean_unit('owned.service', self.unit, self.root)
        self.assertFalse(self.unit.exists())
        self.assertTrue(other.exists())
        self.assertEqual(run.call_args_list[0].args, ('systemctl', 'stop', 'owned.service'))
        self.assertIn(unittest.mock.call('systemctl', 'disable', 'owned.service'), run.call_args_list)


if __name__ == '__main__':
    unittest.main()

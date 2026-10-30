"""Fault-injection checks for the opt-in FW integration test's cleanup."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from integration_fw import cleanup_installation


class FWIntegrationCleanupTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory) / 'private'
        root.mkdir()
        (root / 'realm').write_text('test-core')
        unit = Path(directory) / 'test.service'
        unit.write_text(f'ExecStart={root}/realm')
        return root, unit

    def test_stop_disable_timeout_or_unknown_state_preserves_recovery_files(self):
        for failure in ('stop', 'disable', 'timeout', 'active', 'show'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root, unit = self.fixture(directory)
                def run(args, **kwargs):
                    command = args[1]
                    if command == failure:
                        raise subprocess.CalledProcessError(1, args)
                    if failure == 'timeout' and command == 'stop':
                        raise subprocess.TimeoutExpired(args, 45)
                    state = 'active' if failure == 'active' else 'inactive'
                    return subprocess.CompletedProcess(args, 0, stdout=state + '\n')
                with patch('integration_fw.subprocess.run', side_effect=run):
                    with self.assertRaisesRegex(RuntimeError, 'Cleanup incomplete; retained'):
                        cleanup_installation('test', root, unit)
                self.assertTrue((root / 'realm').exists())
                self.assertTrue(unit.exists())

    def test_successful_cleanup_removes_owned_files_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root, unit = self.fixture(directory)
            other = Path(directory) / 'other'
            other.write_text('preserve')
            with patch('integration_fw.subprocess.run', return_value=
                       subprocess.CompletedProcess([], 0, stdout='inactive\n')):
                cleanup_installation('test', root, unit)
            self.assertFalse(root.exists())
            self.assertFalse(unit.exists())
            self.assertEqual(other.read_text(), 'preserve')

    def test_changed_unit_ownership_is_preserved_without_service_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root, unit = self.fixture(directory)
            unit.write_text('ExecStart=/some/other/program')
            with patch('integration_fw.subprocess.run') as command:
                with self.assertRaisesRegex(RuntimeError, 'ownership changed'):
                    cleanup_installation('test', root, unit)
                command.assert_not_called()
            self.assertTrue(root.exists())
            self.assertTrue(unit.exists())

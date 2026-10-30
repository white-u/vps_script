"""Exercise the Worker's public fetch entry without Cloudflare or real Telegram calls."""

from pathlib import Path
import shutil
import subprocess
import unittest


class WorkerUserFlowTests(unittest.TestCase):
    def test_signed_push_and_telegram_user_workflows(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Worker user-flow tests require Node.js')
        result = subprocess.run(
            [node, '--test', str(Path(__file__).with_name('worker_user_flows.mjs'))],
            text=True, capture_output=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

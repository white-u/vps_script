"""Worker baseline report regression; runs locally without Cloudflare or Telegram."""

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WorkerBaselineTests(unittest.TestCase):
    def test_report_uses_current_burst_policy_and_ignores_old_base_limit(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Worker tests require Node.js")
        result = subprocess.run([node, "--input-type=module", "-e", r'''
import fs from 'node:fs';
import assert from 'node:assert/strict';
const source = fs.readFileSync(process.argv[1], 'utf8') +
               '\nexport { renderReport };\n//# sourceURL=worker-baseline.mjs';
const { renderReport } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const port = {quota_gb: 100, stats: {acc_in: 1024, acc_out: 2048},
              limit_mbps: 10, dyn_limit: {enable: false}, online: {ip_count: 0}};
const input = {nodeKey: 'test', nodeId: 'Test Node', updatedAt: Math.floor(Date.now()/1000),
               ports: {'443': port}, sortedPorts: ['443'], allowedPorts: 'all'};
const text = () => renderReport(input, new Map()).blocks.join('\n');
assert.match(text(), /443/);
assert.match(text(), /3\.0 KB/);
assert.doesNotMatch(text(), /限速|突发保护/);
port.dyn_limit = {enable: true, is_punished: true, punish_mbps: 50};
assert.match(text(), /突发保护/);
assert.match(text(), /突发限速 50 Mbps/);
port.dyn_limit.is_punished = false;
assert.doesNotMatch(text(), /突发限速|旧版出站限速/);
''', str(ROOT / "worker.js")], text=True, capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

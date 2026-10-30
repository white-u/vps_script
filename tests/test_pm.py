"""PM baseline configuration/state tests; all files and system commands are isolated."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("BASH_BIN", shutil.which("bash") or "/bin/bash")
SOURCE, MARKER, ENTRY = (ROOT / "pm.sh").read_text().partition("# 入口逻辑\n")
assert MARKER, "Refuse to load PM without its entry marker"


def setUpModule():
    major = subprocess.check_output([BASH, "-c", 'echo "${BASH_VERSINFO[0]}"'], text=True)
    if int(major) < 4:
        raise RuntimeError("Tests require Bash 4+; set BASH_BIN to a supported Bash")
    if not shutil.which("jq"):
        raise RuntimeError("Tests require jq")


MOCKS = r'''
CONFIG_DIR="$TEST_DIR/config"
CONFIG_FILE="$CONFIG_DIR/config.json"
STATE_DIR="$CONFIG_DIR/state"
LOCK_FILE="$TEST_DIR/pm.lock"
CRON_LOCK_FILE="$TEST_DIR/cron.lock"
LOG_FILE="$TEST_DIR/pm.log"
USER_EDIT_LOCK="$TEST_DIR/edit.lock"
hostname() { printf '%s\n' 'node "quoted"'; }
get_iface() { echo eth0; }
flock() { :; }
check_root() { :; }
install_shortcut() { :; }
cron_task() { touch "$TEST_DIR/cron-ran"; }
'''


class PMBaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pm-baseline-test-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        (self.path / "library.sh").write_text(SOURCE)
        (self.path / "entry.sh").write_text(ENTRY)
        self.config = self.path / "config/config.json"

    def run_pm(self, code, *args):
        return subprocess.run(
            [BASH, "-c", 'source "$TEST_DIR/library.sh"\n' + MOCKS + code, "pm", *args],
            env={**os.environ, "TEST_DIR": str(self.path)},
            text=True, capture_output=True, timeout=8,
        )

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def initialize(self):
        self.assert_ok(self.run_pm("init_config"))
        return json.loads(self.config.read_text())

    def test_first_install_creates_complete_private_config_without_upgrade(self):
        config = self.initialize()
        self.assertEqual(config["config_version"], 6)
        self.assertEqual(config["node_id"], 'node "quoted"')
        self.assertEqual(config["interface"], "eth0")
        self.assertEqual(config["ports"], {})
        self.assertEqual(config["telegram"]["thresholds"], [50, 80, 100])
        self.assertIs(config["telegram"]["enable"], False)
        self.assertEqual(config["push"], {
            "enable": False, "worker_url": "", "secret": "", "node_key": "",
        })
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.config.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.config.parent / "state").stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.path / "pm.log").exists())

    def test_existing_baseline_config_and_state_are_not_rewritten(self):
        config = self.initialize()
        config["ports"] = {"443": {"quota_gb": 100, "dyn_limit": {"enable": True}}}
        config["telegram"].update(enable=True, bot_token="saved-token")
        self.config.write_text(json.dumps(config, indent=4) + "\n")
        self.assert_ok(self.run_pm("_init_port_state_defaults; s_acc_out=123456; _save_port_state 443"))
        state = self.config.parent / "state/443.txt"
        before_config, before_state = self.config.read_bytes(), state.read_bytes()
        self.assert_ok(self.run_pm("init_config"))
        self.assertEqual(self.config.read_bytes(), before_config)
        self.assertEqual(state.read_bytes(), before_state)

    def test_unsupported_config_versions_are_preserved_and_cron_stops(self):
        config = self.initialize()
        for version in (None, 0, 1, 2, 3, 4, 5, 7, "6"):
            with self.subTest(version=version):
                candidate = {**config, "config_version": version}
                if version is None:
                    candidate.pop("config_version")
                self.config.write_text(json.dumps(candidate))
                before = self.config.read_bytes()
                self.assertNotEqual(self.run_pm("init_config").returncode, 0)
                result = self.run_pm('source "$TEST_DIR/entry.sh"', "--monitor")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.config.read_bytes(), before)
                self.assertFalse((self.path / "cron-ran").exists())
                self.assertIn("格式版本不受支持", (self.path / "pm.log").read_text())

    def test_current_config_reaches_monitor_entry(self):
        self.initialize()
        self.assert_ok(self.run_pm('source "$TEST_DIR/entry.sh"', "--monitor"))
        self.assertTrue((self.path / "cron-ran").exists())

    def test_incomplete_or_corrupt_config_is_preserved(self):
        config = self.initialize()
        candidates = ["", "{broken", "[]"]
        for field in ("node_id", "interface", "telegram", "push", "ports"):
            candidate = dict(config)
            candidate.pop(field)
            candidates.append(json.dumps(candidate))
        candidates.append(json.dumps({**config, "ports": {"443": {"quota_gb": -1}}}))
        for content in candidates:
            with self.subTest(content=content):
                self.config.write_text(content)
                self.assertNotEqual(self.run_pm("init_config").returncode, 0)
                self.assertEqual(self.config.read_text(), content)

    def test_failed_initial_write_does_not_create_partial_config(self):
        result = self.run_pm("jq() { return 1; }; init_config")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.config.exists())
        result = self.run_pm("mv() { return 1; }; init_config")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.config.exists())

    def test_current_state_preserves_usage_and_active_burst_on_round_trip(self):
        self.initialize()
        self.assert_ok(self.run_pm(r'''
_init_port_state_defaults
s_acc_in=123; s_acc_out=456; s_last_k_in=12; s_last_k_out=45
s_is_punished=true; s_punish_end_ts=9999999999; s_high_seconds=1200
s_rules_dirty=true; s_pending_qos_notice=punish
_save_port_state 443
'''))
        state = self.config.parent / "state/443.txt"
        before = state.read_bytes()
        self.assert_ok(self.run_pm("_load_port_state 443 && _save_port_state 443"))
        self.assertEqual(state.read_bytes(), before)
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)

    def test_old_future_missing_or_corrupt_state_never_gets_reset(self):
        self.initialize()
        self.assert_ok(self.run_pm("_init_port_state_defaults; s_acc_in=999; _save_port_state 443"))
        state = self.config.parent / "state/443.txt"
        baseline = state.read_text()
        candidates = [baseline.replace("s_state_version=2\n", value) for value in (
            "", "s_state_version=1\n", "s_state_version=3\n", "s_state_version=bad\n",
        )]
        candidates += ["", baseline.replace("s_acc_in=999", "s_acc_in=bad")]
        for content in candidates:
            with self.subTest(content=content):
                state.write_text(content)
                result = self.run_pm("_load_port_state 443; _save_port_state 443")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(state.read_text(), content)
        state.unlink()
        self.assertNotEqual(self.run_pm("_load_port_state 443; _save_port_state 443").returncode, 0)
        self.assertFalse(state.exists())

    def test_rule_recovery_still_runs_and_propagates_failures(self):
        config = self.initialize()
        config["ports"] = {"443": {"quota_gb": 100}}
        self.config.write_text(json.dumps(config))
        for healthy, failed in ((True, False), (False, False), (False, True)):
            with self.subTest(healthy=healthy, failed=failed):
                marker = self.path / "rules-restored"
                marker.unlink(missing_ok=True)
                result = self.run_pm(f'''
nft_table_healthy() {{ return {0 if healthy else 1}; }}
reload_all_rules() {{ touch "$TEST_DIR/rules-restored"; return {1 if failed else 0}; }}
ensure_runtime_rules
''')
                self.assertEqual(result.returncode, 1 if failed else 0)
                self.assertEqual(marker.exists(), not healthy)

    def test_optional_warning_checkpoint_loads_old_v2_state_without_rewriting_it(self):
        self.initialize()
        self.assert_ok(self.run_pm('_init_port_state_defaults; s_acc_in=123456; _save_port_state 443'))
        state=self.config.parent/'state/443.txt'
        legacy='\n'.join(line for line in state.read_text().splitlines()
                         if not line.startswith('s_quota_warned_level='))+'\n'
        state.write_text(legacy)
        result=self.run_pm('_load_port_state 443 && echo "$s_acc_in:$s_quota_warned_level"')
        self.assert_ok(result)
        self.assertIn('123456:0',result.stdout)
        self.assertEqual(state.read_text(),legacy)
        self.assert_ok(self.run_pm('_load_port_state 443; s_quota_warned_level=100; _save_port_state 443'))
        result=self.run_pm('_load_port_state 443 && echo "$s_acc_in:$s_quota_warned_level"')
        self.assert_ok(result)
        self.assertIn('123456:100',result.stdout)
        valid=state.read_text()
        for bad in ('bad','80','-1','9223372036854775808'):
            with self.subTest(bad=bad):
                corrupted=valid.replace('s_quota_warned_level=100',f's_quota_warned_level={bad}')
                state.write_text(corrupted)
                result=self.run_pm('_load_port_state 443 && _save_port_state 443')
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(state.read_text(),corrupted)


if __name__ == "__main__":
    unittest.main()

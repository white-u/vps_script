"""Opt-in Linux/root PM integration: real nftables, TC, flock, systemd and Cron.

Run: sudo python3 tests/integration_pm.py
Uses a temporary network namespace and files; never edits the root crontab.
"""

import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]


def run(args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
    return result.stdout


def main():
    if os.geteuid() != 0:
        raise SystemExit("Requires Linux root and network namespace support")
    for command in ("ip", "nft", "tc", "jq", "bc", "flock", "curl", "systemd-run", "crontab"):
        if not shutil.which(command):
            raise SystemExit(f"Missing integration dependency: {command}")
    source, marker, _ = (ROOT / "pm.sh").read_text().partition("# 入口逻辑\n")
    assert marker
    namespace = f"pm-baseline-{uuid.uuid4().hex[:12]}"
    unit = namespace
    unit_description = f"PM integration {uuid.uuid4().hex}"
    cron_file = Path("/etc/cron.d") / namespace
    cron_owned = False
    cron_identity = None
    cron_committed = False
    cron_content = ""
    namespace_created = False
    server = None

    def interrupted(signum, frame):
        raise SystemExit(f"Integration interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    with tempfile.TemporaryDirectory(prefix="pm-integration-") as directory:
        path = Path(directory)
        library = path / "library.sh"
        library.write_text(source)
        harness = path / "harness.sh"
        harness.write_text(f'''#!/bin/bash
source {shlex.quote(str(library))}
CONFIG_DIR={shlex.quote(str(path / 'config'))}
CONFIG_FILE="$CONFIG_DIR/config.json"
STATE_DIR="$CONFIG_DIR/state"
TC_OWNER_FILE="$CONFIG_DIR/tc_root_owned"
LOCK_FILE={shlex.quote(str(path / 'pm.lock'))}
CRON_LOCK_FILE={shlex.quote(str(path / 'cron.lock'))}
USER_EDIT_LOCK={shlex.quote(str(path / 'editing'))}
LOG_FILE={shlex.quote(str(path / 'pm.log'))}
NFT_TABLE="inet pm_baseline"
get_iface() {{ echo pmtest0; }}
eval "$1"
''')

        def pm(code, success=True):
            result = subprocess.run(
                ["ip", "netns", "exec", namespace, "bash", str(harness), code],
                text=True, capture_output=True, timeout=20,
            )
            if (result.returncode == 0) != success:
                raise AssertionError(f"PM code: {code}\n{result.stdout}\n{result.stderr}")
            return result.stdout

        def state(port=45443):
            return json.loads(pm(f'''_load_port_state {port} && printf '{{"in":%s,"out":%s,"punished":%s}}' "$s_acc_in" "$s_acc_out" "$s_is_punished"'''))

        try:
            run(["ip", "netns", "add", namespace])
            namespace_created = True
            for args in (["link", "set", "lo", "up"],
                         ["link", "add", "pmtest0", "type", "dummy"],
                         ["link", "set", "pmtest0", "up"]):
                run(["ip", "-n", namespace, *args])
            pm("init_config")
            config_file = path / "config/config.json"
            initial = config_file.read_bytes()
            assert json.loads(initial)["config_version"] == 6
            pm("init_config")
            assert config_file.read_bytes() == initial
            print("PASS complete initialization and unchanged current configuration", flush=True)

            config = json.loads(initial)
            config["ports"] = {
                str(port): {"quota_gb": 1, "quota_mode": "in_out", "reset_day": 0,
                            "comment": "integration", "expiry_date": "", "group_id": "",
                            "dyn_limit": {"enable": port == 45443}, "ip_limit": {"enable": False}}
                for port in (45443, 45444, 45445)
            }
            config_file.write_text(json.dumps(config))
            pm('''for port in 45443 45444 45445; do
_init_port_state_defaults
s_last_reset_ts=$(date +%s); s_last_sample_ts=$s_last_reset_ts
_save_port_state "$port" || exit 1
done
ensure_runtime_rules && nft_table_healthy''')
            payload = path / "payload.bin"
            payload.write_bytes(b"x" * 1048576)
            with (path / "http.log").open("w") as output:
                server = subprocess.Popen(
                    ["ip", "netns", "exec", namespace, "python3", "-m", "http.server", "45443",
                     "--bind", "127.0.0.1", "--directory", str(path)], stdout=output, stderr=output,
                )
            for _ in range(30):
                probe = subprocess.run(["ip", "netns", "exec", namespace, "curl", "-fsS",
                                        "--max-time", "2", "-o", "/dev/null",
                                        "http://127.0.0.1:45443/payload.bin"], capture_output=True)
                if probe.returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("HTTP traffic generator did not start")
            pm("cron_task")
            sampled = state()
            assert sampled["out"] > 1048576 and sampled["in"] > 0
            print("PASS real TCP traffic counted and persisted by cron_task", flush=True)

            pm('''_load_port_state 45443 || exit 1
s_high_seconds=1140
_update_burst_state 301 60 "$(date +%s)" true
_save_port_state 45443 && apply_port_rules 45443 && port_limit_healthy 45443''')
            assert state()["punished"] is True
            classes = run(["ip", "netns", "exec", namespace, "tc", "class", "show", "dev", "pmtest0"])
            assert "rate 50Mbit" in classes
            before = state()
            pm("reload_all_rules && nft_table_healthy && port_limit_healthy 45443")
            assert state() == before
            pm("nft delete table $NFT_TABLE && ensure_runtime_rules && nft_table_healthy && port_limit_healthy 45443")
            assert state() == before
            pm('''_load_port_state 45443 || exit 1
s_punish_end_ts=1
_update_burst_state 0 60 "$(date +%s)" true
_save_port_state 45443 && apply_port_rules 45443''')
            assert state()["punished"] is False
            assert not (path / "config/tc_root_owned").exists()
            print("PASS 50 Mbit TC/map creation, rule recovery without usage loss, burst recovery", flush=True)

            ready = path / "lock-ready"
            holder = subprocess.Popen(["ip", "netns", "exec", namespace, "bash", str(harness),
                                       f"start_edit_lock && touch {shlex.quote(str(ready))} && sleep 3"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(50):
                    if ready.exists():
                        break
                    time.sleep(0.05)
                assert ready.exists()
                state_file = path / "config/state/45443.txt"
                locked_state = state_file.read_bytes()
                pm("cron_task")
                assert state_file.read_bytes() == locked_state
            finally:
                holder.wait(timeout=5)
            print("PASS actual flock prevents concurrent background writes", flush=True)

            config["ports"]["45443"]["group_id"] = "shared"
            config["ports"]["45444"]["group_id"] = "shared"
            config["push"] = {"enable": True, "worker_url": "http://127.0.0.1:45443/api/push",
                              "secret": "integration-only", "node_key": "test"}
            config_file.write_text(json.dumps(config))
            pm('''for port in 45444 45445; do
_load_port_state "$port" || exit 1
s_acc_out=1073741825
_save_port_state "$port" || exit 1
done''')
            state_file = path / "config/state/45443.txt"
            current_state = state_file.read_bytes()
            old_state = current_state.replace(b"s_state_version=2", b"s_state_version=1")
            state_file.write_bytes(old_state)
            pm("cron_task", success=False)
            assert state_file.read_bytes() == old_state
            blocked = json.loads(pm("nft -j list set $NFT_TABLE blocked_ports"))
            elements = next(item["set"].get("elem", []) for item in blocked["nftables"] if "set" in item)
            assert 45445 in elements and 45443 not in elements and 45444 not in elements
            assert "Worker 端口状态汇总失败，已停止上报" in (path / "pm.log").read_text()
            assert "PUT /api/push" not in (path / "http.log").read_text()
            print("PASS mixed old/current states: preserve old data and group, enforce independent quota, stop upload", flush=True)

            state_file.write_bytes(current_state)
            config["push"]["enable"] = False
            for port in config["ports"].values():
                port["quota_gb"] = 100
            config_file.write_text(json.dumps(config))
            run(["systemd-run", "--quiet", "--wait", "--pipe", "--collect", f"--unit={unit}",
                 f"--description={unit_description}", "--property=Type=oneshot",
                 "ip", "netns", "exec", namespace, "bash", str(harness),
                 "init_config && ensure_runtime_rules && cron_task"])
            print("PASS systemd executes current initialization, rule recovery and monitoring", flush=True)

            cron_marker = path / "cron-fired"
            cron_command = shlex.join(["/usr/sbin/ip", "netns", "exec", namespace, "/bin/bash", str(harness),
                                       f"cron_task && touch {shlex.quote(str(cron_marker))}"])
            cron_content = f"* * * * * root {cron_command}\n"
            # Finish ownership bookkeeping even if cancellation arrives during creation.
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                with cron_file.open("x") as output:
                    cron_owned = True
                    created = os.fstat(output.fileno())
                    cron_identity = (created.st_dev, created.st_ino)
                    output.write(cron_content)
                cron_file.chmod(0o644)
                cron_committed = True
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            deadline = time.monotonic() + 75
            while not cron_marker.exists() and time.monotonic() < deadline:
                time.sleep(1)
            assert cron_marker.exists(), "Cron did not execute within 75 seconds"
            print("PASS real Cron scheduler executed monitoring successfully", flush=True)
        finally:
            # Repeated termination must not interrupt resource cleanup.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            cleanup_errors = []
            try:
                if cron_owned and cron_file.exists():
                    current = cron_file.stat()
                    same_file = (current.st_dev, current.st_ino) == cron_identity
                    if same_file and (not cron_committed or cron_file.read_text() == cron_content):
                        cron_file.unlink()
                    else:
                        raise RuntimeError(f"Cron file changed externally; preserved: {cron_file}")
            except Exception as error:
                cleanup_errors.append(str(error))
            try:
                description = subprocess.run(
                    ["systemctl", "show", unit, "--property=Description", "--value"],
                    text=True, capture_output=True, timeout=10,
                )
                if description.returncode == 0 and description.stdout.strip() == unit_description:
                    run(["systemctl", "stop", unit])
                    subprocess.run(["systemctl", "reset-failed", unit], capture_output=True, timeout=10)
            except Exception as error:
                cleanup_errors.append(str(error))
            try:
                if server is not None:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=5)
            except Exception as error:
                cleanup_errors.append(str(error))
            try:
                if namespace_created:
                    run(["ip", "netns", "delete", namespace])
            except Exception as error:
                cleanup_errors.append(str(error))
            if cleanup_errors:
                raise RuntimeError("Integration cleanup incomplete: " + "; ".join(cleanup_errors))
    print("PASS integration resources cleaned", flush=True)


if __name__ == "__main__":
    main()

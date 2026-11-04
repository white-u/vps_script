"""Opt-in Linux/root business-safety integration. No production installation.

Usage: PATH=<private-vnstat-package>/usr/bin:<...>/usr/sbin:$PATH \
       python3 tests/integration_traffic_balance.py [--public-interface ens3]
Uses private vnStat data, unique systemd units and an owned veth/namespace HTTP pair.
Public probes are opt-in, <= 1 MiB per source, 1 Mbps, 15 seconds per source;
stop the whole public probe on rate limiting. Never reboots the host.
"""
import argparse
import importlib.util
import ipaddress
import json
import logging
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SOURCE = Path(__file__).resolve().parents[1] / 'traffic_balance.py'
spec = importlib.util.spec_from_file_location('balance_integration', SOURCE)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def require(value, message):
    if not value:
        raise AssertionError(message)


def report(message):
    print('PASS ' + message, flush=True)


def wait_until(condition, seconds=15):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(.2)
    raise AssertionError('Timed out waiting for test condition')


def active(unit):
    return b.run('systemctl', 'show', unit, '-p', 'ActiveState', '--value').strip()


def clean_unit(unit, path, owner_dir):
    if not path.exists():
        return
    require(str(owner_dir) in path.read_text(), 'Unit ownership changed: ' + str(path))
    b.run('systemctl', 'stop', unit)
    require(active(unit) in ('inactive', 'failed'), 'Service did not stop: ' + unit)
    b.run('systemctl', 'disable', unit)
    path.unlink()
    b.run('systemctl', 'daemon-reload')
    subprocess.run(['systemctl', 'reset-failed', unit], capture_output=True, timeout=20)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        amount = 8*b.MIB
        requested = self.headers.get('Range')
        if requested:
            amount = min(amount, int(requested.split('-')[-1])+1)
        self.send_response(206 if requested else 200)
        self.send_header('Content-Length', str(amount))
        if requested:
            self.send_header('Content-Range', f'bytes 0-{amount-1}/{8*b.MIB}')
        self.end_headers()
        try:
            sent = 0
            while sent < amount:
                size = min(8192, amount-sent)
                self.wfile.write(b'x'*size)
                self.wfile.flush()
                sent += size
                time.sleep(.01)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-interface')
    args = parser.parse_args()
    require(sys.platform.startswith('linux') and os.geteuid() == 0 and
            Path('/run/systemd/system').exists(), 'Requires Linux/root with systemd')
    for cmd in ('vnstat', 'vnstatd', 'curl', 'systemctl', 'ip'):
        require(shutil.which(cmd), 'Missing dependency: ' + cmd)
    os.umask(0o077)
    tag = 'balance-it-' + uuid.uuid4().hex[:10]
    root = Path(tempfile.mkdtemp(prefix=tag+'-', dir='/tmp'))
    base = root/'data'
    base.mkdir()
    db = base/'db'
    db.mkdir()
    b.BASE = base
    b.CONFIG, b.STATE, b.LOCK = base/'config.json', base/'state.json', base/'task.lock'
    b.LOG, b.HEADER_DIR = base/'task.log', str(base)
    b.VNSTAT_CONFIG = base/'vnstat.conf'
    b.SERVICE = tag+'.service'
    b.UNIT = Path('/run/systemd/system')/b.SERVICE
    b.SCRIPT = root/'task'
    vnunit = tag+'-vnstat.service'
    vnpath = Path('/run/systemd/system')/vnunit
    host_if, peer_if = 'bt'+tag[-10:], 'bp'+tag[-10:]
    namespace = tag+'-net'
    octet = int(tag[-2:], 16)
    host_ip, peer_ip = f'198.19.{octet}.1', f'198.19.{octet}.2'
    namespace_owned = link_owned = False
    server_process = worker = None
    public_results = []
    protection_log = base/'protection.log'
    log_handler = logging.FileHandler(protection_log)
    log_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    b.logger.addHandler(log_handler)
    print('TEST_DIRECTORY '+str(root), flush=True)

    def signal_exit(signum, _):
        raise SystemExit(f'Test interrupted: {signum}')
    signal.signal(signal.SIGTERM, signal_exit)
    signal.signal(signal.SIGINT, signal_exit)
    original_command = b.curl_command
    try:
        subnet = ipaddress.ip_network(host_ip+'/30', strict=False)
        for route in json.loads(b.run('ip', '-j', 'route', 'show', 'table', 'all')):
            dst = route.get('dst', 'default')
            if dst != 'default':
                network = ipaddress.ip_network(dst, strict=False)
                require(network.version != 4 or not subnet.overlaps(network),
                        'Test subnet conflicts with existing route: '+dst)
        b.run('ip', 'netns', 'add', namespace)
        namespace_owned = True
        b.run('ip', 'link', 'add', host_if, 'type', 'veth', 'peer', 'name', peer_if)
        link_owned = True
        b.run('ip', 'link', 'set', peer_if, 'netns', namespace)
        b.run('ip', 'addr', 'add', host_ip+'/30', 'dev', host_if)
        b.run('ip', 'link', 'set', host_if, 'up')
        b.run('ip', '-n', namespace, 'addr', 'add', peer_ip+'/30', 'dev', peer_if)
        b.run('ip', '-n', namespace, 'link', 'set', peer_if, 'up')
        b.run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
        b.VNSTAT_CONFIG.write_text(f'''DatabaseDir "{db}"
UpdateInterval 2
PollInterval 2
SaveInterval 1
OfflineSaveInterval 1
AlwaysAddNewInterfaces 0
UseLogging 0
DaemonUser "root"
DaemonGroup "root"
''')
        b.run('vnstatd', '--config', str(b.VNSTAT_CONFIG), '--initdb', '--noadd')
        b.run('vnstat', '--add', '-i', host_if)
        c = dict(b.DEFAULT, interface=host_if, ratio=2.1,
                 bandwidth_mbps=30)
        try:
            b.stats(c, b.vn_settings())
        except b.Error:
            report('real new vnStat database is refused as not ready/incomplete')
        else:
            raise AssertionError('Incomplete first day unexpectedly accepted')
        # Private fixture only: simulate a database created yesterday so the
        # real daemon/query pipeline can be exercised without waiting a day.
        database = db/'vnstat.db'
        with sqlite3.connect(database) as con:
            con.execute('UPDATE interface SET created=? WHERE name=?', (int(time.time())-86400*2, host_if))
        vnpath.write_text(f'''[Unit]
Description={tag} private vnStat fixture
[Service]
Type=simple
ExecStart={shutil.which('vnstatd')} --config {b.VNSTAT_CONFIG} --nodaemon
''')
        b.run('systemctl', 'daemon-reload')
        b.run('systemctl', 'start', vnunit)
        server_process = subprocess.Popen(['ip', 'netns', 'exec', namespace, sys.executable,
                                           str(Path(__file__).resolve()), '--serve', peer_ip, '45443'],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        def server_ready():
            try:
                with socket.create_connection((peer_ip, 45443), timeout=.2): return True
            except OSError: return False
        wait_until(server_ready, 10)
        # A small request creates real interface counters for the private daemon.
        b.run('curl', '-q', '-fsS', '--noproxy', '*', '--range', '0-65535',
              '--output', '/dev/null', f'http://{peer_ip}:45443/seed')
        time.sleep(3)  # allow the real daemon's initial interface-counter sync
        b.run('curl', '-q', '-fsS', '--noproxy', '*', '--range', '0-65535',
              '--output', '/dev/null', f'http://{peer_ip}:45443/seed-again')
        s = b.initial_state()
        print('WAIT real vnStat save/update (up to 3 minutes)', flush=True)
        settings = b.vn_settings()
        # Initially there may be no daily row. The product intentionally rejects
        # that condition; only this harness waits for the new fixture to start.
        def has_day():
            try:
                b.stats(c, settings)
                return True
            except b.Error:
                return False
        wait_until(has_day, 90)
        started = int(time.time())
        day, v = b.wait_fresh_stats(c, s, settings)
        require(v['updated'] > started, 'Freshness check used an old sample')
        require(v['rx'] > 0 and v['tx'] > 0, 'Actual veth traffic missing')
        report('real vnStat 2.x day/total/date and fresh-sample wait')
        pre = b.preflight(c)
        require(pre.received >= 0 and b.effective_speed(c) == 12, 'Idle preflight or 30 Mbps cap failed')
        report('5-second real CPU/network preflight and fixed 12 Mbps cap for 30 Mbps server')

        def local_command(config, source, amount, seconds):
            cmd = original_command(config, source, amount, seconds)
            cmd[cmd.index('--proto')+1] = '=http'
            cmd[-1] = f'http://{peer_ip}:45443/download'
            return cmd
        b.curl_command = local_command
        amount, ok, _, reason = b.download(c, 'wechat', 1024*1024, settings, day, time.monotonic()+15)
        require(ok and amount == 1024*1024, 'Real limited curl failed: '+reason)
        report('real Linux curl payload accounting, interface binding and header cleanup')
        require(not list(base.glob('traffic-balance-header-*')), 'Temporary header was retained')

        busy_c = dict(c, bandwidth_mbps=1)
        worker = subprocess.Popen(['curl', '-q', '-sS', '--noproxy', '*', '--limit-rate', '128000',
                                   '--output', '/dev/null', f'http://{peer_ip}:45443/busy'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            try:
                b.preflight(busy_c)
            except b.Error as e:
                require('当前占用' in str(e) and '[预检保护]' in str(e) and
                        '>= 0.4 Mbps' in str(e), str(e))
                b.logger.warning('%s', e)
                print('PROTECTION_PREFLIGHT '+str(e), flush=True)
            else:
                raise AssertionError('Busy network preflight allowed a download')
            report('busy real isolated veth traffic prevents new downloads')
            before = time.monotonic()
            amount, ok, _, reason = b.download(busy_c, 'wechat', 4*b.MIB, settings, day, before+15)
            require(not ok and '带宽' in reason and '[下载保护]' in reason and
                    '> 0.8 Mbps' in reason and time.monotonic()-before < 6,
                    'Live protection did not stop promptly: '+reason)
            log_handler.flush()
            require('当前占用' in protection_log.read_text() and reason.split(' → 停止本轮')[0] in protection_log.read_text(),
                    'Trigger detail did not reach the log file')
            print('PROTECTION_ACTIVE '+reason, flush=True)
            report('3-second guard logs measured bandwidth and threshold, then interrupts active curl')
        finally:
            worker.terminate()
            worker.wait(timeout=5)
            worker = None
        b.curl_command = original_command

        b.atomic_json(b.CONFIG, c)
        s['mode'] = 'running'
        b.atomic_json(b.STATE, s)
        module = root/'traffic_balance.py'
        shutil.copyfile(SOURCE, module)
        b.SCRIPT.write_text(f'''import importlib.util, sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('balance_task', {str(module)!r})
b=importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
b.BASE=Path({str(base)!r})
b.CONFIG=b.BASE/'config.json'
b.STATE=b.BASE/'state.json'
b.LOCK=b.BASE/'task.lock'
b.LOG=b.BASE/'task.log'
b.HEADER_DIR=str(b.BASE)
b.VNSTAT_CONFIG=b.BASE/'vnstat.conf'
# The private veth is intentionally not the host's public default route.
# Isolate only route discovery; verify_interface still checks this fixture.
b.detect_interface=lambda: {host_if!r}
sys.exit(b.main())
''')
        # Exec env needs private extracted binaries too; remaining unit settings
        # are generated by the production function (including its hardening).
        unit = b.service_content().replace('[Unit]', '[Unit]\nStartLimitIntervalSec=0').replace('vnstat.service', vnunit).replace('[Service]', '[Service]\nEnvironment="PATH='+os.environ['PATH']+'"')
        require('vnstat.service' not in unit.replace(vnunit, ''), 'Test unit references production vnStat')
        b.UNIT.write_text(unit)
        b.run('systemctl', 'daemon-reload')
        b.control('running')
        wait_until(lambda: b.load_json(b.STATE)['next_check'] > time.time()+1000)
        require(b.load_json(b.STATE)['attempts'] == 0, 'Startup downloaded without waiting')
        require(b.load_json(b.STATE)['reason'].startswith('启动统计检查通过'),
                'Startup skipped statistics validation: '+b.load_json(b.STATE)['reason'])
        report('real hardened systemd service starts, validates stats, and waits randomly')
        # Exercise the real update transaction using a self-contained isolated
        # payload. All paths, service dependencies and route discovery stay local.
        candidate = root/'update-candidate.py'
        overrides = f"""
BASE=Path({str(base)!r})
CONFIG=BASE/'config.json'
STATE=BASE/'state.json'
LOCK=BASE/'task.lock'
UPDATE_LOCK=BASE/'management.lock'
LOG=BASE/'task.log'
HEADER_DIR=str(BASE)
VNSTAT_CONFIG=BASE/'vnstat.conf'
SCRIPT=Path({str(b.SCRIPT)!r})
UNIT=Path({str(b.UNIT)!r})
SERVICE={b.SERVICE!r}
detect_interface=lambda: {host_if!r}
"""
        # Accelerated lifecycle tests must not hit systemd's default 5-start limit.
        # This override is confined to the generated test payload/unit.
        payload = SOURCE.read_text().replace('vnstat.service', vnunit).replace(
            'Description=Daily inbound traffic balance',
            'StartLimitIntervalSec=0\nDescription=Daily inbound traffic balance')
        payload = payload.replace("if __name__ == '__main__':", overrides+"\nif __name__ == '__main__':")
        candidate.write_text(payload)
        before_update = b.load_json(b.STATE)
        b.run(sys.executable, str(candidate), '--apply-update', timeout=90, live=True)
        after_update = b.load_json(b.STATE)
        require(active(b.SERVICE) == 'active' and after_update['next_check'] > time.time(),
                'Updated service did not complete startup checks')
        require((before_update['used'], before_update['attempts']) ==
                (after_update['used'], after_update['attempts']), 'Online update changed accounting')
        require(b.SCRIPT.read_text() == payload, 'Update did not replace installed source')
        report('real online update stops, installs, restarts and retains accounting')
        bad = payload.replace("elif args.daemon:\n            handler", "elif args.daemon:\n            raise Error('integration intentional startup failure')\n            handler")
        require(bad != payload, 'Failed to construct controlled startup failure')
        candidate.write_text(bad)
        try:
            b.run(sys.executable, str(candidate), '--apply-update', timeout=90, live=True)
        except b.Error:
            pass
        else:
            raise AssertionError('Broken update reported success')
        require(b.SCRIPT.read_text() == payload and active(b.SERVICE) in ('inactive', 'failed'),
                'Failed update did not restore old code and stop')
        after_failure = b.load_json(b.STATE)
        require(after_failure['mode'] == 'stopped' and after_failure['used'] == before_update['used'],
                'Failed update changed quota or left running mode')
        report('real failed-start update restores old code, stops and preserves quota')
        b.control('running')
        b.run('systemctl', 'restart', b.SERVICE)
        wait_until(lambda: active(b.SERVICE) == 'active')
        require(b.load_json(b.STATE)['attempts'] == 0, 'Service restart issued download')
        b.run('systemctl', 'stop', b.SERVICE)
        s = b.validate_state(b.load_json(b.STATE))
        b.reserve(s, b.MIB, s['last'])
        b.atomic_json(b.STATE, s)
        b.run('systemctl', 'start', b.SERVICE)
        wait_until(lambda: b.load_json(b.STATE)['pending'] is None)
        require(b.load_json(b.STATE)['used'] == b.MIB and b.load_json(b.STATE)['attempts'] == 1,
                'Unsettled reservation was lost or double-counted')
        report('real process restart conservatively preserves unsettled reservation')
        b.control('paused')
        b.run('systemctl', 'start', b.SERVICE)  # emulate boot of enabled paused unit
        wait_until(lambda: active(b.SERVICE) == 'inactive')
        require(b.load_json(b.STATE)['mode'] == 'paused' and b.load_json(b.STATE)['used'] == b.MIB,
                'Pause was not preserved across process start')
        b.control('stopped')
        require(b.STATE.exists() and b.CONFIG.exists(), 'Stop removed accounting')
        b.STATE.write_text('{broken')
        try:
            b.control('paused')
        except b.Error:
            pass
        else:
            raise AssertionError('Corrupt state was silently accepted')
        require(active(b.SERVICE) in ('inactive', 'failed') and b.STATE.read_text() == '{broken',
                'Corrupt state did not stop safely')
        enabled = subprocess.run(['systemctl', 'is-enabled', b.SERVICE], capture_output=True, text=True, timeout=10)
        require(enabled.stdout.strip() == 'disabled', 'Corrupt state left boot enabled')
        report('pause/stop persistence and corrupt-state shutdown without clearing accounting')

        if args.public_interface:
            public = dict(c, interface=args.public_interface, download_percent=100/c['bandwidth_mbps'])
            b.preflight(public)
            for source in b.SOURCES:
                try:
                    amount, ok, until, reason = b.download(public, source, b.MIB, settings,
                                                         b.date_now(settings), time.monotonic()+15)
                    public_results.append(dict(source=source, bytes=amount, ok=ok, reason=reason))
                    print('PUBLIC '+json.dumps(public_results[-1], ensure_ascii=False), flush=True)
                    if until:
                        print('PUBLIC halted on rate limiting; no source switch or retry', flush=True)
                        break
                except b.Error as e:
                    public_results.append(dict(source=source, ok=False, error=str(e)))
                    print('PUBLIC '+json.dumps(public_results[-1], ensure_ascii=False), flush=True)
            require(any(x['ok'] for x in public_results), 'No public source was usable; private integration passed')
        print('RESULT '+json.dumps(dict(private='passed', public=public_results), ensure_ascii=False), flush=True)
    finally:
        b.curl_command = original_command
        if worker is not None:
            worker.terminate()
            worker.wait(timeout=5)
        if server_process is not None:
            server_process.terminate()
            server_process.wait(timeout=5)
            server_process.stderr.close()
        try:
            clean_unit(b.SERVICE, b.UNIT, root)
            clean_unit(vnunit, vnpath, root)
            if link_owned:
                b.run('ip', 'link', 'del', host_if)
            if namespace_owned:
                b.run('ip', 'netns', 'del', namespace)
        except Exception as e:
            raise RuntimeError(f'Cleanup incomplete; retained {root}: {e}') from e
        b.logger.removeHandler(log_handler)
        log_handler.close()
        shutil.rmtree(root)
        print('CLEANUP removed only owned units/database/files; existing services unchanged', flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--serve':
        server = ThreadingHTTPServer((sys.argv[2], int(sys.argv[3])), Handler)
        server.daemon_threads = True
        server.serve_forever()
    else:
        main()

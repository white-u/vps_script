"""Opt-in root/Linux FW user journey with real Realm, systemd and TCP/UDP.

Downloads the pinned, checksum-verified core through the actual installer.
Uses private /opt files, a unique service and loopback-only listeners.
Run: sudo python3 tests/integration_fw.py
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.request.recv(4096))


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def cleanup_installation(unit, path, service_file):
    """Keep recovery files if stopping/disabling the owned service is uncertain."""
    try:
        present = service_file.exists()
        if present and str(path / 'realm') not in service_file.read_text():
            raise RuntimeError('Service ownership changed; refusing cleanup')
        if present:
            subprocess.run(['systemctl', 'stop', unit], check=True,
                           capture_output=True, timeout=45)
        state = subprocess.run(['systemctl', 'show', unit, '--property=ActiveState', '--value'],
                               check=True, text=True, capture_output=True, timeout=10).stdout.strip()
        if state not in ('inactive', 'failed'):
            raise RuntimeError('Service still active or state unknown: ' + state)
        if present:
            subprocess.run(['systemctl', 'disable', unit], check=True,
                           capture_output=True, timeout=20)
            service_file.unlink()
        subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True, timeout=20)
        # reset-failed can report unit-not-found after a successful uninstall.
        subprocess.run(['systemctl', 'reset-failed', unit], capture_output=True, timeout=20)
    except Exception as error:
        raise RuntimeError(f'Cleanup incomplete; retained {path}; service {unit}; '
                           f'unit path {service_file}: {error}') from error
    shutil.rmtree(path)


def main():
    if os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise SystemExit('Requires Linux root with running systemd')
    unit = 'vps-fw-user-' + uuid.uuid4().hex[:12]
    service_file = Path('/etc/systemd/system') / (unit + '.service')
    assert not service_file.exists()
    source, marker, _ = (ROOT / 'fw.sh').read_text().partition('\ncheck_root\ncheck_platform\n')
    assert marker, 'Cannot find FW entry boundary'

    def interrupted(signum, frame):
        raise SystemExit(f'Interrupted by signal {signum}')

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    directory = tempfile.mkdtemp(prefix=unit + '-', dir='/opt')
    path = Path(directory)
    library = path / 'library.sh'
    library.write_text(source)
    harness = path / 'harness.sh'
    harness.write_text(f'''#!/bin/bash
source {shlex.quote(str(library))}
REALM_BIN={shlex.quote(str(path / 'realm'))}
CONFIG_DIR={shlex.quote(str(path / 'config'))}
CONFIG_TOML="$CONFIG_DIR/config.toml"
META_FILE="$CONFIG_DIR/fw.json"
SERVICE_NAME={unit}
SERVICE_FILE={service_file}
SCRIPT_PATH={shlex.quote(str(path / 'fw'))}
# Confine test listeners to loopback; actual rules, installer and service logic are unchanged.
detect_listen_addr() {{ echo 127.0.0.1; }}
init_meta
eval "$1"
''')

    def run(code, stdin='', success=True):
        result = subprocess.run(['bash', str(harness), code], input=stdin,
                                text=True, capture_output=True, timeout=180)
        if success and result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        if not success and result.returncode == 0:
            raise AssertionError('Expected failure: ' + result.stdout)
        return result

    def running():
        return subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode == 0

    try:
        run('install_realm')
        assert (path / 'realm').is_file() and service_file.is_file()
        assert not running(), 'An installation without rules must not run'
        print('PASS: pinned core download/checksum/install; empty rules keep service stopped', flush=True)
        with socketserver.ThreadingTCPServer(('127.0.0.1', 0), TCPHandler) as tcp:
            target = tcp.server_address[1]
            with socketserver.ThreadingUDPServer(('127.0.0.1', target), UDPHandler) as udp:
                for server in (tcp, udp):
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                try:
                    with socket.socket() as reserve:
                        reserve.bind(('127.0.0.1', 0))
                        port = reserve.getsockname()[1]
                    added = run('menu_add', f'bad\n{port}\n127.0.0.1\n{target}\nuser test\ny\nn\n\n')
                    meta = path / 'config/fw.json'
                    saved = meta.read_bytes()
                    assert json.loads(saved)['rules'] and json.loads(saved)['rules'][0]['src_port'] == port, added.stdout + added.stderr
                    assert running()
                    with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                        client.sendall(b'FW real TCP user request')
                        assert client.recv(4096) == b'FW real TCP user request'
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                        client.settimeout(5)
                        client.sendto(b'FW real UDP user request', ('127.0.0.1', port))
                        assert client.recv(4096) == b'FW real UDP user request'
                    print('PASS: invalid input corrected; confirmed rule forwards real TCP and UDP', flush=True)
                    assert str(port) in run('show_all_configs').stdout
                    run(f'add_forward {port} 127.0.0.1 {target} duplicate', success=False)
                    assert meta.read_bytes() == saved
                    run('menu_delete', '1\nn\n')
                    run('install_realm', 'n\n')
                    run('uninstall_all', 'no\n')
                    assert meta.read_bytes() == saved and running()
                    print('PASS: list/export, duplicate rejection, cancel delete/reinstall/uninstall preserve rules', flush=True)
                    run('menu_delete', '1\ny\n\n')
                    assert json.loads(meta.read_text())['rules'] == [] and not running()
                    run('uninstall_all', 'yes\n')
                    assert not service_file.exists() and not (path / 'realm').exists()
                    assert not (path / 'config').exists()
                    print('PASS: deleting last rule stops service; confirmed uninstall removes test installation', flush=True)
                finally:
                    tcp.shutdown()
                    udp.shutdown()
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup_installation(unit, path, service_file)


if __name__ == '__main__':
    main()

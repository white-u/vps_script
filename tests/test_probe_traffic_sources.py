"""Offline source-probe checks; no external network or system services."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('probe_sources', Path(__file__).with_name('probe_traffic_sources.py'))
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


class ProbeTests(unittest.TestCase):
    def test_exact_range_and_api_validation(self):
        self.assertEqual(p.response_ok('HTTP/1.1 200 OK\r\nContent-Length: 4\r\n', 'api', 4), (200, True))
        good = 'HTTP/1.1 206 OK\r\nContent-Length: 4\r\nContent-Range: bytes 0-3/100\r\n'
        self.assertEqual(p.response_ok(good, 'range', 4), (206, True))
        for header in (good.replace('0-3', '1-4'), good.replace('Length: 4', 'Length: 5'),
                       good+'Content-Length: 4\r\n', good+'Transfer-Encoding: chunked\r\n'):
            self.assertFalse(p.response_ok(header, 'range', 4)[1])

    def test_connect_block_is_not_confused_with_response(self):
        headers = 'HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n'
        self.assertEqual(p.response_ok(headers, 'api', 4), (403, False))

    def test_preflight_failure_never_starts_curl(self):
        class Error(Exception): pass
        b = SimpleNamespace(Error=Error, preflight=lambda *a, **kw: (_ for _ in ()).throw(Error('busy')))
        with patch.object(p.subprocess, 'Popen') as start:
            result = p.probe(b, {}, 'ovh', 1024)
        start.assert_not_called()
        self.assertEqual(result['actual_bytes'], 0)
        self.assertEqual(result['status'], 'protected_or_error')

    def test_requires_finite_bandwidth(self):
        for value in ('0', '-1', 'nan', 'inf'):
            with self.assertRaises(Exception): p.positive(value)

    def test_real_local_curl_count_and_rate_limit(self):
        if not p.shutil.which('curl'): self.skipTest('curl not available')
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                limited = self.path == '/limited'
                body = b'x'*32768 if not limited else b'wait'
                self.send_response(429 if limited else 200)
                self.send_header('Content-Length', str(len(body)))
                if limited: self.send_header('Retry-After', '60')
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        class Error(Exception): pass
        b = SimpleNamespace(Error=Error, STOP=threading.Event(),
            preflight=lambda *a, **kw: SimpleNamespace(check=lambda: False),
            effective_speed=lambda c: 80,
            retry_after=lambda text, now: int(now)+60 if 'Retry-After: 60' in text else 0)
        original = subprocess.Popen
        def local_only(cmd, **kw):
            cmd = list(cmd)
            cmd[cmd.index('--proto')+1] = '=http'
            i = cmd.index('--interface'); del cmd[i:i+2]
            return original(cmd, **kw)
        try:
            for route in ('/ok', '/limited'):
                with patch.dict(p.SOURCES, {'local': (f'http://127.0.0.1:{server.server_port}{route}', 'api')}), \
                     patch.object(p.subprocess, 'Popen', side_effect=local_only):
                    result = p.probe(b, dict(interface='unused'), 'local', 32768)
                if route == '/ok':
                    self.assertTrue(result['success'], result)
                    self.assertEqual(result['actual_bytes'], 32768)
                else:
                    self.assertFalse(result['success'])
                    self.assertEqual(result['http'], 429)
                    self.assertGreater(result['limited_until'], 0)
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__': unittest.main()

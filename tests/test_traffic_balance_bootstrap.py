"""Download launcher tests with fake curl/APT; never install or use the network."""
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


SOURCE = (Path(__file__).resolve().parents[1]/'tb.sh').read_text()
BASH = os.environ.get('BASH_BIN', shutil.which('bash') or '/bin/bash')


def function(name):
    match = re.search(r'(?ms)^'+name+r'\(\) \{.*?^\}', SOURCE)
    if not match:
        raise AssertionError('Missing function: '+name)
    return match[0]+'\n'


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root/'bin'
        self.bin.mkdir()
        self.record = self.root/'curl.json'
        stub = self.bin/'curl'
        stub.write_text('#!'+sys.executable+'\n'+'''import json, os, pathlib, sys
args=sys.argv[1:]
pathlib.Path(os.environ['CURL_RECORD']).write_text(json.dumps(args))
with open(os.environ['CURL_RECORD']+'.history','a') as history: history.write(json.dumps(args)+'\\n')
payload=os.environ.get('PAYLOAD','')
status=int(os.environ.get('CURL_EXIT','0'))
if 'raw.githubusercontent.com' in args[-1]:
    if os.environ.get('CURL_MODE')=='primary-fails': status=28; payload='partial'
    if os.environ.get('CURL_MODE')=='primary-invalid': payload='print("wrong payload")'
pathlib.Path(args[args.index('--output')+1]).write_text(payload)
sys.exit(status)
''')
        stub.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                        TMPDIR=str(self.root), CURL_RECORD=str(self.record))

    def run_shell(self, code, *, payload='print("menu")\n', status=0, stdin='', mode='', digest=None):
        env = dict(self.env, PAYLOAD=payload, CURL_EXIT=str(status), CURL_MODE=mode,
                   SOURCE_SHA256=digest or hashlib.sha256(payload.encode()).hexdigest())
        return subprocess.run([BASH, '-c', 'set -euo pipefail\n'+code], env=env,
                              input=stdin, capture_output=True, text=True, timeout=15)

    def download(self, **kwargs):
        code = '''SOURCE_URLS=(
https://raw.githubusercontent.com/white-u/vps_script/example/traffic_balance.py
https://api.github.com/repos/white-u/vps_script/contents/traffic_balance.py
https://cdn.jsdelivr.net/gh/white-u/vps_script@example/traffic_balance.py
)
'''
        code += function('download_script')+'download_script "$TMPDIR/download.py"\n'
        return self.run_shell(code, **kwargs)

    def test_valid_download_uses_verified_https_and_checks_python(self):
        result = self.download()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads(self.record.read_text())
        self.assertIn('-q', args)
        self.assertIn('--fail', args)
        self.assertIn('--progress-bar', args)
        self.assertEqual(args[args.index('--proto')+1], '=https')
        self.assertEqual(args[args.index('--proto-redir')+1], '=https')
        self.assertNotIn('--insecure', args)
        self.assertEqual(args[args.index('--header')+1], 'Accept: application/vnd.github.raw+json')
        self.assertEqual((self.root/'download.py').read_text(), 'print("menu")\n')

    def test_download_failure_does_not_execute_even_valid_partial_payload(self):
        result = self.download(payload='raise RuntimeError("must not execute")\n', status=22)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('下载失败', result.stderr)
        self.assertNotIn('RuntimeError', result.stderr)

    def test_empty_and_invalid_python_are_refused(self):
        for payload in ('', '<html>bad gateway</html>', 'def broken(:'):
            result = self.download(payload=payload)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('未执行脚本', result.stderr)

    def test_blocked_raw_host_falls_back_to_official_api(self):
        result = self.download(mode='primary-fails')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in Path(str(self.record)+'.history').read_text().splitlines()]
        self.assertEqual(len(calls), 2)
        self.assertIn('api.github.com', calls[-1][-1])
        self.assertEqual((self.root/'download.py').read_text(), 'print("menu")\n')

    def test_successful_but_wrong_content_cannot_bypass_digest_check(self):
        result = self.download(mode='primary-invalid')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('摘要不匹配', result.stderr)
        calls = Path(str(self.record)+'.history').read_text().splitlines()
        self.assertEqual(len(calls), 2)

    def test_all_digest_mismatches_fail_without_running_any_content(self):
        result = self.download(digest='0'*64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('未执行脚本', result.stderr)
        self.assertEqual(len(Path(str(self.record)+'.history').read_text().splitlines()), 3)

    def test_release_digest_matches_the_published_payload_file(self):
        digest = re.search(r"^SOURCE_SHA256='([0-9a-f]{64})'$", SOURCE, re.M).group(1)
        payload = (Path(__file__).resolve().parents[1]/'traffic_balance.py').read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), digest,
                         'Update the pinned payload ref and digest when releasing a new Python script')

    def test_main_preserves_menu_input_and_cleans_temporary_source(self):
        code = 'TASK_TMP=""\n'+function('cleanup')+function('main')+'''
check_platform() { return 0; }
ensure_dependencies() { return 0; }
download_script() { printf 'print(input("menu: "))\\n' > "$1"; }
main
'''
        result = self.run_shell(code, stdin='7\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('menu: 7', result.stdout)
        self.assertEqual(list(self.root.glob('tb-install.*')), [])

    def test_dependency_failure_stops_before_download_or_menu(self):
        code = 'TASK_TMP=""\n'+function('cleanup')+function('main')+'''
check_platform() { return 0; }
ensure_dependencies() { return 1; }
download_script() { touch "$TMPDIR/unexpected-download"; }
main
'''
        result = self.run_shell(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root/'unexpected-download').exists())
        self.assertEqual(list(self.root.glob('tb-install.*')), [])

    def test_apt_failure_is_reported_and_not_ignored(self):
        stub = self.bin/'apt-get'
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TMPDIR/apt.args"\nexit 1\n')
        stub.chmod(0o755)
        code = function('ensure_dependencies')+'''
command() {
    if [[ "$1" == -v && "$2" == ip ]]; then return 1; fi
    builtin command "$@"
}
ensure_dependencies
'''
        result = self.run_shell(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('基础工具安装失败', result.stderr)
        self.assertEqual((self.root/'apt.args').read_text().splitlines(), ['update'])


if __name__ == '__main__':
    unittest.main()

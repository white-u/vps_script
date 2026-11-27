#!/usr/bin/env python3
"""Opt-in source probes. Imports protection functions only; never installs a task."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

MIB = 1024**2
SOURCES = {
    'cloudflare': ('https://speed.cloudflare.com/__down?bytes={amount}', 'api'),
    'ovh': ('https://proof.ovh.net/files/1Gb.dat', 'range'),
    'hetzner': ('https://fsn1-speed.hetzner.com/1GB.bin', 'range'),
}
TOTAL_LIMIT = 1024*MIB
FULL_BYTES = 384*MIB
ATTEMPT_SECONDS = 200


def positive(text):
    value = float(text)
    if not math.isfinite(value) or not 0 < value <= 1000000:
        raise argparse.ArgumentTypeError('带宽必须是已确认的 Mbps 正数')
    return value


def response_ok(headers, mode, amount):
    # Select the final response; ignore a possible connection-establishment block.
    blocks = re.split(r'(?=^HTTP/)', headers, flags=re.M)
    final = next((x for x in reversed(blocks) if x.startswith('HTTP/')), '')
    code = re.match(r'HTTP/\S+\s+(\d{3})', final)
    status = int(code[1]) if code else 0
    lengths = re.findall(r'^Content-Length:\s*(\d+)\s*$', final, re.I | re.M)
    if len(lengths) != 1 or int(lengths[0]) != amount:
        return status, False
    if re.search(r'^Transfer-Encoding:', final, re.I | re.M):
        return status, False
    if mode == 'api':
        return status, status == 200
    ranges = re.findall(r'^Content-Range:\s*bytes\s+(\d+)-(\d+)/(\d+)\s*$', final, re.I | re.M)
    return status, (status == 206 and len(ranges) == 1 and
                    tuple(map(int, ranges[0][:2])) == (0, amount-1) and int(ranges[0][2]) >= amount)


def rss_kib(pid):
    try:
        return int((Path('/proc')/str(pid)/'statm').read_text().split()[1])*os.sysconf('SC_PAGE_SIZE')/1024
    except (OSError, ValueError, IndexError):
        return 0


def probe(b, c, source, amount, deadline=None):
    started = time.monotonic()
    deadline = started+ATTEMPT_SECONDS if deadline is None else deadline
    result = dict(source=source, requested_bytes=amount, actual_bytes=0, success=False,
                  status='not_started', http=0, curl=None, reason='', limited_until=0)
    usage0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu0 = time.process_time()
    own_peak, curl_peak = rss_kib(os.getpid()), 0
    proc = None
    try:
        # Includes preflight in the 200-second shared attempt deadline.
        guard = b.preflight(c, deadline=deadline)
        if b.STOP.is_set() or time.monotonic() >= deadline:
            raise b.Error('预检后取消或超时；未发起下载')
        template, mode = SOURCES[source]
        url = template.format(amount=amount)
        with tempfile.TemporaryDirectory(prefix='tb-source-probe-') as tmp:
            header, error = Path(tmp)/'headers', Path(tmp)/'stderr'
            cmd = ['curl', '-q', '--silent', '--show-error', '--fail', '--noproxy', '*',
                   '--proto', '=https', '--http1.1', '--interface', c['interface'],
                   '--limit-rate', str(max(1, int(b.effective_speed(c)*1000000/8))),
                   '--connect-timeout', '5', '--speed-limit', '1', '--speed-time', '5',
                   '--max-time', str(max(.01, deadline-time.monotonic())),
                   '--max-filesize', str(amount), '--dump-header', str(header)]
            if mode == 'range':
                cmd += ['--range', f'0-{amount-1}']
            cmd += [url]
            with error.open('wb') as err:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err,
                                        env={**os.environ, 'LC_ALL': 'C'})
                result['status'] = 'running'
                tick, kill_at = time.monotonic()+3, None
                with selectors.DefaultSelector() as sel:
                    sel.register(proc.stdout, selectors.EVENT_READ)
                    while sel.get_map():
                        for key, _ in sel.select(.2):
                            chunk = os.read(key.fileobj.fileno(), 65536)
                            if not chunk:
                                sel.unregister(key.fileobj)
                            else:
                                result['actual_bytes'] += len(chunk)
                        now = time.monotonic()
                        own_peak = max(own_peak, rss_kib(os.getpid()))
                        curl_peak = max(curl_peak, rss_kib(proc.pid))
                        if not result['reason']:
                            if result['actual_bytes'] > amount:
                                result['reason'] = '来源超出请求范围，停止并记录全部已接收正文'
                            elif b.STOP.is_set():
                                result['reason'] = '用户中断，停止测试'
                            elif now >= deadline:
                                result['reason'] = '200 秒时限到达'
                            elif header.exists() and header.stat().st_size > 65536:
                                result['reason'] = '响应头异常过大'
                            elif now >= tick:
                                try:
                                    if guard.check():
                                        result['reason'] = guard.reason
                                except b.Error as e:
                                    result['reason'] = str(e)
                                tick = now+3
                        if result['reason'] and proc.poll() is None:
                            if kill_at is None:
                                proc.terminate(); kill_at = now+2
                            elif now >= kill_at:
                                proc.kill()
                result['curl'] = proc.wait(timeout=3)
                proc.stdout.close()
            headers = header.read_bytes()[:65537].decode('iso-8859-1') if header.exists() else ''
            status, valid = response_ok(headers, mode, amount)
            result['http'] = status
            until = b.retry_after(headers, time.time())
            if status in (429, 503) or until > time.time():
                result['limited_until'] = max(until, int(time.time())+60)
                result['reason'] = '服务限流；结束整次测试，不切源绕过'
            result['success'] = (result['curl'] == 0 and valid and
                                 result['actual_bytes'] == amount and not result['reason'])
            result['status'] = 'passed' if result['success'] else 'failed'
            if not result['reason'] and not result['success']:
                result['reason'] = ('HTTP/长度或范围校验失败；'+
                                    error.read_bytes()[:500].decode('utf-8', errors='replace'))
    except (b.Error, OSError, subprocess.TimeoutExpired) as e:
        result['reason'] = str(e)
        result['status'] = 'protected_or_error'
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.kill(); proc.wait()
            if proc.stdout and not proc.stdout.closed:
                proc.stdout.close()
        seconds = time.monotonic()-started
        usage1 = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu = time.process_time()-cpu0 + usage1.ru_utime-usage0.ru_utime + usage1.ru_stime-usage0.ru_stime
        result.update(elapsed_seconds=round(seconds, 3),
                      average_mbps=round(result['actual_bytes']*8/max(seconds,.001)/1000000, 3),
                      cpu_one_core_percent=round(cpu/max(seconds,.001)*100, 2),
                      tester_peak_rss_kib=round(own_peak), curl_peak_sampled_rss_kib=round(curl_peak))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script', type=Path, default=Path(__file__).resolve().parents[1]/'traffic_balance.py')
    parser.add_argument('--bandwidth-mbps', type=positive, required=True, help='必须先向用户确认，不得猜测')
    parser.add_argument('--full', action='store_true', help='初筛通过后，追加384 MiB验证；总预算1 GiB，最多两家完整验证')
    parser.add_argument('--output', type=Path, required=True, help='新的报告路径，不覆盖已有文件')
    args = parser.parse_args()
    if not Path('/proc/stat').exists() or not shutil.which('curl') or not shutil.which('ip'):
        parser.error('需要 Linux、Python 3.8+、curl、iproute2；本脚本不会安装依赖')
    spec = importlib.util.spec_from_file_location('balance_probe_guard', args.script)
    b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
    # Limit 80 Mbps while preserving the existing 40% download-share cap.
    speed = min(80, args.bandwidth_mbps*.4)
    c = dict(b.DEFAULT, interface=b.detect_interface(), bandwidth_mbps=args.bandwidth_mbps,
             download_percent=speed/args.bandwidth_mbps*100)
    b.STOP.clear()
    report = dict(schema=2, started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  hostname=os.uname().nodename, bandwidth_mbps=args.bandwidth_mbps,
                  effective_limit_mbps=b.effective_speed(c), module_sha256=hashlib.sha256(args.script.read_bytes()).hexdigest(),
                  scope='source_probe_only; no install, state modification, or online update', results=[],
                  short_term_candidates=[], round_384mib_candidates=[], limitations=[
                      '平均速度包含5秒预检；CPU百分比按一个核计算，非全机繁忙率',
                      'RSS为采样峰值；不代表所有区域或长期稳定性；不验证真实业务延迟',
                      '总预算1 GiB正文；异常在途/缓冲字节可能超额，仍如实报告'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents accidentally overwriting earlier evidence.
    with args.output.open('x') as output:
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            for sig in previous:
                signal.signal(sig, lambda *_: b.STOP.set())
            halted = False
            for source in SOURCES:
                passed = 0
                for attempt in range(3):
                    if b.STOP.is_set():
                        halted = True; break
                    item = probe(b, c, source, 8*MIB)
                    item.update(phase='small', attempt=attempt+1)
                    report['results'].append(item)
                    print(json.dumps(item, ensure_ascii=False), flush=True)
                    if item['limited_until'] or item['status'] == 'protected_or_error' or '[下载保护]' in item['reason']:
                        halted = True; break
                    if not item['success']:
                        break
                    passed += 1
                    if b.STOP.wait(10):
                        halted = True; break
                if passed == 3:
                    report['short_term_candidates'].append(source)
                if halted: break
            if args.full and not halted:
                for source in report['short_term_candidates']:
                    if b.STOP.is_set(): break
                    if FULL_BYTES*8/(speed*1000000) > ATTEMPT_SECONDS-5:
                        report['results'].append(dict(source=source, phase='full', status='skipped',
                            reason='安全限速不足以在200秒内完成384 MiB，不能据此判定来源故障'))
                        continue
                    consumed = sum(x.get('actual_bytes',0) for x in report['results'])
                    if consumed+FULL_BYTES > TOTAL_LIMIT:
                        report['results'].append(dict(source=source, phase='full', status='skipped',
                            reason='剩余测试总预算不足384 MiB'))
                        continue
                    item = probe(b, c, source, FULL_BYTES)
                    item['phase'] = 'full'
                    report['results'].append(item)
                    print(json.dumps(item, ensure_ascii=False), flush=True)
                    if item['success']: report['round_384mib_candidates'].append(source)
                    if item['limited_until'] or item['status'] == 'protected_or_error' or '[下载保护]' in item['reason']:
                        halted = True; break
                    if not item['success']:
                        report['full_stopped_after_failure'] = source
                        break
                    if b.STOP.wait(10): break
        finally:
            for sig, handler in previous.items(): signal.signal(sig, handler)
            report['halted_by_limit_or_protection'] = halted
            report['interrupted'] = b.STOP.is_set()
            report['actual_total_bytes'] = sum(x.get('actual_bytes',0) for x in report['results'])
            json.dump(report, output, ensure_ascii=False, indent=2)
            output.write('\n'); output.flush(); os.fsync(output.fileno())
    print('报告已保存：'+str(args.output))
    passed = bool(report['round_384mib_candidates'] or (not args.full and report['short_term_candidates']))
    return 0 if passed and not report['interrupted'] and not halted else 1


if __name__ == '__main__':
    raise SystemExit(main())

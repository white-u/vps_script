#!/usr/bin/env python3
"""独立的 Debian/Ubuntu 每日入站流量调节器。仅使用 Python 标准库。"""
import argparse
import contextlib
import datetime as dt
import decimal
import email.utils
import fcntl
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import os
from pathlib import Path
import random
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import time

MIB = 1024 ** 2
BASE = Path('/etc/traffic-balance')
CONFIG = BASE / 'config.json'
VNSTAT_CONFIG = Path('/etc/vnstat.conf')
STATE = BASE / 'state.json'
SCRIPT = Path('/usr/local/bin/traffic-balance')
SHORTCUT = Path('/usr/local/bin/tb')
UNIT = Path('/etc/systemd/system/traffic-balance.service')
LOCK = Path('/run/traffic-balance.lock')
LOG = Path('/var/log/traffic-balance.log')
# Only small HTTP metadata is temporary; all payload stays in a pipe. /run is
# memory-backed on the supported systemd systems. Non-Linux path is for tests.
HEADER_DIR = '/run' if sys.platform.startswith('linux') else tempfile.gettempdir()
SERVICE = 'traffic-balance.service'
SOURCES = ['cloudflare', 'ovh', 'hetzner']
STOP = threading.Event()
logger = logging.getLogger('traffic-balance')
CPU_LIMIT = 70
START_BANDWIDTH_PERCENT = 40
BANDWIDTH_LIMIT_PERCENT = 80
DOWNLOAD_CHECK_SECONDS = 3
ROUND_SECONDS = 300
DEFAULT = dict(version=3, interface='', ratio=2.1,
               daily_mib=10240, interval_min=20, interval_max=60, speed_mbps=80,
               max_attempts=100, round_mib=512, min_tx_mib=200,
               bandwidth_mbps=0, download_percent=40, load_per_cpu=0.8)


class Error(Exception):
    pass


class PersistenceError(Error):
    pass


class DownloadNotStarted(Error):
    pass


class Cancelled(Exception):
    pass


def run(*args, timeout=30):
    if args[0] == 'vnstat':
        args = (args[0], '--config', str(VNSTAT_CONFIG), *args[1:])
    try:
        p = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, check=False,
                           env={**os.environ, 'LC_ALL': 'C', 'HOME': '/root'})
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Error(f'{args[0]} 执行失败：{e}') from e
    if p.returncode:
        raise Error(f'{args[0]} 返回 {p.returncode}：{(p.stderr.strip() or p.stdout.strip())[:500]}')
    return p.stdout


def load_json(path):
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError('不是普通文件或文件缺失')
        with path.open() as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError('必须为 JSON 对象')
        return data
    except (OSError, ValueError) as e:
        raise Error(f'{path} 无法读取：{e}；拒绝本次操作，请先停止任务再检查文件，禁止直接清零额度') from e


def atomic_json(path, data):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + '\n', 0o600)


def atomic_write(path, text, mode):
    """先 fsync 文件，再替换并 fsync 目录；失败绝不继续下载。"""
    name = None
    try:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise OSError('目标不是普通文件')
        fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=str(path.parent))
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), mode)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as e:
        raise PersistenceError(f'{path} 保存失败：{e}；已停止补量，请修复存储或权限后手动启动') from e
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


@contextlib.contextmanager
def locked(path=None):
    path = LOCK if path is None else path
    with path.open('a') as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise Error('已有实例或管理操作正在运行；未启动新实例，无需重复操作') from e
        yield


def number(value, low, high, name, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise Error(f'{name} 必须为有限数值')
    if not low <= value <= high or (integer and type(value) is not int):
        raise Error(f'{name} 有效范围 {low}～{high}' + ('，必须为整数' if integer else ''))
    return value


def validate_config(c, legacy=False):
    version = c.get('version')
    if not legacy and version in (1, 2):
        raise Error('旧版配置需要确认新设置；请选 1「配置任务」或 2「启动任务」进入向导，当天额度保留')
    keys = set(DEFAULT)
    if legacy:
        keys = (keys-{'download_percent'}) | {'bandwidth_percent'}
        if version == 1:
            keys = (keys-{'ratio'}) | {'ratio_low', 'ratio_high'}
    if set(c) != keys or version not in ((1, 2) if legacy else (3,)):
        raise Error('配置字段缺失或版本不支持；未使用默认值补齐，请检查 config.json')
    if not isinstance(c['interface'], str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', c['interface']):
        raise Error('自动识别的公网网卡名称无效；请重新配置并检查服务器网络')
    if legacy and version == 1:
        number(c['ratio_low'], .01, 1000, '旧比例下限')
        number(c['ratio_high'], .01, 1000, '旧比例上限')
        if c['ratio_low'] >= c['ratio_high']:
            raise Error('旧配置比例区间无效；请检查 config.json')
    else:
        number(c['ratio'], 2, 5, '出站:入站目标比例')
    for key, lo, hi, integer in [
        ('daily_mib', 1, 1048576, False), ('interval_min', 1, 1440, True),
        ('interval_max', 1, 1440, True), ('speed_mbps', .001, 10000, False),
        ('max_attempts', 1, 10000, True), ('round_mib', .001, 102400, False),
        ('min_tx_mib', 0, 1048576, False), ('bandwidth_mbps', 0 if legacy and version == 1 else .001, 1000000, False),
        ('bandwidth_percent' if legacy else 'download_percent', 1, 100, False),
        ('load_per_cpu', .01, 100, False),
    ]:
        number(c[key], lo, hi, key, integer)
    if c['interval_min'] > c['interval_max']:
        raise Error('检查间隔下限不能超过上限；未保存')
    return c


def config_for_edit():
    if not CONFIG.exists():
        if STATE.exists():
            state = validate_state(load_json(STATE))
            if state['date'] or state['last'] or state['pending']:
                raise Error('配置文件丢失但已有流量账本；拒绝重新识别并覆盖配置，请先停止任务并恢复可信 config.json，额度未清零')
        return DEFAULT.copy()
    old = load_json(CONFIG)
    if old.get('version') not in (1, 2):
        return validate_config(old)
    validate_config(old, legacy=True)
    if old['version'] == 1:
        print(f"旧设置使用入站/出站区间 {old['ratio_low']:g}～{old['ratio_high']:g}，请确认新的出站:入站目标。")
    print('新版补下载带宽占比默认 40%，总带宽保护线固定 80%；请核对汇总，保存前不转换，当天额度和次数保留。')
    return dict(DEFAULT, **{k: v for k, v in old.items() if k in DEFAULT and k != 'version'})


def initial_state():
    return dict(version=1, mode='stopped', date='', used=0, attempts=0,
                pending=None, barrier=None, last=None, next_check=0,
                cooldown=0, reason='尚未启动', source_order=[], source_index=0)


def validate_state(s):
    if set(s) != set(initial_state()) or s['version'] != 1:
        raise Error('状态字段缺失或版本不支持；暂停补量，请修复 state.json，禁止清零继续')
    if s['mode'] not in ('running', 'paused', 'stopped') or not isinstance(s['reason'], str):
        raise Error('任务状态损坏；暂停补量，请检查 state.json')
    if not isinstance(s['date'], str):
        raise Error('状态日期不是字符串；暂停补量，请检查 state.json')
    if s['date']:
        try:
            dt.date.fromisoformat(s['date'])
        except (ValueError, TypeError) as e:
            raise Error('状态日期损坏；暂停补量，请检查 state.json') from e
    for k in ('used', 'attempts', 'next_check', 'cooldown', 'source_index'):
        number(s[k], 0, 10**18, k, True)
    if (not isinstance(s['source_order'], list) or
            (s['source_order'] and (not all(isinstance(x, str) for x in s['source_order']) or
                                    sorted(s['source_order']) != sorted(SOURCES)))):
        raise Error('下载源轮换状态损坏；暂停补量，请检查 state.json')
    for key in ('pending', 'barrier', 'last'):
        v = s[key]
        if v is None:
            continue
        expected = {'amount', 'started', 'total_rx'} if key == 'pending' else (
            {'after', 'total_rx'} if key == 'barrier' else {'updated', 'rx', 'tx', 'total_rx', 'total_tx', 'created'})
        if not isinstance(v, dict) or set(v) != expected:
            raise Error(f'{key} 状态损坏；暂停补量，请检查 state.json')
        for n in v.values():
            number(n, 0, 10**18, key, True)
    if (bool(s['date']) != (s['last'] is not None) or
            (not s['date'] and (s['used'] or s['attempts'] or s['pending'] or s['barrier'])) or
            (s['pending'] and (s['used'] < s['pending']['amount'] or s['attempts'] == 0))):
        raise Error('状态账本不一致；暂停补量，请检查 state.json，禁止清零继续')
    return s


def vn_settings():
    text = run('vnstat', '--showconfig')
    result = {}
    for key in ('UseUTC', 'SaveInterval'):
        m = re.search(r'^\s*;?\s*' + key + r'\s+(\d+)\s*(?:#.*)?$', text, re.M)
        if m:
            result[key] = int(m.group(1))
    # Older vnStat 2.x releases do not expose UseUTC and use local dates.
    result.setdefault('UseUTC', 0)
    if result['UseUTC'] not in (0, 1) or not 1 <= result.get('SaveInterval', 0) <= 60:
        raise Error('无法确认 vnStat 保存间隔或时区；暂停本轮，请检查 vnstat --showconfig')
    return result


def date_now(settings, now=None):
    stamp = time.time() if now is None else now
    return (dt.datetime.fromtimestamp(stamp, dt.timezone.utc) if settings['UseUTC']
            else dt.datetime.fromtimestamp(stamp)).date().isoformat()


def vn_timestamp(value, settings, updated=False):
    if 'timestamp' in value:
        return number(value['timestamp'], 0, 10**18, 'vnStat 时间戳', True)
    # vnStat < 2.10 only emits calendar fields. Minute resolution is rounded
    # down, so a coverage barrier is released only by a later whole minute.
    d = value['date']
    t = value['time'] if updated else dict(hour=0, minute=0)
    fields = [d['year'], d['month'], d['day'], t['hour'], t['minute']]
    if not all(type(n) is int for n in fields):
        raise ValueError('vnStat 日期或时间字段不是整数')
    date = dt.datetime(*fields)
    if settings['UseUTC']:
        return int(date.replace(tzinfo=dt.timezone.utc).timestamp())
    return int(date.timestamp())


def parse_stats(raw, interface, settings, now):
    try:
        j = json.loads(raw)
        if str(j['jsonversion']) != '2' or not str(j['vnstatversion']).startswith('2.'):
            raise ValueError('仅支持 vnStat 2.x JSON API 2')
        matches = [i for i in j['interfaces'] if i['name'] == interface]
        if len(matches) != 1:
            raise ValueError('网卡统计缺失或重复')
        i = matches[0]
        updated = vn_timestamp(i['updated'], settings, updated=True)
        created = vn_timestamp(i['created'], settings)
        today = date_now(settings, now)
        entries = [d for d in i['traffic']['day']
                   if '%04d-%02d-%02d' % (d['date']['year'], d['date']['month'], d['date']['day']) == today]
        if len(entries) != 1:
            raise ValueError('当天统计尚未就绪')
        d = entries[0]
        total = i['traffic']['total']
        v = dict(updated=updated, rx=d['rx'], tx=d['tx'], total_rx=total['rx'],
                 total_tx=total['tx'], created=created)
        for n in v.values():
            number(n, 0, 10**18, 'vnStat 计数', True)
        age = now - updated
        if age < 0 or age > settings['SaveInterval'] * 60 + 120:
            raise ValueError('统计时间在未来或已过旧')
        if date_now(settings, updated) != today or created > updated:
            raise ValueError('统计日期未切换或创建时间异常')
        created_date = date_now(settings, created)
        if created_date >= today:
            raise ValueError('网卡数据库今天才建立，首日统计不完整，等待下一个完整日期')
        if total['rx'] < d['rx'] or total['tx'] < d['tx']:
            raise ValueError('累计计数小于当天计数')
        return today, v
    except (ValueError, TypeError, KeyError, Error) as e:
        raise Error(f'vnStat 统计异常：{e}；暂停本轮，将在下次检查重试，请检查 vnstat 服务与网卡') from e


def stats(c, settings):
    return parse_stats(run('vnstat', '-i', c['interface'], '--json', 'd', '2'),
                       c['interface'], settings, time.time())


def observe(s, date, v):
    """只由可信 vnStat 日期重置额度；同日回退、数据库更换均拒绝。"""
    if s['date'] and date < s['date']:
        raise Error('统计日期倒退；暂停补量，请检查系统时钟')
    last = s['last']
    if last:
        if v['created'] != last['created'] or v['updated'] < last['updated'] or any(
                v[k] < last[k] for k in ('total_rx', 'total_tx')):
            raise Error('vnStat 数据库重建或累计计数回退；暂停补量，请核查数据库')
        if date == s['date'] and (v['rx'] < last['rx'] or v['tx'] < last['tx']):
            raise Error('当天流量计数回退；暂停补量，请核查 vnStat')
    if s['date'] != date:
        s.update(date=date, used=0, attempts=0, barrier=None)
    s['last'] = v
    b = s['barrier']
    if b and v['updated'] > b['after'] and v['total_rx'] >= b['total_rx']:
        s['barrier'] = None


def recover(s):
    if s['pending']:
        p = s['pending']
        s['barrier'] = dict(after=p['started'] + ROUND_SECONDS, total_rx=p['total_rx'])
        s['pending'] = None
        s['reason'] = '检测到未结算下载，预留额度已保守计入；等待统计更新'
        logger.warning(s['reason'])


def target_reached(c, rx, tx):
    return decimal.Decimal(rx)*decimal.Decimal(str(c['ratio'])) >= tx


def plan(c, s, v):
    if s['barrier']:
        return 0, '等待 vnStat 采样覆盖上轮下载'
    if time.time() < s['cooldown']:
        return 0, '测速服务限流，遵守 Retry-After 等待，不切源绕过'
    if s['used'] >= int(c['daily_mib'] * MIB) or s['attempts'] >= c['max_attempts']:
        return 0, '已达每日额度或次数限制，等待下一统计日'
    if v['tx'] < c['min_tx_mib'] * MIB or v['tx'] == 0:
        return 0, '出站流量未达到起补门槛'
    if target_reached(c, v['rx'], v['tx']):
        return 0, '出站/入站比例未超过目标，无需补量'
    required_rx = (decimal.Decimal(v['tx'])/decimal.Decimal(str(c['ratio']))).to_integral_value(
        rounding=decimal.ROUND_CEILING)
    amount = min(int(required_rx)-v['rx'], int(c['round_mib'] * MIB),
                 int(c['daily_mib'] * MIB) - s['used'])
    return amount, '准备按比例缺口补量'


def reserve(s, amount, v):
    s['used'] += amount
    s['attempts'] += 1
    baseline = s['barrier']['total_rx'] if s['barrier'] else v['total_rx']
    s['pending'] = dict(amount=amount, started=int(time.time()), total_rx=baseline)
    s['reason'] = '下载中，额度已预留'


def settle(s, actual):
    p = s['pending']
    s['used'] += actual - p['amount']
    s['pending'] = None
    s['barrier'] = dict(after=int(time.time()), total_rx=p['total_rx'] + actual)


def counters(interface):
    base = Path('/sys/class/net') / interface / 'statistics'
    try:
        return tuple(int((base / n).read_text().strip()) for n in ('rx_bytes', 'tx_bytes'))
    except (OSError, ValueError) as e:
        raise Error(f'无法读取网卡实时计数：{e}；终止本轮，请检查公网网卡') from e


def effective_speed(c):
    # A fixed rate for this round, never a dynamic ramp or an attempt to catch up.
    allowance = c['bandwidth_mbps'] * c['download_percent']/100
    return min(c['speed_mbps'], allowance)


def cpu_times():
    try:
        with Path('/proc/stat').open() as f:
            values = [int(v) for v in f.readline().split()[1:9]]
        if len(values) < 4 or min(values) < 0:
            raise ValueError('CPU 计数格式异常')
        # guest is already part of user/nice; iowait and steal count as pressure.
        return sum(values), values[3]
    except (OSError, ValueError) as e:
        raise Error(f'无法读取实时 CPU 压力：{e}；跳过补量，请检查系统统计') from e


def short_number(value):
    return f'{value:.2f}'.rstrip('0').rstrip('.')


def over_limit(label, value, threshold, unit=''):
    actual, limit = short_number(value), short_number(threshold)
    # Keep tiny genuine overruns distinguishable after display rounding.
    if actual == limit and value != threshold:
        actual, limit = repr(value), repr(threshold)
    if unit == '%':
        return f'{label} {actual}% > {limit}%'
    return f'{label} {actual} > {limit}'+(f' {unit}' if unit else '')


class Guard:
    def __init__(self, c):
        self.c = c
        self.last = counters(c['interface'])
        self.start_rx = self.last[0]
        self.received = 0
        self.cpu_last = cpu_times()
        self.at = time.monotonic()
        self.reason = ''
        load1 = os.getloadavg()[0]
        cpus = os.cpu_count() or 1
        load = load1/cpus
        if load > c['load_per_cpu']:
            raise Error('[启动保护] '+over_limit('每核负载', load, c['load_per_cpu'])
                        +' → 跳过本轮')

    def check(self, before_download=False):
        now = time.monotonic()
        current = counters(self.c['interface'])
        delta = [a - b for a, b in zip(current, self.last)]
        cpu = cpu_times()
        cpu_delta = cpu[0] - self.cpu_last[0]
        idle_delta = cpu[1] - self.cpu_last[1]
        if min(delta) < 0 or now <= self.at or cpu_delta <= 0 or not 0 <= idle_delta <= cpu_delta:
            raise Error('实时网卡或 CPU 计数异常；终止本轮，请检查系统统计')
        seconds = now-self.at
        rx_rate, tx_rate = (n*8/seconds/1000000 for n in delta)
        rate = max(rx_rate, tx_rate)
        cpu_busy = 1-idle_delta/cpu_delta
        load1 = os.getloadavg()[0]
        cpus = os.cpu_count() or 1
        load = load1/cpus
        causes = []
        if cpu_busy > CPU_LIMIT/100:
            causes.append(over_limit('CPU', cpu_busy*100, CPU_LIMIT, '%'))
        if load > self.c['load_per_cpu']:
            causes.append(over_limit('每核负载', load, self.c['load_per_cpu']))
        line = self.c['bandwidth_mbps']*BANDWIDTH_LIMIT_PERCENT/100
        if before_download:
            start_line = self.c['bandwidth_mbps']*START_BANDWIDTH_PERCENT/100
            if rate >= start_line:
                causes.append(f'当前占用 {short_number(rate)} >= {short_number(start_line)} Mbps')
            # Full duplex: the download increases RX, not TX. No extra reserve.
            projected = max(rx_rate+effective_speed(self.c), tx_rate)
            if projected > line:
                causes.append(over_limit('预计带宽', projected, line, 'Mbps'))
        elif rate > line:
            causes.append(over_limit('带宽', rate, line, 'Mbps'))
        stage = '预检' if before_download else '下载'
        self.reason = (f'[{stage}保护] '+'；'.join(causes)) if causes else ''
        self.received = current[0]-self.start_rx
        self.last, self.cpu_last, self.at = current, cpu, now
        return bool(causes)


def preflight(c, deadline=None):
    guard = Guard(c)
    for _ in range(5):
        remaining = 1 if deadline is None else min(1, deadline-time.monotonic())
        if remaining <= 0:
            raise Error('单轮总时长已达 300 秒；结束预检，不发起新的下载')
        if STOP.wait(remaining):
            raise Error('任务已暂停或停止；尚未发起下载，不计量、不计次')
        if deadline is not None and time.monotonic() >= deadline:
            raise Error('单轮总时长已达 300 秒；结束预检，不发起新的下载')
        if guard.check(before_download=True):
            raise Error(guard.reason+' → 跳过本轮')
    return guard


def wait_fresh_stats(c, s, settings):
    started = int(time.time())
    deadline = time.monotonic() + settings['SaveInterval']*60 + 120
    s['reason'] = '等待 vnStat 产生本次检查之后的新采样，暂不补下载'
    atomic_json(STATE, s)
    while not STOP.is_set():
        day, v = stats(c, settings)
        observe(s, day, v)
        if time.monotonic() >= deadline:
            break
        if v['updated'] > started:
            return day, v
        if STOP.wait(min(5, max(0, deadline-time.monotonic()))):
            break
    if STOP.is_set():
        raise Error('等待统计期间任务已暂停或停止，未发起下载')
    raise Error('等待 vnStat 新采样超时；跳过本轮，请检查 vnStat 服务，不使用旧数据补量')


def retry_after(headers, now):
    values = re.findall(r'^Retry-After:\s*(.*?)\s*$', headers, re.I | re.M)
    if not values:
        return 0
    value = values[-1]
    if value.isdigit():
        return int(now) + int(value)
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            return 0
        return max(0, math.ceil(parsed.timestamp()))
    except (ValueError, TypeError, OverflowError):
        return 0


def curl_command(c, source, amount, seconds):
    url = {'cloudflare': f'https://speed.cloudflare.com/__down?bytes={amount}',
           'ovh': 'https://proof.ovh.net/files/1Gb.dat',
           'hetzner': 'https://fsn1-speed.hetzner.com/1GB.bin'}[source]
    return ['curl', '-q', '--silent', '--show-error', '--no-buffer', '--fail', '--noproxy', '*',
            '--proto', '=https', '--http1.1', '--interface', c['interface'],
            '--limit-rate', str(max(1, int(effective_speed(c) * 1000000 / 8))),
            '--connect-timeout', '5', '--speed-limit', '1', '--speed-time', '5',
            '--max-time', str(seconds), '--max-filesize', str(amount),
            '--range', f'0-{amount - 1}', url]


def download(c, source, amount, settings, day, deadline, guard=None):
    """正文流式计数后丢弃；小型响应头单独放内存临时文件，避免 trailers 混入。"""
    try:
        guard = Guard(c) if guard is None else guard
        header_file = tempfile.NamedTemporaryFile(prefix='traffic-balance-header-', dir=HEADER_DIR)
    except (Error, OSError) as e:
        raise DownloadNotStarted(f'下载尚未发起：{e}；本次不计量、不计次，请检查提示') from e
    with header_file as header:
        seconds = deadline-time.monotonic()
        if seconds <= 0 or STOP.is_set():
            raise DownloadNotStarted('单轮时间已到或任务已暂停/停止；尚未发起下载，本次预留与计次退回')
        cmd = curl_command(c, source, amount, seconds)
        cmd[-1:-1] = ['--dump-header', header.name]
        logger.info('开始下载 source=%s budget=%d fixed_rate=%s Mbps', source, amount, effective_speed(c))
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env={**os.environ, 'LC_ALL': 'C'})
        except OSError as e:
            raise DownloadNotStarted(f'无法启动 curl：{e}；本次不计量、不计次，请检查安装和权限') from e
        actual, errors, reason = 0, bytearray(), ''
        tick = time.monotonic() + DOWNLOAD_CHECK_SECONDS
        kill_at = None
        budget_stop = False
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stdout, selectors.EVENT_READ, 'body')
                sel.register(proc.stderr, selectors.EVENT_READ, 'error')
                while sel.get_map():
                    for key, _ in sel.select(timeout=.2):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            sel.unregister(key.fileobj)
                        elif key.data == 'body':
                            actual += len(chunk)
                        else:
                            if len(errors) + len(chunk) > 65536:
                                reason = '错误输出过长'
                            errors.extend(chunk[:max(0, 65536-len(errors))])
                    now = time.monotonic()
                    if actual > amount:
                        reason = '来源超过请求的下载范围，已终止并计入实际消耗'
                        budget_stop = False
                    if os.fstat(header.fileno()).st_size > 65536:
                        reason = '响应头过长'
                        budget_stop = False
                    if not reason:
                        if STOP.is_set():
                            reason = '任务收到暂停或停止信号'
                        elif now >= deadline:
                            reason = '单轮总时长已达 300 秒'
                        elif date_now(settings) != day:
                            reason = '统计日已切换，终止本轮，不跨午夜追量'
                        elif actual == amount and proc.poll() is None:
                            # Old curl cannot cap unknown-size bodies. Stop at the
                            # budget, drain and account everything already queued.
                            reason = '已达到本轮补量预算，结束下载'
                            budget_stop = True
                        elif now >= tick:
                            try:
                                if guard.check():
                                    reason = guard.reason+' → 停止本轮'
                                    # Record the triggering sample before pipe draining
                                    # or a later HTTP error can replace the end reason.
                                    logger.warning('%s', reason)
                            except (Error, OSError) as e:
                                reason = str(e)
                            tick = now + DOWNLOAD_CHECK_SECONDS
                    if reason and proc.poll() is None:
                        if kill_at is None:
                            proc.terminate()
                            kill_at = now + 2
                        elif now >= kill_at:
                            proc.kill()
            code = proc.wait(timeout=3)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            proc.stdout.close()
            proc.stderr.close()
        header.seek(0)
        text = header.read(65537).decode('iso-8859-1')
    if len(text) > 65536:
        reason, budget_stop = '响应头过长', False
    codes = re.findall(r'^HTTP/\S+\s+(\d{3})', text, re.M)
    http = int(codes[-1]) if codes else 0
    until = retry_after(text, time.time())
    limited = http in (429, 503) or until > time.time()
    if limited:
        until = max(until, int(time.time()) + 60)
        reason, budget_stop = '服务限流；已结束本轮并保存等待时间，不切源绕过', False
    # A deliberate stop after receiving exactly our payload budget is complete;
    # an interrupted/failed transfer or an overrun is never reported as success.
    ok = (200 <= http < 300 and actual == amount and
          ((code == 0 and not reason) or (budget_stop and code in (0, -signal.SIGTERM))))
    reason = ('已完成本轮补量预算' if budget_stop and ok else reason) or (
        '下载成功' if ok else f'下载失败 curl={code} HTTP={http} {bytes(errors[:300]).decode("utf-8", errors="replace").strip()}，已记录实际消耗，下次检查再试')
    logger.info('%s source=%s bytes=%d', reason, source, actual)
    return actual, ok, until if limited else 0, reason


def source_candidates(s):
    if not s['source_order'] or s['source_index'] >= len(SOURCES):
        s['source_order'] = random.sample(SOURCES, len(SOURCES))
        s['source_index'] = 0
    order = s['source_order']
    index = s['source_index']
    s['source_index'] += 1
    return order[index:] + order[:index]


def round_download(c, s, amount, settings, day, save=atomic_json):
    deadline = time.monotonic() + ROUND_SECONDS
    remaining = amount
    observed_rx = s['last']['rx']
    observed_tx = s['last']['tx']
    for source in source_candidates(s):
        if STOP.is_set() or remaining <= 0 or s['attempts'] >= c['max_attempts'] or time.monotonic() >= deadline:
            break
        if date_now(settings, time.time() + 315) != day:
            s['reason'] = '临近统计日边界，不发起可能跨日的下载，等待下一轮'
            break
        # 前置保护检查失败不计次；预留后仅确定未启动时退款，不确定消耗保留预留。
        guard = preflight(c, deadline=deadline)
        observed_rx += guard.received
        if target_reached(c, observed_rx, observed_tx):
            s['reason'] = '预检入站使保守比例达标；不再补下载'
            break
        # Only reduce the original plan. Extra outgoing business traffic must
        # never increase a round or bypass its already checked outbound floor.
        remaining -= guard.received
        if remaining <= 0:
            s['reason'] = '预检入站已覆盖本轮补量；本轮不再下载'
            break
        if STOP.is_set():
            s['reason'] = '预检后任务收到暂停或停止信号；尚未发起下载'
            break
        if time.monotonic() >= deadline:
            s['reason'] = '单轮总时长已达 300 秒；尚未发起新的下载'
            break
        if date_now(settings, time.time() + 315) != day:
            s['reason'] = '临近统计日边界，不发起可能跨日的下载，等待下一轮'
            break
        reserve(s, remaining, s['last'])
        save(STATE, s)
        try:
            actual, ok, until, reason = download(c, source, remaining, settings, day, deadline, guard=guard)
        except DownloadNotStarted as e:
            # Only a positively known pre-process failure can refund a reservation.
            # A crash or any uncertain post-start failure keeps it conservatively.
            s['used'] -= s['pending']['amount']
            s['attempts'] -= 1
            s['pending'] = None
            s['reason'] = str(e)
            save(STATE, s)
            logger.warning(s['reason'])
            break
        settle(s, actual)
        s['cooldown'] = max(s['cooldown'], until)
        s['reason'] = reason
        observed_rx += actual
        reached = target_reached(c, observed_rx, observed_tx)
        if reached and not ok:
            s['reason'] += '；已收到流量使保守比例达标，不再切换备用源'
        save(STATE, s)
        remaining -= actual
        if reached or ok or until or '失败' not in reason:
            break


def schedule(c, s, reason=None):
    s['next_check'] = int(time.time()) + random.randint(c['interval_min'] * 60, c['interval_max'] * 60)
    if reason:
        s['reason'] = reason
    atomic_json(STATE, s)


def daemon():
    with locked():
        c = validate_config(load_json(CONFIG))
        s = validate_state(load_json(STATE))
        recover(s)
        atomic_json(STATE, s)
        if s['mode'] != 'running':
            return
        try:
            verify_interface(c)
            settings = vn_settings()
            day, v = stats(c, settings)
            observe(s, day, v)
            reason = '启动统计检查通过；先随机等待，不集中补跑'
        except Error as e:
            reason = str(e)
            logger.warning(reason)
        schedule(c, s, reason)
        while not STOP.wait(1):
            if s['mode'] != 'running' or time.time() < s['next_check']:
                continue
            try:
                verify_interface(c)
                settings = vn_settings()
                day, v = wait_fresh_stats(c, s, settings)
                amount, s['reason'] = plan(c, s, v)
                atomic_json(STATE, s)
                if amount:
                    round_download(c, s, amount, settings, day)
            except Error as e:
                # 未结算、持久化失败属于安全停机，不能在循环中用内存状态继续。
                if s['pending'] is not None or isinstance(e, PersistenceError):
                    raise
                s['reason'] = str(e)
                logger.warning(s['reason'])
            schedule(c, s)


def platform_check():
    if os.geteuid() != 0:
        raise Error('需要 root 管理系统服务；未修改系统，请使用 sudo python3 traffic_balance.py')
    release = Path('/etc/os-release').read_text()
    if not re.search(r'^ID=["\']?(debian|ubuntu)["\']?$', release, re.M) or not Path('/run/systemd/system').is_dir():
        raise Error('仅支持使用 systemd 的 Debian/Ubuntu；未安装，请在支持的 VPS 上运行')


def service_content():
    return f'''[Unit]
Description=Daily inbound traffic balance
After=network-online.target vnstat.service
Wants=network-online.target vnstat.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 {SCRIPT} --daemon
Restart=no
KillMode=mixed
TimeoutStopSec=15
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={BASE} /var/log /run
[Install]
WantedBy=multi-user.target
'''


def install():
    run('apt-get', 'update', timeout=300)
    run('apt-get', 'install', '-y', 'curl', 'vnstat', 'ca-certificates', 'python3', 'iproute2', timeout=300)
    run('systemctl', 'enable', '--now', 'vnstat.service')
    BASE.mkdir(mode=0o700, exist_ok=True)
    os.chmod(BASE, 0o700)
    # 已有安装须先停服以免更新正在执行的脚本。
    if UNIT.exists():
        run('systemctl', 'stop', SERVICE)
    with locked():
        atomic_write(SCRIPT, Path(__file__).read_text(), 0o755)
        atomic_write(UNIT, service_content(), 0o644)
        # 缺失状态但配置仍在，视为丢失，不能创建零额度状态。
        if not STATE.exists():
            if CONFIG.exists():
                raise Error('配置存在但状态丢失；服务保持停止，请从备份恢复 state.json')
            atomic_json(STATE, initial_state())
        validate_state(load_json(STATE))
    run('systemctl', 'daemon-reload')


def owns_shortcut():
    try:
        return SHORTCUT.is_symlink() and os.readlink(SHORTCUT) == str(SCRIPT)
    except OSError:
        return False


def ensure_shortcut():
    try:
        if owns_shortcut():
            return
        if SHORTCUT.exists() or SHORTCUT.is_symlink():
            print('快捷命令 tb 已被其他程序使用；已保留原文件，请使用 traffic-balance。')
            return
        SHORTCUT.symlink_to(SCRIPT)
    except OSError as e:
        print(f'快捷命令 tb 未创建：{e}；配置已保留，请使用 traffic-balance。')


def ask(label, default=None):
    value = input(label + (f' [{default}]' if default is not None else '') + ': ').strip()
    if value.lower() == 'q':
        raise Cancelled()
    return str(default) if not value and default is not None else value


def amount_input(text):
    match = re.fullmatch(r'(\d+(?:\.\d+)?)\s*(MiB|GiB)', text, re.I)
    if not match:
        raise Error('下载量请输入 MiB 或 GiB，例如 500 MiB、0.5 GiB；未保存')
    return float(match[1]) * (1024 if match[2].lower() == 'gib' else 1)


def yes_no(text):
    if text.lower() in ('y', 'yes', '是'):
        return True
    if text.lower() in ('n', 'no', '否'):
        return False
    raise Error('请输入 y（是）或 n（否），也可回车使用默认值')


def ask_valid(label, default, parse):
    while True:
        try:
            return parse(ask(label, default))
        except (Error, ValueError, OverflowError) as e:
            message = str(e) if isinstance(e, Error) else '请输入有效数字，并使用提示中的单位'
            print(f'输入无效：{message}。请重新输入这一项，或输入 q 取消；尚未保存。')


def ask_number(label, default, low, high, integer=False, suffix=''):
    def parse(text):
        if suffix and text.lower().endswith(suffix.lower()):
            text = text[:-len(suffix)].strip()
        try:
            value = int(text) if integer else float(text)
        except ValueError as e:
            raise Error('请输入整数' if integer else '请输入数字，例如 4 或 0.5') from e
        return number(value, low, high, label, integer)
    return ask_valid(f'{label}（{low}～{high}）', default, parse)


def ask_amount(label, default, low, high):
    def parse(text):
        if re.fullmatch(r'\d+(?:\.\d+)?', text):
            text += ' MiB'
        return number(amount_input(text), low, high, label + ' MiB')
    shown = f'{default/1024:g} GiB' if default >= 1024 else f'{default:g}'
    return ask_valid(f'{label}（MiB，{low}～{high}；也可输入 0.5 GiB）', shown, parse)


def ask_interval(old):
    def parse(text):
        parts = re.split(r'\s*[～~-]\s*|\s+', text.strip())
        if len(parts) != 2:
            raise Error('请输入两个整数分钟，例如 20-60 或 20 60')
        try:
            low, high = map(int, parts)
        except ValueError as e:
            raise Error('检查间隔必须为整数分钟，例如 20-60') from e
        if not 1 <= low <= high <= 1440:
            raise Error('间隔须在 1～1440 分钟内，前一个值不能大于后一个值')
        return low, high
    return ask_valid('多久检查一次？（随机分钟范围）', f"{old['interval_min']}-{old['interval_max']}", parse)


def ask_ratio(default):
    def parse(text):
        match = re.fullmatch(r'(\d+(?:\.\d+)?)\s*(?:[:：]\s*1)?', text.strip())
        if not match:
            raise Error('请输入 2～5 之间的出站/入站比例，例如 2.1 或 2.1:1')
        return number(float(match[1]), 2, 5, '出站/入站比例')
    return ask_valid('出站:入站目标（2～5，支持小数）', f'{default:g}:1', parse)


def detect_interface():
    """Query kernel routes only; no probe packets or public downloads are sent."""
    def query(*args):
        value = json.loads(run('ip', '-j', *args, timeout=5))
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise ValueError('出口路由格式异常')
        return value
    try:
        names = set()
        for family, probes in (('-4', ('1.1.1.1', '8.8.8.8')),
                               ('-6', ('2606:4700:4700::1111', '2001:4860:4860::8888'))):
            defaults = query(family, 'route', 'show', 'table', 'all', 'default')
            if not defaults:
                continue
            if any(route.get('nexthops') for route in defaults):
                raise ValueError('多路径默认出口暂不支持')
            for address in probes:
                routes = query(family, 'route', 'get', address)
                if len(routes) != 1 or routes[0].get('nexthops'):
                    raise ValueError('出口路由不唯一')
                route = routes[0]
                name = route.get('dev', '')
                if (route.get('type', 'unicast') != 'unicast' or name == 'lo'
                        or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', name)):
                    raise ValueError('没有可用的公网出口')
                names.add(name)
        if len(names) != 1:
            raise ValueError('没有默认出口，或 IPv4/IPv6、不同目的地址使用不同网卡')
        name = names.pop()
        links = query('-d', 'link', 'show', 'dev', name)
        if len(links) != 1 or not isinstance(links[0].get('linkinfo', {}), dict):
            raise ValueError('出口网卡信息异常')
        if (len(links) != 1 or links[0].get('ifname') != name
                or links[0].get('link_type') != 'ether'
                or links[0].get('linkinfo', {}).get('info_kind')
                or not {'UP', 'LOWER_UP'} <= set(links[0].get('flags', []))):
            raise ValueError('出口为隧道、桥接等特殊网卡，或网卡尚未就绪')
        counters(name)
        return name
    except (Error, ValueError, TypeError, KeyError) as e:
        if isinstance(e.__cause__, FileNotFoundError):
            raise Error('自动识别需要 iproute2，但未找到 ip；未修改任务，请先运行 sudo apt-get update && sudo apt-get install -y iproute2，再重新配置') from e
        raise Error(f'公网网卡自动识别失败：{e}；不发起下载，请检查默认出口与 iproute2，复杂路由暂不支持') from e


def verify_interface(c):
    if detect_interface() != c['interface']:
        raise Error('自动识别的出口网卡与已有账本网卡不一致；暂停本轮，请检查网络，不自动换网卡或清零额度')


def format_amount(amount):
    return f'{amount / (1024*MIB):.2f} GiB' if amount >= 1024*MIB else f'{amount/MIB:.2f} MiB'


def config_summary(c, start_after=False):
    print('\n请核对本次设置：')
    print(f"  公网网卡：{c['interface']}（自动识别）\n  目标比例：出站 : 入站 = {c['ratio']:g} : 1")
    print(f"  每日最多补：{format_amount(c['daily_mib']*MIB)}；每轮最多 {format_amount(c['round_mib']*MIB)}")
    print(f"  每隔 {c['interval_min']}～{c['interval_max']} 分钟随机检查；限速 {c['speed_mbps']:g} Mbps")
    print(f"  出站达到 {format_amount(c['min_tx_mib']*MIB)} 才考虑补量；每日最多 {c['max_attempts']} 次请求（失败也计次）")
    print(f"  服务器带宽：{c['bandwidth_mbps']:g} Mbps；补下载最多使用 {c['download_percent']:g}%")
    print(f"  实际下载最高速度：{effective_speed(c):g} Mbps（用户限速与带宽占比取较小值）")
    print('  启动条件：当前网卡占用低于服务器带宽的 40%，预计入站和当前出站均不超过 80%。')
    if effective_speed(c) > c['bandwidth_mbps']*BANDWIDTH_LIMIT_PERCENT/100:
        print('  提示：下载速度已超过 80% 带宽保护线，当前设置会跳过下载；请调低下载限速或补下载带宽占比。')
    print(f"  负载保护：1 分钟负载 ÷ CPU 数 > {c['load_per_cpu']:g}")
    print('  CPU 超过 70% 或带宽超过 80% 时保护；下载前观察 5 秒，每秒检查；下载期间每 3 秒检查。')
    print('  上述额度和次数都是安全上限，不是每天必须完成的任务量。')
    print('  出站/入站比例超过目标才补下载；按真实缺口补量，达标后停止补量。')
    print('  保存后将启动任务，先检查统计再随机等待。' if start_after else '  保存后任务保持停止；在菜单选择 2 启动。')
    print('  已有的当天额度和次数会保留。')


def ensure_interface(interface):
    # --dbiflist is absent in vnStat 2.6 (Ubuntu 20.04); use the common JSON API.
    try:
        raw = run('vnstat', '--json', 'd', '1')
    except Error as e:
        print(f'{e}；尝试注册指定网卡，已有数据库不会被覆盖；若失败请检查 vnStat。')
        run('vnstat', '--add', '-i', interface)
        run('systemctl', 'restart', 'vnstat.service')
        return
    try:
        data = json.loads(raw)
        if str(data['jsonversion']) != '2' or not isinstance(data['interfaces'], list):
            raise ValueError('不支持的 JSON 统计格式')
        known = [i['name'] for i in data['interfaces']]
    except (ValueError, TypeError, KeyError) as e:
        raise Error(f'vnStat 网卡列表异常：{e}；未保存配置，请检查数据库') from e
    if interface not in known:
        run('vnstat', '--add', '-i', interface)
        run('systemctl', 'restart', 'vnstat.service')


def configure(start_after=False):
    old = config_for_edit()
    print('\n配置向导：入站是服务器收到的流量，出站是服务器发出的流量。')
    print('回车使用方括号内的值；任何一项输入 q 都可取消，保存前不会修改任务。')
    c = old.copy()
    c['interface'] = detect_interface()
    print(f"第 1 步：已自动识别公网网卡 {c['interface']}，无需选择。")
    print('\n第 2 步：设置出站:入站目标比例。支持小数，例如 2.1:1 表示出站 2.1 GiB 对应入站 1 GiB。')
    print('可输入 2.1 或 2.1:1；出站相对入站过多时才补下载，入站已足够时不补。')
    c['ratio'] = ask_ratio(old['ratio'])
    c['bandwidth_mbps'] = ask_number('服务器带宽 Mbps（必填）', old['bandwidth_mbps'] or None,
                                     .001, 1000000, suffix='Mbps')
    print('\n第 3 步：设置每日额度、检查间隔和速度。不确定时可回车保留默认值。')
    c['daily_mib'] = ask_amount('每天最多额外下载多少', old['daily_mib'], 1, 1048576)
    c['interval_min'], c['interval_max'] = ask_interval(old)
    print('速度使用 Mbps；实际速度还受高级设置的补下载带宽占比限制，默认 40%。')
    c['speed_mbps'] = ask_number('下载限速 Mbps', old['speed_mbps'], .001, 10000, suffix='Mbps')
    advanced = ask_valid('是否修改高级设置？普通使用可直接回车（y/n）', 'n', yes_no)
    if advanced:
        c['download_percent'] = ask_number('补下载带宽占比 %', old['download_percent'], 1, 100)
        c['max_attempts'] = ask_number('每日最多下载请求数（失败、备用源请求也计次）', old['max_attempts'], 1, 10000, True)
        c['round_mib'] = ask_amount('每轮最多补下载多少', old['round_mib'], .001, 102400)
        c['min_tx_mib'] = ask_amount('当天出站达到多少才开始考虑补量', old['min_tx_mib'], 0, 1048576)
        print('负载保护：使用 1 分钟系统负载 ÷ CPU 数，超过阈值时优先保护业务。')
        c['load_per_cpu'] = ask_number('负载保护阈值', old['load_per_cpu'], .01, 100)
    validate_config(c)
    config_summary(c, start_after=start_after)
    if not ask_valid('保存并启动任务？（y/n）' if start_after else '保存以上设置？（y/n）', 'y', yes_no):
        print('已取消保存，原任务保持不变。')
        return False
    validate_config(c)
    verify_interface(c)
    # 所有输入确认有效后才安装、停服、保存；无效输入不会改动任务。
    if not UNIT.exists():
        install()
    else:
        run('systemctl', 'stop', SERVICE)
    print('服务已停止；后续保存失败时也保持停止，请修复后手动启动。')
    with locked():
        s = validate_state(load_json(STATE))
        recover(s)
        if CONFIG.exists() and c['interface'] != old['interface'] and s['date']:
            raise Error('已有统计不能直接换网卡；配置未保存，请先核对原网卡和账本')
        ensure_interface(c['interface'])
        if Path(__file__).resolve() != SCRIPT.resolve():
            atomic_write(SCRIPT, Path(__file__).read_text(), 0o755)
        s['mode'], s['reason'] = 'stopped', '配置已保存；请启动任务'
        atomic_json(STATE, s)
        atomic_json(CONFIG, c)
        ensure_shortcut()
    print('配置已保存。' if start_after else '配置已保存。下一步：在主菜单选择 2「启动任务」。')
    print('如果这是首次建立流量统计，今天会先收集数据，下一个完整统计日再补量。')
    if start_after:
        control('running')
    return True


def start_task():
    if CONFIG.exists():
        c = load_json(CONFIG)
        if c.get('version') == DEFAULT['version']:
            control('running')
            return
        # Only a fully valid old configuration can enter the conversion wizard.
        validate_config(c, legacy=True)
    if STATE.exists():
        s = validate_state(load_json(STATE))
        if s['mode'] == 'running' and run('systemctl', 'show', SERVICE, '-p', 'ActiveState', '--value').strip() == 'active':
            raise Error('任务已运行；阻止重复启动，无需操作')
    print('首次使用或旧配置需要确认设置；完成向导后可直接保存并启动。')
    configure(start_after=True)


def control(mode):
    if mode == 'running':
        validate_config(load_json(CONFIG))
        current = validate_state(load_json(STATE))
        if (run('systemctl', 'show', SERVICE, '-p', 'ActiveState', '--value').strip() == 'active'
                and current['mode'] == 'running'):
            raise Error('任务已运行；阻止重复启动，无需操作')
    # 即使 JSON 已损坏，暂停/停止也必须先终止内存中的工作实例。
    run('systemctl', 'stop', SERVICE)
    run('systemctl', 'disable', SERVICE)
    try:
        with locked():
            s = validate_state(load_json(STATE))
            recover(s)
            s['mode'], s['reason'], s['next_check'] = mode, {'running': '等待启动检查', 'paused': '用户手动暂停', 'stopped': '用户手动停止'}[mode], 0
            atomic_json(STATE, s)
    except (Error, OSError):
        print('任务已停止并关闭开机启动，但设置未完成。请修复提示中的问题后重新启动。')
        raise
    if mode != 'stopped':
        run('systemctl', 'enable', SERVICE)
        if mode == 'running':
            run('systemctl', 'start', SERVICE)
            run('systemctl', 'is-active', SERVICE)
    print({'running': '任务已启动。先检查统计，再随机等待；不会立即集中下载。退出菜单或 SSH 后仍会继续。',
           'paused': '任务已暂停，不再补下载；重启服务器后也保持暂停。选择 3 可继续，已用额度不会清零。',
           'stopped': '任务已停止，已关闭开机启动；配置和已用额度保留。选择 2 可重新启动。'}[mode])


def recent_logs(count):
    print(f'\n最近 {count} 条记录（日志自动轮转，最多保留 3 份）：')
    if not LOG.exists():
        print('暂无日志；首次启动后会开始记录。')
        return
    try:
        from collections import deque
        with LOG.open() as f:
            print(''.join(deque(f, maxlen=count)).rstrip())
    except OSError as e:
        print(f'无法读取日志：{e}；请检查日志文件权限或磁盘。')


def diagnostics():
    print('\n详细运行检查：')
    try:
        print(run('systemctl', 'show', SERVICE, '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result'))
    except Error as e:
        print(f'无法查询后台服务：{e}；请检查系统服务管理器。')
    recent_logs(25)
    print(f'配置文件：{CONFIG}\n状态文件：{STATE}\n完整日志：{LOG}')
    print('若服务启动失败，可运行：sudo journalctl -u traffic-balance.service -n 50 --no-pager')


def status():
    print('\n── 任务概况 ──')
    active = None
    try:
        active = run('systemctl', 'show', SERVICE, '-p', 'ActiveState', '--value').strip()
        if active not in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading', 'maintenance'):
            raise Error(f'后台状态无法识别：{active!r}')
    except Error as e:
        print(f'后台服务：无法确认（{e}）；请查看详细运行检查。')
        active = None
    try:
        c = validate_config(load_json(CONFIG))
        s = validate_state(load_json(STATE))
    except Error as e:
        print(f'配置或记录暂不可用：{e}')
        print('需要处理：若任务仍在运行，请先选 4「停止任务」，再检查或恢复文件。')
        recent_logs(5)
        return
    if s['mode'] == 'paused':
        label, action = '已暂停', '选择 3「继续任务」后恢复；今天的已用额度会保留。'
    elif s['mode'] == 'stopped':
        label, action = '已停止', '选择 2「启动任务」后开始检查。'
    elif active == 'active':
        label = '正在补下载' if s['pending'] else '后台运行中'
        action = '无需操作。脚本会按计划检查，满足条件才下载。'
    else:
        label, action = '后台尚未运行' if active else '后台状态待确认', '请查看详细运行检查；排除错误后选择 2「启动任务」。'
    print(f'当前状态：{label}\n最近情况：{s["reason"]}\n操作提示：{action}')
    print(f"本轮固定限速上限：{effective_speed(c):g} Mbps（用户上限 {c['speed_mbps']:g} Mbps）")
    print(f"\n目标：出站 : 入站 = {c['ratio']:g} : 1；出站/入站超过目标才补下载。")
    try:
        day, v = stats(c, vn_settings())
        print(f"今日流量（{day}，网卡 {c['interface']}）：")
        print(f"  入站 / 收到：{format_amount(v['rx'])}\n  出站 / 发出：{format_amount(v['tx'])}")
        if v['rx']:
            ratio = v['tx']/v['rx']
            meaning = ('已达标或入站已足够，无需补下载' if target_reached(c, v['rx'], v['tx']) else
                       '超过目标，满足额度和保护条件时才会补下载')
            print(f'  当前比例：出站 : 入站 = {ratio:.3f} : 1（{meaning}）')
        elif v['tx']:
            print('  当前比例：暂无入站，无法计算；出站达到门槛且保护允许时按目标缺口补量。')
        else:
            print('  当前比例：暂无流量，暂不能计算，不补下载。')
    except Error as e:
        print(f'今日流量：暂不可用，未按零流量处理。\n  {e}')
    remaining = max(0, int(c['daily_mib']*MIB)-s['used'])
    print(f"\n补下载记录（记账日 {s['date'] or '尚未开始'}）：")
    print(f"  已用 {format_amount(s['used'])} / 上限 {format_amount(c['daily_mib']*MIB)}；剩余 {format_amount(remaining)}")
    if s['pending']:
        print('  已用额度包含当前下载预留；完成后按实际量结算。')
    print(f"  请求次数：{s['attempts']} / {c['max_attempts']}（失败、切换备用源也计次）")
    when = s['next_check']
    if s['mode'] == 'running' and active == 'active':
        if when > time.time():
            stamp = dt.datetime.fromtimestamp(when).astimezone().strftime('%m-%d %H:%M:%S %Z')
            minutes = max(1, math.ceil((when-time.time())/60))
            print(f'下次检查：{stamp}（约 {minutes} 分钟后；检查不一定下载）')
        else:
            print('下次检查：正在检查或等待服务完成启动。')
    else:
        print('下次检查：暂无，任务恢复运行后才会安排。')
    recent_logs(5)


def uninstall():
    if ask('卸载将删除本任务配置、额度状态和日志；保留 vnStat 及其数据库。输入 DELETE 确认') != 'DELETE':
        print('未卸载，任务状态保持。')
        return False
    run('systemctl', 'disable', '--now', SERVICE)
    with locked():
        if owns_shortcut():
            SHORTCUT.unlink()
        for path in (CONFIG, STATE, SCRIPT, UNIT, LOG, Path(str(LOG) + '.1'), Path(str(LOG) + '.2')):
            path.unlink(missing_ok=True)
        if BASE.exists():
            BASE.rmdir()
    run('systemctl', 'daemon-reload')
    print('已卸载本任务；vnStat 及其数据库保留。')
    return True


def menu():
    print('每日流量调节：只在入站比例偏低时，限速、限额补下载。')
    print('首次使用可直接选 2，完成必要设置后保存并启动；选 1 只配置。默认每 20～60 分钟检查一次。')
    print('按当天比例缺口决定补多少；额度是上限，比例达标就不再发起下载。')
    print('业务繁忙时会让路；应用层限速可能短时突发，不能保证避免服务商 QoS。')
    while True:
        try:
            pause_label = '暂停 / 继续任务'
            task_status = '尚未配置'
            try:
                mode = validate_state(load_json(STATE))['mode']
                if mode == 'running':
                    active = run('systemctl', 'show', SERVICE, '-p', 'ActiveState', '--value').strip()
                    task_status = '后台运行中' if active == 'active' else '后台尚未运行，请查看状态与日志'
                    pause_label = '暂停任务（稍后可继续）'
                else:
                    task_status = '已暂停' if mode == 'paused' else '已停止'
                    pause_label = '继续任务（保留今天额度）' if mode == 'paused' else '暂停 / 继续任务（启动后可用）'
            except Error as e:
                if STATE.exists() or CONFIG.exists():
                    task_status = '配置或记录需要检查'
                    print(f'任务记录需要检查：{e}；可选 4 先停止任务，选 5 查看诊断。')
            choice = input(f'\n当前状态：{task_status}\n1. 配置任务（首次设置 / 修改）\n2. 启动任务\n3. {pause_label}\n4. 停止任务（关闭开机启动，保留配置）\n5. 查看状态、日志与运行检查\n6. 卸载（删除本任务配置和记录）\n7. 退出菜单（不影响后台任务）\n选择: ').strip()
            if choice == '1':
                configure()
            elif choice == '2':
                start_task()
            elif choice == '3':
                try:
                    s = validate_state(load_json(STATE))
                except Error:
                    if CONFIG.exists() or STATE.exists() or UNIT.exists():
                        control('paused')
                    else:
                        print('尚未配置任务，请先选择 1。')
                else:
                    if s['mode'] == 'stopped':
                        print('任务已停止。选择 2「启动任务」即可，不需要先暂停或继续。')
                    else:
                        control('running' if s['mode'] == 'paused' else 'paused')
            elif choice == '4':
                control('stopped')
            elif choice == '5':
                if not CONFIG.exists() and not STATE.exists():
                    print('尚未配置任务。先选择 1「配置任务」，保存后再选择 2 启动。')
                else:
                    status()
                    if ask('输入 1 查看详细运行检查，直接回车返回菜单') == '1':
                        diagnostics()
            elif choice == '6':
                if uninstall():
                    return
            elif choice == '7':
                return
            else:
                print('无效选项，请输入 1～7；未修改任务。')
        except Cancelled:
            print('已取消当前操作，尚未保存设置；原任务保持不变。')
        except (Error, ValueError, OSError) as e:
            print(f'操作失败：{e}；未报告成功，请按提示检查后重试。', file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', action='store_true', help='systemd 后台入口，不安装依赖')
    parser.add_argument('--status', action='store_true', help='显示中文状态概况和最近记录')
    parser.add_argument('--diagnose', action='store_true', help='显示服务诊断和详细日志')
    args = parser.parse_args()
    try:
        platform_check()
        os.umask(0o077)
        if args.daemon:
            handler = RotatingFileHandler(LOG, maxBytes=MIB, backupCount=2)
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: STOP.set())
            daemon()
        elif args.diagnose:
            diagnostics()
        elif args.status:
            status()
        else:
            menu()
    except (Error, OSError, ValueError) as e:
        logger.error('%s；安全停止，请检查日志、配置和状态后手动启动', e)
        print(f'{e}；安全停止，请检查后手动启动。', file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print('\n已退出菜单，后台任务保持原状态。')
    return 0


if __name__ == '__main__':
    sys.exit(main())

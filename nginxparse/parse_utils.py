"""Stateless-утилиты: парсинг строк, IP-маски, даты, итерирование по логам."""

import gzip
import ipaddress
import os
import re
import subprocess
import sys
from datetime import datetime

from .constants import LINE_RE, TIME_FMT, TS_RE, WHOIS_FIELDS


def iter_lines(paths):
    if not paths:
        yield from sys.stdin
        return
    for path in paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for name in sorted(files):
                    yield from iter_lines([os.path.join(root, name)])
        else:
            opener = gzip.open if path.endswith('.gz') else open
            try:
                with opener(path, 'rt', errors='replace') as fh:
                    yield from fh
            except OSError:
                pass


def _parse_bytes(s):
    return int(s) if s and s.isdigit() else 0


def parse(line):
    m = LINE_RE.match(line)
    if not m:
        return None
    host = m.group('host')
    request = m.group('request') or m.group('request2') or ''
    parts = request.split()
    if len(parts) >= 2 and parts[0].isalpha() and parts[0].isupper():
        path = parts[1]
    else:
        path = request if request != '-' else '-'
    return {'ip': m.group('ip'), 'host': host, 'path': path, 'ua': m.group('ua'),
            'status': m.group('status'), 'bytes': _parse_bytes(m.group('bytes'))}


def parse_ts(line):
    m = TS_RE.search(line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), TIME_FMT)
    except ValueError:
        return None


def _ipaddr(ip):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def mask16(ip):
    a = _ipaddr(ip)
    if a is None:
        return None
    if isinstance(a, ipaddress.IPv4Address):
        return str(ipaddress.IPv4Address(int(a) & 0xFFFF0000))
    return ':'.join(ip.split(':')[:3]) + '::'


def mask24(ip):
    a = _ipaddr(ip)
    if a is None:
        return None
    if isinstance(a, ipaddress.IPv4Address):
        return str(ipaddress.IPv4Address(int(a) & 0xFFFFFF00))
    return ':'.join(ip.split(':')[:4]) + '::'


def net_address(ip, pfx):
    if pfx:
        try:
            return str(ipaddress.ip_network(f'{ip}/{pfx}', strict=False).network_address)
        except ValueError:
            return ip
    return ip


def fmt_request(host, path):
    return f'{host if host else "-"} {path}'


def in_range(dt, t_from, t_to):
    if dt is None:
        return True
    if t_from and dt < t_from:
        return False
    if t_to and dt > t_to:
        return False
    return True


def parse_dt(s, default_time=None, is_end=False):
    if not s:
        return None
    s = s.strip()
    if re.fullmatch(r'\d{1,2}\.\d{1,2}\.\d{4}', s):
        s = s + ' ' + (default_time or ('23:59:59' if is_end else '00:00:00'))
    m = re.fullmatch(r'(\d{1,2}\.\d{1,2}\.\d{4})(?:[ T](\d{1,2}:\d{2}(?::\d{2})?))?', s)
    if m:
        date, tm = m.group(1), m.group(2) or default_time or ('23:59:59' if is_end else '00:00:00')
        if re.fullmatch(r'\d{1,2}:\d{2}', tm):
            tm += ':00'  # HH:MM без секунд — дополняем, формат ниже требует HH:MM:SS
        try:
            dt = datetime.strptime(f'{date} {tm}', '%d.%m.%Y %H:%M:%S')
        except ValueError as err:
            raise ValueError(f'Некорректная дата: {s!r}. Пример: 19.08.2026 11:11:11') from err
        return dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    try:
        return datetime.strptime(s, TIME_FMT)
    except ValueError as err:
        raise ValueError(f'Некорректная дата: {s!r}. Примеры: '
                         '19.08.2026 11:11:11 или 19/Aug/2026:11:11:11 +0300') from err


def prompt_dt(prompt, default_time=None, is_end=False):
    while True:
        try:
            s = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not s:
            return None
        try:
            return parse_dt(s, default_time=default_time, is_end=is_end)
        except ValueError as e:
            print(e)


def ask_time_range():
    print('Диапазон времени (можно пропустить, нажав Enter):')
    try:
        d_from = input('  Дата от (ДД.ММ.ГГГГ): ').strip()
        if not d_from:
            return None, None
        t_from = input('  Время от (ЧЧ:ММ:СС, Enter = 00:00:00): ').strip() or '00:00:00'
        d_to = input('  Дата до (ДД.ММ.ГГГГ): ').strip()
        if not d_to:
            return None, None
        t_to = input('  Время до (ЧЧ:ММ:СС, Enter = 23:59:59): ').strip() or '23:59:59'
    except (EOFError, KeyboardInterrupt):
        print()
        return None, None
    try:
        return (parse_dt(f'{d_from} {t_from}'), parse_dt(f'{d_to} {t_to}',
                                                          default_time='23:59:59', is_end=True))
    except ValueError as e:
        print(e)
        return None, None


def run_whois(ip):
    try:
        proc = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=30)
        out = proc.stdout
    except FileNotFoundError:
        return '[ошибка] whois не установлен (установите: sudo pacman -S whois)'
    except Exception as e:
        return f'[ошибка] {e}'
    if not out.strip():
        return '[пустой ответ]'
    lines = [ln.strip() for ln in out.splitlines() if WHOIS_FIELDS.match(ln)]
    seen = set()
    res = []
    for ln in lines:
        key = ln.lower()
        if key in seen:
            continue
        seen.add(key)
        res.append(ln)
    return '\n'.join(res) if res else out


def is_access_log(path):
    low = os.path.basename(path).lower()
    return ('access' in low or low.endswith('.gz')) and 'error' not in low and 'access' in low


def expand_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, fs in os.walk(p):
                for f in sorted(fs):
                    full = os.path.join(root, f)
                    if is_access_log(full):
                        files.append(full)
        elif is_access_log(p):
            files.append(p)
    return files

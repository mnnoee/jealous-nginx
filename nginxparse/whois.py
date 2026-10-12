"""Whois-обогащение: кэш, abuse-контакты, CIDR, batch-режим."""

import ipaddress
import json
import os
import re
import subprocess
import time

from .parse_utils import net_address, run_whois

ABUSE_KEYS = ('orgabuseemail', 'abuse-mailbox', 'registrar abuse contact email')
ABUSE_FALLBACK_KEYS = ('e-mail',)

CACHE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.whois_cache.json')
CACHE_TTL = 7 * 24 * 3600
_cache = None


def _load_cache():
    global _cache
    if _cache is None:
        try:
            with open(CACHE_FILE) as f:
                _cache = json.load(f)
        except (OSError, ValueError):
            _cache = {}
    return _cache


def _save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    tmp = CACHE_FILE + '.tmp'
    try:
        with open(tmp, 'w') as f:
            json.dump(cache, f)
        os.replace(tmp, CACHE_FILE)
    except OSError:
        pass


def _do_whois(ip):
    try:
        proc = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=30)
        return proc.stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return ''


def run_whois_raw(ip, use_cache=True, ttl=CACHE_TTL):
    if not use_cache:
        return _do_whois(ip)
    cache = _load_cache()
    entry = cache.get(ip)
    now = time.time()
    if entry and now - entry.get('t', 0) < ttl:
        return entry['out']
    out = _do_whois(ip)
    cache[ip] = {'t': now, 'out': out}
    _save_cache(cache)
    return out


def to_cidr(subnet):
    if not subnet or subnet == 'N/A':
        return subnet
    m = re.match(r'^\s*([0-9a-fA-F:.]+)\s*-\s*([0-9a-fA-F:.]+)\s*$', subnet)
    if m:
        try:
            start = ipaddress.ip_address(m.group(1))
            end = ipaddress.ip_address(m.group(2))
            return ', '.join(str(c) for c in ipaddress.summarize_address_range(start, end))
        except ValueError:
            return subnet
    return subnet


def whois_abuse(ip):
    out = run_whois_raw(ip)
    country = ''
    subnets = []
    abuses = []
    seen = set()
    fallback = []
    for line in out.splitlines():
        m = re.match(r'^\s*([^:]+):\s*(.+)$', line)
        if not m:
            continue
        key = m.group(1).strip().lower()
        val = m.group(2).strip()
        if key == 'country' and not country:
            country = val
        elif key in ('inetnum', 'inet6num', 'cidr'):
            c = to_cidr(val)
            if c and c != 'N/A' and c not in subnets:
                subnets.append(c)
        elif key in ABUSE_KEYS and val not in seen:
            seen.add(val)
            abuses.append(val)
        elif key in ABUSE_FALLBACK_KEYS and val not in fallback:
            fallback.append(val)
    if not abuses:
        abuses = fallback
    return country or 'N/A', ', '.join(subnets) if subnets else 'N/A', abuses or ['N/A']


def run_batch_whois(nets):
    for net in nets:
        ip, pfx = (net.split('/', 1) + [None])[:2]
        target = net_address(ip, pfx)
        print(f'== {net} -> {target} ==')
        print(run_whois(target))
        print()


def print_top_whois(title, counter, limit, w=None):
    import sys
    top = counter.most_common(limit)
    if w is None:
        w = len(str(counter.most_common(1)[0][1])) if counter else 1
    print()
    print(title)
    print('=' * 41)
    for i, (net, cnt) in enumerate(top, 1):
        print(f'  [{i}/{len(top)}] {net} ...', file=sys.stderr, end='\r')
        country, subnet, abuses = whois_abuse(net)
        abuse = ', '.join(abuses)
        print(f'{cnt:>{w}}  {net:<18}  {country:<12}  {abuse:<38}  {subnet}')
    print(file=sys.stderr)
    return top


def whois_hint():
    print()
    print('Для whois по любой сети/IP: python3 -m nginxparse.whois <сеть>')
    print('  например: python3 -m nginxparse.whois 45.148.0.0/16')
    print('  или:      python3 -m nginxparse.whois 45.148.10.0/24 95.108.213.241')
    print('  также:    python3 nginx_log_parser.py --whois 45.148.0.0/16')


def main():
    import sys
    args = sys.argv[1:]
    if args:
        run_batch_whois(args)
        return
    print('Интерактивный whois. Введите сеть/IP (q — выход):')
    while True:
        try:
            cmd = input('whois> ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd or cmd.lower() in ('q', 'quit', 'exit'):
            break
        ip, pfx = (cmd.split('/', 1) + [None])[:2]
        target = net_address(ip, pfx)
        print(f'whois {target} ...')
        print(run_whois(target))
        print('-' * 41)


if __name__ == '__main__':
    main()

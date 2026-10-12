"""Ядро: класс NginxLogParser и функция analyze()."""

from collections import Counter, defaultdict
from datetime import timezone

from .parse_utils import in_range, iter_lines, mask16, mask24, parse, parse_ts


class NginxLogParser:
    def __init__(self):
        self.net16 = Counter()
        self.net24 = Counter()
        self.req16 = defaultdict(Counter)
        self.ua16 = defaultdict(Counter)
        self.paths16 = defaultdict(Counter)
        self.req24 = defaultdict(Counter)
        self.ua24 = defaultdict(Counter)
        self.paths24 = defaultdict(Counter)
        self.hours = Counter()
        self.minutes = Counter()
        self.ua_all = Counter()
        self.chains = defaultdict(list)
        self.status_bytes = defaultdict(list)
        self.status_paths = defaultdict(set)
        self.total = 0


def analyze(paths, t_from=None, t_to=None, proto='all', skip403=False):
    p = NginxLogParser()

    for line in iter_lines(paths):
        dt = parse_ts(line)
        if not in_range(dt, t_from, t_to):
            continue
        rec = parse(line)
        if not rec:
            continue
        if skip403 and rec['status'] == '403':
            continue
        is6 = ':' in rec['ip']
        if proto == 'ipv4' and is6:
            continue
        if proto == 'ipv6' and not is6:
            continue
        m16 = mask16(rec['ip'])
        if m16 is None:
            continue
        p.net16[m16] += 1
        p.req16[m16][(rec['ip'], rec['host'], rec['path'])] += 1
        p.ua16[m16][rec['ua']] += 1
        p.paths16[m16][rec['path']] += 1
        m24 = mask24(rec['ip'])
        if m24 is None:
            continue
        p.net24[m24] += 1
        p.req24[m24][(rec['ip'], rec['host'], rec['path'])] += 1
        p.ua24[m24][rec['ua']] += 1
        p.paths24[m24][rec['path']] += 1
        p.ua_all[rec['ua']] += 1
        if dt is not None:
            p.hours[dt.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)] += 1
            p.minutes[dt.astimezone(timezone.utc).replace(second=0, microsecond=0)] += 1
        p.chains[(rec['ip'], rec['path'])].append((dt, rec['status'], rec['bytes']))
        p.status_bytes[rec['status']].append(rec['bytes'])
        p.status_paths[rec['status']].add(rec['path'])

    p.total = sum(p.net16.values())
    return p

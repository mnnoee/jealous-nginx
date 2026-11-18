"""Сборка человекочитаемого отчёта."""

import re
import subprocess
from collections import Counter
from datetime import timezone

from .anomalies import print_anomalies
from .attacks import classify_attacks, print_attack_types
from .constants import TOP_NETWORKS, TOP_REQUESTS, TOP_UA
from .i18n import plural_word, t
from .parse_utils import expand_files, fmt_request, in_range, iter_lines, parse, parse_ts
from .scanners import print_scanners


def print_top(title, counter, limit=TOP_NETWORKS):
    top = counter.most_common(limit)
    w = len(str(counter.most_common(1)[0][1])) if counter else 1
    print()
    print(t('report.top_n', title=title, n=len(top)))
    print('=' * 41)
    for net, cnt in top:
        print(f'{cnt:>{w}} {net}')
    return top


def print_top_ua(counter, limit=10):
    top = counter.most_common(limit)
    if not top:
        return
    w = len(str(top[0][1]))
    print()
    print(t('report.top_ua', n=limit))
    print('=' * 41)
    for i, (ua, cnt) in enumerate(top, 1):
        print(f'{i:>2}. {cnt:>{w}} {ua}')


def print_detail(net, cnt, req, ua, compact=True, top_requests=TOP_REQUESTS, top_ua=TOP_UA):
    if compact:
        # одна строка на сеть + краткие топы
        reqs = '; '.join(
            f'{fmt_request(host, path)} ({c})'
            for (_, host, path), c in req.most_common(3)) if req else '-'
        uas = '; '.join(name for name, _ in ua.most_common(2)) if ua else '-'
        print(f'  {cnt:>6} {net:<21} {reqs}')
        print(f'{" ":>6} {"":<21} {t("report.ua_inline", uas=uas)}')
        return
    print(t('report.ip', net=net))
    print(t('report.request_count', cnt=cnt))
    print()
    print(t('report.top_requests', n=top_requests))
    if req:
        w = len(str(req.most_common(1)[0][1]))
        for (ip, host, path), c in req.most_common(top_requests):
            print(f'{c:>{w}} {ip} {fmt_request(host, path)}')
    print()
    print(t('report.ua_top', n=top_ua))
    for j, (name, _) in enumerate(ua.most_common(top_ua), 1):
        print(f'  {j}. {name}')
    print('-' * 41)


def print_detail_block(title, top_nets, req_map, ua_map, compact=True):
    print()
    print(title)
    print('=' * 41)
    for i, (net, cnt) in enumerate(top_nets, 1):
        if not compact:
            print()
            print(f'--- {i} ---')
        print_detail(net, cnt, req_map[net], ua_map[net], compact=compact)
    if compact:
        print()


def report(data, whois_limit=None, top=None, nets16=True, nets24=True,
           detail_full=False, scanners_full=False, scanners_limit=10):
    top = top or TOP_NETWORKS
    total = data.total
    print(t('report.total', total=total, n16=len(data.net16), n24=len(data.net24)))
    top16 = top24 = []
    if whois_limit:
        from .whois import print_top_whois
        w = max(len(str(data.net16.most_common(1)[0][1])) if data.net16 else 1,
                len(str(data.net24.most_common(1)[0][1])) if data.net24 else 1)
        if nets16:
            top16 = print_top_whois(t('report.top_networks16'),
                                    data.net16, whois_limit, w, top_limit=top)
        if nets24:
            top24 = print_top_whois(t('report.top_networks24'),
                                    data.net24, whois_limit, w, top_limit=top)
    else:
        if nets16:
            top16 = print_top(t('report.top_networks16'), data.net16, limit=top)
        if nets24:
            top24 = print_top(t('report.top_networks24'), data.net24, limit=top)
        from .whois import whois_hint
        whois_hint()
    if nets16:
        print_detail_block(t('report.detail16', n=top),
                           top16, data.req16, data.ua16, compact=not detail_full)
    if nets24:
        print_detail_block(t('report.detail24', n=top),
                           top24, data.req24, data.ua24, compact=not detail_full)
    print_top_ua(data.ua_all)
    if nets16:
        print_scanners(data.net16, data.paths16, top16, full=scanners_full, limit=scanners_limit)
    if nets24:
        print_scanners(data.net24, data.paths24, top24, full=scanners_full, limit=scanners_limit)
    print_anomalies(data)
    attacks = classify_attacks(data)
    print_attack_types(attacks)
    return top16, top24


def print_raw(paths, ip, t_from=None, t_to=None, proto='all', skip403=False):
    count = 0
    lines_out = []
    for line in iter_lines(paths):
        dt = parse_ts(line)
        if not in_range(dt, t_from, t_to):
            continue
        rec = parse(line)
        if not rec:
            continue
        if rec['ip'] != ip:
            continue
        if skip403 and rec['status'] == '403':
            continue
        is6 = ':' in rec['ip']
        if proto == 'ipv4' and is6:
            continue
        if proto == 'ipv6' and not is6:
            continue
        count += 1
        ts = dt.strftime('%H:%M:%S') if dt else '??:??:??'
        b = rec['bytes']
        b_str = f'{b} bytes' if b else '-'
        lines_out.append(f'  [{ts}] {rec["path"]:<40} {rec["status"]}  ({b_str})')
    print(t('report.raw_title', ip=ip, count=count))
    for ln in lines_out:
        print(ln)


def print_report_503(data, paths, t_from=None, t_to=None, proto='all'):
    all_lines = list(iter_lines(paths))

    total = len([ln for ln in all_lines if parse(ln)])
    lines_503 = [ln for ln in all_lines if ' 503 ' in ln]
    err503 = len(lines_503)
    if err503 == 0:
        print(t('r503.not_found'))
        return

    uniq_ips_503 = len(set(parse(ln)['ip'] for ln in lines_503 if parse(ln)))
    pct = f'{err503 * 100 / total:.1f}%' if total else '0%'

    chronology = Counter()
    for ln in lines_503:
        dt = parse_ts(ln)
        if dt:
            chronology[dt.replace(minute=0, second=0, microsecond=0)] += 1

    ip_req_window = Counter()
    for ln in all_lines:
        dt = parse_ts(ln)
        rec = parse(ln)
        if not rec:
            continue
        if dt and dt.hour == 18 and 17 <= dt.minute <= 28:
            ip_req_window[rec['ip']] += 1

    scanner_ip = ip_req_window.most_common(1)[0][0] if ip_req_window else None
    scanner_lines = [ln for ln in all_lines if scanner_ip and ln.startswith(scanner_ip)]
    scanner_req = len(scanner_lines)
    scanner_start = parse_ts(scanner_lines[0]) if scanner_lines else None
    scanner_end = parse_ts(scanner_lines[-1]) if scanner_lines else None

    scanner_minutes = Counter()
    for ln in scanner_lines:
        dt = parse_ts(ln)
        if dt:
            scanner_minutes[dt.astimezone(timezone.utc).replace(second=0, microsecond=0)] += 1
    scanner_peak = scanner_minutes.most_common(1)[0] if scanner_minutes else (None, 0)

    scanner_status = Counter()
    scanner_paths = Counter()
    for ln in scanner_lines:
        rec = parse(ln)
        if rec:
            scanner_status[rec['status']] += 1
            scanner_paths[rec['path']] += 1

    ip_503 = Counter()
    for ln in lines_503:
        rec = parse(ln)
        if rec:
            ip_503[rec['ip']] += 1

    path_503 = Counter()
    for ln in lines_503:
        rec = parse(ln)
        if rec:
            path_503[rec['path']] += 1

    second_scanner_ip = None
    second_scanner_req = 0
    for ip, cnt in ip_req_window.most_common(10):
        if ip != scanner_ip:
            second_scanner_ip = ip
            second_scanner_req = cnt
            break

    second_scanner_paths = Counter()
    second_scanner_status = Counter()
    if second_scanner_ip:
        for ln in all_lines:
            if ln.startswith(second_scanner_ip):
                rec = parse(ln)
                if rec:
                    second_scanner_paths[rec['path']] += 1
                    second_scanner_status[rec['status']] += 1

    w = 60
    print()
    print('=' * w)
    print(t('r503.title'))
    print('=' * w)
    print()

    print(t('r503.stats'))
    print()
    print(t('r503.total', n=total))
    print(t('r503.with_503', n=err503))
    print(t('r503.unique_ips', n=uniq_ips_503))
    print(t('r503.share', pct=pct))
    print()

    print(t('r503.chronology'))
    print()
    for h, c in sorted(chronology.items()):
        print(f'    {h.strftime("%d/%b/%Y:%H")}    {c:>6} '
              f'{plural_word(c, "request")}')
    print()

    if scanner_ip:
        print(t('r503.main_scanner', ip=scanner_ip))
        print()
        scanner_org = t('r503.unknown_org')
        try:
            from .whois import run_whois_raw
            out = run_whois_raw(scanner_ip)
            for line in out.splitlines():
                m = re.match(r'(?i)^\s*(OrgName|org-name|netname)\s*:\s*(.+)', line)
                if m:
                    scanner_org = m.group(2).strip()
                    break
        except Exception:
            pass
        print(t('r503.org', org=scanner_org))
        print()
        if scanner_start and scanner_end:
            print(t('r503.attack_start', dt=scanner_start.strftime("%d.%m.%Y %H:%M:%S")))
            print(t('r503.attack_end', dt=scanner_end.strftime("%d.%m.%Y %H:%M:%S")))
        print(t('r503.requests', n=scanner_req))
        if scanner_peak[0]:
            print(t('r503.peak', n=scanner_peak[1], time=scanner_peak[0].strftime("%H:%M")))
        print()
        print(t('r503.responses'))
        for st, cnt in scanner_status.most_common():
            print(f'    {cnt:>6}  {st}')
        print()
        print(t('r503.top_paths'))
        for p, cnt in scanner_paths.most_common(15):
            print(f'    {cnt:>3}  {p}')
        print()

    other_scanners = [(ip, cnt) for ip, cnt in ip_req_window.most_common(10)
                      if ip != scanner_ip and cnt >= 50]
    if other_scanners:
        print(t('r503.other_scanners'))
        print()
        w_ip = max(len(ip) for ip, _ in other_scanners)
        try:
            from .whois import run_whois_raw
            for ip, cnt in other_scanners:
                out = run_whois_raw(ip)
                org = t('r503.unknown_org')
                for line in out.splitlines():
                    m = re.match(r'(?i)^\s*(OrgName|org-name|netname)\s*:\s*(.+)', line)
                    if m:
                        org = m.group(2).strip()
                        break
                print(t('r503.scanner_line', ip=ip, w=w_ip, n=cnt,
                        word=plural_word(cnt, 'request'), org=org))
        except Exception:
            for ip, cnt in other_scanners:
                print(t('r503.scanner_line_no_org', ip=ip, w=w_ip, n=cnt,
                        word=plural_word(cnt, 'request')))
        print()

    if second_scanner_ip:
        print(t('r503.second_scanner', ip=second_scanner_ip))
        print()
        print(t('r503.second_requests', n=second_scanner_req))
        print(t('r503.top_paths'))
        for p, cnt in second_scanner_paths.most_common(10):
            print(f'    {cnt:>3}  {p}')
        print()

    print(t('r503.top_ips'))
    print()
    for ip, cnt in ip_503.most_common(10):
        print(f'    {cnt:>4}  {ip}')
    print()

    print(t('r503.top_countries'))
    print()
    countries = Counter()
    for ip, _ in ip_503.most_common(20):
        try:
            proc = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
            for line in proc.stdout.splitlines():
                if re.match(r'(?i)^\s*Country\s*:', line):
                    c = line.split(':', 1)[1].strip()
                    countries[c] += ip_503[ip]
                    break
        except Exception:
            pass
    for c, cnt in countries.most_common(5):
        print(f'    {cnt:>4}  {c}')
    print()

    print(t('r503.top_paths_503'))
    print()
    for p, cnt in path_503.most_common(10):
        print(f'    {cnt:>4}  {p}')
    print()

    print(t('r503.neighbors'))
    print()
    # индекс: ip -> [(dt, path, status)] по всем распарсенным строкам
    by_ip = {}
    for ln in all_lines:
        rec = parse(ln)
        if not rec:
            continue
        dt = parse_ts(ln)
        if dt:
            by_ip.setdefault(rec['ip'], []).append((dt, rec['path'], rec['status']))
    for lst in by_ip.values():
        lst.sort(key=lambda x: x[0])

    top_503 = ip_503.most_common(5)
    for ip, cnt in top_503:
        print(t('r503.ip_responses', ip=ip, n=cnt, word=plural_word(cnt, 'response')))
        lst = by_ip.get(ip, [])
        idx503 = [i for i, (_, _, st) in enumerate(lst) if st == '503']
        # переходные точки: 503, у которых сосед НЕ 503 (вход/выход из полосы 503),
        # вокруг каждой показываем 2 запроса до и 2 после
        shown = set()
        for i in idx503:
            if (i == 0 or lst[i - 1][2] != '503') or (i == len(lst) - 1 or lst[i + 1][2] != '503'):
                for j in range(max(0, i - 2), min(len(lst), i + 3)):
                    shown.add(j)
        if not shown:  # сплошные 503 без не-503 соседей: показать первый/последний
            for j in idx503[:2] + idx503[-2:]:
                shown.add(j)
        for j in sorted(shown):
            dt, path, st = lst[j]
            mark = ' <-- 503' if st == '503' else ''
            print(f'    [{dt.strftime("%d.%m %H:%M:%S")}] {st} {path[:60]}{mark}')
        print()
    print()

    print('=' * w)
    print(t('r503.end'))
    print('=' * w)


def summarize(paths, t_from=None, t_to=None, proto='all', skip403=False):
    files = expand_files(paths)
    if not files:
        print(t('summary.no_files'))
        return
    print(t('summary.title', n=len(files)))
    print('=' * 41)
    for path in files:
        ips = Counter()
        uas = Counter()
        total = 0
        ipv6 = 0
        for line in iter_lines([path]):
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
            total += 1
            ips[rec['ip']] += 1
            uas[rec['ua']] += 1
            if is6:
                ipv6 += 1
        print()
        print(t('summary.file', path=path))
        print(t('summary.unique_ips', n=len(ips)))
        print(t('summary.requests', n=total))
        print(t('summary.ipv6', n=ipv6))
        print(t('summary.top_ips'))
        w = len(str(ips.most_common(1)[0][1])) if ips else 1
        for ip, c in ips.most_common(10):
            print(f'    {c:>{w}} {ip}')
        print(t('summary.top_ua'))
        for j, (ua, _) in enumerate(uas.most_common(10), 1):
            print(f'    {j}. {ua}')
        print('-' * 41)

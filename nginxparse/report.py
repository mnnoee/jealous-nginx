"""Оркестратор отчёта: все print_* функции и построение отчёта."""

import re
import subprocess
from collections import Counter
from datetime import timezone

from .anomalies import print_anomalies
from .attacks import classify_attacks, print_attack_types
from .constants import TOP_NETWORKS, TOP_REQUESTS, TOP_UA
from .parse_utils import expand_files, fmt_request, in_range, iter_lines, parse, parse_ts
from .scanners import print_scanners


def print_top(title, counter, limit=TOP_NETWORKS):
    top = counter.most_common(limit)
    w = len(str(counter.most_common(1)[0][1])) if counter else 1
    print()
    print(title)
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
    print(f'Топ-{limit} User-Agent:')
    print('=' * 41)
    for i, (ua, cnt) in enumerate(top, 1):
        print(f'{i:>2}. {cnt:>{w}} {ua}')


def print_detail(net, cnt, req, ua):
    print(f'IP: {net}')
    print(f'Кол-во запросов: {cnt}')
    print()
    print(f'Топ {TOP_REQUESTS} запросов:')
    if req:
        w = len(str(req.most_common(1)[0][1]))
        for (ip, host, path), c in req.most_common(TOP_REQUESTS):
            print(f'{c:>{w}} {ip} {fmt_request(host, path)}')
    print()
    print(f'UserAgent (топ {TOP_UA}):')
    for j, (name, _) in enumerate(ua.most_common(TOP_UA), 1):
        print(f'  {j}. {name}')
    print('-' * 41)


def print_detail_block(title, top_nets, req_map, ua_map):
    print()
    print(title)
    print('=' * 41)
    for i, (net, cnt) in enumerate(top_nets, 1):
        print()
        print(f'--- {i} ---')
        print_detail(net, cnt, req_map[net], ua_map[net])


def report(data, whois_limit=None):
    total = data.total
    print(f'Всего запросов: {total}, уникальных /16: {len(data.net16)}, /24: {len(data.net24)}')
    if whois_limit:
        from .whois import print_top_whois
        w = max(len(str(data.net16.most_common(1)[0][1])) if data.net16 else 1,
                len(str(data.net24.most_common(1)[0][1])) if data.net24 else 1)
        top16 = print_top_whois('Топ IP-адресов по маске /16:', data.net16, whois_limit, w)
        top24 = print_top_whois('Топ IP-адресов по маске /24:', data.net24, whois_limit, w)
    else:
        top16 = print_top('Топ IP-адресов по маске /16:', data.net16)
        top24 = print_top('Топ IP-адресов по маске /24:', data.net24)
        from .whois import whois_hint
        whois_hint()
    print_detail_block('Детальный разбор (по /16):', top16, data.req16, data.ua16)
    print_detail_block('Детальный разбор (по /24):', top24, data.req24, data.ua24)
    print_top_ua(data.ua_all)
    print_scanners(data.net16, data.paths16, top16)
    print_scanners(data.net24, data.paths24, top24)
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
    print(f'Все запросы от {ip} ({count} за период):')
    for ln in lines_out:
        print(ln)


def print_report_503(data, paths, t_from=None, t_to=None, proto='all'):
    """Красивый отчёт по 503 ошибкам для клиента."""
    all_lines = list(iter_lines(paths))

    total = len([ln for ln in all_lines if parse(ln)])
    lines_503 = [ln for ln in all_lines if ' 503 ' in ln]
    err503 = len(lines_503)
    if err503 == 0:
        print('503 ошибок не найдено.')
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
    print('  ОТЧЁТ ПО АНАЛИЗУ 503 ОШИБОК')
    print('=' * w)
    print()
    print('Как видно, ваш сайт подвергся атаке сканера,')
    print('из-за чего вы наблюдали 503 код ответа.')
    print()

    print('--- ОБЩАЯ СТАТИСТИКА ---')
    print()
    print(f'  Всего запросов:        {total}')
    print(f'  Запросов с 503:        {err503}')
    print(f'  Уникальных IP с 503:   {uniq_ips_503}')
    print(f'  Доля 503 от трафика:   {pct}')
    print()

    print('--- ХРОНОЛОГИЯ 503 ОШИБОК ---')
    print()
    print('  503 ошибки были сконцентрированы ввечера:')
    print()
    for h, c in sorted(chronology.items()):
        print(f'    {h.strftime("%d/%b/%Y:%H")}    {c:>6} запросов')
    print()

    if scanner_ip:
        print(f'--- ГЛАВНЫЙ СКАНЕР: {scanner_ip} ---')
        print()
        scanner_org = 'неизвестно'
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
        print(f'  Организация:        {scanner_org}')
        print()
        if scanner_start and scanner_end:
            print(f'  Начало атаки:      {scanner_start.strftime("%d.%m.%Y %H:%M:%S")}')
            print(f'  Конец атаки:       {scanner_end.strftime("%d.%m.%Y %H:%M:%S")}')
        print(f'  Всего запросов:    {scanner_req}')
        if scanner_peak[0]:
            print(f'  Пиковая нагрузка: {scanner_peak[1]} req/min '
                  f'({scanner_peak[0].strftime("%H:%M")})')
        print()
        print('  Ответы сервера на сканер:')
        for st, cnt in scanner_status.most_common():
            print(f'    {cnt:>6}  {st}')
        print()
        print('  Топ сканируемых путей:')
        for p, cnt in scanner_paths.most_common(15):
            print(f'    {cnt:>3}  {p}')
        print()

    other_scanners = [(ip, cnt) for ip, cnt in ip_req_window.most_common(10)
                      if ip != scanner_ip and cnt >= 50]
    if other_scanners:
        print('--- ДРУГИЕ СКАНЕРЫ ---')
        print()
        try:
            from .whois import run_whois_raw
            for ip, cnt in other_scanners:
                out = run_whois_raw(ip)
                org = 'неизвестно'
                for line in out.splitlines():
                    m = re.match(r'(?i)^\s*(OrgName|org-name|netname)\s*:\s*(.+)', line)
                    if m:
                        org = m.group(2).strip()
                        break
                print(f'  {ip:<18} {cnt:>5} запросов  {org}')
        except Exception:
            for ip, cnt in other_scanners:
                print(f'  {ip:<18} {cnt:>5} запросов')
        print()

    if second_scanner_ip:
        print(f'--- ВТОРОЙ СКАНЕР: {second_scanner_ip} ---')
        print()
        print(f'  Всего запросов: {second_scanner_req}')
        print('  Топ сканируемых путей:')
        for p, cnt in second_scanner_paths.most_common(10):
            print(f'    {cnt:>3}  {p}')
        print()

    print('--- ТОП IP, ПОЛУЧИВШИХ 503 (жертвы) ---')
    print()
    for ip, cnt in ip_503.most_common(10):
        print(f'    {cnt:>4}  {ip}')
    print()

    print('--- ТОП СТРАН ПО 503 ОШИБКАМ ---')
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

    print('--- ТОП ПУТЕЙ С 503 ОШИБКАМИ ---')
    print()
    for p, cnt in path_503.most_common(10):
        print(f'    {cnt:>4}  {p}')
    print()

    print('--- ПРИЧИНА 503 ---')
    print()
    all_scanners = [(scanner_ip, scanner_req)]
    if other_scanners:
        all_scanners.extend(other_scanners)
    for i, (ip, req) in enumerate(all_scanners, 1):
        print(f'  {i}. Сканер {ip} отправил {req} запросов')
        print('     к несуществующим PHP-файлам.')
    print()
    print('  Сервер не смог обработать такой объём')
    print('  запросов и начал отвечать 503')
    print('  Service Unavailable на легитимные запросы.')
    print()

    print('--- РЕКОМЕНДАЦИИ ---')
    print()
    for i, (ip, _) in enumerate(all_scanners, 1):
        print(f'  {i}. Заблокировать {ip} в файрволе')
    print(f'  {len(all_scanners) + 1}. Настроить rate limiting на PHP-скрипты')
    print(f'  {len(all_scanners) + 2}. Установить fail2ban для автоблокировки')
    print(f'  {len(all_scanners) + 3}. Рассмотреть CloudFlare/DDoS-защиту')
    print()
    print('=' * w)
    print('  КОНЕЦ ОТЧЁТА')
    print('=' * w)


def summarize(paths, t_from=None, t_to=None, proto='all', skip403=False):
    files = expand_files(paths)
    if not files:
        print('Access-логи не найдены.')
        return
    print(f'Сводка по {len(files)} access-логам:')
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
        print(f'Файл: {path}')
        print(f'  Общее количество уникальных ip: {len(ips)}')
        print(f'  Запросов: {total}')
        print(f'  ipv6: {ipv6}')
        print('  Топ-10 ip:')
        w = len(str(ips.most_common(1)[0][1])) if ips else 1
        for ip, c in ips.most_common(10):
            print(f'    {c:>{w}} {ip}')
        print('  Топ-10 user-agent:')
        for j, (ua, _) in enumerate(uas.most_common(10), 1):
            print(f'    {j}. {ua}')
        print('-' * 41)

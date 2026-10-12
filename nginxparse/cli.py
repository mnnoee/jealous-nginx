"""CLI: argparse, main(), pick_file()."""

import argparse
import os
import sys

from . import json_export
from .constants import DEFAULT_PATH, VERSION
from .core import analyze
from .parse_utils import ask_time_range, parse_dt
from .redirects import print_redirects
from .report import print_raw, print_report_503, report, summarize
from .stats import print_hourly, print_per_minute


def find_log_files():
    found = []
    for root, dirs, files in os.walk('.', followlinks=False):
        dirs[:] = [d for d in dirs if d != '.git']
        for f in files:
            low = f.lower()
            if not (low.endswith('.gz') or '.log' in low or 'access' in low or 'error' in low):
                continue
            p = os.path.join(root, f)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            if sz == 0:
                continue
            found.append((p, sz))
    return sorted(found, key=lambda x: x[1], reverse=True)


def pick_file():
    found = find_log_files()
    if not found:
        print('Логи не найдены в текущем каталоге.')
        return None
    print(f'Найдено логов: {len(found)}')
    print('   [ 0] все файлы')
    for i, (p, sz) in enumerate(found, 1):
        print(f'   [{i:2}] {p:60} {sz / 1024:8.0f} K')
    print('   [ q] выход')
    while True:
        try:
            choice = input('Выберите файл: ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if choice in ('q', 'quit', 'exit'):
            return None
        if choice in ('a', 'all', '0', '*'):
            return [p for p, _ in found]
        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(found):
                return [found[n - 1][0]]
        print('Некорректный ввод.')


def main():
    parser = argparse.ArgumentParser(
        description='Парсер access-логов nginx (интерактивный)',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {VERSION}')
    parser.add_argument('paths', nargs='*', help='файлы или каталоги с логами (по умолчанию — интерактивный выбор)')
    parser.add_argument('--from', dest='t_from', metavar='DT', help='начало диапазона времени')
    parser.add_argument('--to', dest='t_to', metavar='DT', help='конец диапазона времени')
    parser.add_argument('--summary', action='store_true', help='сводка по каждому access-логу отдельно')
    parser.add_argument('--hourly', nargs='?', const=0, type=int, metavar='N',
                        help='запросы по часам (N — последних часов, 0 = все)')
    parser.add_argument('--whois', nargs='+', metavar='NET',
                        help='whois для указанных сетей/IP (без анализа логов)')
    parser.add_argument('--whois-cidr', dest='whois_cidr', nargs='?', const=10, type=int,
                        metavar='N', help='обогатить топы /16 и /24 whois-данными (N сетей)')
    parser.add_argument('--proto', choices=('all', 'ipv4', 'ipv6'), default='all',
                        help='фильтр трафика: all | ipv4 | ipv6 (по умолчанию all)')
    parser.add_argument('--403', dest='skip403', action='store_true',
                        help='исключить запросы с HTTP 403 из статистики')
    parser.add_argument('--raw', metavar='IP',
                        help='все строки лога для конкретного IP')
    parser.add_argument('--per-minute', nargs='?', const=0, type=int, metavar='N',
                        help='запросы по минутам (N — последних минут, 0 = все)')
    parser.add_argument('--redirects', action='store_true',
                        help='показать цепочки редиректов (301->301->404)')
    parser.add_argument('--report-503', action='store_true',
                        help='отчёт по 503 ошибкам (причины, сканеры, хронология)')
    parser.add_argument('--json', nargs='?', const='report.json', metavar='PATH',
                        help='записать машиночитаемый JSON-отчёт (по умолчанию report.json)')
    args = parser.parse_args()

    if args.whois:
        from .whois import run_batch_whois
        run_batch_whois(args.whois)
        return

    try:
        t_from = parse_dt(args.t_from)
        t_to = parse_dt(args.t_to)
    except ValueError as e:
        print(e)
        return

    if args.raw:
        paths = args.paths or [DEFAULT_PATH]
        print_raw(paths, args.raw, t_from, t_to, proto=args.proto, skip403=args.skip403)
        return

    if args.redirects:
        paths = args.paths or [DEFAULT_PATH]
        data = analyze(paths, t_from, t_to, proto=args.proto, skip403=args.skip403)
        if not data.net16:
            print('Нет данных.')
            return
        print_redirects(data.chains)
        return

    if args.report_503:
        paths = args.paths or [DEFAULT_PATH]
        data = analyze(paths, t_from, t_to, proto=args.proto, skip403=args.skip403)
        if not data.net16:
            print('Нет данных.')
            return
        print_report_503(data, paths, t_from, t_to, proto=args.proto)
        return

    if args.summary:
        summarize(args.paths or [DEFAULT_PATH], t_from, t_to, proto=args.proto, skip403=args.skip403)
        return

    paths = args.paths
    interactive = sys.stdin.isatty()

    if not paths:
        if interactive:
            selected = pick_file()
            if not selected:
                return
            paths = selected
            if t_from is None and t_to is None:
                print()
                t_from, t_to = ask_time_range()

    data = analyze(paths, t_from, t_to, proto=args.proto, skip403=args.skip403)
    if not data.net16:
        # контракт --json: отчёт пишется даже когда распарсить нечего
        if args.json:
            path = json_export.write_json_report(data, args.json,
                                                 t_from=t_from, t_to=t_to, proto=args.proto)
            print(f'JSON-отчёт записан в: {path}', file=sys.stderr)
            return
        print('Нет данных.')
        return
    report(data, whois_limit=args.whois_cidr)
    if args.hourly is not None:
        print_hourly(data.hours, args.hourly)
    if args.per_minute is not None:
        print_per_minute(data.minutes, args.per_minute)
    if args.json:
        path = json_export.write_json_report(data, args.json,
                                             t_from=t_from, t_to=t_to, proto=args.proto,
                                             whois_limit=args.whois_cidr)
        print(f'JSON-отчёт записан в: {path}', file=sys.stderr)

"""CLI: argparse, main(), pick_file()."""

import argparse
import os
import sys

from . import json_export
from .constants import DEFAULT_PATH, VERSION
from .core import analyze
from .i18n import set_lang, t
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
        print(t('cli.no_logs'))
        return None
    print(t('cli.found', n=len(found)))
    print(f"   [ 0] {t('cli.all_files')}")
    for i, (p, sz) in enumerate(found, 1):
        print(f'   [{i:2}] {p:60} {sz / 1024:8.0f} K')
    print(f"   [ q] {t('cli.quit')}")
    while True:
        try:
            choice = input(t('cli.choose')).strip().lower()
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
        print(t('cli.bad_input'))


def _prescan_lang(argv):
    for i, arg in enumerate(argv):
        if arg == '--lang' and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith('--lang='):
            return arg.split('=', 1)[1]
    return None


def main():
    set_lang(_prescan_lang(sys.argv[1:]))
    parser = argparse.ArgumentParser(
        description=t('cli.desc'),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {VERSION}')
    parser.add_argument('paths', nargs='*', help=t('cli.paths'))
    parser.add_argument('--from', dest='t_from', metavar='DT', help=t('cli.from'))
    parser.add_argument('--to', dest='t_to', metavar='DT', help=t('cli.to'))
    parser.add_argument('--summary', action='store_true', help=t('cli.summary'))
    parser.add_argument('--hourly', nargs='?', const=0, type=int, metavar='N',
                        help=t('cli.hourly'))
    parser.add_argument('--whois', nargs='+', metavar='NET',
                        help=t('cli.whois'))
    parser.add_argument('--whois-cidr', dest='whois_cidr', nargs='?', const=10, type=int,
                        metavar='N', help=t('cli.whois_cidr'))
    parser.add_argument('--proto', choices=('all', 'ipv4', 'ipv6'), default='all',
                        help=t('cli.proto'))
    parser.add_argument('--403', dest='skip403', action='store_true',
                        help=t('cli.skip403'))
    parser.add_argument('--raw', metavar='IP',
                        help=t('cli.raw'))
    parser.add_argument('--per-minute', nargs='?', const=0, type=int, metavar='N',
                        help=t('cli.per_minute'))
    parser.add_argument('--redirects', action='store_true',
                        help=t('cli.redirects'))
    parser.add_argument('--report-503', action='store_true',
                        help=t('cli.report_503'))
    parser.add_argument('--16', dest='nets16', action='store_true',
                        help=t('cli.nets16'))
    parser.add_argument('--24', dest='nets24', action='store_true',
                        help=t('cli.nets24'))
    parser.add_argument('--top', type=int, metavar='N', default=None,
                        help=t('cli.top'))
    parser.add_argument('--full', action='store_true',
                        help=t('cli.full'))
    parser.add_argument('--scanners', type=int, metavar='N', default=10,
                        help=t('cli.scanners'))
    parser.add_argument('--json', nargs='?', const='report.json', metavar='PATH',
                        help=t('cli.json'))
    parser.add_argument('--lang', choices=('auto', 'ru', 'en'), default='auto',
                        help=t('cli.lang'))
    args = parser.parse_args()
    set_lang(args.lang)

    if args.whois:
        from .whois import run_batch_whois
        run_batch_whois(args.whois)
        return

    try:
        t_from = parse_dt(args.t_from)
        # дата без времени в --to означает конец дня (23:59:59)
        t_to = parse_dt(args.t_to, is_end=True)
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
            print(t('data.none'))
            return
        print_redirects(data.chains)
        return

    if args.report_503:
        paths = args.paths or [DEFAULT_PATH]
        data = analyze(paths, t_from, t_to, proto=args.proto, skip403=args.skip403)
        if not data.net16:
            print(t('data.none'))
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
            print(t('cli.json_written', path=path), file=sys.stderr)
            return
        print(t('data.none'))
        return
    # флаги-исключения: только --16 -> без /24; только --24 -> без /16; оба или ни одного -> обе
    show16 = args.nets16 or not args.nets24
    show24 = args.nets24 or not args.nets16
    report(data, whois_limit=args.whois_cidr, top=args.top,
           nets16=show16, nets24=show24,
           detail_full=args.full, scanners_full=args.full, scanners_limit=args.scanners)
    if args.hourly is not None:
        print_hourly(data.hours, args.hourly)
    if args.per_minute is not None:
        print_per_minute(data.minutes, args.per_minute)
    if args.json:
        path = json_export.write_json_report(data, args.json,
                                             t_from=t_from, t_to=t_to, proto=args.proto,
                                             whois_limit=args.whois_cidr)
        print(t('cli.json_written', path=path), file=sys.stderr)

"""Анализ цепочек редиректов (301->301->404)."""

from datetime import datetime as _dt
from datetime import timezone

from .i18n import t

REDIRECT_CHAIN = ('301', '301', '404')


def find_redirect_chains(chains):
    """Возвращает список (ip, path, entries[(dt, status, bytes)])."""
    found = []
    for (ip, path), entries in chains.items():
        sorted_entries = sorted(entries, key=lambda e: e[0] if e[0] else _dt.min.replace(tzinfo=timezone.utc))
        statuses = [e[1] for e in sorted_entries]
        for i in range(len(statuses) - 2):
            if tuple(statuses[i:i+3]) == REDIRECT_CHAIN:
                found.append((ip, path, sorted_entries[i:i+3]))
    return found


def print_redirects(chains):
    found = find_redirect_chains(chains)
    print()
    print('=' * 41)
    print(t('redirects.title'))
    print('=' * 41)
    if not found:
        print(t('not_found'))
        return
    for ip, path, entries in found:
        print(f'--- {ip} -> {path} ---')
        for dt, st, b in entries:
            ts = dt.strftime('%H:%M:%S') if dt else '??:??:??'
            b_str = f'{b} bytes' if b else '-'
            heavy = t('redirects.heavy') if st == '404' and b > 50000 else ''
            print(f'  [{ts}] GET {path:<35} -> {st}  ({b_str}){heavy}')
        print()
    print(t('redirects.total', n=len(found)))

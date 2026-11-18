"""Детекция сканеров и SEO-ботов."""

from .constants import SCANNER_PATHS_LIMIT, SCANNER_THRESHOLD, SUSPICIOUS_RE
from .i18n import t


def detect_scanners(net_counter, paths_map, top_nets):
    """Возвращает структурированный список {network, type, paths}."""
    results = []
    top_set = set(net for net, _ in top_nets)
    for net, _ in sorted(net_counter.items(), key=lambda kv: kv[1], reverse=True):
        paths = paths_map[net]
        suspicious = sorted(p for p in paths if SUSPICIOUS_RE.search(p))
        bot_paths = sorted(p for p in paths
                           if p.startswith('/robots.txt') or p.startswith('/.well-known/'))
        if len(suspicious) >= SCANNER_THRESHOLD:
            results.append({'network': net, 'type': 'scanner',
                            'paths': suspicious[:SCANNER_PATHS_LIMIT]})
        elif bot_paths and net in top_set:
            results.append({'network': net, 'type': 'seo_bot',
                            'paths': bot_paths[:SCANNER_PATHS_LIMIT]})
    return results


def print_scanners(net_counter, paths_map, top_nets, full=False, limit=10):
    results = detect_scanners(net_counter, paths_map, top_nets)
    print()
    print('=' * 41)
    if limit and len(results) > limit:
        print(t('scanners.title_limited', limit=limit, total=len(results)))
    else:
        print(t('scanners.title'))
    if not results:
        print(t('not_found'))
        return
    if limit:
        results = results[:limit]
    for item in results:
        if item['type'] == 'seo_bot':
            print(t('scanners.seo_bot', net=item['network']))
        else:
            print(item['network'])
        if full:
            for p in item['paths']:
                print(f'  {p}')
        else:
            n = len(item['paths'])
            print(t('scanners.paths', n=n) +
                  ', '.join(item['paths'][:3]) + (' ...' if n > 3 else ''))
        print()

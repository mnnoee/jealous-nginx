"""Детекция сканеров и SEO-ботов."""

from .constants import SCANNER_PATHS_LIMIT, SCANNER_THRESHOLD, SUSPICIOUS_RE


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


def print_scanners(net_counter, paths_map, top_nets, full=False):
    results = detect_scanners(net_counter, paths_map, top_nets)
    print()
    print('=' * 41)
    print('Выявленные сканеры:')
    if not results:
        print('  Не найдено.')
        return
    for item in results:
        if item['type'] == 'seo_bot':
            print(f"{item['network']} <-------------- вероятно, SEO-бот, а не сканер")
        else:
            print(item['network'])
        if full:
            for p in item['paths']:
                print(f'  {p}')
        else:
            n = len(item['paths'])
            print(f'  подозрительных путей: {n}; примеры: ' +
                  ', '.join(item['paths'][:3]) + (' ...' if n > 3 else ''))
        print()

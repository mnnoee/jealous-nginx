"""Классификация атак по поведению IP."""

from collections import Counter, defaultdict

from .constants import (
    BRUTE_FORCE_THRESHOLD,
    REDIRECT_LOOP_THRESHOLD,
    SCAN_SHELLS_THRESHOLD,
    XMLRPC_THRESHOLD,
)
from .i18n import plural_word, t


def classify_attacks(data):
    attacks = []
    ip_req = defaultdict(Counter)
    ip_paths = defaultdict(set)
    ip_total = Counter()
    for _net, req_counter in data.req16.items():
        for (ip, _host, path), cnt in req_counter.items():
            ip_req[ip][path] += cnt
            ip_paths[ip].add(path)
            ip_total[ip] += cnt
    for ip, paths in ip_paths.items():
        wp_attempts = sum(ip_req[ip].get(p, 0) for p in paths
                          if '/wp-login.php' in p and 'redirect_to' not in p)
        if wp_attempts > BRUTE_FORCE_THRESHOLD:
            attacks.append(('BRUTE-FORCE', ip,
                            t('attacks.attempts', n=wp_attempts,
                              word=plural_word(wp_attempts, 'attempt')),
                            '/wp-login.php'))
        shell_paths = [p for p in paths if p.endswith('.php') and ip_req[ip][p] <= 3]
        if len(shell_paths) > SCAN_SHELLS_THRESHOLD:
            examples = ', '.join(sorted(shell_paths)[:3])
            attacks.append(('SCAN-SHELLS', ip,
                            t('attacks.requests', n=ip_total[ip]),
                            f'{examples} ... ({len(shell_paths)} '
                            f'{plural_word(len(shell_paths), "path")})'))
        xmlrpc = sum(ip_req[ip].get(p, 0) for p in paths if '/xmlrpc.php' in p)
        if xmlrpc > XMLRPC_THRESHOLD:
            attacks.append(('XMLRPC-ABUSE', ip, t('attacks.requests', n=xmlrpc),
                            '/xmlrpc.php'))
        redirect_302 = sum(ip_req[ip].get(p, 0) for p in paths
                           if '/wp-login.php' in p and 'redirect_to' in p)
        if redirect_302 > REDIRECT_LOOP_THRESHOLD:
            attacks.append(('REDIRECT-LOOP', ip,
                            t('attacks.requests', n=redirect_302),
                            '/wp-login.php?redirect_to=...'))
    return attacks


def print_attack_types(attacks):
    if not attacks:
        return
    print()
    print(t('attacks.title'))
    print(t('attacks.note'))
    for atype, ip, detail, path in sorted(attacks, key=lambda x: x[0]):
        print(f'[{atype:<15}] {ip:<20} {detail:<16} {path}')

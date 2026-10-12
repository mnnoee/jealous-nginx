"""Юнит-тесты классификации атак (nginxparse/attacks.py).

Только синтетические данные: документированные диапазоны примеров
(203.0.113.0/24, 198.51.100.0/24) и generic-домены.
"""

import unittest
from collections import Counter

from nginxparse.attacks import classify_attacks
from nginxparse.constants import (
    BRUTE_FORCE_THRESHOLD,
    REDIRECT_LOOP_THRESHOLD,
    SCAN_SHELLS_THRESHOLD,
    XMLRPC_THRESHOLD,
)
from nginxparse.core import NginxLogParser

NET = '203.0.0.0'
IP = '203.0.113.7'


def _data(req16):
    p = NginxLogParser()
    p.req16 = req16
    return p


def _one_ip(paths_counts):
    """req16 для одного IP: {path: count}."""
    req = Counter()
    for path, cnt in paths_counts:
        req[(IP, 'acme.local', path)] += cnt
    return {NET: req}


class BruteForceTest(unittest.TestCase):
    def test_detected_above_threshold(self):
        data = _data(_one_ip([('/wp-login.php', BRUTE_FORCE_THRESHOLD + 1)]))
        attacks = classify_attacks(data)
        bf = [a for a in attacks if a[0] == 'BRUTE-FORCE']
        self.assertEqual(len(bf), 1)
        self.assertEqual(bf[0][1], IP)
        self.assertEqual(bf[0][3], '/wp-login.php')

    def test_not_detected_below_threshold(self):
        data = _data(_one_ip([('/wp-login.php', BRUTE_FORCE_THRESHOLD)]))
        attacks = classify_attacks(data)
        self.assertFalse([a for a in attacks if a[0] == 'BRUTE-FORCE'])

    def test_redirect_to_not_counted_as_brute_force(self):
        # /wp-login.php?redirect_to=... считается REDIRECT-LOOP, не BRUTE-FORCE
        data = _data(_one_ip([
            ('/wp-login.php?redirect_to=http://acme.local/wp-admin/', 50),
        ]))
        attacks = classify_attacks(data)
        self.assertFalse([a for a in attacks if a[0] == 'BRUTE-FORCE'])
        self.assertTrue([a for a in attacks if a[0] == 'REDIRECT-LOOP'])


class ScanShellsTest(unittest.TestCase):
    def test_detected_above_threshold(self):
        paths = [(f'/shell{i}.php', 1) for i in range(SCAN_SHELLS_THRESHOLD + 1)]
        data = _data(_one_ip(paths))
        attacks = classify_attacks(data)
        ss = [a for a in attacks if a[0] == 'SCAN-SHELLS']
        self.assertEqual(len(ss), 1)
        # в detail — общее число запросов, в path — примеры и число путей
        self.assertIn('путей', ss[0][3])

    def test_not_detected_below_threshold(self):
        paths = [(f'/shell{i}.php', 1) for i in range(SCAN_SHELLS_THRESHOLD)]
        data = _data(_one_ip(paths))
        attacks = classify_attacks(data)
        self.assertFalse([a for a in attacks if a[0] == 'SCAN-SHELLS'])

    def test_heavy_paths_not_counted(self):
        # путь, запрашиваемый >3 раз, не считается перебором шеллов
        paths = [(f'/shell{i}.php', 1) for i in range(SCAN_SHELLS_THRESHOLD + 1)]
        paths.append(('/index.php', 10))
        data = _data(_one_ip(paths))
        attacks = classify_attacks(data)
        ss = [a for a in attacks if a[0] == 'SCAN-SHELLS']
        self.assertEqual(len(ss), 1)
        self.assertNotIn('/index.php', ss[0][3])


class XmlrpcAbuseTest(unittest.TestCase):
    def test_detected_above_threshold(self):
        data = _data(_one_ip([('/xmlrpc.php', XMLRPC_THRESHOLD + 1)]))
        attacks = classify_attacks(data)
        xa = [a for a in attacks if a[0] == 'XMLRPC-ABUSE']
        self.assertEqual(len(xa), 1)
        self.assertEqual(xa[0][3], '/xmlrpc.php')

    def test_not_detected_below_threshold(self):
        data = _data(_one_ip([('/xmlrpc.php', XMLRPC_THRESHOLD)]))
        attacks = classify_attacks(data)
        self.assertFalse([a for a in attacks if a[0] == 'XMLRPC-ABUSE'])


class RedirectLoopTest(unittest.TestCase):
    def test_detected_above_threshold(self):
        path = '/wp-login.php?redirect_to=http://acme.local/wp-admin/'
        data = _data(_one_ip([(path, REDIRECT_LOOP_THRESHOLD + 1)]))
        attacks = classify_attacks(data)
        rl = [a for a in attacks if a[0] == 'REDIRECT-LOOP']
        self.assertEqual(len(rl), 1)

    def test_not_detected_below_threshold(self):
        path = '/wp-login.php?redirect_to=http://acme.local/wp-admin/'
        data = _data(_one_ip([(path, REDIRECT_LOOP_THRESHOLD)]))
        attacks = classify_attacks(data)
        self.assertFalse([a for a in attacks if a[0] == 'REDIRECT-LOOP'])


class MultipleIpsTest(unittest.TestCase):
    def test_attacks_per_ip(self):
        req = Counter()
        req[(IP, 'acme.local', '/wp-login.php')] = 10
        other = '198.51.100.7'
        req[(other, '', '/xmlrpc.php')] = 60
        data = _data({NET: req})
        attacks = classify_attacks(data)
        ips = {a[1] for a in attacks}
        self.assertEqual(ips, {IP, other})

    def test_clean_log_no_attacks(self):
        data = _data(_one_ip([('/index.html', 500), ('/about', 100)]))
        self.assertEqual(classify_attacks(data), [])


if __name__ == "__main__":
    unittest.main()

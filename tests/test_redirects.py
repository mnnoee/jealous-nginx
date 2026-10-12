"""Юнит-тесты цепочек редиректов (nginxparse/redirects.py)."""

import unittest
from datetime import datetime, timedelta, timezone

from nginxparse.redirects import REDIRECT_CHAIN, find_redirect_chains

DT = datetime(2026, 8, 19, 11, 0, 0, tzinfo=timezone.utc)


class RedirectChainTest(unittest.TestCase):
    def test_chain_detected(self):
        # 301 -> 301 -> 404 (PHP-карусель)
        chains = {
            ('203.0.113.7', '/a.php'): [
                (DT, '301', 100),
                (DT, '301', 100),
                (DT, '404', 200),
            ],
        }
        found = find_redirect_chains(chains)
        self.assertEqual(len(found), 1)
        ip, path, entries = found[0]
        self.assertEqual(ip, '203.0.113.7')
        self.assertEqual(path, '/a.php')
        self.assertEqual([e[1] for e in entries], list(REDIRECT_CHAIN))

    def test_no_chain_on_normal_redirects(self):
        chains = {
            ('203.0.113.7', '/a.php'): [
                (DT, '301', 100),
                (DT, '200', 200),
            ],
        }
        self.assertEqual(find_redirect_chains(chains), [])

    def test_unsorted_entries_still_detected(self):
        # записи сортируются по времени: 404 стоит в списке первым,
        # но по таймстампу — последним
        chains = {
            ('203.0.113.7', '/a.php'): [
                (DT + timedelta(seconds=3), '404', 200),
                (DT + timedelta(seconds=1), '301', 100),
                (DT + timedelta(seconds=2), '301', 100),
            ],
        }
        found = find_redirect_chains(chains)
        self.assertEqual(len(found), 1)

    def test_none_timestamp_handled(self):
        # None-время сортируется первым и не роняет сортировку
        chains = {
            ('203.0.113.7', '/a.php'): [
                (None, '200', 50),
                (DT, '301', 100),
                (DT + timedelta(seconds=1), '301', 100),
                (DT + timedelta(seconds=2), '404', 200),
            ],
        }
        self.assertEqual(len(find_redirect_chains(chains)), 1)

    def test_multiple_ips(self):
        chains = {
            ('203.0.113.7', '/a.php'): [(DT, '301', 100), (DT, '301', 100), (DT, '404', 200)],
            ('198.51.100.7', '/b.php'): [(DT, '301', 100), (DT, '301', 100), (DT, '404', 200)],
        }
        found = find_redirect_chains(chains)
        self.assertEqual(len(found), 2)


if __name__ == "__main__":
    unittest.main()

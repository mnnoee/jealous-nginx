"""Юнит-тесты детекции сканеров и SEO-ботов (nginxparse/scanners.py)."""

import unittest
from collections import Counter

from nginxparse.constants import SCANNER_THRESHOLD
from nginxparse.scanners import detect_scanners

NET = '203.0.0.0'
TOP = [(NET, 100)]


class ScannerTest(unittest.TestCase):
    def test_detected_above_threshold(self):
        paths = [f'/shell{i}.php' for i in range(SCANNER_THRESHOLD)]
        res = detect_scanners(Counter({NET: 100}), {NET: paths}, TOP)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['type'], 'scanner')
        self.assertEqual(res[0]['network'], NET)

    def test_not_detected_below_threshold(self):
        paths = [f'/shell{i}.php' for i in range(SCANNER_THRESHOLD - 1)]
        res = detect_scanners(Counter({NET: 100}), {NET: paths}, TOP)
        self.assertEqual(res, [])

    def test_paths_limited(self):
        from nginxparse.constants import SCANNER_PATHS_LIMIT
        paths = [f'/shell{i}.php' for i in range(SCANNER_PATHS_LIMIT + 10)]
        res = detect_scanners(Counter({NET: 100}), {NET: paths}, TOP)
        self.assertEqual(len(res[0]['paths']), SCANNER_PATHS_LIMIT)

    def test_suspicious_patterns(self):
        # .php, /wp-admin, /.git, /config, .env — подозрительные пути
        paths = ['/a.php', '/wp-admin/', '/.git/HEAD', '/config', '/.env']
        res = detect_scanners(Counter({NET: 100}), {NET: paths}, TOP)
        self.assertEqual(len(res), 1)
        self.assertEqual(len(res[0]['paths']), 5)


class SeoBotTest(unittest.TestCase):
    def test_robots_txt_in_top_net(self):
        paths = ['/robots.txt', '/index.html']
        res = detect_scanners(Counter({NET: 100}), {NET: paths}, TOP)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['type'], 'seo_bot')

    def test_well_known_in_top_net(self):
        paths = ['/.well-known/acme-challenge/token', '/index.html']
        res = detect_scanners(Counter({NET: 100}), {NET: paths}, TOP)
        self.assertEqual(res[0]['type'], 'seo_bot')

    def test_bot_paths_not_in_top_net_ignored(self):
        # seo_bot детектится только для топ-сетей
        paths = ['/robots.txt', '/index.html']
        res = detect_scanners(Counter({NET: 1}), {NET: paths}, [('другая-сеть', 999)])
        self.assertEqual(res, [])

    def test_normal_traffic_no_detection(self):
        paths = ['/index.html', '/about', '/assets/style.css']
        res = detect_scanners(Counter({NET: 100}), {NET: paths}, TOP)
        self.assertEqual(res, [])


if __name__ == "__main__":
    unittest.main()

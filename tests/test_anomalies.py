"""Юнит-тесты детекции аномальных ответов (nginxparse/anomalies.py)."""

import unittest
from collections import defaultdict

from nginxparse.anomalies import detect_anomalies
from nginxparse.constants import ANOMALY_2XX_MB, ANOMALY_3XX_KB, ANOMALY_4XX_KB


def _data(status_bytes):
    p = type('Data', (), {})()
    p.status_bytes = status_bytes
    p.status_paths = defaultdict(set)
    for status, sizes in status_bytes.items():
        p.status_paths[status] = {f'/path{i}' for i in range(len(sizes))}
    return p


class Heavy4xxTest(unittest.TestCase):
    def test_detected(self):
        data = _data({'404': [ANOMALY_4XX_KB * 1024 + 1, 100]})
        res = detect_anomalies(data)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['status'], '404')
        self.assertEqual(res[0]['count'], 1)
        self.assertIn('KB', res[0]['label'])

    def test_not_detected_below_threshold(self):
        data = _data({'404': [ANOMALY_4XX_KB * 1024, 100]})
        self.assertEqual(detect_anomalies(data), [])


class Heavy3xxTest(unittest.TestCase):
    def test_detected(self):
        data = _data({'301': [ANOMALY_3XX_KB * 1024 + 1]})
        res = detect_anomalies(data)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['status'], '301')

    def test_not_detected_below_threshold(self):
        data = _data({'301': [ANOMALY_3XX_KB * 1024]})
        self.assertEqual(detect_anomalies(data), [])


class Heavy2xxTest(unittest.TestCase):
    def test_detected(self):
        data = _data({'200': [ANOMALY_2XX_MB * 1024 * 1024 + 1]})
        res = detect_anomalies(data)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['status'], '200')
        self.assertIn('MB', res[0]['label'])

    def test_not_detected_below_threshold(self):
        data = _data({'200': [ANOMALY_2XX_MB * 1024 * 1024]})
        self.assertEqual(detect_anomalies(data), [])


class OtherStatusesTest(unittest.TestCase):
    def test_5xx_ignored(self):
        # пороги заданы только для 2xx/3xx/4xx
        data = _data({'503': [10 * 1024 * 1024]})
        self.assertEqual(detect_anomalies(data), [])

    def test_example_paths_included(self):
        data = _data({'404': [ANOMALY_4XX_KB * 1024 + 1] * 7})
        res = detect_anomalies(data)
        self.assertEqual(res[0]['count'], 7)
        self.assertIn('путей', res[0]['example'])


if __name__ == "__main__":
    unittest.main()

"""Юнит-тесты JSON-отчёта (nginxparse/json_export.py).

Полный конвейер на синтетическом логе: analyze() -> build_json().
Офлайн, только generic-данные.
"""

import json
import os
import sys
import tempfile
import unittest

from nginxparse.constants import VERSION
from nginxparse.core import analyze
from nginxparse.json_export import build_json, write_json_report

LINE = (
    '{ip} - - [19/Aug/2026:{time} +0300] acme.local '
    '"GET {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0" "-" rt=0.1 ut=0.2'
)

EXPECTED_KEYS = {
    'meta', 'top_networks_16', 'top_networks_24', 'networks_16', 'networks_24',
    'user_agents', 'hours', 'minutes', 'statuses', 'anomalies',
    'scanners_16', 'scanners_24', 'attacks', 'redirect_chains',
}


def _make_log(tmp, lines):
    path = os.path.join(tmp, 'access.log')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    return path


class BuildJsonTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = cls._tmp.name
        lines = [
            # обычный трафик
            LINE.format(ip='203.0.113.7', time='11:11:11', path='/index.php',
                        status=200, size=1234),
            LINE.format(ip='203.0.113.7', time='11:11:12', path='/about',
                        status=200, size=800),
            # брутфорс-паттерн (>3 попыток wp-login)
            *[LINE.format(ip='198.51.100.91', time=f'12:00:{i:02d}',
                          path='/wp-login.php', status=403, size=512)
              for i in range(5)],
        ]
        cls.log_path = _make_log(tmp, lines)
        cls.data = analyze([cls.log_path])
        cls.doc = build_json(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_all_keys_present(self):
        self.assertEqual(set(self.doc), EXPECTED_KEYS)

    def test_meta(self):
        meta = self.doc['meta']
        self.assertEqual(meta['version'], VERSION)
        self.assertEqual(meta['total_requests'], 7)
        self.assertEqual(meta['unique_networks_16'], 2)
        self.assertIsNone(meta['filters']['from'])
        self.assertIsNone(meta['filters']['to'])
        self.assertEqual(meta['filters']['proto'], 'all')

    def test_top_networks(self):
        for key in ('top_networks_16', 'top_networks_24'):
            nets = self.doc[key]
            self.assertTrue(all('network' in n and 'count' in n for n in nets))
        top16 = {n['network']: n['count'] for n in self.doc['top_networks_16']}
        self.assertEqual(top16.get('203.0.0.0'), 2)
        self.assertEqual(top16.get('198.51.0.0'), 5)

    def test_networks_detail(self):
        detail = self.doc['networks_16']
        self.assertEqual(len(detail), 2)
        entry = detail[0]
        self.assertIn('network', entry)
        self.assertIn('top_requests', entry)
        self.assertIn('top_paths', entry)
        self.assertIn('top_ua', entry)

    def test_user_agents(self):
        uas = self.doc['user_agents']
        self.assertEqual(uas[0], {'ua': 'Mozilla/5.0', 'count': 7})

    def test_hours_sorted(self):
        hours = self.doc['hours']
        times = [h['time'] for h in hours]
        self.assertEqual(times, sorted(times))
        self.assertEqual(sum(h['count'] for h in hours), 7)

    def test_statuses(self):
        st = self.doc['statuses']
        self.assertEqual(st['200']['count'], 2)
        self.assertEqual(st['403']['count'], 5)
        self.assertEqual(st['200']['bytes_total'], 1234 + 800)
        self.assertIn('/index.php', st['200']['paths'])

    def test_attacks_detected(self):
        # атаки в JSON — dict: {type, ip, detail, path}
        attacks = self.doc['attacks']
        bf = [a for a in attacks if a['type'] == 'BRUTE-FORCE']
        self.assertEqual(len(bf), 1)
        self.assertEqual(bf[0]['ip'], '198.51.100.91')
        self.assertEqual(bf[0]['path'], '/wp-login.php')

    def test_filters_recorded_in_meta(self):
        # build_json не перефильтровывает данные, а записывает фильтры в meta;
        # сама фильтрация происходит в analyze()
        from datetime import datetime, timezone
        t_from = datetime(2026, 8, 19, 11, 0, 0, tzinfo=timezone.utc)
        t_to = datetime(2026, 8, 19, 11, 59, 59, tzinfo=timezone.utc)
        doc = build_json(self.data, t_from=t_from, t_to=t_to)
        self.assertEqual(doc['meta']['filters']['proto'], 'all')
        self.assertIn('2026-08-19', doc['meta']['filters']['from'])
        self.assertIn('2026-08-19', doc['meta']['filters']['to'])

    def test_analyze_applies_time_filter(self):
        # границы в той же зоне, что и лог (+0300): сравнение aware-дат
        # абсолютное, так что тест не зависит от таймзоны машины
        from datetime import datetime, timedelta, timezone
        tz3 = timezone(timedelta(hours=3))
        t_from = datetime(2026, 8, 19, 11, 0, 0, tzinfo=tz3)
        t_to = datetime(2026, 8, 19, 11, 59, 59, tzinfo=tz3)
        filtered = analyze([self.log_path], t_from=t_from, t_to=t_to)
        self.assertEqual(filtered.total, 2)


class WriteJsonReportTest(unittest.TestCase):
    def test_writes_valid_json(self):
        # analyze([]) читает stdin — для теста нужен реальный (пустой) файл
        with tempfile.TemporaryDirectory() as tmp:
            log = _make_log(tmp, [])
            data = analyze([log])
            path = os.path.join(tmp, 'report.json')
            out = write_json_report(data, path)
            self.assertEqual(os.path.abspath(path), out)
            with open(out, encoding='utf-8') as f:
                doc = json.load(f)
        self.assertEqual(doc['meta']['total_requests'], 0)
        self.assertEqual(doc['attacks'], [])

    def test_default_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = _make_log(tmp, [])
            data = analyze([log])
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                out = write_json_report(data)
                self.assertEqual(os.path.basename(out), 'report.json')
                self.assertTrue(os.path.exists(out))
            finally:
                os.chdir(cwd)


class CliJsonOnGarbageTest(unittest.TestCase):
    def test_json_written_even_when_nothing_parses(self):
        # error-лог nginx (не access-формат): контракт --json — отчёт пишется
        # даже когда распарсить нечего (дашборд читает файл всегда)
        from nginxparse import cli as cli_mod
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, 'error.log')
            with open(log, 'w', encoding='utf-8') as f:
                f.write('2026/10/09 01:49:52 [warn] 1993#1993: *1 an upstream response '
                        'is buffered to a temporary file, client: 203.0.113.9, '
                        'server: acme.local, request: "GET / HTTP/1.1"\n')
            out = os.path.join(tmp, 'report.json')
            argv = sys.argv
            sys.argv = ['nginx_log_parser.py', log, '--json', out]
            try:
                cli_mod.main()
            finally:
                sys.argv = argv
            with open(out, encoding='utf-8') as f:
                doc = json.load(f)
        self.assertEqual(doc['meta']['total_requests'], 0)
        self.assertEqual(doc['attacks'], [])


if __name__ == "__main__":
    unittest.main()

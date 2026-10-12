"""Юнит-тесты whois-обогащения (nginxparse/whois.py).

Сеть не нужна: subprocess и кэш замоканы. Только generic-данные.
"""

import tempfile
import unittest
from unittest.mock import patch

from nginxparse import whois as W

# Generic whois-ответ (документированные диапазоны, без реальных данных)
WHOIS_TEXT = """
domain:     example.com
country:    DE
inetnum:    203.0.113.0 - 203.0.113.255
abuse-mailbox: abuse@example-isp.de
OrgAbuseEmail: abuse@example-isp.de
e-mail: fallback@example-isp.de
"""


class ToCidrTest(unittest.TestCase):
    def test_range_to_cidr(self):
        self.assertEqual(W.to_cidr('203.0.113.0 - 203.0.113.255'), '203.0.113.0/24')

    def test_multi_block_range(self):
        # диапазон, покрывающий два блока /24 -> два CIDR через запятую
        res = W.to_cidr('203.0.0.0 - 203.0.1.255')
        self.assertEqual(res, '203.0.0.0/23')

    def test_plain_cidr_passthrough(self):
        self.assertEqual(W.to_cidr('203.0.113.0/24'), '203.0.113.0/24')

    def test_na_passthrough(self):
        self.assertEqual(W.to_cidr('N/A'), 'N/A')
        self.assertEqual(W.to_cidr(''), '')

    def test_invalid_returns_as_is(self):
        self.assertEqual(W.to_cidr('мусор'), 'мусор')


class WhoisAbuseTest(unittest.TestCase):
    def test_country_subnet_abuse(self):
        with patch.object(W, 'run_whois_raw', return_value=WHOIS_TEXT):
            country, subnets, abuses = W.whois_abuse('203.0.113.7')
        self.assertEqual(country, 'DE')
        self.assertEqual(subnets, '203.0.113.0/24')
        # abuse-mailbox и OrgAbuseEmail дедуплицируются
        self.assertEqual(abuses, ['abuse@example-isp.de'])

    def test_fallback_only_if_no_primary(self):
        text = WHOIS_TEXT.replace('abuse-mailbox: abuse@example-isp.de\n', '') \
                         .replace('OrgAbuseEmail: abuse@example-isp.de\n', '')
        with patch.object(W, 'run_whois_raw', return_value=text):
            _, _, abuses = W.whois_abuse('203.0.113.7')
        self.assertEqual(abuses, ['fallback@example-isp.de'])

    def test_no_whois_output(self):
        with patch.object(W, 'run_whois_raw', return_value=''):
            country, subnets, abuses = W.whois_abuse('203.0.113.7')
        self.assertEqual(country, 'N/A')
        self.assertEqual(abuses, ['N/A'])


class CacheTest(unittest.TestCase):
    def test_cache_hit_skips_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_file = f'{tmp}/.whois_cache.json'
            with open(cache_file, 'w') as f:
                import json
                import time
                json.dump({'203.0.113.7': {'t': time.time(), 'out': 'cached-out'}}, f)
            with patch.object(W, 'CACHE_FILE', cache_file), \
                 patch.object(W, '_do_whois', side_effect=AssertionError('не должен зваться')):
                out = W.run_whois_raw('203.0.113.7')
            self.assertEqual(out, 'cached-out')

    def test_no_cache_bypasses(self):
        with patch.object(W, '_do_whois', return_value='fresh-out') as m:
            out = W.run_whois_raw('203.0.113.7', use_cache=False)
        self.assertEqual(out, 'fresh-out')
        m.assert_called_once_with('203.0.113.7')

    def test_missing_utility_returns_empty(self):
        # whois отсутствует в системе -> пустой ответ, не исключение
        with patch.object(W.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertEqual(W._do_whois('203.0.113.7'), '')


if __name__ == "__main__":
    unittest.main()

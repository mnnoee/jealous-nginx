"""Юнит-тесты парсинга строк access-лога nginx.

Только синтетические данные (generic-домены, RFC 5737/3849-адреса) —
никаких реальных клиентских логов.
"""

import unittest

from nginxparse.parse_utils import mask16, mask24, net_address, parse, parse_dt, parse_ts

# Формат с доменом: IP - user [date] host "REQUEST" status bytes "referer" "UA" "xff" rt=.. ut=..
# (host без кавычек — как в реальном логе и как ожидает LINE_RE)
LINE_WITH_HOST = (
    '203.0.113.7 - - [19/Aug/2026:11:11:11 +0300] acme.local '
    '"GET /index.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0" "-" rt=0.1 ut=0.2'
)
# Формат combined (без домена): IP - user [date] "REQUEST" status bytes "referer" "UA"
LINE_COMBINED = (
    '198.51.100.42 - - [19/Aug/2026:12:00:00 +0300] '
    '"POST /wp-login.php HTTP/1.1" 403 512 "http://acme.local/" "curl/8.0"'
)


class ParseTest(unittest.TestCase):
    def test_line_with_host(self):
        r = parse(LINE_WITH_HOST)
        self.assertEqual(r["ip"], "203.0.113.7")
        self.assertEqual(r["host"], "acme.local")
        self.assertEqual(r["path"], "/index.php")
        self.assertEqual(r["status"], "200")
        self.assertEqual(r["bytes"], 1234)

    def test_line_combined(self):
        r = parse(LINE_COMBINED)
        self.assertEqual(r["ip"], "198.51.100.100"[:0] + "198.51.100.42")
        self.assertEqual(r["path"], "/wp-login.php")
        self.assertEqual(r["status"], "403")

    def test_garbage_returns_none(self):
        self.assertIsNone(parse("не лог вообще"))
        self.assertIsNone(parse(""))

    def test_dash_bytes_is_zero(self):
        line = LINE_COMBINED.replace("512", "-")
        self.assertEqual(parse(line)["bytes"], 0)


class MaskTest(unittest.TestCase):
    def test_mask16_ipv4(self):
        self.assertEqual(mask16("203.0.113.7"), "203.0.0.0")

    def test_mask24_ipv4(self):
        self.assertEqual(mask24("203.0.113.7"), "203.0.113.0")

    def test_net_address_slash24(self):
        self.assertEqual(net_address("203.0.113.7", 24), "203.0.113.0")

    def test_net_address_invalid_falls_back(self):
        self.assertEqual(net_address("not-an-ip", 24), "not-an-ip")


class TimestampTest(unittest.TestCase):
    def test_combined_format(self):
        # parse_ts принимает полную строку лога (дата в квадратных скобках)
        ts = parse_ts('1.2.3.4 - - [19/Aug/2026:11:11:11 +0300] "GET / HTTP/1.1" 200 1')
        self.assertIsNotNone(ts)
        self.assertEqual(ts.year, 2026)
        self.assertEqual(ts.hour, 11)

    def test_no_brackets_returns_none(self):
        self.assertIsNone(parse_ts("19/Aug/2026:11:11:11 +0300"))

    def test_garbage(self):
        self.assertIsNone(parse_ts("мусор"))


class ParseDtTest(unittest.TestCase):
    """Форматы --from/--to, задокументированные в README."""

    def test_full_datetime(self):
        dt = parse_dt("19.08.2026 11:11:11")
        self.assertEqual((dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second),
                         (2026, 8, 19, 11, 11, 11))

    def test_datetime_without_seconds(self):
        # 19.08.2026 11:11 — README документирует, регэкс принимал, strptime падал
        dt = parse_dt("19.08.2026 11:11")
        self.assertEqual((dt.year, dt.month, dt.day, dt.hour, dt.minute), (2026, 8, 19, 11, 11))
        self.assertEqual(dt.second, 0)

    def test_date_only_uses_default_time(self):
        dt = parse_dt("19.08.2026")
        self.assertEqual((dt.hour, dt.minute, dt.second), (0, 0, 0))
        dt_end = parse_dt("19.08.2026", is_end=True)
        self.assertEqual((dt_end.hour, dt_end.minute, dt_end.second), (23, 59, 59))

    def test_combined_format(self):
        self.assertEqual(parse_dt("19/Aug/2026:11:11:11 +0300").hour, 11)

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            parse_dt("мусор")


if __name__ == "__main__":
    unittest.main()

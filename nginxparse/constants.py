"""Константы: regex-паттерны, пороги, форматы дат."""

import re

VERSION = '1.2.0'

TOP_NETWORKS = 20
TOP_REQUESTS = 10
TOP_UA = 5
SCANNER_THRESHOLD = 5
SCANNER_PATHS_LIMIT = 20
DEFAULT_PATH = 'logs'
TIME_FMT = '%d/%b/%Y:%H:%M:%S %z'
ANOMALY_4XX_KB = 50
ANOMALY_3XX_KB = 1
ANOMALY_2XX_MB = 1

BRUTE_FORCE_THRESHOLD = 3
SCAN_SHELLS_THRESHOLD = 10
XMLRPC_THRESHOLD = 50
REDIRECT_LOOP_THRESHOLD = 10

# Две ветви вместо одной: host (если есть в формате лога) берётся только когда
# дальше идёт запрос в кавычках, иначе метод уезжал в host, а в path оставался
# хвост ' HTTP/1.1"'.
LINE_RE = re.compile(
    r'^(?P<ip>\S+) - \S+ \[[^\]]+\]'
    r'(?:'
    r'(?:\s+(?P<host>[^"\s]+))?\s+"(?P<request>[^"]*)"'
    r'|'
    r'\s+(?P<request2>\S+(?:\s+\S+)*?)'
    r')'
    r'\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

TS_RE = re.compile(r'\[([^\]]+)\]')

SUSPICIOUS_RE = re.compile(
    r'(?i)(\.php|\.asp|\.aspx|\.jsp|\.jspx|\.cgi|\.sh|\.pl|\.py|\.env|\.bak|\.sql)'
    r'|/wp-(login|admin|includes|content/plugins|content/themes|config)'
    r'|xmlrpc|\.git|/etc/|passwd|\.htaccess|/shell|c99|/cmd|/config|/admin|/administrator'
)

WHOIS_FIELDS = re.compile(
    r'(?i)^\s*(inetnum|inet6num|netname|orgname|org-name|descr|role|org-tech-name|'
    r'mnt-by|country|cidr|admin-c|tech-c)\s*:'
)

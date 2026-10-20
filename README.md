# jealous-nginx

[![CI](https://github.com/mnnoee/jealous-nginx/actions/workflows/ci.yml/badge.svg)](https://github.com/mnnoee/jealous-nginx/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.2.0-green.svg)](CHANGELOG.md)

> Part of the [Jealous Moon](https://github.com/mnnoee) toolkit — offline
> server and domain diagnostics.

Interactive nginx access log parser: traffic analysis by /16 and /24 subnets,
detailed breakdown per network range, scanner and SEO-bot detection,
whois enrichment with subnet owner data, time and IP version (IPv4/IPv6)
filtering.

> [README на русском](README.ru.md) — полная документация.

## Features

- Traffic top by /16 and /24 networks, detailed breakdown per range
  (default: compact, one line per network; `--full` for the long form).
  Size of the top is set with `--top N`, masks are chosen with `--16` and `--24`
- Scanner and SEO-bot detection (compact by default: path count plus 3
  examples per network; all paths with `--full`), attack classification
  (BRUTE-FORCE, SCAN-SHELLS, XMLRPC-ABUSE, REDIRECT-LOOP)
- 503 report: hourly chronology, top IPs hit with 503 and their
  surrounding requests
- whois enrichment: subnet owners, abuse contacts (cached, batch mode)
- Time range and IP version filtering, redirects, minute/hour stats
- Human-readable report + machine-readable JSON export
- Offline: works on log files only (whois enrichment is optional)

## Install

Not on PyPI yet (planned). Install straight from GitHub:

```bash
pip install git+https://github.com/mnnoee/jealous-nginx.git
```

Or run straight from a clone:

```bash
python3 nginx_log_parser.py access.log
```

## Usage

```bash
jealous-nginx access.log                  # interactive report
jealous-nginx access.log --from 19.08.2026 --to 20.08.2026
jealous-nginx access.log --16 --top 5     # only /16, top 5 networks
jealous-nginx access.log --full           # full breakdown, all scanner paths
jealous-nginx access.log --report-503     # 503 chronology and affected IPs
jealous-nginx access.log --whois          # whois enrichment
jealous-nginx access.log --json out.json  # machine-readable report
jealous-nginx --help                      # all options
```

## Example log

```log
# with host: IP - user [date] host "REQUEST" status bytes "referer" "UA" "xff" rt=.. ut=..
203.0.113.7 - - [19/Aug/2026:11:11:11 +0300] acme.local "GET /index.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0" "-" rt=0.1 ut=0.2
# combined (no host)
198.51.100.42 - - [19/Aug/2026:12:00:00 +0300] "POST /wp-login.php HTTP/1.1" 403 512 "http://acme.local/" "curl/8.0"
```

IP addresses in examples are documentation ranges (RFC 5737), not real data.

## Ideas & suggestions

Have an idea for the project? Open an issue — suggestions for new report
sections, detections, export formats and integrations are welcome.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.

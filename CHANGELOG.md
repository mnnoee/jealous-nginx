# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.3.0] - 2026-11-18

### Added
- Multilingual interface with Russian and English output. The language is
  chosen from the locale (`LC_ALL`, `LC_MESSAGES`, `LANG`, `LANGUAGE`).
  `LC_ALL=C`, `POSIX` and `en_*` give English, `ru_*` gives Russian.
- `--lang {auto,ru,en}` flag for an explicit output language;
  `auto` (the default) takes the language from the locale.
- `nginxparse/i18n.py` module with string catalogs, locale detection and
  language-aware plurals.

### Changed
- All messages from the CLI, report, 503 report, scanners, attacks, anomalies,
  redirects, statistics and whois hints moved into the translation catalog.
- The English locale now gives English output by default; previously the
  output was always Russian.
- Em dashes replaced with hyphens in interface texts and documentation.

### Fixed
- Word pluralisation now respects the language, with two forms in English
  (`1 request`, `2 requests`), three in Russian.

## [1.2.1] - 2026-11-02

### Changed
- Report labels clarified. `/16` is IPv4 `/16` (IPv6 `/48`),
  `/24` is IPv4 `/24` (IPv6 `/64`).

### Fixed
- Subnet auto-detection corrected. IPv4 masks `/16`, `/24` and IPv6
  `/48`, `/64`.

## [1.2.0] - 2026-10-12

### Added
- Project packaging with `pyproject.toml` (PEP 621), installation via
  `pip install jealous-nginx` and the `jealous-nginx` console command.
- `--version` flag in the CLI.
- GPL-3.0-or-later license (`LICENSE`, `NOTICE`).
- `CHANGELOG.md` and `CONTRIBUTING.md`.
- First unit tests (log line parsing, /16 /24 masks, date formats).
- CI covers a Python 3.9-3.13 matrix, ruff + tests + CLI smoke test.

### Changed
- The version is now defined in one place - `nginxparse/constants.py`
  (`VERSION`); `nginxparse/__init__.py` re-exports it as `__version__`,
  and `pyproject.toml` reads it via `[tool.setuptools.dynamic]`.

### Fixed
- `parse_dt` accepted time without seconds (`19.08.2026 11:11`) in the regex
  but failed in `strptime`, even though the README documents this format.
  Seconds are now padded with zeros.
- `whois_hint()` referenced the removed `whois_module.py`; it now points to
  `python3 -m nginxparse.whois`.
- `LINE_RE` distinguishes host and request. Host is taken only when a quoted
  request follows, otherwise the method slipped into host and the path kept
  the trailing ` HTTP/1.1"`.

## [1.1.0] - 2026-09-14

### Added
- Machine-readable JSON report (`--json [PATH]`).

### Changed
- The project used to be one large monolithic script that became harder to
  maintain as it grew. It was split into the `nginxparse/` package (12 modules)
  with identical behaviour. Output is bit-for-bit identical to the original.
  `nginx_log_parser.py` is kept as a thin wrapper for backward compatibility.

[Unreleased]: https://github.com/mnnoee/jealous-nginx/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/mnnoee/jealous-nginx/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/mnnoee/jealous-nginx/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/mnnoee/jealous-nginx/releases/tag/v1.2.0

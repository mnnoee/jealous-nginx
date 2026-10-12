# Changelog

Все заметные изменения проекта документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

## [1.2.0] — 2026-10-12

### Added
- Упаковка проекта: `pyproject.toml` (PEP 621), установка через
  `pip install jealous-nginx` и консольная команда `jealous-nginx`.
- Флаг `--version` в CLI.
- Лицензия GPL-3.0-or-later (`LICENSE`, `NOTICE`).
- `CHANGELOG.md` и `CONTRIBUTING.md`.
- Первые юнит-тесты (парсинг строк лога, маски /16 /24, форматы дат).
- CI: матрица Python 3.9–3.13, ruff + тесты + smoke-тест CLI.

### Changed
- Версия теперь задаётся в одном месте — `nginxparse/constants.py`
  (`VERSION`); `nginxparse/__init__.py` реэкспортирует её как
  `__version__`, `pyproject.toml` читает через `[tool.setuptools.dynamic]`.

### Fixed
- `parse_dt` принимал время без секунд (`19.08.2026 11:11`) в регэкспе,
  но падал в `strptime`, хотя README этот формат документирует. Теперь
  секунды дополняются нулями.
- `whois_hint()` ссылался на удалённый `whois_module.py`; теперь
  указывает на `python3 -m nginxparse.whois`.
- `LINE_RE` различает host и request: host берётся только когда дальше
  идёт запрос в кавычках, иначе метод уезжал в host, а в path оставался
  хвост ` HTTP/1.1"`.

## [1.1.0] — 2026-09-14

### Added
- Машиночитаемый JSON-отчёт (`--json [PATH]`).

### Changed
- Монолит разбит на пакет `nginxparse/` (12 модулей); вывод бит-в-бит
  идентичен оригиналу. `nginx_log_parser.py` — тонкая обёртка для
  обратной совместимости.

## [1.0.0] и ранее

См. историю git.

[Unreleased]: https://github.com/mnnoee/jealous-nginx/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/mnnoee/jealous-nginx/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/mnnoee/jealous-nginx/releases/tag/v1.1.0

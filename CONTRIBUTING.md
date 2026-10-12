# Участие в разработке

## Как предлагать идеи/фичи

Создайте Issue в репозитории с кратким описанием проблемы и желаемого поведения.

## Как предлагать код

Отправьте Pull Request с описанием изменений. До мержа убедитесь, что:

```bash
# тесты
python -m pytest

# линтер
ruff check .
```

- Код проходит тесты и линтер
- Описание PR содержит контекст: что было, что стало, зачем
- `detect_*`/`find_*` функции возвращают структурированные данные,
  `print_*` только форматируют — новая фича = новая пара функций,
  а не разрастание существующих файлов

## Структура проекта

```
nginx_log_parser.py       тонкая CLI-обёртка
nginxparse/
  __init__.py             фасад: VERSION, NginxLogParser, analyze, build_report, main
  constants.py            VERSION, regex-паттерны, пороги
  parse_utils.py          stateless-утилиты: парсинг строк, IP-маски, даты, whois
  core.py                 NginxLogParser (сбор данных) + analyze()
  scanners.py             детекция сканеров и SEO-ботов
  attacks.py              классификация атак
  anomalies.py            детекция аномальных ответов
  redirects.py            анализ цепочек редиректов
  stats.py                поминутная/почасовая статистика
  whois.py                whois-обогащение (кэш, abuse-контакты, batch)
  json_export.py          машиночитаемый JSON-отчёт
  report.py               оркестратор отчёта (print_* функции)
  cli.py                  argparse + main()
tests/                    юнит-тесты на синтетических данных
pyproject.toml            упаковка, версия, pytest, ruff
.github/workflows/ci.yml  CI: матрица 3.9–3.13, lint + тесты + smoke
LICENSE / NOTICE          GPL-3.0-or-later
CHANGELOG.md              история изменений
CONTRIBUTING.md           как участвовать в разработке
```

## Важно: конфиденциальность access-логов

Access-логи содержат реальные IP, User-Agent и пути. Если PR или Issue
включает примеры логов или вывод отчёта, **обязательно** перед публикацией:

- заменяйте реальные IP на документированные диапазоны примеров
  (`203.0.113.0/24`, `198.51.100.0/24`, `2001:db8::/32`)
- заменяйте реальные домены на `example.com` / `example.local`
- в тестах и фикстурах — только синтетические данные, никаких реальных логов

## Версионирование и релизы

- SemVer: `MAJOR.MINOR.PATCH`. Источник истины — `VERSION` в
  `nginxparse/constants.py`; `pyproject.toml` читает её автоматически,
  руками версию нигде дублировать не нужно.
- Каждое изменение — запись в `CHANGELOG.md` (Keep a Changelog).
- Релиз: обновить `VERSION` -> запись в CHANGELOG -> тег `vX.Y.Z`.

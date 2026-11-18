"""Локализация вывода ru + eng"""

import os

DEFAULT_LANG = 'en'
LANG_EN = 'en'
LANG_RU = 'ru'
LANGUAGES = (LANG_RU, LANG_EN)
ENV_VARS = ('LC_ALL', 'LC_MESSAGES', 'LANG', 'LANGUAGE')

_RU = {
    # общее
    'data.none': 'Нет данных.',
    'not_found': '  Не найдено.',

    # CLI: справка и подсказки
    'cli.desc': 'Парсер access-логов nginx (интерактивный)',
    'cli.paths': 'файлы или каталоги с логами (по умолчанию - интерактивный выбор)',
    'cli.from': 'начало диапазона времени',
    'cli.to': 'конец диапазона времени',
    'cli.summary': 'сводка по каждому access-логу отдельно',
    'cli.hourly': 'запросы по часам (N - последних часов, 0 = все)',
    'cli.whois': 'whois для указанных сетей/IP (без анализа логов)',
    'cli.whois_cidr': 'обогатить топы /16 и /24 whois-данными (N сетей)',
    'cli.proto': 'фильтр трафика: all | ipv4 | ipv6 (по умолчанию all)',
    'cli.skip403': 'исключить запросы с HTTP 403 из статистики',
    'cli.raw': 'все строки лога для конкретного IP',
    'cli.per_minute': 'запросы по минутам (N - последних минут, 0 = все)',
    'cli.redirects': 'показать цепочки редиректов (301->301->404)',
    'cli.report_503': 'отчёт по 503 ошибкам (хронология, топ IP с их соседними запросами)',
    'cli.nets16': 'включить разбор по /16 (без флагов --16/--24 показываются обе)',
    'cli.nets24': 'включить разбор по /24 (без флагов --16/--24 показываются обе)',
    'cli.top': 'размер топа сетей и детального разбора (по умолчанию 20)',
    'cli.full': 'полный (некомпактный) детальный разбор и все пути сканеров',
    'cli.scanners': 'сколько сетей-сканеров показывать (по умолчанию 10, 0 - все)',
    'cli.json': 'записать машиночитаемый JSON-отчёт (по умолчанию report.json)',
    'cli.lang': 'язык вывода: auto | ru | en (по умолчанию auto - по локали)',
    'cli.no_logs': 'Логи не найдены в текущем каталоге.',
    'cli.found': 'Найдено логов: {n}',
    'cli.all_files': 'все файлы',
    'cli.quit': 'выход',
    'cli.choose': 'Выберите файл: ',
    'cli.bad_input': 'Некорректный ввод.',
    'cli.json_written': 'JSON-отчёт записан в: {path}',

    # основной отчёт
    'report.total': 'Всего запросов: {total}, уникальных сетей: /16 (IPv6 /48): {n16}, /24 (IPv6 /64): {n24}',
    'report.top_networks16': 'Топ сетей (IPv4 /16, IPv6 /48):',
    'report.top_networks24': 'Топ сетей (IPv4 /24, IPv6 /64):',
    'report.detail16': 'Детальный разбор (IPv4 /16, IPv6 /48, топ {n}):',
    'report.detail24': 'Детальный разбор (IPv4 /24, IPv6 /64, топ {n}):',
    'report.top_n': '{title} (топ {n}):',
    'report.top_ua': 'Топ-{n} User-Agent:',
    'report.ua_inline': 'UA: {uas}',
    'report.ip': 'IP: {net}',
    'report.request_count': 'Кол-во запросов: {cnt}',
    'report.top_requests': 'Топ {n} запросов:',
    'report.ua_top': 'UserAgent (топ {n}):',
    'report.raw_title': 'Все запросы от {ip} ({count} за период):',

    # отчёт по 503
    'r503.not_found': '503 ошибок не найдено.',
    'r503.title': '  ОТЧЁТ ПО АНАЛИЗУ 503 ОШИБОК',
    'r503.stats': '--- ОБЩАЯ СТАТИСТИКА ---',
    'r503.total': '  Всего запросов:        {n}',
    'r503.with_503': '  Запросов с 503:        {n}',
    'r503.unique_ips': '  Уникальных IP с 503:   {n}',
    'r503.share': '  Доля 503 от трафика:   {pct}',
    'r503.chronology': '--- ХРОНОЛОГИЯ 503 ОШИБОК ---',
    'r503.main_scanner': '--- ГЛАВНЫЙ СКАНЕР: {ip} ---',
    'r503.org': '  Организация:        {org}',
    'r503.unknown_org': 'неизвестно',
    'r503.attack_start': '  Начало атаки:      {dt}',
    'r503.attack_end': '  Конец атаки:       {dt}',
    'r503.requests': '  Всего запросов:    {n}',
    'r503.peak': '  Пиковая нагрузка: {n} req/min ({time})',
    'r503.responses': '  Ответы сервера на сканер:',
    'r503.top_paths': '  Топ сканируемых путей:',
    'r503.other_scanners': '--- ДРУГИЕ СКАНЕРЫ ---',
    'r503.scanner_line': '  {ip:<{w}} {n:>5} {word}  {org}',
    'r503.scanner_line_no_org': '  {ip:<{w}} {n:>5} {word}',
    'r503.second_scanner': '--- ВТОРОЙ СКАНЕР: {ip} ---',
    'r503.second_requests': '  Всего запросов: {n}',
    'r503.top_ips': '--- ТОП IP, ПОЛУЧИВШИХ 503 ---',
    'r503.top_countries': '--- ТОП СТРАН ПО 503 ОШИБКАМ ---',
    'r503.top_paths_503': '--- ТОП ПУТЕЙ С 503 ОШИБКАМИ ---',
    'r503.neighbors': '--- ТОП IP, ПОЛУЧИВШИХ 503, И ИХ СОСЕДНИЕ ЗАПРОСЫ ---',
    'r503.ip_responses': '  {ip} - {n} {word} 503:',
    'r503.end': '  КОНЕЦ ОТЧЁТА',

    # сводка по файлам
    'summary.no_files': 'Access-логи не найдены.',
    'summary.title': 'Сводка по {n} access-логам:',
    'summary.file': 'Файл: {path}',
    'summary.unique_ips': '  Общее количество уникальных ip: {n}',
    'summary.requests': '  Запросов: {n}',
    'summary.ipv6': '  ipv6: {n}',
    'summary.top_ips': '  Топ-10 ip:',
    'summary.top_ua': '  Топ-10 user-agent:',

    # аномалии
    'anomalies.title': '--- АНОМАЛЬНЫЕ ОТВЕТЫ ---',
    'anomalies.status': 'Статус',
    'anomalies.size': 'Размер',
    'anomalies.count': 'Кол-во',
    'anomalies.example': 'Пример пути',
    'anomalies.more_paths': ' ... ({n} {word})',

    # атаки
    'attacks.title': '--- ТИПЫ АТАК ---',
    'attacks.note': 'эвристика по порогам, не истина: метка - повод для проверки, а не вердикт',
    'attacks.attempts': '{n} {word}',
    'attacks.requests': '{n} запросов',

    # сканеры
    'scanners.title_limited': 'Выявленные сканеры (топ {limit} из {total}, все - с --scanners 0):',
    'scanners.title': 'Выявленные сканеры:',
    'scanners.seo_bot': '{net} <-------------- вероятно, SEO-бот, а не сканер',
    'scanners.paths': '  подозрительных путей: {n}; примеры: ',

    # статистика
    'stats.by_hour': 'Запросы по часам (UTC):',
    'stats.by_minute': 'Запросы по минутам (UTC):',
    'stats.no_data': '  Нет данных.',
    'stats.rhythm': 'Стабильный ритм: {mean:.1f} req/min (откл={stdev:.1f}) - вероятно, автоматизация',

    # редиректы
    'redirects.title': 'Цепочки редиректов (301->301->404):',
    'redirects.heavy': '  <- тяжёлый ответ!',
    'redirects.total': 'Всего цепочек: {n}',

    # даты и whois-утилиты
    'date.invalid': 'Некорректная дата: {s!r}. Пример: 19.08.2026 11:11:11',
    'date.invalid_examples': 'Некорректная дата: {s!r}. Примеры: '
                             '19.08.2026 11:11:11 или 19/Aug/2026:11:11:11 +0300',
    'range.title': 'Диапазон времени (можно пропустить, нажав Enter):',
    'range.from_date': '  Дата от (ДД.ММ.ГГГГ): ',
    'range.from_time': '  Время от (ЧЧ:ММ:СС, Enter = 00:00:00): ',
    'range.to_date': '  Дата до (ДД.ММ.ГГГГ): ',
    'range.to_time': '  Время до (ЧЧ:ММ:СС, Enter = 23:59:59): ',
    'whois.not_installed': '[ошибка] whois не установлен',
    'whois.empty': '[пустой ответ]',
    'whois.error': '[ошибка] {e}',

    # модуль whois
    'whois.hint_any': 'Для whois по любой сети/IP: python3 -m nginxparse.whois <сеть>',
    'whois.hint_example': '  например: python3 -m nginxparse.whois 45.148.0.0/16',
    'whois.hint_multi': '  или:      python3 -m nginxparse.whois 45.148.10.0/24 95.108.213.241',
    'whois.hint_cli': '  также:    python3 nginx_log_parser.py --whois 45.148.0.0/16',
    'whois.interactive': 'Интерактивный whois. Введите сеть/IP (q - выход):',
    'whois.prompt': 'whois> ',

    # склонения
    'plural': {
        'request': ('запрос', 'запроса', 'запросов'),
        'response': ('ответ', 'ответа', 'ответов'),
        'attempt': ('попытка', 'попытки', 'попыток'),
        'path': ('путь', 'пути', 'путей'),
    },
}

_EN = {
    # common
    'data.none': 'No data.',
    'not_found': '  Not found.',

    # CLI: help and prompts
    'cli.desc': 'nginx access-log parser (interactive)',
    'cli.paths': 'log files or directories (default: interactive picker)',
    'cli.from': 'start of the time range',
    'cli.to': 'end of the time range',
    'cli.summary': 'per-file summary for each access log',
    'cli.hourly': 'requests by hour (N - last N hours, 0 = all)',
    'cli.whois': 'whois for the given networks/IPs (without log analysis)',
    'cli.whois_cidr': 'enrich /16 and /24 tops with whois data (N networks)',
    'cli.proto': 'traffic filter: all | ipv4 | ipv6 (default: all)',
    'cli.skip403': 'exclude HTTP 403 requests from the statistics',
    'cli.raw': 'all log lines for a specific IP',
    'cli.per_minute': 'requests by minute (N - last N minutes, 0 = all)',
    'cli.redirects': 'show redirect chains (301->301->404)',
    'cli.report_503': '503 report (chronology, top IPs with their neighbouring requests)',
    'cli.nets16': 'include the /16 breakdown (without --16/--24 both are shown)',
    'cli.nets24': 'include the /24 breakdown (without --16/--24 both are shown)',
    'cli.top': 'size of the network top and of the detailed breakdown (default: 20)',
    'cli.full': 'full (non-compact) detailed breakdown and all scanner paths',
    'cli.scanners': 'how many scanner networks to show (default: 10, 0 - all)',
    'cli.json': 'write a machine-readable JSON report (default: report.json)',
    'cli.lang': 'output language: auto | ru | en (default: auto - from the locale)',
    'cli.no_logs': 'No logs found in the current directory.',
    'cli.found': 'Logs found: {n}',
    'cli.all_files': 'all files',
    'cli.quit': 'quit',
    'cli.choose': 'Choose a file: ',
    'cli.bad_input': 'Invalid input.',
    'cli.json_written': 'JSON report written to: {path}',

    # main report
    'report.total': 'Total requests: {total}, unique networks: /16 (IPv6 /48): {n16}, /24 (IPv6 /64): {n24}',
    'report.top_networks16': 'Top networks (IPv4 /16, IPv6 /48):',
    'report.top_networks24': 'Top networks (IPv4 /24, IPv6 /64):',
    'report.detail16': 'Detailed breakdown (IPv4 /16, IPv6 /48, top {n}):',
    'report.detail24': 'Detailed breakdown (IPv4 /24, IPv6 /64, top {n}):',
    'report.top_n': '{title} (top {n}):',
    'report.top_ua': 'Top {n} User-Agents:',
    'report.ua_inline': 'UA: {uas}',
    'report.ip': 'IP: {net}',
    'report.request_count': 'Requests: {cnt}',
    'report.top_requests': 'Top {n} requests:',
    'report.ua_top': 'User-Agent (top {n}):',
    'report.raw_title': 'All requests from {ip} ({count} in the period):',

    # 503 report
    'r503.not_found': 'No 503 errors found.',
    'r503.title': '  503 ERROR ANALYSIS REPORT',
    'r503.stats': '--- GENERAL STATISTICS ---',
    'r503.total': '  Total requests:        {n}',
    'r503.with_503': '  Requests with 503:     {n}',
    'r503.unique_ips': '  Unique IPs with 503:   {n}',
    'r503.share': '  Share of 503:          {pct}',
    'r503.chronology': '--- 503 CHRONOLOGY ---',
    'r503.main_scanner': '--- MAIN SCANNER: {ip} ---',
    'r503.org': '  Organization:       {org}',
    'r503.unknown_org': 'unknown',
    'r503.attack_start': '  Attack start:      {dt}',
    'r503.attack_end': '  Attack end:        {dt}',
    'r503.requests': '  Total requests:    {n}',
    'r503.peak': '  Peak load: {n} req/min ({time})',
    'r503.responses': '  Server responses to the scanner:',
    'r503.top_paths': '  Top scanned paths:',
    'r503.other_scanners': '--- OTHER SCANNERS ---',
    'r503.scanner_line': '  {ip:<{w}} {n:>5} {word}  {org}',
    'r503.scanner_line_no_org': '  {ip:<{w}} {n:>5} {word}',
    'r503.second_scanner': '--- SECOND SCANNER: {ip} ---',
    'r503.second_requests': '  Total requests: {n}',
    'r503.top_ips': '--- TOP IPs THAT GOT 503 ---',
    'r503.top_countries': '--- TOP COUNTRIES BY 503 ERRORS ---',
    'r503.top_paths_503': '--- TOP PATHS WITH 503 ERRORS ---',
    'r503.neighbors': '--- TOP IPs THAT GOT 503 AND THEIR NEIGHBOURING REQUESTS ---',
    'r503.ip_responses': '  {ip} - {n} 503 {word}:',
    'r503.end': '  END OF REPORT',

    # per-file summary
    'summary.no_files': 'No access logs found.',
    'summary.title': 'Summary across {n} access logs:',
    'summary.file': 'File: {path}',
    'summary.unique_ips': '  Unique IPs: {n}',
    'summary.requests': '  Requests: {n}',
    'summary.ipv6': '  ipv6: {n}',
    'summary.top_ips': '  Top-10 IPs:',
    'summary.top_ua': '  Top-10 user-agents:',

    # anomalies
    'anomalies.title': '--- ANOMALOUS RESPONSES ---',
    'anomalies.status': 'Status',
    'anomalies.size': 'Size',
    'anomalies.count': 'Count',
    'anomalies.example': 'Example path',
    'anomalies.more_paths': ' ... ({n} {word})',

    # attacks
    'attacks.title': '--- ATTACK TYPES ---',
    'attacks.note': 'threshold heuristics, not the truth: a label is a reason to check, not a verdict',
    'attacks.attempts': '{n} {word}',
    'attacks.requests': '{n} requests',

    # scanners
    'scanners.title_limited': 'Detected scanners (top {limit} of {total}, all - with --scanners 0):',
    'scanners.title': 'Detected scanners:',
    'scanners.seo_bot': '{net} <-------------- probably an SEO bot, not a scanner',
    'scanners.paths': '  suspicious paths: {n}; examples: ',

    # statistics
    'stats.by_hour': 'Requests by hour (UTC):',
    'stats.by_minute': 'Requests by minute (UTC):',
    'stats.no_data': '  No data.',
    'stats.rhythm': 'Stable rhythm: {mean:.1f} req/min (stdev={stdev:.1f}) - probably automation',

    # redirects
    'redirects.title': 'Redirect chains (301->301->404):',
    'redirects.heavy': '  <- heavy response!',
    'redirects.total': 'Total chains: {n}',

    # dates and whois helpers
    'date.invalid': 'Invalid date: {s!r}. Example: 19.08.2026 11:11:11',
    'date.invalid_examples': 'Invalid date: {s!r}. Examples: '
                             '19.08.2026 11:11:11 or 19/Aug/2026:11:11:11 +0300',
    'range.title': 'Time range (press Enter to skip):',
    'range.from_date': '  Date from (DD.MM.YYYY): ',
    'range.from_time': '  Time from (HH:MM:SS, Enter = 00:00:00): ',
    'range.to_date': '  Date to (DD.MM.YYYY): ',
    'range.to_time': '  Time to (HH:MM:SS, Enter = 23:59:59): ',
    'whois.not_installed': '[error] whois is not installed',
    'whois.empty': '[empty response]',
    'whois.error': '[error] {e}',

    # whois module
    'whois.hint_any': 'For whois on any network/IP: python3 -m nginxparse.whois <network>',
    'whois.hint_example': '  e.g.:     python3 -m nginxparse.whois 45.148.0.0/16',
    'whois.hint_multi': '  or:       python3 -m nginxparse.whois 45.148.10.0/24 95.108.213.241',
    'whois.hint_cli': '  also:     python3 nginx_log_parser.py --whois 45.148.0.0/16',
    'whois.interactive': 'Interactive whois. Enter a network/IP (q - quit):',
    'whois.prompt': 'whois> ',

    # plurals
    'plural': {
        'request': ('request', 'requests', 'requests'),
        'response': ('response', 'responses', 'responses'),
        'attempt': ('attempt', 'attempts', 'attempts'),
        'path': ('path', 'paths', 'paths'),
    },
}

_CATALOG = {LANG_RU: _RU, LANG_EN: _EN}


def lang_from_locale(value):
    """Превращает строку локали POSIX в поддерживаемый язык."""
    if not value:
        return DEFAULT_LANG
    for item in value.split(':'):
        item = item.strip()
        if not item:
            continue
        base = item.split('.', 1)[0].split('@', 1)[0].lower()
        if base in ('c', 'posix'):
            return LANG_EN
        if base.startswith('ru'):
            return LANG_RU
        if base.startswith('en'):
            return LANG_EN
    return DEFAULT_LANG


def detect_lang(env=None):
    """Определяет язык по переменным локали (первая непустая побеждает)."""
    env = os.environ if env is None else env
    for var in ENV_VARS:
        value = env.get(var)
        if value:
            return lang_from_locale(value)
    return DEFAULT_LANG


def resolve_lang(value=None):
    if not value or value == 'auto':
        return detect_lang()
    value = value.strip().lower()
    if value in _CATALOG:
        return value
    return lang_from_locale(value)


_lang = detect_lang()


def get_lang():
    return _lang


def set_lang(lang):
    global _lang
    _lang = resolve_lang(lang)
    return _lang


def t(key, **kwargs):
    template = _CATALOG[_lang].get(key)
    if template is None:
        template = _CATALOG[DEFAULT_LANG].get(key, key)
    return template.format(**kwargs) if kwargs else template


def plural(n, one, few, many):
    n = abs(int(n))
    if _lang == LANG_RU:
        if n % 10 == 1 and n % 100 != 11:
            return one
        if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
            return few
        return many
    return one if n == 1 else many


def plural_word(n, key):
    one, few, many = _CATALOG[_lang]['plural'][key]
    return plural(n, one, few, many)

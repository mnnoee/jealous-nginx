"""Почасовая и поминутная статистика запросов."""


def print_hourly(hours, last_n=0):
    items = sorted(hours.items())
    if last_n:
        items = items[-last_n:]
    print()
    print('=' * 41)
    print('Запросы по часам (UTC):')
    print('=' * 41)
    w = len(str(max(hours.values()))) if hours else 1
    for h, c in items:
        print(f'{c:>{w}}  {h.strftime("%d/%b/%Y %H:00")}')


def print_per_minute(minutes, last_n=0):
    items = sorted(minutes.items())
    if last_n:
        items = items[-last_n:]
    print()
    print('=' * 41)
    print('Запросы по минутам (UTC):')
    print('=' * 41)
    if not items:
        print('  Нет данных.')
        return
    w = len(str(max(c for _, c in items)))
    vals = []
    for dt, c in items:
        bar = '#' * c
        print(f'{c:>{w}}  {dt.strftime("%d/%b/%Y %H:%M")}  {bar}')
        vals.append(c)
    if len(vals) >= 5:
        import statistics
        mean = statistics.mean(vals)
        stdev = statistics.stdev(vals) if len(vals) > 1 else 0
        if mean > 0 and stdev / mean < 0.2:
            print()
            print(f'Стабильный ритм: {mean:.1f} req/min (откл={stdev:.1f}) — вероятно, автоматизация')

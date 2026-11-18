"""Детекция аномальных размеров ответов."""

from .constants import ANOMALY_2XX_MB, ANOMALY_3XX_KB, ANOMALY_4XX_KB
from .i18n import plural_word, t


def detect_anomalies(data):
    """Возвращает структурированный список {status, label, count, example}."""
    anomalies = []
    for status, sizes in data.status_bytes.items():
        paths = data.status_paths[status]
        if status.startswith('4'):
            heavy = [s for s in sizes if s > ANOMALY_4XX_KB * 1024]
            label = f'>{ANOMALY_4XX_KB}KB'
        elif status.startswith('3'):
            heavy = [s for s in sizes if s > ANOMALY_3XX_KB * 1024]
            label = f'>{ANOMALY_3XX_KB}KB'
        elif status.startswith('2'):
            heavy = [s for s in sizes if s > ANOMALY_2XX_MB * 1024 * 1024]
            label = f'>{ANOMALY_2XX_MB}MB'
        else:
            continue
        if heavy:
            examples = ', '.join(sorted(paths)[:5])
            if len(paths) > 5:
                examples += t('anomalies.more_paths', n=len(paths),
                              word=plural_word(len(paths), 'path'))
            anomalies.append({'status': status, 'label': label,
                              'count': len(heavy), 'example': examples})
    return anomalies


def print_anomalies(data):
    anomalies = detect_anomalies(data)
    if not anomalies:
        return
    print()
    print(t('anomalies.title'))
    print(f'{t("anomalies.status"):<8} {t("anomalies.size"):<12} '
          f'{t("anomalies.count"):<8} {t("anomalies.example")}')
    for item in sorted(anomalies, key=lambda x: -x['count']):
        print(f"{item['status']:<8} {item['label']:<12} {item['count']:<8} {item['example']}")

"""JSON-экспорт: машиночитаемый отчёт (как в strace_parser)."""

import json
import os

from .anomalies import detect_anomalies
from .attacks import classify_attacks
from .constants import TOP_NETWORKS, TOP_REQUESTS, TOP_UA, VERSION
from .redirects import find_redirect_chains
from .scanners import detect_scanners


def _ts(v):
    return v.isoformat() if hasattr(v, "isoformat") else v


def _req_list(counter, limit):
    """(ip, host, path) -> [{ip, host, path, count}]."""
    return [
        {"ip": ip, "host": host or None, "path": path, "count": cnt}
        for (ip, host, path), cnt in counter.most_common(limit)
    ]


def _net_detail(net_counter, req_map, ua_map, paths_map, limit=TOP_NETWORKS):
    out = []
    for net, cnt in net_counter.most_common(limit):
        out.append({
            "network": net,
            "count": cnt,
            "top_requests": _req_list(req_map[net], TOP_REQUESTS),
            "top_paths": [
                {"path": p, "count": c}
                for p, c in paths_map[net].most_common(TOP_REQUESTS)
            ],
            "top_ua": [
                {"ua": ua, "count": c}
                for ua, c in ua_map[net].most_common(TOP_UA)
            ],
        })
    return out


def _top_list(counter, limit=TOP_NETWORKS):
    return [{"network": net, "count": cnt} for net, cnt in counter.most_common(limit)]


def _attacks(data):
    return [{"type": t, "ip": ip, "detail": d, "path": p}
            for t, ip, d, p in classify_attacks(data)]


def _redirect_chains(data):
    chains = []
    for ip, path, entries in find_redirect_chains(data.chains):
        chains.append({
            "ip": ip,
            "path": path,
            "chain": [
                {"time": _ts(dt) if dt else None, "status": st, "bytes": b}
                for dt, st, b in entries
            ],
        })
    return chains


def build_json(data, t_from=None, t_to=None, proto="all"):
    """Собирает dict со всеми результатами анализа."""
    top16 = data.net16.most_common(TOP_NETWORKS)
    top24 = data.net24.most_common(TOP_NETWORKS)

    statuses = {}
    for status, sizes in data.status_bytes.items():
        paths = sorted(data.status_paths[status])
        statuses[status] = {
            "count": len(sizes),
            "bytes_total": sum(sizes),
            "bytes_max": max(sizes) if sizes else 0,
            "unique_paths": len(paths),
            "paths": paths[:50],
        }

    return {
        "meta": {
            "version": VERSION,
            "total_requests": data.total,
            "unique_networks_16": len(data.net16),
            "unique_networks_24": len(data.net24),
            "filters": {
                "from": _ts(t_from) if t_from else None,
                "to": _ts(t_to) if t_to else None,
                "proto": proto,
            },
        },
        "top_networks_16": _top_list(data.net16),
        "top_networks_24": _top_list(data.net24),
        "networks_16": _net_detail(data.net16, data.req16, data.ua16, data.paths16),
        "networks_24": _net_detail(data.net24, data.req24, data.ua24, data.paths24),
        "user_agents": [
            {"ua": ua, "count": cnt}
            for ua, cnt in data.ua_all.most_common(20)
        ],
        "hours": [
            {"time": _ts(dt), "count": cnt}
            for dt, cnt in sorted(data.hours.items())
        ],
        "minutes": [
            {"time": _ts(dt), "count": cnt}
            for dt, cnt in sorted(data.minutes.items())
        ],
        "statuses": statuses,
        "anomalies": detect_anomalies(data),
        "scanners_16": detect_scanners(data.net16, data.paths16, top16),
        "scanners_24": detect_scanners(data.net24, data.paths24, top24),
        "attacks": _attacks(data),
        "redirect_chains": _redirect_chains(data),
    }


def write_json_report(data, path="report.json", **kwargs):
    """Пишет report.json (машиночитаемый отчёт), возвращает путь к файлу."""
    doc = build_json(data, **kwargs)
    full = os.path.abspath(path)
    with open(full, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, default=str)
    return full

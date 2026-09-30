from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping, Any
import math

from .bounded import increment_bounded
from .storage import read_jsonl


def analyze_files(
    paths: Iterable[str | Path],
    top_n: int = 20,
    rare_threshold: int = 3,
    max_unique_values: int = 100_000,
) -> dict:
    if max_unique_values < 1:
        raise ValueError("max_unique_values must be positive")
    total = 0
    aggregation_limited = False
    host_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    src_ip_counts: Counter[str] = Counter()
    keyword_counts: Counter[str] = Counter()
    for path in paths:
        for event in read_jsonl(path):
            total += 1
            aggregation_limited |= _inc(host_counts, event, "host", max_unique_values)
            aggregation_limited |= _inc(source_counts, event, "source", max_unique_values)
            aggregation_limited |= _inc(user_counts, event, "user", max_unique_values)
            aggregation_limited |= _inc(src_ip_counts, event, "src_ip", max_unique_values)
            text = str(event.get("event") or event.get("_raw") or "").lower()
            for word in ("failed", "error", "denied", "malware", "ransomware", "token", "password"):
                if word in text:
                    keyword_counts[word] += 1
    rare_hosts = [k for k, v in host_counts.items() if v <= rare_threshold]
    anomaly_score = _score(total, keyword_counts)
    return {
        "total_events": total,
        "top_hosts": host_counts.most_common(top_n),
        "top_sources": source_counts.most_common(top_n),
        "top_users": user_counts.most_common(top_n),
        "top_src_ips": src_ip_counts.most_common(top_n),
        "keyword_counts": keyword_counts.most_common(),
        "rare_hosts": rare_hosts[:top_n],
        "aggregation_limited": aggregation_limited,
        "max_unique_values": max_unique_values,
        "model_comparison": [
            {"name": "rules_keywords", "type": "baseline", "score": anomaly_score, "labels_required": False},
            {"name": "frequency_outliers", "type": "statistical", "score": len(rare_hosts), "labels_required": False},
        ],
    }


def _inc(counter: Counter[str], event: Mapping[str, Any], key: str, limit: int) -> bool:
    value = event.get(key)
    if value not in (None, ""):
        return increment_bounded(counter, str(value), limit)
    return False


def _score(total: int, keywords: Counter[str]) -> float:
    if total <= 0:
        return 0.0
    weighted = keywords.get("failed", 0) + keywords.get("error", 0) + keywords.get("denied", 0) * 2
    return round(min(100.0, 100.0 * math.log1p(weighted) / math.log1p(max(total, 1))), 2)


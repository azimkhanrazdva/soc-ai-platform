from __future__ import annotations

from collections import Counter
from pathlib import Path
import json
import time

from .bounded import increment_bounded
from .storage import read_jsonl


PROFILE_FIELDS = ("host", "source", "sourcetype", "user", "src_ip")


def train_profile(
    paths: list[str | Path],
    output_path: str | Path = "reports/model_profile.json",
    max_unique_values: int = 100_000,
) -> dict:
    if max_unique_values < 1:
        raise ValueError("max_unique_values must be positive")
    counts = {field: Counter() for field in PROFILE_FIELDS}
    total = 0
    aggregation_limited = False
    for path in paths:
        for row in read_jsonl(path):
            total += 1
            for field in PROFILE_FIELDS:
                value = row.get(field)
                if value not in (None, ""):
                    aggregation_limited |= increment_bounded(counts[field], str(value), max_unique_values)
    profile = {
        "type": "frequency_profile",
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_events": total,
        "aggregation_limited": aggregation_limited,
        "max_unique_values": max_unique_values,
        "fields": {field: dict(counter.most_common()) for field, counter in counts.items()},
    }
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(profile, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return {
        "output": str(p),
        "total_events": total,
        "fields": list(PROFILE_FIELDS),
        "aggregation_limited": aggregation_limited,
    }


def evaluate_profile(profile_path: str | Path, paths: list[str | Path], output_path: str | Path = "reports/evaluation.json") -> dict:
    profile = json.loads(Path(profile_path).read_text(encoding="utf-8"))
    known = {field: set(values) for field, values in profile.get("fields", {}).items()}
    total = 0
    unseen = Counter()
    for path in paths:
        for row in read_jsonl(path):
            total += 1
            for field in PROFILE_FIELDS:
                value = row.get(field)
                if value not in (None, "") and str(value) not in known.get(field, set()):
                    unseen[field] += 1
    metrics = {
        "model": "frequency_profile",
        "total_events": total,
        "unseen_counts": dict(unseen),
        "unseen_rates": {field: round(unseen.get(field, 0) / total, 6) if total else 0 for field in PROFILE_FIELDS},
        "accuracy_note": "Precision/recall/F1/ROC-AUC require labeled data; this profile reports unsupervised drift/anomaly indicators.",
    }
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(metrics, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return {"output": str(p), **metrics}


def evaluate_labeled(
    paths: list[str | Path],
    label_field: str = "label",
    score_field: str = "score",
    threshold: float = 0.5,
    positive_label: str = "1",
    output_path: str | Path = "reports/labeled_evaluation.json",
) -> dict:
    tp = fp = tn = fn = 0
    total = 0
    for path in paths:
        for row in read_jsonl(path):
            if label_field not in row or score_field not in row:
                continue
            total += 1
            truth = str(row[label_field]).lower() in {positive_label.lower(), "true", "yes", "malicious", "attack"}
            predicted = float(row[score_field]) >= threshold
            if truth and predicted:
                tp += 1
            elif not truth and predicted:
                fp += 1
            elif not truth and not predicted:
                tn += 1
            else:
                fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    metrics = {
        "total_labeled": total,
        "threshold": threshold,
        "positive_label": positive_label,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "roc_auc": round(_roc_auc(_iter_labeled(paths, label_field, score_field, positive_label)), 6) if total else 0.0,
    }
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(metrics, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return {"output": str(p), **metrics}


def _iter_labeled(paths: list[str | Path], label_field: str, score_field: str, positive_label: str):
    for path in paths:
        for row in read_jsonl(path):
            if label_field not in row or score_field not in row:
                continue
            truth = str(row[label_field]).lower() in {positive_label.lower(), "true", "yes", "malicious", "attack"}
            yield truth, float(row[score_field])


def _roc_auc(rows) -> float:
    ranked = sorted(rows, key=lambda row: row[1])
    positive_count = sum(1 for truth, _ in ranked if truth)
    negative_count = len(ranked) - positive_count
    if not positive_count or not negative_count:
        return 0.0
    positive_rank_sum = 0.0
    index = 0
    while index < len(ranked):
        end = index + 1
        while end < len(ranked) and ranked[end][1] == ranked[index][1]:
            end += 1
        average_rank = (index + 1 + end) / 2
        positive_rank_sum += average_rank * sum(1 for truth, _ in ranked[index:end] if truth)
        index = end
    return (positive_rank_sum - positive_count * (positive_count + 1) / 2) / (positive_count * negative_count)

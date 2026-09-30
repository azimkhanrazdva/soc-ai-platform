from __future__ import annotations

from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import math
import os
import shutil
import time
import uuid

from soc_ai.report import write_report
from soc_ai.rules import _finding, _matches, load_rules


KEYWORDS = ("failed", "error", "denied", "malware", "ransomware", "token", "password")
PROFILE_FIELDS = ("host", "source", "sourcetype", "user", "src_ip")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--workers", type=int, default=max(1, min(os.cpu_count() or 1, 8)))
    parser.add_argument("--max-findings", type=int, default=100000)
    parser.add_argument("--top-n", type=int, default=50)
    parser.add_argument("--rare-threshold", type=int, default=3)
    parser.add_argument("--rules", default="configs/detection_rules.json")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    reports_dir = run_dir / "reports"
    data_dir = run_dir / "data"
    manifest_path = reports_dir / "chunk_manifest.json"
    checkpoint_path = data_dir / "splunk_checkpoints.json"
    partial_dir = reports_dir / "accelerated_partials"
    partial_dir.mkdir(parents=True, exist_ok=True)

    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    records = checkpoint.get("chunks", [])
    if not records or any(item.get("status") != "done" for item in records):
        raise RuntimeError("checkpoint is incomplete; refusing accelerated postprocess")
    expected_export_rows = sum(int(item.get("rows") or 0) for item in records)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    chunks = manifest.get("chunks", [])
    if len(chunks) != len(records):
        raise RuntimeError("manifest chunk count differs from checkpoint")

    rules = load_rules(args.rules)
    started = time.time()
    run_id = uuid.uuid4().hex
    log_path = reports_dir / "accelerated_postprocess.log.jsonl"
    _log(log_path, "started", run_id=run_id, chunks=len(chunks), workers=args.workers, expected_rows=expected_export_rows)

    pending = []
    completed = []
    for idx, chunk in enumerate(chunks, start=1):
        partial = partial_dir / (Path(chunk["path"]).name + ".stats.json")
        if _partial_ok(partial, chunk):
            completed.append(partial)
        else:
            pending.append((idx, chunk, str(partial), rules, args.max_findings))
    _log(log_path, "planned", run_id=run_id, pending=len(pending), cached=len(completed))

    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(_process_chunk, *item) for item in pending]
        for future in as_completed(futures):
            payload = future.result()
            completed.append(Path(payload["partial_path"]))
            if payload["index"] % 25 == 0 or payload["index"] == len(chunks):
                _log(log_path, "chunk_done", run_id=run_id, index=payload["index"], rows=payload["rows"], chunk_path=payload["path"])

    partials = [partial_dir / (Path(chunk["path"]).name + ".stats.json") for chunk in chunks]
    merged = _merge_partials(partials, args.top_n, args.rare_threshold, args.max_findings)
    integrity = {
        "manifest": str(manifest_path),
        "ok": not merged["integrity_failures"] and merged["total_events"] == manifest.get("total_rows") == expected_export_rows,
        "verified_rows": merged["total_events"],
        "expected_rows": manifest.get("total_rows"),
        "failures": merged.pop("integrity_failures"),
        "parallel": True,
    }
    if not integrity["ok"]:
        raise RuntimeError("parallel integrity verification failed; inspect accelerated_postprocess.json")

    analysis_path = reports_dir / "analysis.json"
    rules_path = reports_dir / "rule_findings.json"
    profile_path = reports_dir / "model_profile.json"
    evaluation_path = reports_dir / "evaluation.json"
    summary_path = reports_dir / "accelerated_postprocess.json"

    analysis = {
        "total_events": merged["total_events"],
        "top_hosts": merged["host_counts"].most_common(args.top_n),
        "top_sources": merged["source_counts"].most_common(args.top_n),
        "top_users": merged["user_counts"].most_common(args.top_n),
        "top_src_ips": merged["src_ip_counts"].most_common(args.top_n),
        "keyword_counts": merged["keyword_counts"].most_common(),
        "rare_hosts": [k for k, v in merged["host_counts"].items() if v <= args.rare_threshold][: args.top_n],
        "aggregation_limited": False,
        "max_unique_values": "parallel_unbounded_merge",
        "model_comparison": [
            {"name": "rules_keywords", "type": "baseline", "score": _score(merged["total_events"], merged["keyword_counts"]), "labels_required": False},
            {"name": "frequency_outliers", "type": "statistical", "score": sum(1 for v in merged["host_counts"].values() if v <= args.rare_threshold), "labels_required": False},
        ],
    }
    rules_summary = {
        "output": str(rules_path),
        "rules_loaded": len(rules),
        "events_scanned": merged["total_events"],
        "findings_count": merged["findings_count"],
        "findings_by_severity": dict(merged["findings_by_severity"]),
        "findings_truncated": merged["findings_count"] > len(merged["findings"]),
        "findings": merged["findings"],
    }
    profile = {
        "type": "frequency_profile",
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_events": merged["total_events"],
        "aggregation_limited": False,
        "max_unique_values": "parallel_unbounded_merge",
        "fields": {field: dict(merged[f"{field}_counts"].most_common()) for field in PROFILE_FIELDS},
    }
    evaluation = {
        "output": str(evaluation_path),
        "model": "frequency_profile",
        "total_events": merged["total_events"],
        "unseen_counts": {},
        "unseen_rates": {field: 0 for field in PROFILE_FIELDS},
        "accuracy_note": "Precision/recall/F1/ROC-AUC require labeled data; this 400M run uses unsupervised aggregate indicators.",
    }

    _write_json(analysis_path, analysis)
    _write_json(rules_path, rules_summary)
    _write_json(profile_path, profile)
    _write_json(evaluation_path, evaluation)

    report_payload = analysis | {"integrity": integrity, "rules": rules_summary, "evaluation": evaluation, "ingest": {"rows": expected_export_rows, "planned_chunks": len(chunks), "failed_chunks": 0}}
    report = write_report(report_payload, reports_dir, title="SOC AI 400M Analysis Report")
    final_md = reports_dir / "SOC-AI-400M-final-report.md"
    final_pdf = reports_dir / "SOC-AI-400M-final-report.pdf"
    shutil.copy2(report["markdown"], final_md)
    shutil.copy2(report["pdf"], final_pdf)

    summary = {
        "run_id": run_id,
        "status": "complete",
        "runtime_seconds": round(time.time() - started, 2),
        "chunks": len(chunks),
        "rows": merged["total_events"],
        "integrity": integrity,
        "analysis": str(analysis_path),
        "rules": str(rules_path),
        "profile": str(profile_path),
        "evaluation": str(evaluation_path),
        "report": report,
        "final_markdown": str(final_md),
        "final_pdf": str(final_pdf),
    }
    _write_json(summary_path, summary)
    _log(log_path, "finished", **summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


def _process_chunk(index: int, chunk: dict, partial_path: str, rules: list[dict], max_findings: int) -> dict:
    path = Path(chunk["path"])
    h = hashlib.sha256()
    rows = 0
    counters = {field: Counter() for field in PROFILE_FIELDS}
    keyword_counts: Counter[str] = Counter()
    findings = []
    findings_count = 0
    findings_by_severity: Counter[str] = Counter()

    with path.open("rb") as raw:
        for block in iter(lambda: raw.read(1024 * 1024), b""):
            h.update(block)
    actual_hash = h.hexdigest()
    if actual_hash != chunk.get("sha256"):
        return _write_partial(partial_path, {"index": index, "path": str(path), "ok": False, "error": "sha256 mismatch", "partial_path": partial_path})

    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            rows += 1
            for field in PROFILE_FIELDS:
                value = event.get(field)
                if value not in (None, ""):
                    counters[field][str(value)] += 1
            text = str(event.get("event") or event.get("_raw") or "").lower()
            for word in KEYWORDS:
                if word in text:
                    keyword_counts[word] += 1
            for rule in rules:
                if _matches(event, rule.get("match", {})):
                    findings_count += 1
                    severity = str(rule.get("severity", "medium"))
                    findings_by_severity[severity] += 1
                    if len(findings) < max_findings:
                        findings.append(_finding(rule, path, line_no, event))
    if rows != chunk.get("rows"):
        return _write_partial(partial_path, {"index": index, "path": str(path), "ok": False, "error": "row count mismatch", "rows": rows, "expected_rows": chunk.get("rows"), "partial_path": partial_path})
    payload = {
        "index": index,
        "path": str(path),
        "ok": True,
        "rows": rows,
        "sha256": actual_hash,
        "expected_sha256": chunk.get("sha256"),
        "partial_path": partial_path,
        "counters": {field: dict(counters[field]) for field in PROFILE_FIELDS},
        "keyword_counts": dict(keyword_counts),
        "findings": findings,
        "findings_count": findings_count,
        "findings_by_severity": dict(findings_by_severity),
    }
    return _write_partial(partial_path, payload)


def _merge_partials(partials: list[Path], top_n: int, rare_threshold: int, max_findings: int) -> dict:
    merged = {f"{field}_counts": Counter() for field in PROFILE_FIELDS}
    merged.update({"keyword_counts": Counter(), "findings_by_severity": Counter(), "findings": [], "findings_count": 0, "total_events": 0, "integrity_failures": []})
    for partial in partials:
        payload = json.loads(partial.read_text(encoding="utf-8"))
        if not payload.get("ok"):
            merged["integrity_failures"].append({"path": payload.get("path"), "error": payload.get("error")})
            continue
        merged["total_events"] += int(payload.get("rows") or 0)
        for field in PROFILE_FIELDS:
            merged[f"{field}_counts"].update(payload.get("counters", {}).get(field, {}))
        merged["keyword_counts"].update(payload.get("keyword_counts", {}))
        merged["findings_count"] += int(payload.get("findings_count") or 0)
        merged["findings_by_severity"].update(payload.get("findings_by_severity", {}))
        if len(merged["findings"]) < max_findings:
            merged["findings"].extend(payload.get("findings", [])[: max_findings - len(merged["findings"])])
    return merged


def _partial_ok(path: Path, chunk: dict) -> bool:
    if not path.exists():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return payload.get("ok") is True and payload.get("path") == chunk.get("path") and payload.get("sha256") == chunk.get("sha256") and payload.get("rows") == chunk.get("rows")


def _write_partial(path: str | Path, payload: dict) -> dict:
    _write_json(path, payload)
    return payload


def _write_json(path: str | Path, payload: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp." + uuid.uuid4().hex)
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(p)


def _log(path: Path, event_status: str, **fields) -> None:
    payload = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event_status": event_status, **fields}
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _score(total: int, keywords: Counter[str]) -> float:
    if total <= 0:
        return 0.0
    weighted = keywords.get("failed", 0) + keywords.get("error", 0) + keywords.get("denied", 0) * 2
    return round(min(100.0, 100.0 * math.log1p(weighted) / math.log1p(max(total, 1))), 2)


if __name__ == "__main__":
    raise SystemExit(main())

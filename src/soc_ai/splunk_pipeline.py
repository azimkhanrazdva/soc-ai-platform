from __future__ import annotations

from pathlib import Path
import json
import time

from .analyze import analyze_files
from .config import AppConfig
from .data_audit import build_data_audit
from .integrity import build_manifest, verify_manifest
from .modeling import evaluate_profile, train_profile
from .recovery import export_guard
from .report import write_report
from .rules import run_rules
from .splunk import _export_splunk_chunked_locked, export_splunk_chunked, splunk_preflight
from .storage import ensure_dir
from .validation import parse_partitions_json


def run_splunk_pipeline(
    config: AppConfig,
    spl: str,
    start: str,
    end: str,
    partitions_json: str | None = None,
    run_dir: str | Path | None = None,
    estimate_only: int | None = None,
    dry_run: bool = False,
) -> dict:
    started = time.strftime("%Y%m%d-%H%M%S")
    root = Path(run_dir or Path(config.runtime.reports_dir) / f"splunk-run-{started}")
    data_dir = ensure_dir(root / "data")
    reports_dir = ensure_dir(root / "reports")
    partitions = parse_partitions_json(partitions_json)
    preflight = splunk_preflight(config, spl, start, end, estimate_only=estimate_only, partitions=partitions, skip_remote_count=estimate_only is not None)
    if dry_run:
        return {"run_dir": str(root), "preflight": preflight, "dry_run": True}
    with export_guard([root / ".pipeline.lock", data_dir / ".export.lock"]) as stop:
        ingest = _export_splunk_chunked_locked(
            config,
            spl,
            start,
            end,
            data_dir,
            data_dir / "splunk_checkpoints.json",
            partitions,
            False,
            preflight.get("estimated_events"),
            False,
            reports_dir / "run.log.jsonl",
            stop,
        )
        if ingest.get("failed_chunks", 0) or not ingest.get("complete"):
            raise RuntimeError("Splunk export is incomplete; resume failed chunks before analysis/reporting")
        chunk_paths = sorted(str(chunk["path"]) for chunk in ingest.get("chunks", []) if chunk.get("path"))
        if len(chunk_paths) != ingest.get("planned_chunks"):
            raise RuntimeError("Verified chunk list is incomplete; report generation blocked")
    manifest = build_manifest(chunk_paths, reports_dir / "chunk_manifest.json") if chunk_paths else {"output": None, "total_rows": 0, "chunks": []}
    integrity = verify_manifest(manifest["output"]) if manifest.get("output") else {"ok": False, "verified_rows": 0, "failures": ["no chunks"]}
    if manifest["total_rows"] != ingest["rows"]:
        raise RuntimeError("Export row count differs from manifest; refusing to analyze inconsistent data")
    if preflight.get("remote_count_used") and ingest["rows"] != preflight["estimated_events"]:
        raise RuntimeError("Export row count differs from Splunk count; verify source stability and partition coverage")
    if not integrity.get("ok"):
        raise RuntimeError("Chunk integrity verification failed; report generation blocked")
    metrics = (
        analyze_files(
            chunk_paths,
            top_n=config.analysis.top_n,
            rare_threshold=config.analysis.rare_threshold,
            max_unique_values=config.analysis.max_unique_values,
        )
        if chunk_paths
        else {"total_events": 0, "model_comparison": []}
    )
    analysis_path = reports_dir / "analysis.json"
    analysis_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    rules = (
        run_rules(
            chunk_paths,
            output_path=reports_dir / "rule_findings.json",
            max_findings=config.runtime.max_rule_findings,
        )
        if chunk_paths
        else {"output": None, "findings_count": 0}
    )
    profile = (
        train_profile(
            chunk_paths,
            reports_dir / "model_profile.json",
            max_unique_values=config.analysis.max_unique_values,
        )
        if chunk_paths
        else {"output": None, "total_events": 0}
    )
    evaluation = evaluate_profile(profile["output"], chunk_paths, reports_dir / "evaluation.json") if profile.get("output") else {"output": None}
    report_metrics = metrics | {"preflight": preflight, "ingest": ingest, "integrity": integrity, "rules": rules, "evaluation": evaluation}
    data_audit = build_data_audit(report_metrics, manifest, reports_dir / "data-audit.json")
    if data_audit["status"] != "pass":
        raise RuntimeError("Data usage audit failed; report generation blocked")
    report = write_report(report_metrics | {"data_audit": data_audit}, reports_dir)
    return {
        "run_dir": str(root),
        "preflight": preflight,
        "ingest": ingest,
        "chunks": len(chunk_paths),
        "manifest": manifest.get("output"),
        "integrity_ok": integrity.get("ok"),
        "analysis": str(analysis_path),
        "rules": rules.get("output"),
        "profile": profile.get("output"),
        "evaluation": evaluation.get("output"),
        "data_audit": data_audit.get("output"),
        "report": report,
    }

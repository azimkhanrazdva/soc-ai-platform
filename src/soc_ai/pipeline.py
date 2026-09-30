from __future__ import annotations

from pathlib import Path
import json
import time

from .analyze import analyze_files
from .benchmark import benchmark_analysis
from .config import AppConfig
from .integrity import build_manifest, verify_manifest
from .local_ingest import ingest_local
from .modeling import evaluate_profile, train_profile
from .report import write_report
from .rules import run_rules


def run_local_pipeline(config: AppConfig, input_path: str | Path, run_dir: str | Path | None = None) -> dict:
    started = time.strftime("%Y%m%d-%H%M%S")
    root = Path(run_dir or Path(config.runtime.reports_dir) / f"local-run-{started}")
    data_dir = root / "data"
    reports_dir = root / "reports"
    redacted = data_dir / ("events.redacted.jsonl.gz" if config.runtime.compress_jsonl else "events.redacted.jsonl")

    ingest = ingest_local(config, input_path, redacted)
    metrics = analyze_files(
        [redacted],
        top_n=config.analysis.top_n,
        rare_threshold=config.analysis.rare_threshold,
        max_unique_values=config.analysis.max_unique_values,
    )

    analysis_path = reports_dir / "analysis.json"
    analysis_path.parent.mkdir(parents=True, exist_ok=True)
    analysis_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")

    profile = train_profile(
        [redacted],
        reports_dir / "model_profile.json",
        max_unique_values=config.analysis.max_unique_values,
    )
    evaluation = evaluate_profile(profile["output"], [redacted], reports_dir / "evaluation.json")
    rules = run_rules(
        [redacted],
        output_path=reports_dir / "rule_findings.json",
        max_findings=config.runtime.max_rule_findings,
    )
    manifest = build_manifest([redacted], reports_dir / "chunk_manifest.json")
    integrity = verify_manifest(manifest["output"])
    report = write_report(metrics | {"integrity": integrity, "evaluation": evaluation, "rules": rules}, reports_dir)
    benchmark = benchmark_analysis([redacted], reports_dir / "benchmark.json")

    return {
        "run_dir": str(root),
        "ingest": ingest,
        "analysis": str(analysis_path),
        "profile": profile["output"],
        "evaluation": evaluation["output"],
        "rules": rules["output"],
        "manifest": manifest["output"],
        "integrity_ok": integrity["ok"],
        "report": report,
        "benchmark": benchmark,
    }

from __future__ import annotations

from pathlib import Path
import json
import time

from .config import AppConfig
from .pipeline import run_local_pipeline
from .synthetic import generate_synthetic


def run_stage_tests(config: AppConfig, counts: list[int], output_dir: str | Path = "reports/stage-tests", keep_raw: bool = False) -> dict:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    results = []
    for count in counts:
        started = time.perf_counter()
        raw = root / f"synthetic-{count}.jsonl"
        generate_synthetic(raw, count)
        result = run_local_pipeline(config, raw, root / f"run-{count}")
        if not keep_raw:
            raw.unlink(missing_ok=True)
        elapsed = time.perf_counter() - started
        results.append({"events": count, "elapsed_seconds": round(elapsed, 4), "pipeline": result})
    summary = {"counts": counts, "results": results}
    out = root / "summary.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return {"output": str(out), **summary}

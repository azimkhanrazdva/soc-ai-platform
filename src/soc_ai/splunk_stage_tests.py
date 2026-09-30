from __future__ import annotations

from pathlib import Path
import json
import time

from .config import AppConfig
from .hec import hec_send
from .pipeline import run_local_pipeline
from .qa import qa_run
from .splunk_pipeline import run_splunk_pipeline
from .synthetic import generate_synthetic


def run_splunk_stage_tests(
    config: AppConfig,
    counts: list[int],
    start: str,
    end: str,
    output_dir: str | Path = "reports/splunk-stage-tests",
    index: str = "main",
    sourcetype: str = "soc_ai_json",
    source_prefix: str = "soc-ai-stage",
    batch_size: int = 5000,
    wait_seconds: int = 20,
    keep_raw: bool = False,
    local_only: bool = False,
) -> dict:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    results = []
    for count in counts:
        stage_started = time.perf_counter()
        stage_dir = root / f"stage-{count}"
        stage_dir.mkdir(parents=True, exist_ok=True)
        raw_path = stage_dir / f"synthetic-{count}.jsonl"
        source = f"{source_prefix}-{count}"

        generated = generate_synthetic(raw_path, count)
        if local_only:
            pipeline = run_local_pipeline(config, raw_path, stage_dir / "pipeline-local")
            qa = qa_run(pipeline["run_dir"])
            hec = {"skipped": True}
            splunk_pipeline = {"skipped": True}
        else:
            hec = hec_send(config, raw_path, index=index, sourcetype=sourcetype, source=source, batch_size=batch_size)
            if not keep_raw:
                raw_path.unlink(missing_ok=True)
            if wait_seconds > 0:
                time.sleep(wait_seconds)
            spl = f'index="{index}" source="{source}"'
            splunk_pipeline = run_splunk_pipeline(config, spl, start, end, run_dir=stage_dir / "pipeline-splunk")
            qa = qa_run(splunk_pipeline["run_dir"])
            pipeline = splunk_pipeline

        elapsed = time.perf_counter() - stage_started
        result = {
            "events": count,
            "source": source,
            "elapsed_seconds": round(elapsed, 4),
            "generated": generated,
            "hec": hec,
            "pipeline": pipeline,
            "splunk_pipeline": splunk_pipeline,
            "qa": qa,
        }
        results.append(result)
        _write_summary(root, counts, results)

    return _write_summary(root, counts, results)


def _write_summary(root: Path, counts: list[int], results: list[dict]) -> dict:
    summary = {
        "counts": counts,
        "completed": len(results),
        "status": "pass" if all(item.get("qa", {}).get("status") == "pass" for item in results) else "fail",
        "results": results,
    }
    out = root / "summary.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return {"output": str(out), **summary}

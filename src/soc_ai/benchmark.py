from __future__ import annotations

from pathlib import Path
import json
import time

try:
    import resource
except ModuleNotFoundError:  # pragma: no cover - Windows fallback.
    resource = None

from .analyze import analyze_files


def benchmark_analysis(paths: list[str | Path], output_path: str | Path = "reports/benchmark.json") -> dict:
    start = time.perf_counter()
    metrics = analyze_files(paths)
    elapsed = time.perf_counter() - start
    rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if resource is not None else 0
    result = {
        "events": metrics["total_events"],
        "elapsed_seconds": round(elapsed, 4),
        "events_per_second": round(metrics["total_events"] / elapsed, 2) if elapsed > 0 else 0,
        "max_rss_kb": rss_kb,
    }
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result

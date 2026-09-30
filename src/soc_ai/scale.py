from __future__ import annotations

from pathlib import Path
import shutil


def scale_plan(
    counts: list[int],
    avg_event_bytes: int = 700,
    copies_per_run: int = 2,
    safety_factor: float = 1.4,
    compression_ratio: float = 0.25,
    output_dir: str | Path = ".",
) -> dict:
    free = shutil.disk_usage(Path(output_dir)).free
    plans = []
    cumulative = 0
    for count in counts:
        estimated = int(count * avg_event_bytes * copies_per_run * safety_factor * compression_ratio)
        cumulative += estimated
        plans.append(
            {
                "events": count,
                "estimated_bytes": estimated,
                "estimated_gb": round(estimated / (1024**3), 2),
                "cumulative_estimated_gb": round(cumulative / (1024**3), 2),
                "fits_remaining_disk": cumulative < free * 0.8,
            }
        )
    return {
        "free_disk_gb": round(free / (1024**3), 2),
        "avg_event_bytes": avg_event_bytes,
        "copies_per_run": copies_per_run,
        "safety_factor": safety_factor,
        "compression_ratio": compression_ratio,
        "plans": plans,
        "safe_to_run_all": all(item["fits_remaining_disk"] for item in plans),
    }

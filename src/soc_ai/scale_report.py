from __future__ import annotations

from pathlib import Path
import json
import time


def write_scale_report(
    output_path: str | Path,
    title: str,
    scale_plan: dict,
    audit: dict | None = None,
    stage_summary: dict | None = None,
) -> dict:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# {title}",
        "",
        f"Generated at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
        "## Executive summary",
        "",
        _summary(scale_plan, stage_summary),
        "",
        "## 400M capacity plan",
        "",
        "| Stage events | Estimated GB | Cumulative GB | Fits guard |",
        "| ---: | ---: | ---: | :--- |",
    ]
    for item in scale_plan.get("plans", []):
        lines.append(
            f"| {item.get('events', 0):,} | {item.get('estimated_gb', 0)} | "
            f"{item.get('cumulative_estimated_gb', 0)} | {item.get('fits_remaining_disk')} |"
        )
    lines.extend(["", f"Safe to run all planned stages: `{scale_plan.get('safe_to_run_all')}`", ""])
    if stage_summary:
        lines.extend(["## Completed stage tests", ""])
        for item in stage_summary.get("results", []):
            pipeline = item.get("pipeline", {})
            ingest = pipeline.get("ingest", {})
            qa = item.get("qa", {})
            lines.append(
                f"- {item.get('events', 0):,} events: elapsed `{item.get('elapsed_seconds')}` sec, "
                f"ingested `{ingest.get('rows')}`, integrity `{pipeline.get('integrity_ok')}`, QA `{qa.get('status')}`."
            )
        lines.append("")
    if audit:
        lines.extend(
            [
                "## Operational audit",
                "",
                f"- Git dirty: `{audit.get('git', {}).get('dirty')}`",
                f"- Free disk GB: `{audit.get('disk', {}).get('free_gb')}`",
                f"- GPU: `{audit.get('gpu', {}).get('name', 'unavailable')}`",
                f"- Ollama: `{audit.get('ollama', {}).get('ok')}` models `{', '.join(audit.get('ollama', {}).get('models', []))}`",
                f"- Remote Splunk healthy: `{audit.get('splunk_remote', {}).get('healthy')}`",
                "",
                "## Risks",
                "",
            ]
        )
        risks = audit.get("risk_summary", [])
        lines.extend([f"- {risk}" for risk in risks] or ["- No current audit risks."])
        lines.append("")
    lines.extend(
        [
            "## Data safety",
            "",
            "- Streaming HEC mode avoids storing 400M raw generated events on disk.",
            "- SPL export remains chunked and checkpointed.",
            "- Reports are based on aggregate metrics; raw logs are not sent to the local AI model.",
            "- `accounted_rows = sent_rows + skipped_rows` is the HEC resume safety counter.",
            "",
        ]
    )
    out.write_text("\n".join(lines), encoding="utf-8")
    return {"output": str(out)}


def _summary(scale_plan: dict, stage_summary: dict | None) -> str:
    total = sum(item.get("events", 0) for item in scale_plan.get("plans", []))
    safe = scale_plan.get("safe_to_run_all")
    completed = stage_summary.get("completed", 0) if stage_summary else 0
    return (
        f"The requested target is {total:,} events. Current disk guard says safe_to_run_all={safe}. "
        f"Completed stage groups in this report: {completed}. Large runs should continue progressively "
        "only while disk, Splunk health, and QA remain green."
    )

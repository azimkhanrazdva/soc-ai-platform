from __future__ import annotations

from pathlib import Path
import json
import time

from .integrity import file_sha256
from .storage import atomic_write_json


def build_data_audit(
    metrics: dict,
    manifest: dict,
    output_json: str | Path = "reports/data-audit.json",
    output_markdown: str | Path | None = None,
) -> dict:
    ingest = metrics.get("ingest") or {}
    integrity = metrics.get("integrity") or {}
    rules = metrics.get("rules") or {}
    preflight = metrics.get("preflight") or {}
    total_events = metrics.get("total_events")
    chunks = manifest.get("chunks") or []
    failures: list[str] = []

    manifest_rows = manifest.get("total_rows")
    manifest_files = manifest.get("total_files", len(chunks))
    verified_rows = integrity.get("verified_rows")
    expected_rows = integrity.get("expected_rows")
    ingest_rows = ingest.get("rows")
    rules_scanned = rules.get("events_scanned")
    planned_chunks = ingest.get("planned_chunks")

    if ingest and ingest.get("complete") is not True:
        failures.append("Splunk export is not marked complete")
    if ingest and ingest.get("failed_chunks", 0):
        failures.append("Splunk export contains failed chunks")
    if planned_chunks is not None and planned_chunks != len(chunks):
        failures.append("Manifest chunk count differs from planned Splunk chunks")
    if manifest_files != len(chunks):
        failures.append("Manifest total_files differs from chunk list length")
    for name, value in {
        "manifest.total_rows": manifest_rows,
        "integrity.verified_rows": verified_rows,
        "integrity.expected_rows": expected_rows,
        "ingest.rows": ingest_rows,
        "metrics.total_events": total_events,
        "rules.events_scanned": rules_scanned,
    }.items():
        if value is not None and value != total_events:
            failures.append(f"{name} differs from metrics.total_events")
    if integrity.get("ok") is not True:
        failures.append("Integrity verification did not pass")
    if preflight.get("remote_count_used") and preflight.get("estimated_events") != total_events:
        failures.append("Splunk preflight count differs from analyzed events")

    chunk_summaries = []
    for index, chunk in enumerate(chunks, 1):
        path = Path(chunk.get("path", ""))
        exists = path.exists()
        actual_sha = file_sha256(path) if exists else ""
        ok = exists and actual_sha == chunk.get("sha256")
        if not ok:
            failures.append(f"Chunk {index} failed existence or sha256 verification")
        chunk_summaries.append({
            "index": index,
            "path": str(path),
            "rows": chunk.get("rows"),
            "sha256": chunk.get("sha256"),
            "exists": exists,
            "sha256_verified": ok,
        })

    output = {
        "schema": "soc-data-audit-v1",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "fail" if failures else "pass",
        "all_data_used": not failures,
        "summary": {
            "total_events": total_events,
            "manifest_rows": manifest_rows,
            "verified_rows": verified_rows,
            "ingest_rows": ingest_rows,
            "rules_events_scanned": rules_scanned,
            "planned_chunks": planned_chunks,
            "manifest_chunks": len(chunks),
            "remote_splunk_count": preflight.get("estimated_events") if preflight.get("remote_count_used") else None,
        },
        "failures": failures,
        "chunks": chunk_summaries,
        "decision": "report_allowed" if not failures else "report_blocked",
        "note": "This audit uses counts, manifests, hashes, and rule coverage. It does not prove Splunk retained events before export.",
    }
    out = Path(output_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(out, output)
    md_path = Path(output_markdown) if output_markdown else out.with_suffix(".md")
    md_path.write_text(markdown_data_audit(output), encoding="utf-8")
    md_path.chmod(0o600)
    return {"output": str(out), "markdown": str(md_path), **output}


def markdown_data_audit(audit: dict) -> str:
    summary = audit.get("summary") or {}
    lines = [
        "# Data usage audit",
        "",
        f"Status: {audit.get('status')}",
        f"Decision: {audit.get('decision')}",
        f"All data used: {audit.get('all_data_used')}",
        "",
        "## Counters",
        "",
        "| Counter | Value |",
        "| --- | ---: |",
    ]
    for key, value in summary.items():
        lines.append(f"| {key} | {value} |")
    lines.extend(["", "## Failures", ""])
    failures = audit.get("failures") or []
    lines.extend([f"- {item}" for item in failures] or ["- none"])
    lines.extend(["", "## Chunks", "", "| # | Rows | SHA-256 verified | Path |", "| ---: | ---: | --- | --- |"])
    for chunk in audit.get("chunks") or []:
        lines.append(f"| {chunk.get('index')} | {chunk.get('rows')} | {chunk.get('sha256_verified')} | {chunk.get('path')} |")
    lines.extend(["", audit.get("note", "")])
    return "\n".join(lines) + "\n"

from __future__ import annotations

from pathlib import Path
from datetime import datetime
import json
import os
import ssl
import time
import urllib.request

from .checkpoints import CheckpointStore, ChunkRecord, chunk_id
from .config import AppConfig
from .storage import read_jsonl
from .synthetic import iter_synthetic_events


def hec_send(
    config: AppConfig,
    input_path: str | Path,
    index: str,
    sourcetype: str = "_json",
    source: str = "soc-ai",
    batch_size: int = 1000,
    checkpoint_path: str | Path | None = None,
    dry_run: bool = False,
) -> dict:
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    url = os.getenv("SPLUNK_HEC_URL", "https://127.0.0.1:8088/services/collector/event")
    token = os.getenv("SPLUNK_HEC_TOKEN", "")
    verify = os.getenv(config.splunk.verify_tls_env, "true").lower() not in {"0", "false", "no"}
    path = Path(input_path)
    checkpoint = CheckpointStore(checkpoint_path or path.with_suffix(path.suffix + ".hec_checkpoint.json"))
    total = 0
    sent = 0
    skipped = 0
    batch = []
    batch_no = 0
    for row in read_jsonl(path):
        total += 1
        batch.append(row)
        if len(batch) >= batch_size:
            batch_no += 1
            result = _send_batch(url, token, verify, index, sourcetype, source, batch, batch_no, checkpoint, dry_run)
            sent += result["sent_rows"]
            skipped += result["skipped_rows"]
            batch = []
    if batch:
        batch_no += 1
        result = _send_batch(url, token, verify, index, sourcetype, source, batch, batch_no, checkpoint, dry_run)
        sent += result["sent_rows"]
        skipped += result["skipped_rows"]
    return {
        "input": str(path),
        "index": index,
        "sourcetype": sourcetype,
        "total_rows": total,
        "sent_rows": sent,
        "skipped_rows": skipped,
        "accounted_rows": sent + skipped,
        "batches": batch_no,
        "dry_run": dry_run,
    }


def hec_generate_synthetic(
    config: AppConfig,
    rows: int,
    index: str,
    sourcetype: str = "soc_ai_json",
    source: str = "soc-ai-generated",
    batch_size: int = 5000,
    checkpoint_path: str | Path | None = None,
    seed: int = 42,
    span_seconds: int | None = None,
    dry_run: bool = False,
) -> dict:
    if rows < 0:
        raise ValueError("rows must be non-negative")
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    url = os.getenv("SPLUNK_HEC_URL", "https://127.0.0.1:8088/services/collector/event")
    token = os.getenv("SPLUNK_HEC_TOKEN", "")
    verify = os.getenv(config.splunk.verify_tls_env, "true").lower() not in {"0", "false", "no"}
    checkpoint = CheckpointStore(checkpoint_path or Path("data") / f"{source}.hec_checkpoint.json")
    sent = 0
    skipped = 0
    batch = []
    batch_no = 0
    for row in iter_synthetic_events(rows, seed, span_seconds=span_seconds):
        batch.append(row)
        if len(batch) >= batch_size:
            batch_no += 1
            result = _send_batch(url, token, verify, index, sourcetype, source, batch, batch_no, checkpoint, dry_run)
            sent += result["sent_rows"]
            skipped += result["skipped_rows"]
            batch = []
    if batch:
        batch_no += 1
        result = _send_batch(url, token, verify, index, sourcetype, source, batch, batch_no, checkpoint, dry_run)
        sent += result["sent_rows"]
        skipped += result["skipped_rows"]
    return {
        "source": source,
        "index": index,
        "sourcetype": sourcetype,
        "total_rows": rows,
        "sent_rows": sent,
        "skipped_rows": skipped,
        "accounted_rows": sent + skipped,
        "batches": batch_no,
        "checkpoint": str(checkpoint.path),
        "dry_run": dry_run,
        "mode": "streaming-synthetic",
        "span_seconds": span_seconds,
    }


def _send_batch(url: str, token: str, verify: bool, index: str, sourcetype: str, source: str, rows: list[dict], batch_no: int, checkpoint: CheckpointStore, dry_run: bool) -> dict:
    cid = chunk_id(str(batch_no), str(len(rows)), {"index": index, "source": source})
    if checkpoint.is_done(cid):
        return {"sent_rows": 0, "skipped_rows": checkpoint.rows_for(cid) or len(rows)}
    checkpoint.mark(ChunkRecord(cid, "running", str(batch_no), str(batch_no), {"index": index, "source": source}, rows=len(rows)))
    if dry_run:
        checkpoint.mark(ChunkRecord(cid, "done", str(batch_no), str(batch_no), {"index": index, "source": source}, rows=len(rows)))
        return {"sent_rows": len(rows), "skipped_rows": 0}
    if not token:
        raise RuntimeError("SPLUNK_HEC_TOKEN is missing")
    payload = "\n".join(
        json.dumps(_hec_event(index, sourcetype, source, row), ensure_ascii=False)
        for row in rows
    ).encode("utf-8")
    request = urllib.request.Request(url, data=payload, headers={"Authorization": f"Splunk {token}", "Content-Type": "application/json"}, method="POST")
    context = None if verify else ssl._create_unverified_context()
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(request, timeout=120, context=context) as response:
                body = response.read().decode("utf-8", errors="replace")
                if response.status >= 300:
                    raise RuntimeError(f"HEC status={response.status}: {body}")
                _validate_hec_response(body)
            checkpoint.mark(ChunkRecord(cid, "done", str(batch_no), str(batch_no), {"index": index, "source": source}, rows=len(rows)))
            return {"sent_rows": len(rows), "skipped_rows": 0}
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(attempt)
    checkpoint.mark(ChunkRecord(cid, "failed", str(batch_no), str(batch_no), {"index": index, "source": source}, rows=len(rows), error=str(last_error)))
    raise RuntimeError(f"HEC batch failed: {last_error}")


def _validate_hec_response(body: str) -> None:
    if not body.strip():
        return
    try:
        response = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"HEC returned non-JSON response: {body[:200]}") from exc
    if isinstance(response, dict) and response.get("code", 0) != 0:
        raise RuntimeError(f"HEC application error code={response.get('code')}: {response.get('text', '')}")


def _hec_event(index: str, sourcetype: str, source: str, row: dict) -> dict:
    event = {"index": index, "sourcetype": sourcetype, "source": source, "event": row}
    timestamp = _event_timestamp(row.get("_time"))
    if timestamp is not None:
        event["time"] = timestamp
    return event


def _event_timestamp(value) -> float | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None

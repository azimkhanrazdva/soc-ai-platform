from __future__ import annotations

from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from pathlib import Path
from typing import Iterable
import base64
import csv
import io
import json
import os
import ssl
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from .checkpoints import CheckpointStore, ChunkRecord, chunk_id
from .chunking import adaptive_chunk_seconds, build_time_windows, choose_mode, iter_plan, partition_filter
from .config import AppConfig
from .integrity import file_sha256
from .normalize import normalize_splunk_event
from .network import open_service
from .redaction import redact_event
from .recovery import ExportPaused, export_guard
from .runlog import RunLogger
from .storage import sync_directory, write_jsonl
from .validation import validate_spl, validate_strict_raw_spl
from .splunk_jobs import export_verified as export_verified_job


@dataclass(slots=True)
class SplunkClient:
    base_url: str
    token: str = ""
    username: str = ""
    password: str = ""
    verify_tls: bool = True
    timeout: int = 120

    @classmethod
    def from_env(cls, config: AppConfig) -> "SplunkClient":
        base_url = os.getenv(config.splunk.base_url_env, "").rstrip("/")
        token = os.getenv(config.splunk.token_env, "")
        username = os.getenv(config.splunk.username_env, "")
        password = os.getenv(config.splunk.password_env, "")
        verify = os.getenv(config.splunk.verify_tls_env, "true").lower() not in {"0", "false", "no"}
        if not base_url or not (token or (username and password)):
            raise RuntimeError("Splunk URL and token or username/password are missing. See .env.example.")
        return cls(base_url=base_url, token=token, username=username, password=password, verify_tls=verify, timeout=config.splunk.request_timeout_seconds)

    def auth_header(self) -> str:
        if self.token:
            return f"Splunk {self.token}"
        raw = f"{self.username}:{self.password}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def export_csv(self, search: str, earliest: str, latest: str) -> Iterable[dict[str, str]]:
        url = f"{self.base_url}/services/search/jobs/export"
        payload = urllib.parse.urlencode(
            {
                "search": search if search.startswith("search ") else f"search {search}",
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "csv",
            }
        ).encode("utf-8")
        headers = {"Authorization": self.auth_header(), "Content-Type": "application/x-www-form-urlencoded"}
        request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        context = None if self.verify_tls else ssl._create_unverified_context()
        _set_max_csv_field_size()
        try:
            with open_service(request, timeout=self.timeout, context=context) as response:
                text = io.TextIOWrapper(response, encoding="utf-8", errors="surrogateescape", newline="")
                yield from csv.DictReader(text)
        except urllib.error.HTTPError as exc:
            # Error bodies can contain query data or credentials from upstream services.
            exc.close()
            raise RuntimeError(f"Splunk export HTTP {exc.code}") from None
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Splunk export connection failed: {exc.reason}") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise RuntimeError(f"Splunk export timed out while reading CSV: {exc}") from exc

    def count(self, search: str, earliest: str, latest: str) -> int:
        count_search = build_count_search(search)
        for row in self.export_csv(count_search, earliest, latest):
            value = row.get("count") or row.get("Count") or row.get("COUNT") or 0
            return int(float(value))
        return 0

    def export_verified(self, search: str, earliest: str, latest: str, *, evidence, stop, page_rows: int, max_rows: int, job_timeout: int):
        yield from export_verified_job(
            self,
            search,
            earliest,
            latest,
            evidence=evidence,
            stop=stop,
            page_rows=page_rows,
            max_rows=max_rows,
            job_timeout=job_timeout,
        )


def build_count_search(base_spl: str) -> str:
    search = base_spl.strip()
    if not search.startswith("search "):
        search = f"search {search}"
    return f"{search} | stats count as count"


def _set_max_csv_field_size() -> None:
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def build_search(base_spl: str, partition: dict[str, str] | None, max_rows: int | None = None) -> str:
    filt = partition_filter(partition)
    search = f"({base_spl.strip()}) {filt}".strip() if filt else base_spl.strip()
    # Do not append head/limit here. Truncating SPL output would silently lose events.
    # Use smaller time windows or partitions when chunks are too large.
    return search


def _source_context(config: AppConfig, base_spl: str, start: str, end: str, partitions, chunk_seconds: int, planned_chunks: int) -> dict:
    return {
        "splunk_base_url": os.getenv(config.splunk.base_url_env, "").rstrip("/"),
        "base_spl": base_spl.strip(),
        "start": start,
        "end": end,
        "partitions": partitions or [{}],
        "chunk_seconds": chunk_seconds,
        "planned_chunks": planned_chunks,
        "compress_jsonl": bool(config.runtime.compress_jsonl),
        "deny_fields": list(config.privacy.deny_fields),
        "allow_fields": list(config.privacy.allow_fields),
        "mask_ips": bool(config.privacy.mask_ips),
        "mask_users": bool(config.privacy.mask_users),
        "transport": config.splunk.export_transport,
    }


def _verified_done(checkpoint: CheckpointStore, cid: str) -> bool:
    record = checkpoint.record_for(cid)
    if not record or record.status != "done" or not record.output_path:
        return False
    path = Path(record.output_path)
    if not path.is_file() or record.rows < 0:
        return False
    if record.size_bytes is not None and path.stat().st_size != record.size_bytes:
        return False
    if record.sha256 and file_sha256(path) != record.sha256:
        return False
    evidence = record.source_evidence or {}
    return evidence.get("verified") is True and evidence.get("rows") == record.rows


def _prepare_rows(rows, config: AppConfig, out_dir: Path, stop):
    for row in rows:
        _raise_if_paused(stop)
        _raise_if_low_disk(out_dir, config.runtime.min_free_disk_mb)
        yield redact_event(
            normalize_splunk_event(row),
            deny_fields=config.privacy.deny_fields,
            allow_fields=config.privacy.allow_fields,
            mask_ips=config.privacy.mask_ips,
            mask_users=config.privacy.mask_users,
        )


def _free_mb(path: Path) -> int:
    usage = os.statvfs(path) if hasattr(os, "statvfs") else None
    if usage is None:
        import shutil
        return shutil.disk_usage(path).free // (1024 * 1024)
    return (usage.f_bavail * usage.f_frsize) // (1024 * 1024)


def export_splunk_chunked(
    config: AppConfig,
    base_spl: str,
    start: str,
    end: str,
    output_dir: str | Path | None = None,
    checkpoint_path: str | Path | None = None,
    partitions: list[dict[str, str]] | None = None,
    dry_run: bool = False,
    estimated_events: int | None = None,
    allow_lossy_commands: bool = False,
    run_log_path: str | Path | None = None,
) -> dict:
    out_dir = Path(output_dir or config.runtime.output_dir)
    lock_path = out_dir / ".export.lock"
    with export_guard([lock_path]) as stop:
        return _export_splunk_chunked_locked(
            config,
            base_spl,
            start,
            end,
            out_dir,
            checkpoint_path,
            partitions,
            dry_run,
            estimated_events,
            allow_lossy_commands,
            run_log_path,
            stop,
        )


def _export_splunk_chunked_locked(
    config: AppConfig,
    base_spl: str,
    start: str,
    end: str,
    out_dir: Path,
    checkpoint_path: str | Path | None,
    partitions: list[dict[str, str]] | None,
    dry_run: bool,
    estimated_events: int | None,
    allow_lossy_commands: bool,
    run_log_path: str | Path | None,
    stop,
) -> dict:
    runtime = config.runtime
    spl_warnings = validate_spl(base_spl, allow_lossy_commands=allow_lossy_commands)
    if config.splunk.export_transport == "verified":
        validate_strict_raw_spl(base_spl)
    out_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = CheckpointStore(checkpoint_path or out_dir / "splunk_checkpoints.json")
    chunk_seconds = adaptive_chunk_seconds(
        start,
        end,
        estimated_events,
        runtime.target_events_per_chunk,
        runtime.chunk_seconds,
        runtime.min_chunk_seconds,
        runtime.max_chunk_seconds,
    )
    windows = build_time_windows(start, end, chunk_seconds)
    plan = iter_plan(windows, partitions)
    planned_chunks = len(windows) * len(partitions or [{}])
    context = _source_context(config, base_spl, start, end, partitions, chunk_seconds, planned_chunks)
    if not dry_run:
        context = checkpoint.bind_context(context)
    logger = RunLogger(run_log_path or out_dir / "run.log.jsonl")
    logger.event("splunk_ingest", "planned", chunks=planned_chunks, chunk_seconds=chunk_seconds, estimated_events=estimated_events)
    if dry_run:
        return {
            "mode": "chunked",
            "chunk_seconds": chunk_seconds,
            "planned_chunks": planned_chunks,
            "warnings": spl_warnings,
            "windows": [{"earliest": w.splunk_earliest(), "latest": w.splunk_latest(), "partition": p} for w, p in plan],
        }

    if config.splunk.parallel_workers < 1:
        raise ValueError("parallel_workers must be positive")
    if config.splunk.retry_attempts < 1:
        raise ValueError("retry_attempts must be positive")
    client = SplunkClient.from_env(config)
    def process_chunk(window, partition) -> tuple[int, int]:
        earliest = window.splunk_earliest()
        latest = window.splunk_latest()
        cid = chunk_id(earliest, latest, partition)
        if _verified_done(checkpoint, cid):
            logger.event("chunk", "skipped_done", chunk_id=cid, earliest=earliest, latest=latest, partition=partition)
            return checkpoint.rows_for(cid), 0
        if stop.is_set():
            raise ExportPaused("Export interrupted; resume the same run")
        search = build_search(base_spl, partition, runtime.max_rows_per_request)
        if context.get("snapshot_index_latest"):
            search = f'{search} _index_latest={int(context["snapshot_index_latest"])}'
        suffix = ".jsonl.gz" if runtime.compress_jsonl else ".jsonl"
        chunk_path = out_dir / "chunks" / f"{cid}{suffix}"
        prior = checkpoint.record_for(cid)
        record = prior or ChunkRecord(cid, "running", earliest, latest, partition, str(chunk_path))
        record.status = "running"
        record.error = None
        record.output_path = str(chunk_path)
        checkpoint.mark(record)
        logger.event("chunk", "started", chunk_id=cid, earliest=earliest, latest=latest, partition=partition)
        partial_path = chunk_path.parent / f"{chunk_path.stem}.part{chunk_path.suffix}"
        try:
            def write_attempt():
                if _free_mb(out_dir) < runtime.min_free_disk_mb:
                    raise ExportPaused("Free disk space is below the configured safety floor")
                evidence: dict = {}
                if config.splunk.export_transport == "verified":
                    rows = client.export_verified(
                        search,
                        earliest,
                        latest,
                        evidence=evidence,
                        stop=stop,
                        page_rows=config.splunk.result_page_rows,
                        max_rows=config.splunk.max_job_rows,
                        job_timeout=config.splunk.job_timeout_seconds,
                    )
                else:
                    rows = client.export_csv(search, earliest, latest)
                return write_jsonl(
                    partial_path,
                    _prepare_rows(rows, config, out_dir, stop),
                    compresslevel=runtime.gzip_compresslevel,
                ), evidence

            def do_attempt():
                count, evidence = write_attempt()
                return count, evidence

            count, evidence = _retry_write(do_attempt, config.splunk.retry_attempts, config.splunk.retry_backoff_seconds, stop)
            if evidence.get("verified") and evidence.get("rows") != count:
                raise RuntimeError("Verified Splunk row count differs from written rows")
            if config.splunk.export_transport == "verified" and not evidence.get("verified"):
                raise RuntimeError("Splunk chunk finished without verified source evidence")
            partial_path.replace(chunk_path)
            sync_directory(chunk_path.parent)
            record.status = "done"
            record.rows = count
            record.sha256 = file_sha256(chunk_path)
            record.size_bytes = chunk_path.stat().st_size
            record.source_evidence = evidence
            checkpoint.mark(record)
            logger.event("chunk", "done", chunk_id=cid, rows=count, output_path=str(chunk_path))
            return count, 0
        except ExportPaused as exc:
            partial_path.unlink(missing_ok=True)
            record.status = "paused"
            record.error = type(exc).__name__
            checkpoint.mark(record)
            logger.event("chunk", "paused", chunk_id=cid, error=type(exc).__name__)
            raise
        except Exception as exc:  # noqa: BLE001 - persisted for resume/status.
            partial_path.unlink(missing_ok=True)
            record.status = "failed"
            record.error = type(exc).__name__
            checkpoint.mark(record)
            logger.event("chunk", "failed", chunk_id=cid, error=type(exc).__name__)
            return 0, 1

    total_rows = 0
    failed = 0
    exported_chunks: list[dict] = []
    with ThreadPoolExecutor(max_workers=config.splunk.parallel_workers) as executor:
        # Bound queued work as well as active workers for large partition plans.
        pending = set()
        exhausted = False
        while pending or not exhausted:
            while not exhausted and len(pending) < config.splunk.parallel_workers * 2:
                item = next(plan, None)
                if item is None:
                    exhausted = True
                else:
                    pending.add(executor.submit(process_chunk, *item))
            if pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        rows, errors = future.result()
                    except ExportPaused:
                        stop.set()
                        errors = 1
                        rows = 0
                    total_rows += rows
                    failed += errors
                    if stop.is_set():
                        exhausted = True
                        for pending_future in pending:
                            pending_future.cancel()
                        break
    for window in windows:
        for partition in partitions or [{}]:
            cid = chunk_id(window.splunk_earliest(), window.splunk_latest(), partition)
            record = checkpoint.record_for(cid)
            if record and _verified_done(checkpoint, cid):
                exported_chunks.append(
                    {
                        "chunk_id": cid,
                        "path": record.output_path,
                        "rows": record.rows,
                        "sha256": record.sha256,
                        "size_bytes": record.size_bytes,
                        "source_evidence": record.source_evidence,
                    }
                )
    summary = {
        "mode": "chunked",
        "chunk_seconds": chunk_seconds,
        "planned_chunks": planned_chunks,
        "rows": total_rows,
        "failed_chunks": failed,
        "checkpoint": str(checkpoint.path),
        "run_log": str(logger.path),
        "warnings": spl_warnings,
        "source_context": context,
        "chunks": exported_chunks,
        "complete": failed == 0 and len(exported_chunks) == planned_chunks,
    }
    logger.event("splunk_ingest", "finished", **summary)
    return summary


def splunk_preflight(
    config: AppConfig,
    base_spl: str,
    start: str,
    end: str,
    estimate_only: int | None = None,
    partitions: list[dict[str, str]] | None = None,
    skip_remote_count: bool = False,
) -> dict:
    spl_warnings = validate_spl(base_spl, allow_lossy_commands=False)
    estimated_events = estimate_only
    if estimated_events is None and not skip_remote_count:
        client = SplunkClient.from_env(config)
        estimated_events = client.count(base_spl, start, end)
    chunk_seconds = adaptive_chunk_seconds(
        start,
        end,
        estimated_events,
        config.runtime.target_events_per_chunk,
        config.runtime.chunk_seconds,
        config.runtime.min_chunk_seconds,
        config.runtime.max_chunk_seconds,
    )
    windows = build_time_windows(start, end, chunk_seconds)
    partition_count = len(partitions or [{}])
    return {
        "mode": choose_mode(estimated_events, config.runtime.mode, config.runtime.small_run_max_events),
        "estimated_events": estimated_events,
        "target_events_per_chunk": config.runtime.target_events_per_chunk,
        "chunk_seconds": chunk_seconds,
        "planned_windows": len(windows),
        "planned_partitions": partition_count,
        "planned_chunks": len(windows) * partition_count,
        "first_window": {"earliest": windows[0].splunk_earliest(), "latest": windows[0].splunk_latest()} if windows else None,
        "remote_count_used": estimated_events is not None and not skip_remote_count and estimate_only is None,
        "warnings": spl_warnings,
    }


def _raise_if_paused(stop) -> None:
    if stop.is_set():
        raise ExportPaused("Export interrupted; resume the same run")


def _raise_if_low_disk(path: Path, min_free_mb: int) -> None:
    if min_free_mb > 0 and _free_mb(path) < min_free_mb:
        raise ExportPaused("Free disk space is below the configured safety floor")


def _retry_write(write_attempt, attempts: int, backoff: int, stop=None):
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return write_attempt()
        except ExportPaused:
            raise
        except Exception as exc:  # noqa: BLE001 - retrying external service.
            last_error = exc
            if attempt == attempts:
                break
            if stop is not None:
                stop.wait(backoff * attempt)
                if stop.is_set():
                    raise ExportPaused("Export interrupted; resume the same run") from exc
            else:
                time.sleep(backoff * attempt)
    raise RuntimeError(f"Splunk export failed after {attempts} attempts: {last_error}")


def checkpoint_status(path: str | Path) -> dict:
    store = CheckpointStore(path)
    return {"checkpoint": str(path), "counts": store.counts()}

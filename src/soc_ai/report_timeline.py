"""Exact hourly totals from disjoint export windows and boundary chunk reads."""
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import gzip
import hashlib
import json


def timestamp(value):
    if isinstance(value, (int, float)):
        return float(value)
    date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if date.tzinfo is None:
        raise ValueError("Timeline requires timezone-aware timestamps")
    return date.timestamp()


def _boundary(task):
    record, manifest = task
    path = Path(record["output_path"])
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != manifest["sha256"]:
        raise ValueError("Timeline boundary chunk checksum mismatch")
    start, end = timestamp(record["earliest"]), timestamp(record["latest"])
    counts = Counter()
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            value = timestamp(json.loads(line)["_time"])
            if not start <= value < end:
                raise ValueError("Event timestamp is outside its export window")
            counts[int(value // 3600)] += 1
    if sum(counts.values()) != record["rows"]:
        raise ValueError("Timeline boundary row count mismatch")
    return dict(counts)


def build_timeline(checkpoint_path, manifest_path, expected_rows, workers=4):
    checkpoint_bytes = Path(checkpoint_path).read_bytes()
    manifest_bytes = Path(manifest_path).read_bytes()
    records = json.loads(checkpoint_bytes)["chunks"]
    manifests = json.loads(manifest_bytes)["chunks"]
    by_path = {str(Path(m["path"])): m for m in manifests}
    if len(by_path) != len(manifests) or len(records) != len(manifests):
        raise ValueError("Timeline manifest must contain each chunk exactly once")
    records = sorted(records, key=lambda r: timestamp(r["earliest"]))
    counts, tasks = Counter(), []
    previous = None
    seen = set()
    for r in records:
        key = str(Path(r["output_path"]))
        m = by_path.get(key)
        if key in seen or not m or m.get("rows") != r.get("rows") or r.get("status") != "done" or r.get("partition"):
            raise ValueError("Timeline requires complete, matching, unpartitioned chunks")
        seen.add(key)
        start, end = timestamp(r["earliest"]), timestamp(r["latest"])
        if start >= end or (previous is not None and start != previous):
            raise ValueError("Timeline export windows have gaps or overlaps")
        previous = end
        bucket = int(start // 3600)
        if end <= (bucket + 1) * 3600:
            counts[bucket] += r["rows"]
        else:
            tasks.append((r, m))
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(_boundary, tasks):
            counts.update(result)
    if sum(counts.values()) != expected_rows:
        raise ValueError("Timeline count differs from report total")
    daily, hours = Counter(), Counter()
    for bucket, count in sorted(counts.items()):
        date = datetime.fromtimestamp(bucket * 3600, timezone.utc)
        daily[date.strftime("%Y-%m-%d")] += count
        hours[date.strftime("%H:00")] += count
    return dict(daily=list(sorted(daily.items())), hourly=list(sorted(hours.items())), total_events=expected_rows,
                boundary_chunks_read=len(tasks), boundary_rows_read=sum(t[0]["rows"] for t in tasks),
                method="disjoint_export_windows_with_verified_boundary_reads", timezone="UTC",
                checkpoint_sha256=hashlib.sha256(checkpoint_bytes).hexdigest(), manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest())

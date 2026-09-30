from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Iterable
import math
import re


@dataclass(frozen=True, slots=True)
class TimeWindow:
    start: datetime
    end: datetime

    def splunk_earliest(self) -> str:
        return self.start.isoformat().replace("+00:00", "Z")

    def splunk_latest(self) -> str:
        return self.end.isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def build_time_windows(start: str | datetime, end: str | datetime, seconds: int) -> list[TimeWindow]:
    if seconds <= 0:
        raise ValueError("chunk seconds must be positive")
    start_dt = parse_utc(start) if isinstance(start, str) else start.astimezone(timezone.utc)
    end_dt = parse_utc(end) if isinstance(end, str) else end.astimezone(timezone.utc)
    if end_dt <= start_dt:
        raise ValueError("end must be after start")

    windows: list[TimeWindow] = []
    cursor = start_dt
    step = timedelta(seconds=seconds)
    while cursor < end_dt:
        nxt = min(cursor + step, end_dt)
        windows.append(TimeWindow(cursor, nxt))
        cursor = nxt
    return windows


def choose_mode(estimated_events: int | None, configured_mode: str, small_run_max_events: int) -> str:
    mode = configured_mode.lower()
    if mode not in {"auto", "full", "chunked"}:
        raise ValueError("mode must be auto, full, or chunked")
    if mode != "auto":
        return mode
    if estimated_events is None:
        return "chunked"
    return "full" if estimated_events <= small_run_max_events else "chunked"


def adaptive_chunk_seconds(
    start: str | datetime,
    end: str | datetime,
    estimated_events: int | None,
    target_events_per_chunk: int,
    default_seconds: int,
    min_seconds: int = 60,
    max_seconds: int = 86_400,
) -> int:
    if estimated_events is None or estimated_events <= 0:
        return default_seconds
    if target_events_per_chunk <= 0:
        raise ValueError("target events per chunk must be positive")
    start_dt = parse_utc(start) if isinstance(start, str) else start.astimezone(timezone.utc)
    end_dt = parse_utc(end) if isinstance(end, str) else end.astimezone(timezone.utc)
    total_seconds = max(1, int((end_dt - start_dt).total_seconds()))
    planned_chunks = max(1, math.ceil(estimated_events / target_events_per_chunk))
    seconds = max(1, math.ceil(total_seconds / planned_chunks))
    return min(max(seconds, min_seconds), max_seconds)


def partition_filter(partition: dict[str, str] | None) -> str:
    if not partition:
        return ""
    parts = []
    for key, value in sorted(partition.items()):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", key):
            raise ValueError("Invalid partition field name")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Partition values must not contain control characters")
        safe_value = value.replace("\\", "\\\\").replace('"', '\\"')
        parts.append(f'{key}="{safe_value}"')
    return " ".join(parts)


def iter_plan(windows: Iterable[TimeWindow], partitions: list[dict[str, str]] | None = None):
    partitions = partitions or [{}]
    for window in windows:
        for partition in partitions:
            yield window, partition

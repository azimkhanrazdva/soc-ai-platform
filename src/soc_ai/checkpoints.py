from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json
import threading
import time

from .storage import atomic_write_json


@dataclass(slots=True)
class ChunkRecord:
    chunk_id: str
    status: str
    earliest: str
    latest: str
    partition: dict[str, str]
    output_path: str | None = None
    rows: int = 0
    error: str | None = None
    updated_at: float = 0.0
    sha256: str | None = None
    size_bytes: int | None = None
    source_evidence: dict | None = None


class CheckpointStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.context = None
        self._records = self._load()

    def _load(self) -> dict[str, ChunkRecord]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("chunks"), list):
            raise ValueError("Invalid checkpoint; restore a verified backup")
        ids = [item["chunk_id"] for item in raw["chunks"]]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate chunk identifiers in checkpoint")
        self.context = raw.get("context")
        return {item["chunk_id"]: ChunkRecord(**item) for item in raw.get("chunks", [])}

    def bind_context(self, context: dict) -> dict:
        with self._lock:
            if self.context is None:
                if self._records:
                    raise ValueError("Legacy checkpoint has no source identity; audit it before migration or use a new run directory")
                self.context = {**context, "snapshot_index_latest": int(time.time()) - 2}
                self.save()
            elif {k: v for k, v in self.context.items() if k != "snapshot_index_latest"} != context:
                raise ValueError("Checkpoint source/query/plan/privacy context differs; use the original configuration or a new run directory")
            return dict(self.context)

    def record_for(self, cid: str) -> ChunkRecord | None:
        with self._lock:
            record = self._records.get(cid)
            return ChunkRecord(**asdict(record)) if record else None

    def save(self) -> None:
        with self._lock:
            payload = {"chunks": [asdict(r) for r in sorted(self._records.values(), key=lambda x: x.chunk_id)]}
            if self.context is not None:
                payload.update({"version": 2, "context": self.context})
            atomic_write_json(self.path, payload)

    def is_done(self, chunk_id: str) -> bool:
        with self._lock:
            record = self._records.get(chunk_id)
            if not record or record.status != "done":
                return False
            return record.output_path is None or Path(record.output_path).is_file()

    def rows_for(self, chunk_id: str) -> int:
        with self._lock:
            record = self._records.get(chunk_id)
            return record.rows if record and self.is_done(chunk_id) else 0

    def mark(self, record: ChunkRecord) -> None:
        with self._lock:
            record.updated_at = time.time()
            self._records[record.chunk_id] = record
            self.save()

    def counts(self) -> dict[str, int]:
        with self._lock:
            result: dict[str, int] = {}
            for record in self._records.values():
                result[record.status] = result.get(record.status, 0) + 1
            return result


def chunk_id(earliest: str, latest: str, partition: dict[str, str] | None = None) -> str:
    payload = json.dumps({"earliest": earliest, "latest": latest, "partition": partition or {}}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

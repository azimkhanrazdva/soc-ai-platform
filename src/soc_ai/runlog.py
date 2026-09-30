from __future__ import annotations

from pathlib import Path
import json
import threading
import time
import uuid
import os

from .redaction import redact_event


class RunLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = uuid.uuid4().hex
        self._lock = threading.Lock()

    def event(self, stage: str, status: str, **fields) -> None:
        payload = {
            "run_id": self.run_id,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "stage": stage,
            "status": status,
            **fields,
        }
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(redact_event(payload), ensure_ascii=False, sort_keys=True) + "\n")

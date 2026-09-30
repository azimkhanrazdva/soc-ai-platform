from __future__ import annotations

from pathlib import Path
from typing import Iterable, Mapping, Any
import csv
import gzip
import json
import os
import tempfile


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def sync_directory(path: str | Path) -> None:
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def atomic_write_json(path: str | Path, payload: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=p.parent, prefix=p.name + ".", suffix=".tmp", delete=False) as fh:
            temporary = Path(fh.name)
            json.dump(payload, fh, ensure_ascii=True, sort_keys=True, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        temporary.replace(p)
        sync_directory(p.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_jsonl(path: str | Path, rows: Iterable[Mapping[str, Any]], compresslevel: int = 9) -> int:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    opener = gzip.open if p.suffix == ".gz" else open
    options = {"compresslevel": compresslevel} if p.suffix == ".gz" else {}
    with opener(p, "wt", encoding="utf-8", newline="\n", **options) as fh:
        for row in rows:
            fh.write(json.dumps(dict(row), ensure_ascii=True, sort_keys=True) + "\n")
            count += 1
        fh.flush()
        os.fsync(fh.fileno())
    return count


def read_jsonl(path: str | Path):
    p = Path(path)
    opener = gzip.open if p.suffix == ".gz" else open
    with opener(p, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def read_csv(path: str | Path):
    with Path(path).open("r", encoding="utf-8", newline="") as fh:
        yield from csv.DictReader(fh)

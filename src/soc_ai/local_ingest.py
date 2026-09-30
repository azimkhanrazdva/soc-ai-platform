from __future__ import annotations

from pathlib import Path

from .config import AppConfig
from .redaction import redact_event
from .storage import read_csv, read_jsonl, write_jsonl


def ingest_local(config: AppConfig, input_path: str | Path, output_path: str | Path) -> dict:
    p = Path(input_path)
    if p.suffix.lower() == ".csv":
        rows = read_csv(p)
    else:
        rows = read_jsonl(p)
    count = write_jsonl(
        output_path,
        (
            redact_event(
                row,
                deny_fields=config.privacy.deny_fields,
                allow_fields=config.privacy.allow_fields,
                mask_ips=config.privacy.mask_ips,
                mask_users=config.privacy.mask_users,
            )
            for row in rows
        ),
    )
    return {"input": str(input_path), "output": str(output_path), "rows": count}


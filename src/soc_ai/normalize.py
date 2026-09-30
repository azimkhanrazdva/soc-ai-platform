from __future__ import annotations

from typing import Any, Mapping
import json


SPLUNK_METADATA_FIELDS = {"host", "source", "sourcetype", "_time"}


def normalize_splunk_event(row: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(row)
    raw = row.get("_raw")
    if not isinstance(raw, str):
        return result
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return result
    if not isinstance(payload, dict):
        return result
    for key in SPLUNK_METADATA_FIELDS:
        if key in result:
            result[f"splunk_{key.lstrip('_')}"] = result[key]
    result.update(payload)
    return result

from __future__ import annotations

import json
import re
from typing import Any


LOSSY_SPL_PATTERNS = [
    re.compile(r"(?i)\|\s*head\b"),
    re.compile(r"(?i)\|\s*tail\b"),
    re.compile(r"(?i)\|\s*sample\b"),
    re.compile(r"(?i)\|\s*sort\s+\d+\b"),
]

STRICT_RAW_SPL_PATTERNS = [
    re.compile(r"(?i)\|"),
    re.compile(r"\[[^\]]+\]"),
    re.compile(r"(?i)\bearliest\s*="),
    re.compile(r"(?i)\blatest\s*="),
    re.compile(r"(?i)\b_index_earliest\s*="),
    re.compile(r"(?i)\b_index_latest\s*="),
    re.compile(r"`[^`]+`"),
]


def parse_partitions_json(value: str | None) -> list[dict[str, str]] | None:
    if not value:
        return None
    parsed: Any = json.loads(value)
    if not isinstance(parsed, list):
        raise ValueError("partitions JSON must be a list")
    result: list[dict[str, str]] = []
    for item in parsed:
        if not isinstance(item, dict):
            raise ValueError("each partition must be an object")
        result.append({str(k): str(v) for k, v in item.items()})
    return result


def validate_spl(base_spl: str, allow_lossy_commands: bool = False) -> list[str]:
    warnings: list[str] = []
    if not base_spl.strip():
        raise ValueError("SPL must not be empty")
    for pattern in LOSSY_SPL_PATTERNS:
        if pattern.search(base_spl):
            message = f"lossy SPL command detected: {pattern.pattern}"
            if allow_lossy_commands:
                warnings.append(message)
            else:
                raise ValueError(f"{message}. Use smaller windows/partitions instead.")
    return warnings


def validate_strict_raw_spl(base_spl: str) -> None:
    """Verified chunk export only supports raw event searches."""
    validate_spl(base_spl, allow_lossy_commands=False)
    for pattern in STRICT_RAW_SPL_PATTERNS:
        if pattern.search(base_spl):
            raise ValueError(
                "verified Splunk export requires a raw event search without pipes, subsearches, "
                "macros, or embedded time modifiers"
            )

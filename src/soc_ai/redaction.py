from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd)=([^\s,;]+)"),
    re.compile(r"(?i)\b(cookie:\s*)([^\s]+)"),
]

DEFAULT_DENY_FIELDS = {
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "session",
    "cookie",
    "api_key",
}


def mask_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return value
    if ip.version == 4:
        parts = value.split(".")
        return ".".join(parts[:2] + ["x", "x"])
    return str(ip).split(":")[0] + ":xxxx"


def redact_text(value: str, mask_ips: bool = True) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        if pattern.groups >= 2:
            redacted = pattern.sub(lambda m: f"{m.group(1)}=<redacted>", redacted)
        else:
            redacted = pattern.sub(lambda m: f"{m.group(1)}<redacted>", redacted)
    if mask_ips:
        redacted = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lambda m: mask_ip(m.group(0)), redacted)
    return redacted


def redact_event(
    event: Mapping[str, Any],
    deny_fields: list[str] | None = None,
    allow_fields: list[str] | None = None,
    mask_ips: bool = True,
    mask_users: bool = False,
) -> dict[str, Any]:
    deny = {f.lower() for f in (deny_fields or DEFAULT_DENY_FIELDS)}
    allow = set(allow_fields or [])
    result: dict[str, Any] = {}
    for key, value in event.items():
        key_l = key.lower()
        if allow and key not in allow:
            continue
        if key_l in deny or any(token in key_l for token in deny):
            result[key] = "<redacted>"
            continue
        if isinstance(value, Mapping):
            result[key] = redact_event(value, deny_fields=deny_fields, mask_ips=mask_ips, mask_users=mask_users)
        elif isinstance(value, (list, tuple)):
            result[key] = [
                redact_event({"value": item}, deny_fields=deny_fields, mask_ips=mask_ips, mask_users=mask_users)["value"]
                for item in value
            ]
        elif isinstance(value, str):
            if mask_users and key_l in {"user", "username", "account"}:
                result[key] = "<user>"
            elif mask_ips and ("ip" in key_l or key_l in {"src", "dest", "clientip"}):
                result[key] = redact_text(mask_ip(value), mask_ips=mask_ips)
            else:
                result[key] = redact_text(value, mask_ips=mask_ips)
        else:
            result[key] = value
    return result

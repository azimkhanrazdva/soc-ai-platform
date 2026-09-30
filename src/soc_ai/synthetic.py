from __future__ import annotations

from pathlib import Path
from typing import Iterator
import json
import random
from datetime import datetime, timezone, timedelta


def generate_synthetic(output_path: str | Path, count: int, seed: int = 42, span_seconds: int | None = None) -> dict:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="\n") as fh:
        for row in iter_synthetic_events(count, seed, span_seconds=span_seconds):
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return {"output": str(p), "rows": count, "seed": seed}


def iter_synthetic_events(count: int, seed: int = 42, span_seconds: int | None = None) -> Iterator[dict]:
    if span_seconds is not None and span_seconds < 1:
        raise ValueError("span_seconds must be positive")
    rng = random.Random(seed)
    hosts = [f"web-{i:02d}" for i in range(1, 11)] + [f"db-{i:02d}" for i in range(1, 5)]
    users = ["alice", "bob", "service", "root", "deploy", "backup", "svc_api", "analyst"]
    sourcetypes = ["linux_secure", "app_json", "nginx_access", "windows_security", "vpn", "proxy", "dns"]
    ok_events = [
        "Accepted password",
        "request ok",
        "job completed",
        "vpn login success",
        "dns query allowed",
        "proxy request allowed",
        "windows logon success",
    ]
    bad_events = [
        "Failed password",
        "account locked after failed login",
        "proxy denied request",
        "vpn login failed",
        "malware keyword observed",
        "ransomware extension touched",
    ]
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    for i in range(count):
        is_bad = rng.random() < 0.035
        host = rng.choice(hosts)
        user = "root" if is_bad and rng.random() < 0.55 else rng.choice(users)
        src_ip = f"203.0.113.{rng.randint(1, 254)}" if is_bad else f"10.{rng.randint(0, 5)}.{rng.randint(0, 20)}.{rng.randint(1, 254)}"
        event = rng.choice(bad_events if is_bad else ok_events)
        sourcetype = rng.choice(sourcetypes)
        yield {
            "_time": (start + timedelta(seconds=i if span_seconds is None else i % span_seconds)).isoformat().replace("+00:00", "Z"),
            "host": host,
            "source": _source_for(event, sourcetype),
            "sourcetype": sourcetype,
            "user": user,
            "src_ip": src_ip,
            "event": event,
            "severity": "medium" if is_bad else "info",
            "dataset": "synthetic-varied",
        }


def _source_for(event: str, sourcetype: str) -> str:
    text = event.lower()
    if "password" in text or "login" in text or "logon" in text:
        return "auth.log"
    if sourcetype == "dns":
        return "dns.log"
    if sourcetype == "proxy":
        return "proxy.log"
    if sourcetype == "windows_security":
        return "wineventlog"
    return "app.log"

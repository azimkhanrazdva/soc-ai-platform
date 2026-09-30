from __future__ import annotations

from pathlib import Path
import json
import tomllib

from .config import AppConfig
from .splunk import splunk_preflight


def load_export_profiles(path: str | Path = "configs/splunk_exports.toml") -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        raise ValueError("[profiles] must be a TOML table")
    return profiles


def profile_plan(
    config: AppConfig,
    name: str,
    profiles_path: str | Path = "configs/splunk_exports.toml",
    estimate_only: int | None = None,
    skip_remote_count: bool = True,
) -> dict:
    profiles = load_export_profiles(profiles_path)
    if name not in profiles:
        raise KeyError(f"unknown export profile: {name}")
    profile = profiles[name]
    partitions = json.loads(profile.get("partitions_json", "null"))
    preflight = splunk_preflight(
        config,
        profile["spl"],
        profile["start"],
        profile["end"],
        estimate_only=estimate_only,
        partitions=partitions,
        skip_remote_count=skip_remote_count,
    )
    command = [
        "soc-ai",
        "splunk-ingest",
        "--spl",
        profile["spl"],
        "--start",
        profile["start"],
        "--end",
        profile["end"],
    ]
    if profile.get("partitions_json"):
        command.extend(["--partitions-json", profile["partitions_json"]])
    return {"profile": name, "description": profile.get("description", ""), "preflight": preflight, "command": command}


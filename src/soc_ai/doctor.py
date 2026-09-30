from __future__ import annotations

from pathlib import Path
import os
import shutil
import socket

from .config import AppConfig


def run_doctor(config: AppConfig, min_free_gb: int = 20) -> dict:
    runtime = config.runtime
    checks = []
    checks.append(_check("python_project", Path("pyproject.toml").exists(), "pyproject.toml present"))
    checks.append(_check("config", Path("configs/default.toml").exists(), "default config present"))
    checks.append(_check("sample_data", Path("sample_data/events.jsonl").exists(), "sample data present"))
    checks.append(_check("splunk_url_env", bool(os.getenv(config.splunk.base_url_env)), f"{config.splunk.base_url_env} set"))
    has_token = bool(os.getenv(config.splunk.token_env))
    has_basic = bool(os.getenv(config.splunk.username_env) and os.getenv(config.splunk.password_env))
    checks.append(_check("splunk_auth_env", has_token or has_basic, f"{config.splunk.token_env} or {config.splunk.username_env}/{config.splunk.password_env} set"))

    usage = shutil.disk_usage(Path.cwd())
    free_gb = round(usage.free / (1024**3), 2)
    checks.append(_check("disk_free", free_gb >= min_free_gb, f"{free_gb} GB free, required >= {min_free_gb} GB"))
    checks.append(_check("chunk_seconds", runtime.chunk_seconds > 0, f"chunk_seconds={runtime.chunk_seconds}"))
    checks.append(_check("target_events_per_chunk", runtime.target_events_per_chunk > 0, f"target_events_per_chunk={runtime.target_events_per_chunk}"))
    checks.append(_check("local_splunk_management_port", _port_open("127.0.0.1", 8089), "127.0.0.1:8089 reachable"))
    checks.append(_check("local_splunk_web_port", _port_open("127.0.0.1", 8000), "127.0.0.1:8000 reachable"))
    checks.append(_check("local_splunk_receiver_port", _port_open("127.0.0.1", 9997), "127.0.0.1:9997 reachable"))
    optional = {
        "splunk_url_env",
        "splunk_auth_env",
        "local_splunk_management_port",
        "local_splunk_web_port",
        "local_splunk_receiver_port",
    }
    ready = all(item["ok"] for item in checks if item["name"] not in optional)
    splunk_ready = all(item["ok"] for item in checks if item["name"] in {"splunk_url_env", "splunk_auth_env"})
    return {"ready_without_splunk": ready, "splunk_ready": splunk_ready, "checks": checks}


def _check(name: str, ok: bool, detail: str) -> dict:
    return {"name": name, "ok": bool(ok), "detail": detail}


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False

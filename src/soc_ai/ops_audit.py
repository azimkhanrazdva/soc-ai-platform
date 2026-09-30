from __future__ import annotations

from pathlib import Path
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request

from .config import AppConfig
from .doctor import run_doctor


DEFAULT_PORTS = (8000, 8088, 8089, 8091, 11434)


def run_ops_audit(
    config: AppConfig,
    splunk_host: str = "soc-storage.example.test",
    reports_dir: str | Path = "reports",
    ports: tuple[int, ...] = DEFAULT_PORTS,
) -> dict:
    report_root = Path(reports_dir)
    latest_metrics = _latest(report_root, "metrics-*.json")
    largest_metrics = _largest_metrics(report_root)
    latest_review = _latest(report_root, "gpu_review.json")
    audit = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "doctor": run_doctor(config, min_free_gb=1),
        "git": _git_status(),
        "disk": _disk("."),
        "ports": {str(port): _port_open("127.0.0.1", port) for port in ports},
        "gpu": _gpu_status(),
        "ollama": _ollama_status(),
        "splunk_remote": _remote_splunk(splunk_host),
        "latest_metrics": _summarize_metrics(latest_metrics),
        "largest_metrics": _summarize_metrics(largest_metrics),
        "latest_ai_review": _summarize_ai_review(latest_review),
    }
    audit["risk_summary"] = _risk_summary(audit)
    return audit


def _git_status() -> dict:
    status = _run(["git", "status", "--short"])
    head = _run(["git", "rev-parse", "--short", "HEAD"])
    return {"head": head.strip(), "dirty": bool(status.strip()), "changes": status.splitlines()[:50]}


def _disk(path: str | Path) -> dict:
    usage = shutil.disk_usage(path)
    return {
        "total_gb": round(usage.total / (1024**3), 2),
        "used_gb": round(usage.used / (1024**3), 2),
        "free_gb": round(usage.free / (1024**3), 2),
        "used_percent": round(usage.used / usage.total * 100, 2),
    }


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex((host, port)) == 0


def _gpu_status() -> dict:
    out = _run(["nvidia-smi", "--query-gpu=name,memory.used,memory.total,utilization.gpu", "--format=csv,noheader,nounits"], timeout=3)
    if not out:
        return {"available": False}
    try:
        name, mem_used, mem_total, util = [item.strip() for item in out.splitlines()[0].split(",")]
    except ValueError:
        return {"available": False, "raw": out[:200]}
    return {"available": True, "name": name, "memory_used_mib": int(mem_used), "memory_total_mib": int(mem_total), "utilization_percent": int(util)}


def _ollama_status() -> dict:
    checked = {}
    candidates = []
    configured = os.getenv("OLLAMA_ENDPOINT")
    if configured:
        candidates.append(configured.replace("/api/generate", "/api/tags"))
    candidates.append("http://127.0.0.1:11434/api/tags")
    lan_ip = _local_lan_ip()
    if lan_ip:
        candidates.append(f"http://{lan_ip}:11434/api/tags")
    for endpoint in dict.fromkeys(candidates):
        try:
            with urllib.request.urlopen(endpoint, timeout=3) as response:
                data = json.loads(response.read())
        except Exception:
            checked[endpoint] = False
            continue
        checked[endpoint] = True
    active = [endpoint for endpoint, ok in checked.items() if ok]
    models = []
    for endpoint in active[:1]:
        try:
            with urllib.request.urlopen(endpoint, timeout=3) as response:
                models = [item.get("name", "") for item in json.loads(response.read()).get("models", [])]
        except Exception:
            models = []
    lan_exposed = bool(lan_ip and checked.get(f"http://{lan_ip}:11434/api/tags"))
    return {"ok": bool(active), "endpoint": active[0] if active else candidates[0], "models": models,
            "checked": checked, "lan_exposed": lan_exposed, "required_binding": "127.0.0.1:11434"}


def _remote_splunk(host: str) -> dict:
    result = _run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4", host, "docker inspect --format={{.State.Health.Status}} alars-splunk"], timeout=8)
    return {"host": host, "healthy": result.strip() == "healthy", "detail": result.strip() or "unavailable"}


def _latest(root: Path, pattern: str) -> Path | None:
    if not root.is_dir():
        return None
    matches = sorted(root.rglob(pattern), key=lambda path: path.stat().st_mtime)
    return matches[-1] if matches else None


def _largest_metrics(root: Path) -> Path | None:
    best_path = None
    best_events = -1
    for path in root.rglob("metrics-*.json") if root.is_dir() else []:
        events = _read_json(path).get("total_events")
        if isinstance(events, int) and events > best_events:
            best_path = path
            best_events = events
    return best_path


def _summarize_metrics(path: Path | None) -> dict:
    data = _read_json(path)
    if not data:
        return {"path": str(path) if path else "", "found": False}
    return {
        "path": str(path),
        "found": True,
        "total_events": data.get("total_events"),
        "integrity_ok": data.get("integrity", {}).get("ok"),
        "rule_findings": data.get("rules", {}).get("findings_count"),
        "aggregation_limited": data.get("aggregation_limited"),
    }


def _summarize_ai_review(path: Path | None) -> dict:
    data = _read_json(path)
    if not data:
        return {"path": str(path) if path else "", "found": False}
    checks = data.get("quality_checks", {})
    return {"path": str(path), "found": True, "quality_passed": checks.get("passed"), "unsupported_terms": checks.get("unsupported_attack_terms", [])}


def _risk_summary(audit: dict) -> list[str]:
    risks = []
    if audit["git"]["dirty"]:
        risks.append("git worktree has uncommitted changes")
    if audit["disk"]["free_gb"] < 50:
        risks.append("free disk below 50 GB; large Splunk runs may fail")
    if not audit["ollama"]["ok"]:
        risks.append("Ollama endpoint is unavailable")
    if audit["ollama"].get("lan_exposed"):
        risks.append("Ollama API is reachable on LAN; bind it to 127.0.0.1 and use SSH tunnels")
    if not audit["gpu"].get("available"):
        risks.append("GPU is unavailable for local AI review")
    if audit["latest_ai_review"].get("found") and audit["latest_ai_review"].get("quality_passed") is not True:
        risks.append("latest AI review failed quality checks")
    if audit["splunk_remote"]["host"] and not audit["splunk_remote"]["healthy"]:
        risks.append("remote Splunk health check failed")
    return risks


def _local_lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))
            return sock.getsockname()[0]
    except OSError:
        return ""


def _read_json(path: Path | None) -> dict:
    if not path:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _run(command: list[str], timeout: int = 5) -> str:
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import socket
import subprocess
import time


@dataclass(frozen=True)
class BridgeConfig:
    sender_label: str = "workstation"
    test_server: str = "soc-storage.example.test"
    gpu_server: str = "soc-gpu.example.test"
    splunk_index: str = "main"
    sourcetype: str = "soc_ai_json"
    source_prefix: str = "soc-ai-ingress"
    splunk_container: str = "alars-splunk"


def bridge_plan(config: BridgeConfig) -> dict:
    test_address = _host_address(config.test_server)
    source = f"{config.source_prefix}-<batch-id>"
    spl = f'index={config.splunk_index} sourcetype={config.sourcetype} source="{source}"'
    return {
        "schema": "soc-bridge-plan-v1",
        "flow": [
            {"step": "sender_to_test_server", "from": config.sender_label, "to": config.test_server, "protocol": "Splunk HEC 8088 or file drop handled on test server"},
            {"step": "test_server_storage", "host": config.test_server, "system": "Splunk", "index": config.splunk_index, "sourcetype": config.sourcetype, "source_pattern": source},
            {"step": "gpu_export", "host": config.gpu_server, "command": "pipeline-splunk", "spl": spl},
            {"step": "loss_guard", "checks": ["splunk preflight count", "chunk manifest", "sha256 per chunk", "integrity rows", "rules events_scanned", "data-audit"]},
            {"step": "model_update", "method": "frequency profile training on exported chunks; labeled metrics only when labels exist"},
            {"step": "report_release", "condition": "data-audit status pass and PDF QA pass"},
        ],
        "sender_example": {
            "url": f"https://{test_address}:8088/services/collector/event",
            "headers": {"Authorization": "Splunk <HEC_TOKEN>", "Content-Type": "application/json"},
            "event_template": {"index": config.splunk_index, "sourcetype": config.sourcetype, "source": source, "event": {"message": "..."}},
        },
        "gpu_command_template": (
            "soc-ai --config configs/production.toml pipeline-splunk "
            f"--spl '{spl}' --start <ISO-START> --end <ISO-END> --run-dir reports/bridge-run-<batch-id>"
        ),
    }


def bridge_status(config: BridgeConfig) -> dict:
    test_address = _host_address(config.test_server)
    gpu_address = _host_address(config.gpu_server)
    checks = [
        _check("test_server_ssh", _ssh(config.test_server, "echo ok") == "ok", f"ssh {config.test_server}"),
        _check("test_splunk_health", _ssh(config.test_server, f"docker inspect --format='{{{{.State.Health.Status}}}}' {config.splunk_container}") == "healthy", config.splunk_container),
        _check("test_hec_port_from_gpu", _port_open(test_address, 8088), f"{test_address}:8088"),
        _check("test_splunk_management_from_gpu", _port_open(test_address, 8089), f"{test_address}:8089"),
        _check("gpu_ollama_loopback", _port_open("127.0.0.1", 11434), "127.0.0.1:11434"),
    ]
    remote_disk = _remote_disk(config.test_server)
    if remote_disk:
        checks.append(_check("test_server_disk_free", remote_disk.get("free_gb", 0) >= 20, f"{remote_disk.get('free_gb')} GB free"))
    risks = []
    if _port_open(gpu_address, 11434):
        risks.append("GPU Ollama appears reachable on LAN; bind Ollama to 127.0.0.1 before production")
    if not any(item["name"] == "test_hec_port_from_gpu" and item["ok"] for item in checks):
        risks.append("GPU cannot reach test server HEC port; sender ingestion may work but bridge verification is incomplete")
    return {
        "schema": "soc-bridge-status-v1",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "plan": bridge_plan(config),
        "checks": checks,
        "ready": all(item["ok"] for item in checks) and not risks,
        "risks": risks,
    }


def _check(name: str, ok: bool, detail: str) -> dict:
    return {"name": name, "ok": bool(ok), "detail": detail}


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _ssh(host: str, command: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]+", host):
        return ""


def _host_address(target: str) -> str:
    return target.rsplit("@", 1)[-1].strip("[]")
    try:
        return subprocess.check_output(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4", "--", host, command],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=8,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _remote_disk(host: str) -> dict:
    raw = _ssh(host, "python3 - <<'PY'\nimport json, shutil\nu=shutil.disk_usage('.')\nprint(json.dumps({'free_gb': round(u.free/1024**3, 2), 'used_percent': round(u.used/u.total*100, 2)}))\nPY")
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}

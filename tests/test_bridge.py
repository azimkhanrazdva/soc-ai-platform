from soc_ai import bridge
from soc_ai.bridge import BridgeConfig, bridge_plan, bridge_status
from soc_ai.cli import main


def test_bridge_plan_describes_test_server_to_gpu_flow():
    plan = bridge_plan(BridgeConfig(test_server="operator@soc-storage.example.test", gpu_server="soc-gpu.example.test", source_prefix="batch"))
    assert plan["sender_example"]["url"] == "https://soc-storage.example.test:8088/services/collector/event"
    assert 'source="batch-<batch-id>"' in plan["gpu_command_template"]
    assert "data-audit" in plan["flow"][3]["checks"]


def test_bridge_status_reports_lan_ollama_risk(monkeypatch):
    monkeypatch.setattr(bridge, "_ssh", lambda host, command: "healthy" if "docker inspect" in command else "ok")
    monkeypatch.setattr(bridge, "_remote_disk", lambda host: {"free_gb": 100})
    monkeypatch.setattr(bridge, "_port_open", lambda host, port: host == "soc-gpu.example.test" and port == 11434 or port in {8088, 8089, 11434})
    status = bridge_status(BridgeConfig())
    assert status["ready"] is False
    assert any("Ollama" in risk for risk in status["risks"])


def test_bridge_status_uses_plain_host_for_port_checks(monkeypatch):
    seen = []
    monkeypatch.setattr(bridge, "_ssh", lambda host, command: "healthy" if "docker inspect" in command else "ok")
    monkeypatch.setattr(bridge, "_remote_disk", lambda host: {"free_gb": 100})
    monkeypatch.setattr(bridge, "_port_open", lambda host, port: seen.append((host, port)) or True)
    bridge_status(BridgeConfig(test_server="operator@soc-storage.example.test", gpu_server="operator@soc-gpu.example.test"))
    assert ("soc-storage.example.test", 8088) in seen
    assert ("soc-gpu.example.test", 11434) in seen


def test_bridge_plan_cli_returns_success():
    assert main(["bridge-plan", "--test-server", "soc-storage.example.test", "--gpu-server", "soc-gpu.example.test"]) == 0

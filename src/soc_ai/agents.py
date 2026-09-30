from __future__ import annotations

from pathlib import Path
import tomllib
import json
import time
import uuid

from .gpu import gpu_review
from .qa import qa_run, qa_ai_review
from .storage import atomic_write_json


class ReviewPolicyError(ValueError):
    """Local policy rejection with no external response contents."""


def load_agents(path: str | Path = "configs/agents.toml") -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    return {name: value for name, value in data.items() if isinstance(value, dict)}


def agent_plan(path: str | Path = "configs/agents.toml") -> dict:
    agents = load_agents(path)
    return {
        "agents": [
            {
                "name": name,
                "role": cfg.get("role", ""),
                "model": cfg.get("model", ""),
                "requires_human_approval": bool(cfg.get("requires_human_approval", True)),
                "allowed_commands": cfg.get("allowed_commands", []),
                "execution": "review workflow" if name in {"qa_agent", "gpu_review_agent"} else "data usage audit" if name == "data_audit_agent" else "configuration only; no autonomous executor",
                "invokes_model": name == "gpu_review_agent",
            }
            for name, cfg in sorted(agents.items())
        ]
    }


def review_workflow(run_dir: str | Path, agents_path: str | Path = "configs/agents.toml", endpoint: str | None = None) -> dict:
    agents = load_agents(agents_path)
    root = Path(run_dir)
    output = root / "reports" / f"agent-review-{uuid.uuid4().hex}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    result = {"status": "fail", "run_dir": str(root), "steps": [], "output": str(output)}
    started = time.monotonic()

    def check_tool(agent, command):
        cfg = agents.get(agent, {})
        if cfg.get("requires_human_approval", True) or command not in cfg.get("allowed_commands", []):
            raise ReviewPolicyError(f"Agent policy does not authorize {agent}: {command}")

    try:
        check_tool("qa_agent", "qa-run")
        report_check = qa_run(root, strict=True)
        result["steps"].append({"agent": "qa_agent", "command": "qa-run", "result": report_check})
        if report_check["status"] != "pass":
            raise ReviewPolicyError("Report QA failed; inference blocked")
        check_tool("gpu_review_agent", "gpu-review")
        review = gpu_review(report_check["metrics"], output.with_name(output.stem + "-gpu.json"),
                            model=agents["gpu_review_agent"]["model"], endpoint=endpoint)
        result["steps"].append({"agent": "gpu_review_agent", "command": "gpu-review", "output": review["output"]})
        check_tool("qa_agent", "qa-ai-review")
        review_check = qa_ai_review(review["output"], strict=True)
        result["steps"].append({"agent": "qa_agent", "command": "qa-ai-review", "result": review_check})
        result["status"] = review_check["status"]
    except Exception as exc:
        result["error"] = str(exc) if isinstance(exc, ReviewPolicyError) else type(exc).__name__
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    atomic_write_json(output, result)
    return result

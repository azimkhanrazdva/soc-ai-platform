import json

from soc_ai.agents import agent_plan
from soc_ai.config import AppConfig
from soc_ai.export_profiles import profile_plan
from soc_ai.rules import run_rules


def test_agent_plan_loads_boundaries(tmp_path):
    agents = tmp_path / "agents.toml"
    agents.write_text(
        '[worker]\nrole="test"\nmodel="qwen"\nrequires_human_approval=false\nallowed_commands=["doctor"]\n',
        encoding="utf-8",
    )
    result = agent_plan(agents)
    assert result["agents"][0]["name"] == "worker"
    assert result["agents"][0]["allowed_commands"] == ["doctor"]


def test_run_rules_finds_match(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "id": "r1",
                    "title": "Failed",
                    "severity": "high",
                    "match": {"all": [{"field": "event", "contains": "failed"}]},
                }
            ]
        ),
        encoding="utf-8",
    )
    events = tmp_path / "events.jsonl"
    events.write_text(json.dumps({"event": "Failed password", "host": "web"}) + "\n", encoding="utf-8")
    result = run_rules([events], rules, tmp_path / "findings.json")
    assert result["findings_count"] == 1
    assert result["findings_by_severity"] == {"high": 1}


def test_run_rules_bounds_evidence_but_keeps_counts(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([{"id": "r1", "match": {"field": "event", "contains": "failed"}}]), encoding="utf-8")
    events = tmp_path / "events.jsonl"
    events.write_text("\n".join(json.dumps({"event": "failed"}) for _ in range(3)) + "\n", encoding="utf-8")

    result = run_rules([events], rules, tmp_path / "findings.json", max_findings=1)

    assert result["findings_count"] == 3
    assert result["findings_by_severity"] == {"medium": 3}
    assert result["findings_truncated"] is True
    assert len(result["findings"]) == 1


def test_profile_plan_returns_command(tmp_path):
    profiles = tmp_path / "profiles.toml"
    profiles.write_text(
        '[profiles.demo]\ndescription="demo"\nspl="index=main"\nstart="2026-01-01T00:00:00Z"\nend="2026-01-01T01:00:00Z"\npartitions_json="[{\\\"index\\\":\\\"main\\\"}]"\n',
        encoding="utf-8",
    )
    result = profile_plan(AppConfig(), "demo", profiles, estimate_only=100, skip_remote_count=True)
    assert result["profile"] == "demo"
    assert result["preflight"]["planned_chunks"] == 1
    assert result["command"][0:2] == ["soc-ai", "splunk-ingest"]

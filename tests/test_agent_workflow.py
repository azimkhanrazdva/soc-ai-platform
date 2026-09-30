import json
import hashlib

from soc_ai import agents
from soc_ai.cli import main
from soc_ai.qa import qa_ai_review


def test_failed_report_blocks_inference(tmp_path, monkeypatch):
    policy = tmp_path / "agents.toml"
    policy.write_text('[qa_agent]\nrequires_human_approval = false\nallowed_commands = ["qa-run"]\n')
    def unexpected(*args, **kwargs):
        raise AssertionError("inference must not be called")
    monkeypatch.setattr(agents, "gpu_review", unexpected)
    result = agents.review_workflow(tmp_path / "run", policy)
    assert result["status"] == "fail"
    assert "inference blocked" in result["error"]


def test_policy_blocks_unapproved_tool(tmp_path):
    policy = tmp_path / "agents.toml"
    policy.write_text('[qa_agent]\nrequires_human_approval = true\nallowed_commands = ["qa-run"]\n')
    result = agents.review_workflow(tmp_path / "run", policy)
    assert result["status"] == "fail"
    assert not result["steps"]


def test_qa_rejects_forged_pass_flag(tmp_path):
    path = tmp_path / "review.json"
    path.write_text(json.dumps({"done": True, "aggregate": {"total_events": 2},
                               "response": {"top_risks": "wrong"}, "quality_checks": {"passed": True}}))
    assert qa_ai_review(path)["status"] == "fail"


def test_cli_qa_failure_returns_nonzero(tmp_path):
    assert main(["qa-run", "--run-dir", str(tmp_path)]) == 1


def test_qa_rejects_tampered_aggregate_with_valid_source_hash(tmp_path):
    source = tmp_path / "metrics.json"
    source.write_text(json.dumps({"total_events": 2}))
    payload = {"done": True, "metrics": str(source),
               "metrics_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "aggregate": {"total_events": 2}, "quality_checks": {"passed": True},
               "response": {"top_risks": [], "data_quality_concerns": [], "next_actions": []}}
    review = tmp_path / "review.json"
    review.write_text(json.dumps(payload))
    assert qa_ai_review(review)["status"] == "pass"
    payload["aggregate"]["total_events"] = 400000000
    review.write_text(json.dumps(payload))
    assert "AI review aggregate differs from source metrics" in qa_ai_review(review)["failures"]
    del payload["metrics"]
    review.write_text(json.dumps(payload))
    assert "AI review requires source metrics and their digest" in qa_ai_review(review)["failures"]

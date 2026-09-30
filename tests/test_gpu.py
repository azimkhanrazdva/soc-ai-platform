import json

from soc_ai import gpu


def test_aggregate_metrics_excludes_raw_fields():
    result = gpu._aggregate_metrics({"total_events": 3, "event": "secret", "top_hosts": [["web", 3]]})
    assert result == {"total_events": 3, "top_hosts": [["web", 3]]}


def test_quality_checks_flags_low_frequency_host_claims():
    result = gpu._quality_checks(
        {"top_risks": ["ntesla is high frequency"], "data_quality_concerns": [], "next_actions": []},
        {"top_hosts": [["ntesla", 2]]},
    )
    assert result["passed"] is False
    assert result["low_frequency_hosts_mentioned"] == ["ntesla"]


def test_quality_checks_flags_unsupported_attack_names():
    result = gpu._quality_checks(
        {"top_risks": ["possible DDoS attack"], "data_quality_concerns": [], "next_actions": []},
        {"top_hosts": [["web", 100]], "keyword_counts": [["failed", 10]]},
    )
    assert result["passed"] is False
    assert result["unsupported_attack_terms"] == ["attack", "ddos"]


def test_gpu_review_uses_ollama_response(tmp_path, monkeypatch):
    metrics_path = tmp_path / "metrics.json"
    metrics_path.write_text(json.dumps({"total_events": 3, "top_hosts": [["web", 3]]}), encoding="utf-8")

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, *args):
            return b'{"response":"{\\"top_risks\\":[],\\"data_quality_concerns\\":[],\\"next_actions\\":[]}","done":true,"eval_count":4}'

    monkeypatch.setattr(gpu, "open_service", lambda *args, **kwargs: Response())
    result = gpu.gpu_review(metrics_path, tmp_path / "gpu.json")
    assert result["done"] is True
    assert result["eval_count"] == 4


def test_schema_rejects_string_array_and_unknown_evidence():
    for value in ["do something", ["do something"], [{"text": "claim", "evidence": ["invented"]}]]:
        result = gpu._quality_checks({"top_risks": value, "data_quality_concerns": [], "next_actions": []}, {"total_events": 2})
        assert result["passed"] is False
        assert result["schema_errors"]


def test_attack_terms_match_words_not_substrings():
    result = gpu._quality_checks({"top_risks": [], "data_quality_concerns": [],
                                  "next_actions": [{"text": "capture a baseline", "evidence": ["total_events"]}]},
                                 {"total_events": 2})
    assert result["passed"] is True


def test_aggregate_redacts_nested_secrets():
    result = gpu._aggregate_metrics({"total_events": 2, "top_sources": [["token=topsecret", 2]]})
    assert "topsecret" not in json.dumps(result)


def test_aggregate_pseudonymizes_users():
    result = gpu._aggregate_metrics({"top_users": [["alice", 2]]})
    assert result["top_users"] == [["user_1", 2]]

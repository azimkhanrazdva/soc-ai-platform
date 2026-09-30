from soc_ai.config import load_config, load_env_file
from soc_ai.pipeline import run_local_pipeline


def test_load_env_file_does_not_override(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("SPLUNK_TOKEN=from-file\n", encoding="utf-8")
    monkeypatch.setenv("SPLUNK_TOKEN", "existing")
    loaded = load_env_file(env)
    assert loaded == {}


def test_run_local_pipeline(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text('{"host":"a","event":"failed token=secret","src_ip":"10.1.2.3"}\n', encoding="utf-8")
    result = run_local_pipeline(load_config("missing.toml"), events, tmp_path / "run")
    assert result["integrity_ok"] is True
    assert result["benchmark"]["events"] == 1
    assert result["rules"].endswith("rule_findings.json")

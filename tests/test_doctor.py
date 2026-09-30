from soc_ai.config import AppConfig
from soc_ai.doctor import run_doctor


def test_doctor_returns_checks(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SPLUNK_BASE_URL", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("SPLUNK_USERNAME", raising=False)
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)
    (tmp_path / "configs").mkdir()
    (tmp_path / "sample_data").mkdir()
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    (tmp_path / "configs" / "default.toml").write_text("", encoding="utf-8")
    (tmp_path / "sample_data" / "events.jsonl").write_text("", encoding="utf-8")
    result = run_doctor(AppConfig(), min_free_gb=0)
    assert result["ready_without_splunk"] is True
    assert result["splunk_ready"] is False

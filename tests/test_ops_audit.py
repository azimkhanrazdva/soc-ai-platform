from soc_ai.config import AppConfig
from soc_ai.ops_audit import run_ops_audit


def test_ops_audit_returns_safe_summary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "metrics-1.json").write_text(
        '{"total_events": 10, "integrity": {"ok": true}, "rules": {"findings_count": 2}}',
        encoding="utf-8",
    )
    result = run_ops_audit(AppConfig(), splunk_host="", reports_dir=tmp_path / "reports")
    assert result["latest_metrics"]["total_events"] == 10
    assert result["largest_metrics"]["total_events"] == 10
    assert "risk_summary" in result
    assert "doctor" in result

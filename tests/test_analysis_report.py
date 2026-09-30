import json

from soc_ai.analyze import analyze_files
from soc_ai.report import write_report


def test_analyze_and_report(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text(
        "\n".join(
            [
                json.dumps({"host": "a", "src_ip": "1.1.x.x", "event": "failed login"}),
                json.dumps({"host": "b", "src_ip": "1.1.x.x", "event": "ok"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    metrics = analyze_files([events])
    metrics["rules"] = {"events_scanned": 2, "findings_count": 1, "findings_by_severity": {"high": 1}}
    metrics["integrity"] = {"ok": True, "verified_rows": 2, "expected_rows": 2}
    assert metrics["total_events"] == 2
    assert metrics["keyword_counts"][0][0] == "failed"

    outputs = write_report(metrics, tmp_path)
    assert "report-" in outputs["markdown"]
    assert "metrics-" in outputs["metrics"]
    assert "report-" in outputs["pdf"]
    assert "report-" in outputs["docx"]
    assert open(outputs["pdf"], "rb").read(4) == b"%PDF"
    assert open(outputs["docx"], "rb").read(2) == b"PK"


def test_analysis_bounds_high_cardinality_fields(tmp_path):
    events = tmp_path / "high-cardinality.jsonl"
    events.write_text(
        "\n".join(json.dumps({"host": f"host-{index}", "source": f"source-{index}"}) for index in range(10)) + "\n",
        encoding="utf-8",
    )

    metrics = analyze_files([events], max_unique_values=3)

    assert metrics["total_events"] == 10
    assert metrics["aggregation_limited"] is True
    assert len(metrics["top_hosts"]) <= 3


def test_empty_model_list_unique_reports_and_untrusted_table_cells(tmp_path):
    from pathlib import Path
    metrics = {"model_comparison": [], "top_hosts": [["<script>x</script>|\n## forged", 1]]}
    metrics.update(total_events=1, integrity=dict(ok=True, verified_rows=1, expected_rows=1),
                   rules=dict(events_scanned=1, findings_count=0, findings_by_severity={}))
    first = write_report(metrics, tmp_path)
    second = write_report(metrics, tmp_path)
    assert first["markdown"] != second["markdown"]
    text = Path(first["markdown"]).read_text(encoding="utf-8")
    assert "<script>" not in text
    assert "\n## forged" not in text
    assert "&#124;" in text


def test_report_redacts_nested_secret_from_all_artifacts(tmp_path):
    from pathlib import Path
    metrics = dict(total_events=1, integrity=dict(ok=True, verified_rows=1, expected_rows=1),
                   rules=dict(events_scanned=1, findings_count=0, findings_by_severity={}),
                   model_comparison=[], nested={"password": "notforpublication"})
    outputs = write_report(metrics, tmp_path)
    for path in outputs.values():
        if str(path).endswith((".pdf", ".docx")):
            assert b"notforpublication" not in Path(path).read_bytes()
        else:
            assert "notforpublication" not in Path(path).read_text(encoding="utf-8")

import json
from pathlib import Path

import pytest

from soc_ai.report import write_report
from soc_ai.pdf_qa import check_pdf
from soc_ai.report_document import build_document
from soc_ai.redaction import redact_event


def evidence():
    return dict(total_events=2, integrity=dict(ok=True, verified_rows=2, expected_rows=2),
                rules=dict(events_scanned=2, findings_count=0, findings_by_severity={}))


def test_pdf_gate_rejects_missing_content_and_does_not_publish(tmp_path, monkeypatch):
    def broken(document, path):
        from reportlab.pdfgen.canvas import Canvas
        canvas = Canvas(str(path))
        canvas.drawString(50, 700, "Incomplete report")
        canvas.save()
    monkeypatch.setattr("soc_ai.report_document.pdf_document", broken)
    with pytest.raises(ValueError, match="PDF acceptance failed"):
        write_report(evidence(), tmp_path)
    assert not list(tmp_path.iterdir())


def test_invalid_evidence_is_not_published(tmp_path):
    data = evidence()
    data["integrity"]["verified_rows"] = 1
    with pytest.raises(ValueError, match="evidence failed"):
        write_report(data, tmp_path)
    assert not list(tmp_path.iterdir())


def test_accepted_pdf_has_bound_receipt(tmp_path):
    result = write_report(evidence(), tmp_path)
    path = Path(result["pdf"])
    receipt = json.loads(path.with_suffix(".qa.json").read_text())
    assert receipt == check_pdf(path, build_document(evidence()))
    assert receipt["status"] == "pass"


def test_tuple_and_ip_named_text_do_not_bypass_redaction():
    result = redact_event({"top_hosts": [("password=abcdefghi", 2)],
                           "src_ip": "token=abcdefghi"})
    assert "abcdefghi" not in repr(result)


def test_staged_pdf_cannot_be_downloaded(tmp_path):
    from soc_ai.monitor import safe_report_path
    staging = tmp_path / ".report-staging-test"
    staging.mkdir()
    (staging / "report.pdf").write_bytes(b"%PDF")
    assert safe_report_path(tmp_path, ".report-staging-test/report.pdf") is None


def test_run_log_masks_secrets(tmp_path):
    from soc_ai.runlog import RunLogger
    path = tmp_path / "run.jsonl"
    RunLogger(path).event("test", "failed", password="notforpublication",
                          error="token=notforpublication")
    assert "notforpublication" not in path.read_text()


def test_report_replaces_yo_letter_in_published_artifacts(tmp_path):
    data = evidence()
    data["report_metadata"] = {"customer": "Ёлка SOC"}
    data["top_hosts"] = [["сёрвер", 2]]
    result = write_report(data, tmp_path)
    for path in Path(result["pdf"]).parent.iterdir():
        payload = path.read_bytes() if path.suffix in {".pdf", ".docx"} else path.read_text(encoding="utf-8")
        assert "ё" not in str(payload).lower()

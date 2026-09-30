from pathlib import Path
import json

from reportlab.pdfgen.canvas import Canvas

from soc_ai.report_reference import ingest_report_reference


def _pdf(path: Path, text: str):
    canvas = Canvas(str(path))
    canvas.drawString(72, 720, text)
    canvas.save()


def test_reference_ingest_creates_style_dataset_for_readable_pdf(tmp_path):
    source = tmp_path / "official.pdf"
    _pdf(source, "Official SOC report table section 203.0.113.42 HOST-DC01 user.name host01.example.local")
    result = ingest_report_reference(source, tmp_path / "refs", min_text_quality=0.1)
    assert result["rows_written"] >= 1
    row = json.loads((tmp_path / "refs" / "report_style_references.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert "official_report_style" in row["input"]
    assert "Official SOC report" in row["output"]
    assert "203.0.113.42" not in row["output"]
    assert "203.0.x.x" in row["output"]
    assert "HOST-DC01" not in row["output"]
    assert "user.name" not in row["output"]
    assert "host01.example.local" not in row["output"]
    assert "<host>" in row["output"]
    assert "<user>" in row["output"]


def test_reference_ingest_blocks_unreadable_training_text(tmp_path):
    source = tmp_path / "broken.pdf"
    canvas = Canvas(str(source))
    canvas.line(72, 720, 300, 720)
    canvas.save()
    result = ingest_report_reference(source, tmp_path / "refs")
    assert result["rows_written"] == 0
    assert result["status"] == "visual_reference_only"
    assert not (tmp_path / "refs" / "report_style_references.jsonl").exists()

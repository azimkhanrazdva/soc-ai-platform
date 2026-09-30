import gzip
import hashlib
import json
from pathlib import Path

import pytest

from soc_ai.report import write_report
from soc_ai.report_document import build_document, evidence_digest
from soc_ai.report_planner import validate_plan, verify_bound_plan
from soc_ai.report_timeline import build_timeline
from soc_ai.qa import qa_report


def metrics():
    return dict(total_events=2, integrity=dict(ok=True, verified_rows=2, expected_rows=2),
                rules=dict(events_scanned=2, findings_count=0, findings_by_severity={}),
                top_hosts=[["host", 2]])


def test_report_content_tampering_fails_qa(tmp_path):
    output = write_report(metrics(), tmp_path)
    assert qa_report(output["markdown"], output["metrics"])["status"] == "pass"
    path = Path(output["markdown"])
    path.write_text(path.read_text(encoding="utf-8").replace("Обработано 2", "Обработано 9"), encoding="utf-8")
    assert qa_report(path, output["metrics"])["status"] == "fail"


def test_model_cannot_invent_evidence_or_reuse_changed_metrics():
    with pytest.raises(ValueError):
        validate_plan({"selected_ids": ["invented"]}, ["coverage"])
    with pytest.raises(ValueError):
        validate_plan({"selected_ids": ["coverage"], "text": "Invented incident"}, ["coverage"])
    m = metrics()
    m["report_plan"] = dict(status="validated", selected_ids=["coverage"], evidence_sha256=evidence_digest(m))
    verify_bound_plan(m)
    m["total_events"] = 9
    with pytest.raises(ValueError):
        verify_bound_plan(m)


def test_masked_groups_merge_and_inconsistent_counts_fail():
    m = metrics()
    m["top_src_ips"] = [["203.0.113.x", 1], ["203.0.113.x", 1]]
    section = next(s for s in build_document(m)["sections"] if s["id"] == "ips")
    assert section["rows"] == [["203.0.113.x", "2", "100.00%"]]
    m["top_hosts"] = [["host", 3]]
    assert build_document(m)["failures"]


def test_boundary_timeline_counts_actual_timestamps_and_rejects_overlap(tmp_path):
    chunk = tmp_path / "part.jsonl.gz"
    with gzip.open(chunk, "wt", encoding="utf-8") as out:
        for time in ["2026-09-01T00:59:59Z", "2026-09-01T01:00:00Z"]:
            out.write(json.dumps({"_time": time}) + "\n")
    cp = tmp_path / "checkpoint.json"
    manifest = tmp_path / "manifest.json"
    record = dict(output_path=str(chunk), rows=2, status="done", partition={}, earliest="2026-09-01T00:50:00Z", latest="2026-09-01T01:10:00Z")
    cp.write_text(json.dumps({"chunks": [record]}))
    manifest.write_text(json.dumps({"chunks": [dict(path=str(chunk), rows=2, sha256=hashlib.sha256(chunk.read_bytes()).hexdigest())]}))
    result = build_timeline(cp, manifest, 2, workers=1)
    assert result["hourly"] == [("00:00", 1), ("01:00", 1)]
    assert result["daily"] == [("2026-09-01", 2)]
    chunk.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="checksum"):
        build_timeline(cp, manifest, 2, workers=1)

import json

from soc_ai.cli import main
from soc_ai.data_audit import build_data_audit
from soc_ai.integrity import build_manifest, verify_manifest


def _metrics(total, manifest, integrity):
    return {
        "total_events": total,
        "ingest": {"rows": total, "planned_chunks": manifest["total_files"], "failed_chunks": 0, "complete": True},
        "integrity": integrity,
        "rules": {"events_scanned": total, "findings_count": 0, "findings_by_severity": {}},
        "preflight": {"remote_count_used": True, "estimated_events": total},
    }


def test_data_audit_passes_when_every_counter_matches(tmp_path):
    chunk = tmp_path / "chunk.jsonl"
    chunk.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")
    manifest = build_manifest([chunk], tmp_path / "manifest.json")
    integrity = verify_manifest(manifest["output"])
    result = build_data_audit(_metrics(2, manifest, integrity), manifest, tmp_path / "audit.json")
    assert result["status"] == "pass"
    assert result["all_data_used"] is True
    assert (tmp_path / "audit.md").exists()


def test_data_audit_blocks_when_rules_did_not_scan_every_row(tmp_path):
    chunk = tmp_path / "chunk.jsonl"
    chunk.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")
    manifest = build_manifest([chunk], tmp_path / "manifest.json")
    integrity = verify_manifest(manifest["output"])
    metrics = _metrics(2, manifest, integrity)
    metrics["rules"]["events_scanned"] = 1
    result = build_data_audit(metrics, manifest, tmp_path / "audit.json")
    assert result["status"] == "fail"
    assert "rules.events_scanned differs" in " ".join(result["failures"])


def test_data_audit_cli_returns_nonzero_on_loss(tmp_path):
    chunk = tmp_path / "chunk.jsonl"
    chunk.write_text('{"a":1}\n', encoding="utf-8")
    manifest = build_manifest([chunk], tmp_path / "manifest.json")
    metrics = _metrics(2, manifest, {"ok": False, "verified_rows": 1, "expected_rows": 1})
    metrics_path = tmp_path / "metrics.json"
    metrics_path.write_text(json.dumps(metrics), encoding="utf-8")
    assert main(["data-audit", "--metrics", str(metrics_path), "--manifest", manifest["output"], "--output", str(tmp_path / "audit.json")]) == 1

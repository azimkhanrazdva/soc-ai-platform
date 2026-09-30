import json

from soc_ai.integrity import build_manifest, verify_manifest


def test_manifest_roundtrip(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text(json.dumps({"a": 1}) + "\n", encoding="utf-8")
    manifest = build_manifest([events], tmp_path / "manifest.json")
    assert manifest["total_rows"] == 1
    verified = verify_manifest(manifest["output"])
    assert verified["ok"] is True
    assert verified["verified_rows"] == 1


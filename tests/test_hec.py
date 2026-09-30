import json

from soc_ai.config import AppConfig
from soc_ai.hec import _hec_event, _validate_hec_response, hec_generate_synthetic, hec_send
import pytest


def test_hec_send_dry_run_checkpointed(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps({"n": i}) for i in range(3)) + "\n", encoding="utf-8")
    result = hec_send(AppConfig(), path, "main", batch_size=2, dry_run=True)
    assert result["total_rows"] == 3
    assert result["sent_rows"] == 3
    assert result["skipped_rows"] == 0
    assert result["accounted_rows"] == 3
    assert result["batches"] == 2


def test_hec_send_counts_checkpointed_rows_as_accounted(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps({"n": i}) for i in range(3)) + "\n", encoding="utf-8")
    config = AppConfig()
    hec_send(config, path, "main", batch_size=2, dry_run=True)
    result = hec_send(config, path, "main", batch_size=2, dry_run=True)
    assert result["sent_rows"] == 0
    assert result["skipped_rows"] == 3
    assert result["accounted_rows"] == 3


def test_hec_generate_synthetic_streams_without_input_file(tmp_path):
    result = hec_generate_synthetic(
        AppConfig(),
        rows=5,
        index="main",
        source="test-stream",
        batch_size=2,
        checkpoint_path=tmp_path / "checkpoint.json",
        span_seconds=60,
        dry_run=True,
    )
    assert result["total_rows"] == 5
    assert result["accounted_rows"] == 5
    assert result["batches"] == 3
    assert result["mode"] == "streaming-synthetic"
    assert result["span_seconds"] == 60


def test_hec_event_promotes_time_for_splunk_search_windows():
    event = _hec_event("main", "soc_ai_json", "src", {"_time": "2026-09-01T00:00:00Z", "event": "ok"})
    assert event["time"] == 1788220800.0
    assert event["event"]["_time"] == "2026-09-01T00:00:00Z"


def test_hec_rejects_application_error_response():
    with pytest.raises(RuntimeError, match="application error"):
        _validate_hec_response('{"code": 6, "text": "Invalid token"}')

import json

from soc_ai.normalize import normalize_splunk_event


def test_normalize_splunk_event_expands_json_raw_and_preserves_metadata():
    row = {
        "_time": "splunk-time",
        "host": "hec-host",
        "source": "hec-source",
        "sourcetype": "hec-type",
        "_raw": json.dumps({"_time": "event-time", "host": "app-host", "event": "Failed password", "user": "root"}),
    }
    result = normalize_splunk_event(row)
    assert result["_time"] == "event-time"
    assert result["host"] == "app-host"
    assert result["user"] == "root"
    assert result["splunk_host"] == "hec-host"
    assert result["splunk_source"] == "hec-source"

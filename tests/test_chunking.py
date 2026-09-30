from soc_ai.chunking import adaptive_chunk_seconds, build_time_windows, choose_mode, partition_filter
import pytest


@pytest.mark.parametrize("field", ["host | delete", "host=foo", "host\n", "host OR index"])
def test_partition_rejects_spl_in_field(field):
    with pytest.raises(ValueError):
        partition_filter({field: "value"})


def test_partition_escapes_backslash_before_quote():
    value = 'web\\" OR index=*'
    assert partition_filter({"host": value}) == 'host="web' + '\\\\' + '\\"' + ' OR index=*"'
    with pytest.raises(ValueError):
        partition_filter({"host": "web\n| delete"})


def test_build_time_windows_uses_exclusive_next_start():
    windows = build_time_windows("2026-01-01T00:00:00Z", "2026-01-01T02:30:00Z", 3600)
    assert len(windows) == 3
    assert windows[0].end == windows[1].start
    assert windows[-1].splunk_latest() == "2026-01-01T02:30:00Z"


def test_choose_mode_auto():
    assert choose_mode(10, "auto", 100) == "full"
    assert choose_mode(101, "auto", 100) == "chunked"
    assert choose_mode(None, "auto", 100) == "chunked"


def test_partition_filter_quotes_values():
    assert partition_filter({"host": "web-01", "index": "main"}) == 'host="web-01" index="main"'


def test_adaptive_chunk_seconds_targets_event_count():
    seconds = adaptive_chunk_seconds(
        "2026-01-01T00:00:00Z",
        "2026-01-02T00:00:00Z",
        estimated_events=24_000_000,
        target_events_per_chunk=1_000_000,
        default_seconds=3600,
    )
    assert seconds == 3600

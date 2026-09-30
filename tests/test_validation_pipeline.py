import pytest

from soc_ai.config import AppConfig
from soc_ai.splunk import SplunkClient, export_splunk_chunked
from soc_ai.splunk_pipeline import run_splunk_pipeline
from soc_ai.validation import parse_partitions_json, validate_spl
from soc_ai.storage import read_jsonl


def test_validate_spl_rejects_lossy_commands():
    with pytest.raises(ValueError):
        validate_spl("index=main | head 10")
    with pytest.raises(ValueError):
        validate_spl("index=main | sample 0.1")


def test_validate_spl_can_warn_when_allowed():
    warnings = validate_spl("index=main | head 10", allow_lossy_commands=True)
    assert warnings


def test_parse_partitions_json_normalizes_values():
    assert parse_partitions_json('[{"index":"main","tenant":2}]') == [{"index": "main", "tenant": "2"}]


def test_export_splunk_dry_run_uses_adaptive_chunking(tmp_path):
    result = export_splunk_chunked(
        AppConfig(),
        "index=main",
        "2026-01-01T00:00:00Z",
        "2026-01-01T01:00:00Z",
        output_dir=tmp_path,
        dry_run=True,
        estimated_events=2_000_000,
    )
    assert result["planned_chunks"] == 2
    assert result["chunk_seconds"] == 1800


def test_splunk_pipeline_dry_run(tmp_path):
    result = run_splunk_pipeline(
        AppConfig(),
        "index=main",
        "2026-01-01T00:00:00Z",
        "2026-01-01T01:00:00Z",
        run_dir=tmp_path / "run",
        estimate_only=100,
        dry_run=True,
    )
    assert result["dry_run"] is True
    assert result["preflight"]["planned_chunks"] == 1


def test_export_splunk_parallel_writes_valid_compressed_chunks(tmp_path, monkeypatch):
    class FakeClient:
        def export_verified(self, search, earliest, latest, *, evidence, stop, page_rows, max_rows, job_timeout):
            yield {"event": "ok", "host": "web-01"}
            evidence.update({"verified": True, "rows": 1, "event_count": 1, "result_count": 1})

    monkeypatch.setattr(SplunkClient, "from_env", lambda config: FakeClient())
    config = AppConfig()
    config.splunk.parallel_workers = 2

    result = export_splunk_chunked(
        config,
        "index=main",
        "2026-01-01T00:00:00Z",
        "2026-01-01T01:00:00Z",
        output_dir=tmp_path,
        estimated_events=2_000_000,
    )

    assert result["rows"] == 2
    assert result["failed_chunks"] == 0
    assert len(list((tmp_path / "chunks").glob("*.jsonl.gz"))) == 2


@pytest.mark.parametrize("compress", [True, False])
def test_retry_discards_partial_attempt(tmp_path, monkeypatch, compress):
    class FlakyClient:
        calls = 0

        def export_verified(self, *args, evidence, stop, page_rows, max_rows, job_timeout):
            self.calls += 1
            yield {"event": "first"}
            if self.calls == 1:
                raise TimeoutError("connection lost after one row")
            yield {"event": "second"}
            evidence.update({"verified": True, "rows": 2, "event_count": 2, "result_count": 2})

    client = FlakyClient()
    monkeypatch.setattr(SplunkClient, "from_env", lambda config: client)
    config = AppConfig()
    config.runtime.compress_jsonl = compress
    config.splunk.retry_backoff_seconds = 0
    result = export_splunk_chunked(config, "index=main", "2026-01-01T00:00:00Z",
                                  "2026-01-01T00:01:00Z", output_dir=tmp_path)
    assert result["failed_chunks"] == 0
    assert result["rows"] == 2
    paths = list((tmp_path / "chunks").iterdir())
    assert len(paths) == 1
    assert len(list(read_jsonl(paths[0]))) == 2


def test_pipeline_blocks_report_after_failed_export(tmp_path, monkeypatch):
    import soc_ai.splunk_pipeline as pipeline

    monkeypatch.setattr(pipeline, "_export_splunk_chunked_locked", lambda *a, **kw: {"failed_chunks": 1})
    with pytest.raises(RuntimeError, match="incomplete"):
        run_splunk_pipeline(AppConfig(), "index=main", "2026-01-01T00:00:00Z",
                            "2026-01-01T00:01:00Z", run_dir=tmp_path, estimate_only=2)
    assert not list(tmp_path.rglob("report-*.md"))


def test_pipeline_blocks_source_count_mismatch(tmp_path, monkeypatch):
    class FakeClient:
        def count(self, *args):
            return 2

        def export_verified(self, *args, evidence, stop, page_rows, max_rows, job_timeout):
            yield {"event": "only one"}
            evidence.update({"verified": True, "rows": 1, "event_count": 1, "result_count": 1})

    monkeypatch.setattr(SplunkClient, "from_env", lambda config: FakeClient())
    with pytest.raises(RuntimeError, match="Splunk count"):
        run_splunk_pipeline(AppConfig(), "index=main", "2026-01-01T00:00:00Z",
                            "2026-01-01T00:01:00Z", run_dir=tmp_path)
    assert not list(tmp_path.rglob("report-*.md"))


def test_partition_scheduler_does_not_materialize_all_work(tmp_path, monkeypatch):
    import soc_ai.splunk as splunk

    counts = {"planned": 0, "completed": 0}
    original = splunk.iter_plan

    def bounded_plan(*args):
        for item in original(*args):
            counts["planned"] += 1
            assert counts["planned"] - counts["completed"] <= 4
            yield item

    class Client:
        def export_verified(self, *args, evidence, stop, page_rows, max_rows, job_timeout):
            yield {"event": "ok"}
            evidence.update({"verified": True, "rows": 1, "event_count": 1, "result_count": 1})
            counts["completed"] += 1

    monkeypatch.setattr(splunk, "iter_plan", bounded_plan)
    monkeypatch.setattr(SplunkClient, "from_env", lambda config: Client())
    config = AppConfig()
    config.runtime.chunk_seconds = 1
    config.splunk.parallel_workers = 2
    result = export_splunk_chunked(config, "index=main", "2026-01-01T00:00:00Z",
                                  "2026-01-01T00:00:30Z", output_dir=tmp_path)
    assert result["rows"] == result["planned_chunks"] == 30


def test_resume_reexports_corrupted_done_chunk(tmp_path, monkeypatch):
    class Client:
        calls = 0

        def export_verified(self, *args, evidence, stop, page_rows, max_rows, job_timeout):
            self.calls += 1
            yield {"event": f"ok-{self.calls}"}
            evidence.update({"verified": True, "rows": 1, "event_count": 1, "result_count": 1})

    client = Client()
    monkeypatch.setattr(SplunkClient, "from_env", lambda config: client)
    config = AppConfig()
    config.runtime.compress_jsonl = False

    first = export_splunk_chunked(
        config,
        "index=main",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
        output_dir=tmp_path,
    )
    chunk = next((tmp_path / "chunks").glob("*.jsonl"))
    chunk.write_text('{"event":"tampered"}\n', encoding="utf-8")
    second = export_splunk_chunked(
        config,
        "index=main",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
        output_dir=tmp_path,
    )

    assert first["complete"] is True
    assert second["complete"] is True
    assert client.calls == 2
    assert list(read_jsonl(chunk))[0]["event"] == "ok-2"


def test_resume_rejects_legacy_checkpoint_without_context(tmp_path):
    from soc_ai.checkpoints import CheckpointStore, ChunkRecord

    store = CheckpointStore(tmp_path / "splunk_checkpoints.json")
    store.mark(ChunkRecord("legacy", "done", "a", "b", {}, output_path=None, rows=1))

    with pytest.raises(ValueError, match="Legacy checkpoint"):
        export_splunk_chunked(
            AppConfig(),
            "index=main",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:01:00Z",
            output_dir=tmp_path,
        )

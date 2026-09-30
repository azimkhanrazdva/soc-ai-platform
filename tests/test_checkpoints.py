from soc_ai.checkpoints import CheckpointStore, ChunkRecord, chunk_id
import pytest

from soc_ai.storage import atomic_write_json


def test_atomic_checkpoint_preserves_previous_file_after_write_failure(tmp_path, monkeypatch):
    path = tmp_path / "checkpoint.json"
    atomic_write_json(path, {"chunks": []})
    before = path.read_bytes()

    def fail(*args, **kwargs):
        raise OSError("disk error")

    monkeypatch.setattr("soc_ai.storage.os.fsync", fail)
    with pytest.raises(OSError):
        atomic_write_json(path, {"chunks": ["new"]})
    assert path.read_bytes() == before
    assert not list(tmp_path.glob("*.tmp"))


def test_checkpoint_roundtrip(tmp_path):
    path = tmp_path / "checkpoint.json"
    store = CheckpointStore(path)
    cid = chunk_id("a", "b", {"host": "web"})
    store.mark(ChunkRecord(cid, "done", "a", "b", {"host": "web"}, rows=5))

    loaded = CheckpointStore(path)
    assert loaded.is_done(cid)
    assert loaded.rows_for(cid) == 5
    assert loaded.counts() == {"done": 1}


def test_checkpoint_retries_done_chunk_when_output_is_missing(tmp_path):
    path = tmp_path / "checkpoint.json"
    output = tmp_path / "missing.jsonl"
    store = CheckpointStore(path)
    cid = chunk_id("a", "b")
    store.mark(ChunkRecord(cid, "done", "a", "b", {}, output_path=str(output), rows=1))

    loaded = CheckpointStore(path)

    assert loaded.is_done(cid) is False

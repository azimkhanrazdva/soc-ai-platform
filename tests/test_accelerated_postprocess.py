import gzip
import hashlib
import json
import subprocess
import sys


def test_accelerated_postprocess_smoke(tmp_path):
    run_dir = tmp_path / "run"
    chunks_dir = run_dir / "data" / "chunks"
    reports_dir = run_dir / "reports"
    chunks_dir.mkdir(parents=True)
    reports_dir.mkdir()

    manifest_chunks = []
    total_rows = 0
    checkpoint_chunks = []
    for index in range(2):
        path = chunks_dir / f"chunk-{index}.jsonl.gz"
        rows = [
            {"event": "Failed password", "host": f"host-{index}", "source": "lab", "sourcetype": "json", "user": "root", "src_ip": "8.8.8.8"},
            {"event": "ok", "host": f"host-{index}", "source": "lab", "sourcetype": "json", "user": "alice", "src_ip": "203.0.113.1"},
        ]
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_chunks.append({"path": str(path), "rows": len(rows), "sha256": digest})
        checkpoint_chunks.append({"chunk_id": str(index), "status": "done", "rows": len(rows), "output_path": str(path)})
        total_rows += len(rows)

    (reports_dir / "chunk_manifest.json").write_text(json.dumps({"total_files": 2, "total_rows": total_rows, "chunks": manifest_chunks}), encoding="utf-8")
    (run_dir / "data" / "splunk_checkpoints.json").write_text(json.dumps({"chunks": checkpoint_chunks}), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "scripts/accelerated_400m_postprocess.py", "--run-dir", str(run_dir), "--workers", "2"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads((reports_dir / "accelerated_postprocess.json").read_text(encoding="utf-8"))
    assert summary["status"] == "complete"
    assert summary["rows"] == 4
    assert summary["integrity"]["ok"] is True
    assert (reports_dir / "SOC-AI-400M-final-report.md").exists()
    assert (reports_dir / "SOC-AI-400M-final-report.pdf").read_bytes().startswith(b"%PDF")

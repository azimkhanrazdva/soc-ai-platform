from __future__ import annotations

from pathlib import Path
import hashlib
import json

from .storage import read_jsonl


def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def build_manifest(paths: list[str | Path], output_path: str | Path = "reports/chunk_manifest.json") -> dict:
    chunks = []
    total_rows = 0
    for raw_path in paths:
        path = Path(raw_path)
        rows = sum(1 for _ in read_jsonl(path))
        total_rows += rows
        chunks.append({"path": str(path), "rows": rows, "sha256": file_sha256(path)})
    manifest = {"total_files": len(chunks), "total_rows": total_rows, "chunks": chunks}
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return {"output": str(out), **manifest}


def verify_manifest(manifest_path: str | Path) -> dict:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    failures = []
    verified_rows = 0
    for chunk in manifest.get("chunks", []):
        path = Path(chunk["path"])
        if not path.exists():
            failures.append({"path": str(path), "error": "missing"})
            continue
        actual_hash = file_sha256(path)
        actual_rows = sum(1 for _ in read_jsonl(path))
        verified_rows += actual_rows
        if actual_hash != chunk.get("sha256") or actual_rows != chunk.get("rows"):
            failures.append(
                {
                    "path": str(path),
                    "expected_rows": chunk.get("rows"),
                    "actual_rows": actual_rows,
                    "expected_sha256": chunk.get("sha256"),
                    "actual_sha256": actual_hash,
                }
            )
    return {
        "manifest": str(manifest_path),
        "ok": not failures and verified_rows == manifest.get("total_rows", verified_rows),
        "verified_rows": verified_rows,
        "expected_rows": manifest.get("total_rows"),
        "failures": failures,
    }

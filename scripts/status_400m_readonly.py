from __future__ import annotations

from pathlib import Path
import json
import sys
import time


DEFAULT_ROOT = Path("/opt/soc-ai-platform/reports/400m-full-20260907-055835/pipeline-splunk-production")


def main() -> None:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ROOT
    checkpoint = root / "data/splunk_checkpoints.json"
    log = root / "reports/resume-production-20260908-093542.log"
    print("checkpoint_exists", checkpoint.exists())
    if checkpoint.exists():
        data = json.loads(checkpoint.read_text(encoding="utf-8"))
        counts: dict[str, int] = {}
        done_rows = 0
        for item in data.get("chunks", []):
            status = str(item.get("status"))
            counts[status] = counts.get(status, 0) + 1
            if status == "done":
                done_rows += int(item.get("rows") or 0)
        print("counts", counts)
        print("done_rows", done_rows)
        print("checkpoint_mtime", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(checkpoint.stat().st_mtime)))
    print("log_exists", log.exists())
    if log.exists():
        print("log_tail")
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]:
            print(line[:500])


if __name__ == "__main__":
    main()

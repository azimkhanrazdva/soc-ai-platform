from __future__ import annotations

from pathlib import Path
import html
import json


def build_site(report_dir: str | Path = "reports", output_dir: str | Path = "site") -> dict:
    report_root = Path(report_dir)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    metrics_files = sorted(report_root.rglob("metrics-*.json"))
    benchmark_files = sorted(report_root.rglob("benchmark.json"))
    latest_metrics = _read_json(metrics_files[-1]) if metrics_files else {}
    latest_benchmark = _read_json(benchmark_files[-1]) if benchmark_files else {}
    status = {
        "reports_found": len(metrics_files),
        "latest_total_events": latest_metrics.get("total_events", 0),
        "latest_rules": latest_metrics.get("rules", {}).get("findings_count", 0),
        "integrity_ok": latest_metrics.get("integrity", {}).get("ok"),
        "events_per_second": latest_benchmark.get("events_per_second", 0),
    }
    (out / "status.json").write_text(json.dumps(status, indent=2, sort_keys=True), encoding="utf-8")
    (out / "index.html").write_text(_html(status), encoding="utf-8")
    return {"output_dir": str(out), "index": str(out / "index.html"), "status": str(out / "status.json"), **status}


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _html(status: dict) -> str:
    rows = "\n".join(f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>" for k, v in status.items())
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SOC AI Status</title>
  <style>
    body {{ margin: 0; font: 14px system-ui, sans-serif; color: #172026; background: #f5f7f8; }}
    main {{ max-width: 900px; margin: 0 auto; padding: 24px; }}
    h1 {{ font-size: 24px; margin: 0 0 16px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d9e0e4; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e8edf0; }}
    th {{ width: 220px; color: #52616b; font-weight: 600; }}
    .ok {{ color: #0b6b3a; font-weight: 700; }}
  </style>
</head>
<body>
  <main>
    <h1>SOC AI Status</h1>
    <table>{rows}</table>
  </main>
</body>
</html>
"""

from __future__ import annotations

from pathlib import Path
import json
import urllib.request


DATASETS = {
    "botsv3": {
        "name": "Splunk Boss of the SOC v3",
        "source": "https://github.com/splunk/botsv3",
        "download_url": "https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz",
        "format": "pre-indexed-splunk",
        "size": "320.1MB compressed",
        "index_hint": "botsv3",
        "notes": "Install under SPLUNK_HOME/etc/apps and restart Splunk.",
    },
    "lanl-2017": {
        "name": "LANL Unified Host and Network Dataset",
        "source": "https://csr.lanl.gov/data/2017.html",
        "download_url": "",
        "format": "multi-file host/network events",
        "size": "large, multi-day",
        "index_hint": "lanl",
        "notes": "Use LANL/IMPACT pages to select day files; ingest progressively.",
    },
    "splunk-securitydatasets": {
        "name": "Splunk Security Datasets",
        "source": "https://github.com/splunk/securitydatasets",
        "download_url": "https://github.com/splunk/securitydatasets/archive/refs/heads/master.zip",
        "format": "repository of small security datasets",
        "size": "varies",
        "index_hint": "securitydatasets",
        "notes": "Good for functional tests before large LANL-style runs.",
    },
}


def dataset_list() -> dict:
    return {"datasets": DATASETS}


def dataset_download(name: str, output_dir: str | Path = "data/downloads", max_bytes: int | None = None) -> dict:
    if name not in DATASETS:
        raise KeyError(f"unknown dataset: {name}")
    meta = DATASETS[name]
    url = meta.get("download_url")
    if not url:
        raise ValueError(f"dataset {name} does not have a direct download URL; see {meta.get('source')}")
    if max_bytes is not None and max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = url.rstrip("/").split("/")[-1]
    out = out_dir / filename
    downloaded = 0
    request = urllib.request.Request(url, headers={"User-Agent": "soc-ai-platform/0.1"})
    partial = out.with_suffix(out.suffix + ".part")
    try:
        with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as fh:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                downloaded += len(block)
                if max_bytes is not None and downloaded > max_bytes:
                    raise RuntimeError(f"download exceeded max_bytes={max_bytes}")
                fh.write(block)
        partial.replace(out)
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    sidecar = out.with_suffix(out.suffix + ".metadata.json")
    sidecar.write_text(json.dumps(meta | {"downloaded_path": str(out), "downloaded_bytes": downloaded}, indent=2, sort_keys=True), encoding="utf-8")
    return {"dataset": name, "path": str(out), "bytes": downloaded, "metadata": str(sidecar)}


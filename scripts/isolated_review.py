#!/usr/bin/env python3
"""Run report QA or aggregate review with only a private report snapshot exposed."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--with-gpu", action="store_true", help="Allow host networking for Ollama aggregate review")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434/api/generate")
    args = parser.parse_args()
    if sys.platform != "linux" or not shutil.which("bwrap"):
        parser.error("Linux and bubblewrap are required; no unsandboxed fallback")
    repo = Path(__file__).resolve().parents[1]
    source_dir = (args.run_dir / "reports").resolve()
    markdowns = sorted(source_dir.glob("report-*.md"))
    if not markdowns:
        parser.error("No report available for isolated QA")
    markdown = markdowns[-1]
    metrics = markdown.with_name(markdown.name.replace("report-", "metrics-", 1)).with_suffix(".json")
    for path in (markdown, metrics):
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 16 * 1024**2:
            parser.error("Report and matching metrics must be regular files up to 16 MiB")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    reports = output / "reports"
    reports.mkdir(mode=0o700)
    for path in (markdown, metrics):
        target = reports / path.name
        shutil.copyfile(path, target)
        target.chmod(0o600)
    command = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
               "--clearenv", "--setenv", "PATH", "/usr/bin", "--setenv", "HOME", "/tmp",
               "--setenv", "PYTHONPATH", "/app/src", "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
               "--ro-bind", "/usr", "/usr"]
    for system_path in ("/lib", "/lib64", "/etc/ssl/certs"):
        if Path(system_path).exists():
            command.extend(["--ro-bind", system_path, system_path])
    if args.with_gpu:
        command.append("--share-net")
        for network_path in ("/etc/resolv.conf", "/etc/hosts"):
            if Path(network_path).exists():
                command.extend(["--ro-bind", network_path, network_path])
    command.extend(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/app",
                    "--ro-bind", str(repo / "src"), "/app/src",
                    "--ro-bind", str(repo / "configs" / "agents.toml"), "/app/agents.toml",
                    "--bind", str(output), "/work", "--chdir", "/work"])
    # Keep input immutable even though the worker can write its own result files.
    for path in (markdown, metrics):
        command.extend(["--ro-bind", str(reports / path.name), "/work/reports/" + path.name])
    launcher = (
        "import os,resource,runpy;os.umask(0o077);"
        "resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3));"
        "resource.setrlimit(resource.RLIMIT_CPU,(120,120));"
        "resource.setrlimit(resource.RLIMIT_NOFILE,(64,64));"
        "resource.setrlimit(resource.RLIMIT_NPROC,(32,32));"
        "resource.setrlimit(resource.RLIMIT_FSIZE,(32*1024**2,32*1024**2));"
        "runpy.run_module('soc_ai.cli',run_name='__main__')"
    )
    command.extend(["/usr/bin/python3", "-c", launcher])
    if args.with_gpu:
        command.extend(["agent-review", "--run-dir", "/work", "--agents-file", "/app/agents.toml", "--endpoint", args.endpoint])
    else:
        command.extend(["qa-run", "--run-dir", "/work"])
    with (output / "worker.stdout").open("wb") as stdout, (output / "worker.stderr").open("wb") as stderr:
        try:
            completed = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=660, check=False)
            code = completed.returncode
        except subprocess.TimeoutExpired:
            code = 124
    result = {"exit_code": code, "output_dir": str(output),
              "network": "host network for GPU review" if args.with_gpu else "isolated, no network",
              "filesystem": "report snapshot only; source and inputs read-only; no home or credentials mounted"}
    (output / "isolation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

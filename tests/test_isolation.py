import importlib.util
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux" or not shutil.which("bwrap"), reason="Linux bubblewrap required")
def test_offline_agent_has_no_host_files_environment_or_network(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "isolated_review.py"
    spec = importlib.util.spec_from_file_location("isolated_review", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = tmp_path / "run"
    reports = run / "reports"
    reports.mkdir(parents=True)
    (reports / "report-1.md").write_text("\n".join(["Executive summary", "Top hosts", "Rule findings", "Integrity", "Model comparison", "Limitations"]))
    (reports / "metrics-1.json").write_text(json.dumps({"total_events": 2, "integrity": {"ok": True}, "rules": {}}))
    secret = tmp_path / "host-secret"
    secret.write_text("private")
    monkeypatch.setenv("SOC_TEST_SECRET", "private")
    output = tmp_path / "isolated-output"
    monkeypatch.setattr(sys, "argv", [str(script), str(run), "--output-dir", str(output)])
    original_run = subprocess.run
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        probe = (
            "import os,socket;from pathlib import Path;"
            f"assert not Path({str(secret)!r}).exists();"
            "assert 'SOC_TEST_SECRET' not in os.environ;"
            "assert not Path('/home/example/.ssh').exists();"
            "assert not Path('/app/.env').exists();"
            "s=socket.socket();s.settimeout(1);"
            f"assert s.connect_ex(('127.0.0.1',{listener.getsockname()[1]})) != 0;"
            "assert not os.access('/app/src/soc_ai/qa.py',os.W_OK)"
        )

        def checked_run(command, **kwargs):
            prefix = command[:command.index("/usr/bin/python3")]
            check = original_run(prefix + ["/usr/bin/python3", "-c", probe], capture_output=True, timeout=10)
            assert check.returncode == 0, check.stderr.decode()
            return original_run(command, **kwargs)

        monkeypatch.setattr(module.subprocess, "run", checked_run)
        assert module.main() == 0, (output / "worker.stderr").read_text()
    assert json.loads((output / "worker.stdout").read_text())["status"] == "pass"

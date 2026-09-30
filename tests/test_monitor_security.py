import http.client
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from soc_ai import monitor


def test_probe_cache_coalesces_concurrent_requests():
    calls = []
    cache = monitor.CachedProbe(lambda: calls.append(1) or {"ok": True}, ttl=10)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: cache.get(), range(40)))
    assert all(item == {"ok": True} for item in results)
    assert len(calls) == 1


def test_monitor_rejects_public_bind():
    with pytest.raises(ValueError, match="loopback"):
        monitor.create_server("0.0.0.0", 0)


def test_report_list_excludes_external_symlink_and_encodes_url(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "a #.pdf").write_bytes(b"test")
    (reports / "a #.docx").write_bytes(b"docx")
    outside = tmp_path / "private.pdf"
    outside.write_bytes(b"secret")
    try:
        (reports / "leak.pdf").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    entries = monitor.list_reports(reports)
    assert len(entries) == 1
    assert [item["kind"] for item in entries[0]["formats"]] == ["docx", "pdf"]
    assert entries[0]["formats"][1]["url"] == "/reports/a%20%23.pdf"
    assert monitor.safe_report_path(reports, "../private.pdf") is None


def test_monitor_http_guards_and_streaming(tmp_path, monkeypatch):
    report = tmp_path / 'report.pdf'
    report.write_bytes(b"%PDF-" + b"a" * 150000)
    monkeypatch.setattr(monitor, "collect_status", lambda **kw: {"ok": True})
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("report must stream"))
    with monitor.create_server(port=0, reports_dir=tmp_path) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for path, headers, expected in [
                ("/api/status", {"Host": "attacker.example"}, 403),
                ("/api/status", {"Origin": "https://attacker.example"}, 403),
                ("/api/status", {}, 200),
                ("/reports/report.pdf", {}, 200),
                ("/reports/../private.pdf", {}, 404),
            ]:
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request("GET", path, headers=headers)
                response = connection.getresponse()
                body = response.read()
                assert response.status == expected
                assert response.getheader("X-Content-Type-Options") == "nosniff"
                if path == "/reports/report.pdf":
                    assert len(body) == 150005
                    assert response.getheader("Content-Disposition").startswith("attachment;")
                connection.close()
        finally:
            server.shutdown()
            worker.join()


def test_monitor_rejects_ssh_option_injection(monkeypatch):
    monkeypatch.setattr(monitor.subprocess, "check_output", lambda *a, **kw: pytest.fail("SSH must not run"))
    assert not monitor._remote_splunk("-oProxyCommand=touch /tmp/bad")["ok"]


def test_monitor_history_reads_runlog_and_reports(tmp_path):
    reports = tmp_path / "reports"
    uploads = tmp_path / "uploads"
    reports.mkdir()
    uploads.mkdir()
    (reports / "run.log.jsonl").write_text('{"timestamp": 1700000000, "stage": "export", "status": "done"}\n', encoding="utf-8")
    (reports / "report-1.pdf").write_bytes(b"%PDF")
    monitor.save_upload(uploads, "events.jsonl", "8", _Reader(b'{"a":1}\n'))
    result = monitor.collect_history(reports, uploads)
    labels = [event["label"] for event in result["events"]]
    assert "export / done" in labels
    assert any(label.startswith("Создан отчет: report-1") for label in labels)
    assert any(label.startswith("Загружен файл: events") for label in labels)


class _Reader:
    def __init__(self, payload: bytes):
        self.payload = payload

    def read(self, size: int = -1) -> bytes:
        if not self.payload:
            return b""
        if size < 0:
            size = len(self.payload)
        chunk, self.payload = self.payload[:size], self.payload[size:]
        return chunk


def test_upload_saves_stream_with_safe_name_and_metadata(tmp_path):
    result = monitor.save_upload(tmp_path, "../bad name.jsonl", "8", _Reader(b'{"a":1}\n'))
    assert result["name"] == "bad name.jsonl"
    assert result["bytes"] == 8
    assert (tmp_path / "bad name.jsonl").read_bytes() == b'{"a":1}\n'
    assert (tmp_path / "bad name.jsonl.upload.json").exists()
    assert [item["name"] for item in monitor.list_uploads(tmp_path)] == ["bad name.jsonl"]


def test_upload_rejects_unsupported_or_oversized(tmp_path):
    with pytest.raises(ValueError, match="unsupported"):
        monitor.save_upload(tmp_path, "payload.exe", "1", _Reader(b"x"))
    with pytest.raises(ValueError, match="exceeds"):
        monitor.save_upload(tmp_path, "payload.jsonl", "9", _Reader(b"x" * 9), max_bytes=8)


def test_monitor_http_upload_and_upload_list(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor, "collect_status", lambda **kw: {"ok": True})
    with monitor.create_server(port=0, reports_dir=tmp_path / "reports", upload_dir=tmp_path / "uploads") as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("POST", "/api/uploads?name=sample.csv", body=b"a,b\n1,2\n",
                               headers={"Content-Type": "application/octet-stream", "Content-Length": "8"})
            response = connection.getresponse()
            body = response.read()
            assert response.status == 201
            assert b"sample.csv" in body
            connection.close()

            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("GET", "/api/uploads")
            response = connection.getresponse()
            body = response.read()
            assert response.status == 200
            assert b"sample.csv" in body
            connection.close()
        finally:
            server.shutdown()
            worker.join()

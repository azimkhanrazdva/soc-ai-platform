import io
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from soc_ai.network import open_service
from soc_ai.splunk import SplunkClient


def test_redirect_cannot_forward_authorization(monkeypatch):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            self.send_response(302)
            self.send_header("Location", "/secret-target")
            self.end_headers()

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
        monkeypatch.setenv("no_proxy", "")
        try:
            request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/start", headers={"Authorization": "Splunk test-secret"})
            with pytest.raises(urllib.error.HTTPError, match="redirect blocked"):
                open_service(request, timeout=2)
            assert seen == [("/start", "Splunk test-secret")]
        finally:
            server.shutdown()
            worker.join()


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://user:secret@localhost/", "https://localhost/#secret"])
def test_service_rejects_unsafe_url(url):
    with pytest.raises(ValueError):
        open_service(url, timeout=1)


def test_splunk_does_not_persist_error_body(monkeypatch):
    def fail(*args, **kwargs):
        raise urllib.error.HTTPError("http://localhost", 403, "bad", {}, io.BytesIO(b"password=private-source-event"))

    monkeypatch.setattr("soc_ai.splunk.open_service", fail)
    with pytest.raises(RuntimeError) as failure:
        list(SplunkClient("http://localhost").export_csv("index=main", "a", "b"))
    assert str(failure.value) == "Splunk export HTTP 403"

"""Read stable, completed Splunk jobs with checked page offsets and counts."""
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .network import open_service
from .recovery import ExportPaused


def _integer(value, name):
    if isinstance(value, bool) or not str(value).isdigit():
        raise RuntimeError(f"Invalid Splunk {name}")
    return int(value)


def _true(value):
    return value is True or value in (1, "1", "true")


def _messages(value):
    if not isinstance(value, list):
        raise RuntimeError("Invalid Splunk messages")
    if any(not isinstance(item, dict) or str(item.get("type", "")).upper() not in {"INFO", "DEBUG"} for item in value):
        raise RuntimeError("Splunk search reported a warning or error; source completeness is unverified")


def job_request(client, path, params=None, method="GET"):
    params = {"output_mode": "json", **(params or {})}
    encoded = urllib.parse.urlencode(params)
    url = client.base_url.rstrip("/") + "/services/search/jobs" + path
    data = encoded.encode() if method == "POST" else None
    if method != "POST":
        url += "?" + encoded
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Authorization": client.auth_header(), "Content-Type": "application/x-www-form-urlencoded"})
    context = None if client.verify_tls else ssl._create_unverified_context()
    try:
        with open_service(request, timeout=client.timeout, context=context) as response:
            body = response.read(16 * 1024**2 + 1)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        raise RuntimeError(f"Splunk job HTTP {code}") from None
    if len(body) > 16 * 1024**2:
        raise RuntimeError("Splunk page exceeds 16 MiB; decrease result_page_rows")
    result = json.loads(body)
    if not isinstance(result, dict):
        raise RuntimeError("Invalid Splunk job response")
    _messages(result.get("messages", []))
    return result


def _status(client, sid):
    body = job_request(client, "/" + sid)
    entries = body.get("entry", [])
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0].get("content"), dict):
        raise RuntimeError("Missing Splunk job status")
    status = entries[0]["content"]
    _messages(status.get("messages", []))
    if any(_true(status.get(key)) for key in ("isFailed", "isFinalized", "isZombie")) or status.get("dispatchState") in {"FAILED", "FINALIZING", "BAD_INPUT_CANCEL"}:
        raise RuntimeError("Splunk job failed or was finalized before completion")
    return status


def export_verified(client, search, earliest, latest, *, evidence, stop, page_rows=1000, max_rows=1000000, job_timeout=1800):
    if min(page_rows, max_rows, job_timeout) <= 0:
        raise ValueError("Splunk job limits must be positive")
    created = job_request(client, "", {"search": search if search.startswith("search ") else "search " + search,
                           "earliest_time": earliest, "latest_time": latest, "exec_mode": "normal",
                           "max_count": max_rows, "max_time": 0, "auto_cancel": 300, "ttl": 600}, "POST")
    raw_sid = created.get("sid")
    if not isinstance(raw_sid, str) or not raw_sid:
        raise RuntimeError("Splunk did not return a job identifier")
    sid = urllib.parse.quote(raw_sid, safe="")
    deadline = time.monotonic() + job_timeout
    try:
        while True:
            if stop.is_set():
                raise ExportPaused("Export interrupted; resume the same run")
            if time.monotonic() >= deadline:
                raise RuntimeError("Splunk job deadline exceeded")
            status = _status(client, sid)
            if _true(status.get("isDone")) and status.get("dispatchState") == "DONE":
                break
            stop.wait(1)
        expected = _integer(status.get("resultCount"), "resultCount")
        source_events = _integer(status.get("eventCount"), "eventCount")
        if source_events != expected:
            raise RuntimeError("Splunk event/result count mismatch: possible truncation or transforming search")
        if expected >= max_rows:
            raise RuntimeError("Splunk job reached its result ceiling; use smaller time windows")
        offset = 0
        while offset < expected:
            if stop.is_set():
                raise ExportPaused("Export interrupted; resume the same run")
            if time.monotonic() >= deadline:
                raise RuntimeError("Splunk result retrieval deadline exceeded")
            count = min(page_rows, expected - offset)
            page = job_request(client, "/" + sid + "/results", {"offset": offset, "count": count})
            if page.get("preview") is not False or _integer(page.get("init_offset"), "page offset") != offset:
                raise RuntimeError("Splunk returned a preview or unexpected page offset")
            rows = page.get("results")
            if not isinstance(rows, list) or not rows or len(rows) > count or any(not isinstance(row, dict) for row in rows):
                raise RuntimeError("Splunk returned an incomplete or malformed result page")
            yield from rows
            offset += len(rows)
        final = _status(client, sid)
        if not _true(final.get("isDone")) or final.get("dispatchState") != "DONE" or _integer(final.get("resultCount"), "resultCount") != expected or _integer(final.get("eventCount"), "eventCount") != expected:
            raise RuntimeError("Splunk result set changed during retrieval")
        evidence.update({"verified": True, "sid": raw_sid, "rows": offset, "event_count": source_events,
                         "result_count": expected, "dispatch_state": "DONE"})
    finally:
        try:
            job_request(client, "/" + sid, method="DELETE")
        except Exception:
            # The server-side TTL also bounds abandoned jobs after a client crash.
            pass

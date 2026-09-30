from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import hashlib
import json
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
from urllib.parse import parse_qs, quote, unquote, urlparse

from .network import open_service

UPLOAD_EXTENSIONS = {
    ".csv", ".json", ".jsonl", ".log", ".txt", ".ndjson",
    ".gz", ".zip", ".tgz", ".tar", ".parquet", ".evtx",
}
DEFAULT_UPLOAD_MAX_BYTES = 5 * 1024 * 1024 * 1024


DEFAULT_HTML = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC AI Operations</title><style>
:root{color-scheme:dark;--bg:#0f1318;--panel:#171d23;--panel2:#12181e;--line:#2a333b;--text:#eef2f4;--muted:#93a0a8;--good:#62d49d;--warn:#e9bc60;--bad:#ef7777;--accent:#80d7e6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px ui-sans-serif,system-ui,sans-serif}main{max-width:1220px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;align-items:end;border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:16px}h1{margin:0;font-size:26px;letter-spacing:0}.muted{color:var(--muted)}.stamp{color:var(--accent);font-variant-numeric:tabular-nums}.tabs{display:flex;gap:8px;margin:0 0 16px}.tab,.button{border:1px solid var(--line);background:#141a20;color:var(--text);padding:8px 11px;border-radius:6px;text-decoration:none;cursor:pointer}.tab.active,.button:hover{border-color:var(--accent);color:#dffaff}.view{display:none}.view.active{display:block}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:15px;min-height:112px}.panel h2{font-size:12px;text-transform:uppercase;color:var(--muted);margin:0 0 12px;letter-spacing:.08em}.value{font-size:22px;font-weight:700}.detail{color:var(--muted);margin-top:7px;line-height:1.45;overflow-wrap:anywhere}.ok{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}.wide{grid-column:span 2}.full{grid-column:1/-1}.bar{height:7px;background:#28313a;margin-top:12px;border-radius:99px;overflow:hidden}.bar i{display:block;height:100%;background:var(--accent);width:0;transition:width .4s}.list{display:grid;grid-template-columns:1fr 1fr;gap:8px}.row{display:flex;justify-content:space-between;gap:12px;border-bottom:1px solid #242d35;padding:7px 0}.row b{font-weight:600}.steps{display:grid;grid-template-columns:repeat(7,minmax(95px,1fr));gap:8px}.step{border:1px solid var(--line);background:var(--panel2);border-radius:8px;padding:10px;min-height:82px}.dot{width:10px;height:10px;border-radius:50%;display:inline-block;background:var(--muted);margin-right:7px}.step.done .dot{background:var(--good)}.step.active .dot{background:var(--warn)}.step.fail .dot{background:var(--bad)}.step strong{display:block;margin-bottom:6px}.report,.event{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;border-top:1px solid var(--line);padding:12px 0}.formats{display:flex;gap:8px;flex-wrap:wrap}.pill{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:2px 8px;color:var(--muted);font-size:12px}.empty{color:var(--muted)}@media(max-width:900px){main{padding:16px}.grid{grid-template-columns:1fr 1fr}.wide{grid-column:span 2}.steps{grid-template-columns:1fr 1fr}}@media(max-width:560px){.grid,.steps{grid-template-columns:1fr}.wide{grid-column:span 1}.top{display:block}.stamp{display:block;margin-top:8px}.report,.event{grid-template-columns:1fr}.formats{margin-top:4px}}
input[type=file]{display:block;width:100%;border:1px dashed var(--line);border-radius:8px;padding:16px;background:#10161c;color:var(--text);margin:8px 0 12px}.progress{height:8px;background:#28313a;border-radius:99px;overflow:hidden;margin-top:8px}.progress i{display:block;height:100%;background:var(--good);width:0}.upload-row{border-top:1px solid var(--line);padding:10px 0}
</style></head><body><main><div class="top"><div><div class="muted">SOC AI OPERATIONS</div><h1>Панель проекта</h1></div><div class="stamp" id="updated">connecting...</div></div>
<nav class="tabs"><button class="tab active" data-view="overview">Обзор</button><button class="tab" data-view="stages">Этапы</button><button class="tab" data-view="upload">Загрузка данных</button><button class="tab" data-view="history">История и отчеты</button></nav>
<section id="overview" class="view active"><section class="grid">
<article class="panel"><h2>GPU</h2><div class="value" id="gpu">-</div><div class="detail" id="gpuDetail">-</div><div class="bar"><i id="gpuBar"></i></div></article>
<article class="panel"><h2>Ollama</h2><div class="value" id="ollama">-</div><div class="detail" id="ollamaDetail">-</div></article>
<article class="panel"><h2>CPU / RAM</h2><div class="value" id="cpu">-</div><div class="detail" id="ram">-</div><div class="bar"><i id="ramBar"></i></div></article>
<article class="panel"><h2>Storage</h2><div class="value" id="disk">-</div><div class="detail" id="diskDetail">-</div><div class="bar"><i id="diskBar"></i></div></article>
<article class="panel wide"><h2>Splunk node</h2><div class="value" id="splunk">-</div><div class="detail" id="splunkDetail">-</div></article>
<article class="panel wide"><h2>Data pipeline</h2><div class="list" id="pipeline"><div class="empty">Waiting for metrics</div></div></article>
<article class="panel full"><h2>Recent AI review</h2><div class="detail" id="review">No review loaded</div></article>
</section></section>
<section id="stages" class="view"><article class="panel"><h2>Текущие этапы</h2><div class="steps" id="stageList"></div></article></section>
<section id="upload" class="view"><article class="panel"><h2>Загрузить данные</h2><div class="detail">Форматы: CSV, JSON, JSONL, NDJSON, LOG, TXT, GZ, ZIP, TGZ, TAR, PARQUET, EVTX. Файлы сохраняются в data/uploads и не запускают анализ автоматически.</div><input id="fileInput" type="file" multiple><button class="button" id="uploadButton">Загрузить</button><div id="uploadStatus" class="detail"></div><div class="progress"><i id="uploadProgress"></i></div></article><article class="panel" style="margin-top:12px"><h2>Загруженные файлы</h2><div id="uploads"><div class="empty">Loading uploads</div></div></article></section>
<section id="history" class="view"><article class="panel"><h2>Отчеты</h2><div id="reports"><div class="empty">Loading reports</div></div></article><article class="panel" style="margin-top:12px"><h2>История событий</h2><div id="events"><div class="empty">Loading history</div></div></article></section>
</main><script>
const $=id=>document.getElementById(id);const fmt=n=>n==null?'-':(typeof n==='number'?Number(n).toLocaleString():String(n));
function setBar(id,n){$(id).style.width=Math.min(100,Math.max(0,n||0))+'%'}
function el(tag,cls,text){const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=text;return node}
function rows(target,obj){target.replaceChildren();const entries=Object.entries(obj||{});if(!entries.length){target.append(el('div','empty','Нет метрик'));return}for(const [k,v] of entries){const row=el('div','row');row.append(el('b','',k.replaceAll('_',' ')),el('span','',fmt(v)));target.append(row)}}
async function refresh(){try{const s=await fetch('/api/status',{cache:'no-store'}).then(r=>r.json());$('updated').textContent='обновлено '+new Date(s.timestamp*1000).toLocaleTimeString();$('gpu').textContent=s.gpu.available?(s.gpu.utilization+'% GPU'):'offline';$('gpuDetail').textContent=s.gpu.name+' · '+s.gpu.memory_used+' / '+s.gpu.memory_total;setBar('gpuBar',s.gpu.utilization);$('ollama').textContent=s.ollama.ok?'online':'offline';$('ollama').className='value '+(s.ollama.ok?'ok':'bad');$('ollamaDetail').textContent=(s.ollama.models||[]).join(', ')||'no model';$('cpu').textContent=s.system.cpu_count+' cores';$('ram').textContent=s.system.ram_used+' / '+s.system.ram_total;setBar('ramBar',s.system.ram_percent);$('disk').textContent=s.system.disk_free+' free';$('diskDetail').textContent=s.system.disk_used+' / '+s.system.disk_total;setBar('diskBar',s.system.disk_percent);$('splunk').textContent=s.splunk.ok?'healthy':'unreachable';$('splunk').className='value '+(s.splunk.ok?'ok':'bad');$('splunkDetail').textContent=s.splunk.detail;rows($('pipeline'),s.pipeline);$('review').textContent=s.review?JSON.stringify(s.review.response||s.review):'No review loaded';renderStages(s.stages||[])}catch(e){$('updated').textContent='dashboard offline'}}
function renderStages(stages){const box=$('stageList');box.replaceChildren();for(const stage of stages){const item=el('div','step '+stage.state);const title=el('strong','');const dot=el('span','dot');title.append(dot,document.createTextNode(stage.title));item.append(title,el('div','detail',stage.detail));box.append(item)}}
async function refreshReports(){try{const reports=await fetch('/api/reports',{cache:'no-store'}).then(r=>r.json());const box=$('reports');box.replaceChildren();for(const r of reports){const row=el('div','report');const left=el('div');left.append(el('b','',r.name),document.createElement('br'),el('span','muted',r.size+' · '+new Date(r.modified*1000).toLocaleString()));const actions=el('div','formats');for(const f of r.formats){const a=el('a','button',f.kind.toUpperCase());a.href=f.url;a.target='_blank';a.rel='noopener';actions.append(a)}row.append(left,actions);box.append(row)}if(!reports.length)box.append(el('div','empty','PDF/DOCX отчетов пока нет'))}catch(e){$('reports').textContent='Reports unavailable'}}
async function refreshHistory(){try{const data=await fetch('/api/history',{cache:'no-store'}).then(r=>r.json());const box=$('events');box.replaceChildren();for(const event of data.events){const row=el('div','event');row.append(el('div','',event.label),el('span','pill',event.time));box.append(row)}if(!data.events.length)box.append(el('div','empty','История пока пуста'))}catch(e){$('events').textContent='History unavailable'}}
async function refreshUploads(){try{const data=await fetch('/api/uploads',{cache:'no-store'}).then(r=>r.json());const box=$('uploads');box.replaceChildren();for(const file of data.uploads){const row=el('div','upload-row');row.append(el('b','',file.name),document.createElement('br'),el('span','muted',file.size+' · '+new Date(file.modified*1000).toLocaleString()+' · '+file.sha256.slice(0,12)));box.append(row)}if(!data.uploads.length)box.append(el('div','empty','Загруженных файлов пока нет'))}catch(e){$('uploads').textContent='Uploads unavailable'}}
async function uploadFiles(){const files=[...$('fileInput').files];if(!files.length){$('uploadStatus').textContent='Выберите файл';return}let done=0;$('uploadStatus').textContent='Загрузка...';for(const file of files){const response=await fetch('/api/uploads?name='+encodeURIComponent(file.name),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});if(!response.ok){const text=await response.text();throw new Error(file.name+': '+text.slice(0,120))}done++;$('uploadProgress').style.width=Math.round(done/files.length*100)+'%'}$('uploadStatus').textContent='Готово: '+done+' файл(ов)';$('fileInput').value='';refreshUploads();refreshHistory()}
$('uploadButton').addEventListener('click',()=>uploadFiles().catch(error=>{$('uploadStatus').textContent='Ошибка: '+error.message;$('uploadProgress').style.width='0%'}));
document.querySelectorAll('.tab').forEach(tab=>tab.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(item=>item.classList.remove('active'));document.querySelectorAll('.view').forEach(item=>item.classList.remove('active'));tab.classList.add('active');$(tab.dataset.view).classList.add('active');if(tab.dataset.view==='history'){refreshReports();refreshHistory()}if(tab.dataset.view==='upload')refreshUploads()}));refresh();setInterval(refresh,5000);refreshReports();refreshHistory();refreshUploads();
</script></body></html>"""


def collect_status(
    splunk_host: str = "soc-storage.example.test",
    metrics_path: str | Path | None = None,
    review_path: str | Path | None = None,
) -> dict:
    disk = shutil.disk_usage("/")
    memory = _memory()
    gpu = _gpu()
    ollama = _ollama()
    splunk = _remote_splunk(splunk_host)
    metrics = _read_json(metrics_path)
    review = _read_json(review_path)
    pipeline = {key: metrics.get(key) for key in ("total_events", "aggregation_limited", "max_unique_values") if key in metrics}
    if metrics:
        pipeline |= {
            "integrity_ok": metrics.get("integrity", {}).get("ok"),
            "findings": (metrics.get("rules") or {}).get("findings_count"),
            "chunks": (metrics.get("ingest") or {}).get("planned_chunks"),
            "failed_chunks": (metrics.get("ingest") or {}).get("failed_chunks"),
        }
    return {"timestamp": time.time(), "system": {"cpu_count": os.cpu_count() or 0, **memory, "disk_total": _size(disk.total), "disk_used": _size(disk.used), "disk_free": _size(disk.free), "disk_percent": round(disk.used / disk.total * 100, 1)}, "gpu": gpu, "ollama": ollama, "splunk": splunk, "pipeline": pipeline if metrics else {}, "stages": collect_stages(metrics, review), "review": review}


def collect_stages(metrics: dict, review: dict) -> list[dict]:
    integrity = metrics.get("integrity") or {}
    rules = metrics.get("rules") or {}
    ingest = metrics.get("ingest") or {}
    total = metrics.get("total_events")
    stages = [
        ("splunk", "Splunk экспорт", bool(ingest) or bool(total), ingest.get("failed_chunks") == 0 if ingest else None, f"частей: {ingest.get('planned_chunks', '-')}; ошибок: {ingest.get('failed_chunks', '-')}"),
        ("integrity", "Целостность", integrity.get("ok") is True, integrity.get("ok") is True if integrity else None, f"проверено строк: {integrity.get('verified_rows', '-')}"),
        ("analysis", "Анализ логов", bool(total), bool(total), f"событий: {total or '-'}"),
        ("rules", "Правила", rules.get("events_scanned") == total if total else False, rules.get("events_scanned") == total if rules else None, f"срабатываний: {rules.get('findings_count', '-')}"),
        ("model", "AI обзор", bool(review), (review.get("quality_checks") or {}).get("passed") is not False if review else None, "Qwen/Ollama карточки" if review else "не запускался"),
        ("report", "Отчет", bool(metrics), not metrics.get("failures") if metrics else None, "PDF/DOCX формируются после приемки"),
        ("qa", "QA", metrics.get("qa_status") == "pass", metrics.get("qa_status") == "pass" if "qa_status" in metrics else None, metrics.get("qa_status", "ожидает явного QA")),
    ]
    result = []
    for _key, title, done, ok, detail in stages:
        state = "done" if done and ok is not False else "fail" if ok is False else "active" if done else "wait"
        result.append({"title": title, "state": state, "detail": detail})
    return result


class CachedProbe:
    def __init__(self, callback, ttl: float):
        self.callback = callback
        self.ttl = ttl
        self.expires = 0.0
        self.value = None
        self.lock = threading.Lock()

    def get(self):
        with self.lock:
            if time.monotonic() >= self.expires:
                self.value = self.callback()
                self.expires = time.monotonic() + self.ttl
            return self.value


class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        request.settimeout(15)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def create_server(host: str = "127.0.0.1", port: int = 8091, **kwargs):
    if host != "localhost" and not ipaddress.ip_address(host).is_loopback:
        raise ValueError("Unauthenticated monitor must bind to loopback; use an SSH tunnel")
    reports_dir = Path(kwargs.pop("reports_dir", "reports")).resolve()
    upload_dir = Path(kwargs.pop("upload_dir", "data/uploads")).resolve()
    upload_max_bytes = int(os.getenv("SOC_AI_UPLOAD_MAX_BYTES", str(DEFAULT_UPLOAD_MAX_BYTES)))
    status_cache = CachedProbe(lambda: collect_status(**kwargs), 5)
    reports_cache = CachedProbe(lambda: list_reports(reports_dir), 15)
    history_cache = CachedProbe(lambda: collect_history(reports_dir, upload_dir), 10)
    uploads_cache = CachedProbe(lambda: list_uploads(upload_dir), 5)

    class Handler(BaseHTTPRequestHandler):
        def end_headers(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            super().end_headers()

        def _check_request_origin(self) -> bool:
            # Reject DNS rebinding and cross-origin requests to the local dashboard.
            authority = self.headers.get("Host", "")
            try:
                hostname = urlparse("//" + authority).hostname
                origin = self.headers.get("Origin")
                if hostname not in {"localhost", "127.0.0.1", "::1"} or (origin and origin != "http://" + authority):
                    self.send_error(403)
                    return False
            except ValueError:
                self.send_error(400)
                return False
            return True

        def do_GET(self):
            if not self._check_request_origin():
                return
            parsed = urlparse(self.path)
            if parsed.path == "/api/status":
                body = json.dumps(status_cache.get(), ensure_ascii=True).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            elif parsed.path == "/api/reports":
                body = json.dumps(reports_cache.get(), ensure_ascii=True).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            elif parsed.path == "/api/history":
                body = json.dumps(history_cache.get(), ensure_ascii=True).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            elif parsed.path == "/api/uploads":
                body = json.dumps({"uploads": uploads_cache.get()}, ensure_ascii=True).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            elif parsed.path.startswith("/reports/"):
                report = safe_report_path(reports_dir, unquote(parsed.path.removeprefix("/reports/")))
                if report is None:
                    self.send_error(404)
                    return
                try:
                    fh = report.open("rb")
                except OSError:
                    self.send_error(404)
                    return
                with fh:
                    size = os.fstat(fh.fileno()).st_size
                    self.send_response(200)
                    content_type = "application/pdf" if report.suffix.lower() == ".pdf" else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(report.name, safe=""))
                    self.send_header("Content-Length", str(size))
                    self.end_headers()
                    remaining = size
                    while remaining:
                        block = fh.read(min(65536, remaining))
                        if not block:
                            break
                        self.wfile.write(block)
                        remaining -= len(block)
                return
            elif parsed.path == "/":
                body = DEFAULT_HTML.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
            else:
                self.send_error(404)
                return
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if not self._check_request_origin():
                return
            parsed = urlparse(self.path)
            if parsed.path != "/api/uploads":
                self.send_error(404)
                return
            try:
                result = save_upload(
                    upload_dir,
                    (parse_qs(parsed.query).get("name") or [""])[0],
                    self.headers.get("Content-Length"),
                    self.rfile,
                    max_bytes=upload_max_bytes,
                )
            except ValueError as exc:
                self.send_error(400, str(exc))
                return
            except OSError:
                self.send_error(500, "upload failed")
                return
            uploads_cache.expires = 0
            history_cache.expires = 0
            body = json.dumps(result, ensure_ascii=True).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    if host == "::1":
        class IPv6Server(BoundedHTTPServer):
            address_family = socket.AF_INET6
        return IPv6Server((host, port), Handler)
    return BoundedHTTPServer((host, port), Handler)


def serve(host: str = "127.0.0.1", port: int = 8091, **kwargs) -> None:
    with create_server(host, port, **kwargs) as server:
        server.serve_forever()


def list_reports(reports_dir: Path) -> list[dict]:
    reports_dir = reports_dir.resolve()
    grouped = {}
    for path in reports_dir.rglob("*") if reports_dir.is_dir() else []:
        if path.suffix.lower() in {".pdf", ".docx"} and safe_report_path(reports_dir, path.relative_to(reports_dir).as_posix()):
            try:
                stat = path.stat()
            except OSError:
                continue
            key = path.with_suffix("").name
            item = grouped.setdefault(key, {"name": key, "size_bytes": 0, "modified": 0, "formats": []})
            item["size_bytes"] += stat.st_size
            item["modified"] = max(item["modified"], stat.st_mtime)
            item["formats"].append({"kind": path.suffix.lower().lstrip("."), "url": "/reports/" + quote(path.relative_to(reports_dir).as_posix()), "size": _file_size(stat.st_size)})
    reports = []
    for item in grouped.values():
        item["size"] = _file_size(item.pop("size_bytes"))
        item["formats"] = sorted(item["formats"], key=lambda value: value["kind"])
        reports.append(item)
    return sorted(reports, key=lambda item: item["modified"], reverse=True)


def collect_history(reports_dir: Path, upload_dir: Path | None = None, limit: int = 50) -> dict:
    reports_dir = reports_dir.resolve()
    events = []
    for path in reports_dir.rglob("run.log.jsonl") if reports_dir.is_dir() else []:
        if any(part.startswith(".") for part in path.relative_to(reports_dir).parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
        except OSError:
            continue
        for line in lines:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = payload.get("timestamp") or payload.get("time") or path.stat().st_mtime
            label = " / ".join(str(payload.get(key)) for key in ("stage", "status") if payload.get(key))
            if not label:
                label = str(payload.get("event") or payload.get("message") or "run event")
            events.append({"timestamp": _coerce_timestamp(ts), "time": _format_time(ts), "label": label})
    for report in list_reports(reports_dir)[:limit]:
        events.append({"timestamp": report["modified"], "time": _format_time(report["modified"]), "label": "Создан отчет: " + report["name"]})
    if upload_dir is not None:
        for upload in list_uploads(upload_dir)[:limit]:
            events.append({"timestamp": upload["modified"], "time": _format_time(upload["modified"]), "label": "Загружен файл: " + upload["name"]})
    events.sort(key=lambda item: item["timestamp"], reverse=True)
    return {"events": events[:limit]}


def list_uploads(upload_dir: Path) -> list[dict]:
    upload_dir = upload_dir.resolve()
    uploads = []
    for path in upload_dir.iterdir() if upload_dir.is_dir() else []:
        if not path.is_file() or path.name.startswith("."):
            continue
        if path.name.endswith(".upload.json"):
            continue
        if path.suffix.lower() not in UPLOAD_EXTENSIONS:
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        uploads.append({
            "name": path.name,
            "size": _file_size(stat.st_size),
            "bytes": stat.st_size,
            "modified": stat.st_mtime,
            "sha256": _file_sha256(path),
        })
    return sorted(uploads, key=lambda item: item["modified"], reverse=True)


def save_upload(upload_dir: Path, filename: str, content_length: str | None, reader, max_bytes: int = DEFAULT_UPLOAD_MAX_BYTES) -> dict:
    safe_name = _safe_upload_name(filename)
    try:
        expected = int(content_length or "-1")
    except ValueError:
        expected = -1
    if expected < 0:
        raise ValueError("Content-Length is required")
    if expected > max_bytes:
        raise ValueError("upload exceeds size limit")
    upload_dir.mkdir(parents=True, exist_ok=True)
    upload_dir.chmod(0o700)
    destination = (upload_dir / safe_name).resolve()
    if destination.parent != upload_dir.resolve():
        raise ValueError("invalid upload path")
    stem = destination.stem
    suffix = destination.suffix
    counter = 1
    while destination.exists():
        destination = upload_dir / f"{stem}-{counter}{suffix}"
        counter += 1
    temporary = upload_dir / f".upload-{uuid.uuid4().hex}.tmp"
    digest = hashlib.sha256()
    written = 0
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            remaining = expected
            while remaining:
                block = reader.read(min(1024 * 1024, remaining))
                if not block:
                    raise ValueError("upload ended early")
                fh.write(block)
                digest.update(block)
                written += len(block)
                remaining -= len(block)
        os.replace(temporary, destination)
        destination.chmod(0o600)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise
    meta = {"name": destination.name, "bytes": written, "size": _file_size(written), "sha256": digest.hexdigest(), "modified": destination.stat().st_mtime}
    sidecar = destination.with_suffix(destination.suffix + ".upload.json")
    sidecar.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    sidecar.chmod(0o600)
    return meta


def _safe_upload_name(filename: str) -> str:
    name = Path(unquote(filename or "")).name.strip().replace("\x00", "")
    if not name:
        raise ValueError("filename is required")
    name = re.sub(r"[^A-Za-z0-9А-Яа-я._ -]+", "_", name).strip(" .")
    if not name:
        raise ValueError("filename is invalid")
    suffix = Path(name).suffix.lower()
    if suffix not in UPLOAD_EXTENSIONS:
        raise ValueError("unsupported file format")
    return name[:180]


def safe_report_path(reports_dir: Path, relative_name: str) -> Path | None:
    reports_dir = reports_dir.resolve()
    if any(part.startswith(".") for part in Path(relative_name).parts):
        return None
    try:
        candidate = (reports_dir / relative_name).resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    if reports_dir in candidate.parents or candidate == reports_dir:
        return candidate if candidate.is_file() and candidate.suffix.lower() in {".pdf", ".docx"} else None
    return None


def _memory() -> dict:
    values = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key in {"MemTotal", "MemAvailable"}:
            values[key] = int(value.split()[0]) * 1024
    total = values.get("MemTotal", 0)
    used = total - values.get("MemAvailable", total)
    return {"ram_total": _size(total), "ram_used": _size(used), "ram_percent": round(used / total * 100, 1) if total else 0}


def _gpu() -> dict:
    try:
        output = subprocess.check_output(["nvidia-smi", "--query-gpu=name,memory.used,memory.total,utilization.gpu", "--format=csv,noheader,nounits"], text=True, timeout=3).strip().split(",")
        name, used, total, utilization = [item.strip() for item in output]
        return {"available": True, "name": name, "memory_used": f"{used} MiB", "memory_total": f"{total} MiB", "utilization": int(utilization)}
    except (OSError, subprocess.SubprocessError, ValueError):
        return {"available": False, "name": "GPU unavailable", "memory_used": "-", "memory_total": "-", "utilization": 0}


def _ollama() -> dict:
    try:
        with open_service(os.getenv("OLLAMA_ENDPOINT", "http://127.0.0.1:11434/api/tags").replace("/api/generate", "/api/tags"), timeout=3) as response:
            body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise ValueError("Model list exceeds size limit")
            data = json.loads(body)
        return {"ok": True, "models": [model.get("name", "") for model in data.get("models", [])]}
    except Exception:
        return {"ok": False, "models": []}


def _remote_splunk(host: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:@-]*", host):
        return {"ok": False, "detail": "Invalid SSH target"}
    try:
        output = subprocess.check_output(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=3", "--", host, "docker inspect --format='{{.State.Health.Status}}' alars-splunk"], text=True, timeout=6).strip()
        return {"ok": output == "healthy", "detail": output or "no status"}
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "detail": "SSH or Docker unavailable"}


def _read_json(path: str | Path | None) -> dict:
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _size(value: int) -> str:
    return f"{value / (1024 ** 3):.1f} GiB"


def _file_size(value: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}"
        value /= 1024


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _coerce_timestamp(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            try:
                return time.mktime(time.strptime(value[:19], "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                return 0.0
    return 0.0


def _format_time(value) -> str:
    timestamp = _coerce_timestamp(value)
    if not timestamp:
        return str(value or "-")
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

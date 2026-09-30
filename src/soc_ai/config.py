from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import tomllib


@dataclass(slots=True)
class RuntimeConfig:
    mode: str = "auto"
    max_memory_mb: int = 4096
    small_run_max_events: int = 1_000_000
    chunk_seconds: int = 3600
    target_events_per_chunk: int = 1_000_000
    min_chunk_seconds: int = 60
    max_chunk_seconds: int = 86_400
    partition_fields: list[str] = field(default_factory=lambda: ["index", "sourcetype", "host"])
    max_rows_per_request: int = 50_000
    tmp_dir: str = "tmp"
    output_dir: str = "data"
    reports_dir: str = "reports"
    delete_temp_after_success: bool = True
    compress_jsonl: bool = True
    gzip_compresslevel: int = 9
    max_rule_findings: int = 100_000
    min_free_disk_mb: int = 1024


@dataclass(slots=True)
class SplunkConfig:
    base_url_env: str = "SPLUNK_BASE_URL"
    token_env: str = "SPLUNK_TOKEN"
    username_env: str = "SPLUNK_USERNAME"
    password_env: str = "SPLUNK_PASSWORD"
    verify_tls_env: str = "SPLUNK_VERIFY_TLS"
    request_timeout_seconds: int = 120
    retry_attempts: int = 5
    retry_backoff_seconds: int = 2
    parallel_workers: int = 1
    export_transport: str = "verified"
    result_page_rows: int = 1000
    max_job_rows: int = 1000000
    job_timeout_seconds: int = 1800


@dataclass(slots=True)
class PrivacyConfig:
    mask_ips: bool = True
    mask_users: bool = False
    deny_fields: list[str] = field(default_factory=list)
    allow_fields: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisConfig:
    top_n: int = 20
    rare_threshold: int = 3
    max_unique_values: int = 100_000


@dataclass(slots=True)
class AppConfig:
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    splunk: SplunkConfig = field(default_factory=SplunkConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)


def _section(data: dict, name: str) -> dict:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"config section [{name}] must be a table")
    return value


def load_config(path: str | Path = "configs/default.toml") -> AppConfig:
    data: dict = {}
    p = Path(path)
    if p.exists():
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    return AppConfig(
        runtime=RuntimeConfig(**_section(data, "runtime")),
        splunk=SplunkConfig(**_section(data, "splunk")),
        privacy=PrivacyConfig(**_section(data, "privacy")),
        analysis=AnalysisConfig(**_section(data, "analysis")),
    )


def load_env_file(path: str | Path = ".env") -> dict[str, str]:
    p = Path(path)
    loaded: dict[str, str] = {}
    if not p.exists():
        return loaded
    for raw_line in p.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
            loaded[key] = value
    return loaded

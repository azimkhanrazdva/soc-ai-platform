from soc_ai.config import load_config
from soc_ai.splunk_stage_tests import run_splunk_stage_tests


def test_splunk_stage_tests_local_only(tmp_path):
    config = load_config("configs/default.toml")
    result = run_splunk_stage_tests(
        config,
        [25],
        start="2026-09-01T00:00:00Z",
        end="2026-09-02T00:00:00Z",
        output_dir=tmp_path,
        local_only=True,
    )
    assert result["status"] == "pass"
    assert result["completed"] == 1
    assert result["results"][0]["events"] == 25
    assert result["results"][0]["qa"]["status"] == "pass"

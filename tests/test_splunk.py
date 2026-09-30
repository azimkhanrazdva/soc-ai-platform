from soc_ai.splunk import SplunkClient, build_count_search, build_search


def test_build_search_never_truncates_results():
    search = build_search("index=main", {"host": "web-01"}, max_rows=10)
    assert 'host="web-01"' in search
    assert "| head" not in search
    assert "| limit" not in search


def test_build_count_search_adds_stats_count():
    assert build_count_search("index=main").endswith("| stats count as count")


def test_splunk_client_supports_basic_auth():
    client = SplunkClient("https://127.0.0.1:8089", username="admin", password="secret")
    assert client.auth_header().startswith("Basic ")


def test_splunk_client_supports_session_token_auth():
    client = SplunkClient("https://127.0.0.1:8089", token="abc")
    assert client.auth_header() == "Splunk abc"

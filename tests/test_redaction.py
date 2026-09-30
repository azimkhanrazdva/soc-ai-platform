from soc_ai.redaction import redact_event, redact_text


def test_redact_text_masks_secrets_and_ips():
    text = redact_text("token=abcd from 203.0.113.44")
    assert "abcd" not in text
    assert "203.0.113.44" not in text


def test_redact_event_removes_denied_fields():
    event = redact_event({"password": "secret", "src_ip": "10.1.2.3", "event": "api_key=xyz"})
    assert event["password"] == "<redacted>"
    assert event["src_ip"] == "10.1.x.x"
    assert "xyz" not in event["event"]


from soc_ai.scale import scale_plan


def test_scale_plan_marks_counts():
    result = scale_plan([10, 20], avg_event_bytes=100, copies_per_run=2, safety_factor=1.0, compression_ratio=1.0)
    assert result["plans"][0]["events"] == 10
    assert result["plans"][1]["estimated_bytes"] == 4000

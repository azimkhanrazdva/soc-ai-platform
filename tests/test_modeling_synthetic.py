import json

from soc_ai.modeling import evaluate_profile, train_profile
from soc_ai.synthetic import generate_synthetic


def test_synthetic_train_evaluate(tmp_path):
    raw = tmp_path / "synthetic.jsonl"
    generate_synthetic(raw, 10)
    profile = tmp_path / "profile.json"
    trained = train_profile([raw], profile)
    assert trained["total_events"] == 10

    evaluation = evaluate_profile(profile, [raw], tmp_path / "eval.json")
    assert evaluation["total_events"] == 10
    assert evaluation["unseen_rates"]["host"] == 0


def test_profile_bounds_high_cardinality_fields(tmp_path):
    raw = tmp_path / "high-cardinality.jsonl"
    raw.write_text(
        "\n".join(json.dumps({"host": f"host-{index}"}) for index in range(5)) + "\n",
        encoding="utf-8",
    )

    profile_path = tmp_path / "profile.json"
    result = train_profile([raw], profile_path, max_unique_values=2)
    profile = json.loads(profile_path.read_text(encoding="utf-8"))

    assert result["aggregation_limited"] is True
    assert profile["aggregation_limited"] is True
    assert len(profile["fields"]["host"]) <= 2

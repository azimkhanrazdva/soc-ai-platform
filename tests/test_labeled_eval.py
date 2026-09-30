import json

from soc_ai.modeling import evaluate_labeled


def test_evaluate_labeled_metrics(tmp_path):
    path = tmp_path / "labeled.jsonl"
    rows = [
        {"label": 1, "score": 0.9},
        {"label": 0, "score": 0.8},
        {"label": 0, "score": 0.1},
        {"label": 1, "score": 0.2},
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    metrics = evaluate_labeled([path], threshold=0.5, output_path=tmp_path / "metrics.json")
    assert metrics["confusion_matrix"] == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5
    assert metrics["roc_auc"] == 0.75


def test_evaluate_labeled_auc_handles_ties(tmp_path):
    path = tmp_path / "tied.jsonl"
    rows = [
        {"label": 1, "score": 0.5},
        {"label": 0, "score": 0.5},
        {"label": 1, "score": 0.2},
        {"label": 0, "score": 0.1},
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    metrics = evaluate_labeled([path], output_path=tmp_path / "metrics.json")

    assert metrics["roc_auc"] == 0.625

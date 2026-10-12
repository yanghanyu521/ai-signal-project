from __future__ import annotations

from evaluation.gold_standard.adjudicate import adjudicate
from evaluation.gold_standard.evaluate import evaluate


def _row(evidence_id: str, version: str, label: str = "") -> dict:
    return {"evidence_id": evidence_id, "sha256": "a" * 64, "feature_category": "prompt",
            "sample_kind": "script", "family": "fixture", "model_familiarity": "not_applicable",
            "candidate_versions": version, "true_ai_feature": label,
            "static_call_verified": "no", "prompt_role": "program_prompt",
            "adjudication_result": "agreed", "predicted_call_relation": "location_verified"}


def test_unlabeled_candidates_never_acquire_accuracy() -> None:
    result = evaluate([_row("one", "v08_post")])
    score = result["metrics"]["feature:prompt"]["v08_post"]
    assert score["precision"] is None
    assert score["recall_candidate_pool"] is None
    assert result["recall_scope"] == "candidate_pool_only"


def test_candidate_pool_recall_is_explicit() -> None:
    result = evaluate([_row("one", "v07_rule|v08_post", "yes"),
                       _row("two", "v08_post", "yes"),
                       _row("three", "v08_post", "no")])
    old = result["metrics"]["all"]["v07_rule"]
    new = result["metrics"]["all"]["v08_post"]
    assert old["recall_candidate_pool"] == 0.5
    assert new["precision"] == 0.666667
    assert result["recall_scope"] == "candidate_pool_only"


def test_conflict_requires_explicit_adjudication() -> None:
    first = _row("one", "v08_post", "yes")
    first["annotator"] = "A"
    second = dict(first, annotator="B", true_ai_feature="no")
    rows, conflicts = adjudicate([first], [second])
    assert rows[0]["true_ai_feature"] == "uncertain"
    assert rows[0]["adjudication_result"] == "pending"
    assert conflicts[0]["fields"] == ["true_ai_feature"]

from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from streamlit.testing.v1 import AppTest

from ai_signal_hub.similarity import (
    ALGORITHM_VERSION, SIMHASH_ALGORITHM, SampleSimilarityService, compare_profiles,
    compare_code_style, compare_prompts, compare_toolchain, sample_profile,
)


def sample(char="a", model="MODEL_A", language="javascript", metrics=None, prompt=True):
    result = {"sample": {"sha256": char * 64}, "features": {
        "toolchain": {"evidence": [{"type": "model_identifier", "normalized": {"model": model}}]} if model else {},
        "prompt": {"embedded_prompts": [{"text_hash": "sha256:" + "f" * 64}]} if prompt else {},
        "code_style": {"language": language, "recoverability": "original_source", "metrics": metrics or {
            "loc": 100, "function_count": 5, "mean_identifier_length": 5}}}}
    return result


def compare(a, b, weights=None):
    return compare_profiles(sample_profile(a), sample_profile(b), weights)


def prompt_profile(records=None, structure=None):
    return sample_profile({"features": {"prompt": {"embedded_prompts": records or [],
                            "structural_features": structure or {}}}})["prompt"]


def fuzzy(value, algorithm=SIMHASH_ALGORITHM):
    return {"fuzzy_hash": {"algorithm": algorithm, "value": f"simhash64:{value:016x}"}}


def put(repo, *samples):
    for index, result in enumerate(samples):
        repo.upsert_sample(result, source_case=f"case-{index}")


def test_explicit_weighted_sum_and_weight_changes_take_effect():
    a, b = sample(), sample("b", model="OTHER")
    result = compare(a, b)
    assert result["toolchain_similarity"] == 0
    assert result["prompt_similarity"] == result["code_style_similarity"] == 1
    assert result["overall_similarity"] == pytest.approx(.5)
    changed = compare(a, b, {"toolchain": .1, "prompt": .1, "code_style": .8})
    assert changed["overall_similarity"] == pytest.approx(.9)
    assert sum(changed["details"]["contributions"].values()) == changed["overall_similarity"]


@pytest.mark.parametrize("weights", [{}, {"toolchain": -1, "prompt": 1, "code_style": 1},
    {"toolchain": 0, "prompt": 0, "code_style": 0}, {"toolchain": float("nan"), "prompt": 1, "code_style": 1},
    {"toolchain": 1e308, "prompt": 1e308, "code_style": 1e308}])
def test_invalid_weights_fail(weights):
    with pytest.raises(ValueError):
        compare(sample(), sample("b"), weights)


def test_identical_evidence_is_not_penalized_by_sample_identity():
    assert compare(sample("a"), sample("b"))["overall_similarity"] == 1


def test_no_shared_absence_similarity_and_missing_is_null():
    result = compare({}, {})
    assert result["overall_similarity"] is None
    assert all(result[group + "_similarity"] is None for group in ("toolchain", "prompt", "code_style"))
    assert result["common_features"] == []
    assert result["details"]["comparable_weight"] == 0
    json.dumps(result, allow_nan=False)


def test_missing_group_weights_are_not_reassigned():
    a, b = sample(), sample("b")
    a["features"]["code_style"] = b["features"]["code_style"] = {}
    a["features"]["prompt"] = b["features"]["prompt"] = {}
    result = compare(a, b)
    assert result["overall_similarity"] == .5
    assert result["code_style_similarity"] is None
    assert result["details"]["comparable_weight"] == .5
    assert result["details"]["conditional_similarity"] == 1


def test_common_rule_or_evidence_type_is_not_common_toolchain():
    a, b = sample(), sample("b", model="OTHER")
    for result in (a, b):
        result["features"]["toolchain"]["evidence"][0]["rule_id"] = "same_generic_rule"
    score = compare(a, b)
    assert score["toolchain_similarity"] == 0
    assert not score["details"]["groups"]["toolchain"]["matched_facts"]


def test_tool_facts_are_deduplicated_and_use_weighted_union():
    left = {"model:a": 2, "vendor:v": 1}
    right = {"model:b": 2, "vendor:v": 1}
    assert compare_toolchain(left, right)["score"] == pytest.approx(1 / 5)
    a = sample()
    before = sample_profile(a)["toolchain"]
    a["features"]["toolchain"]["evidence"] *= 5
    assert sample_profile(a)["toolchain"] == before


def test_tool_endpoint_drops_credentials_query_and_fragment():
    data = {"features": {"toolchain": {"evidence": [{"type": "endpoint",
            "value": "https://user:secret@example.test/v1/chat?key=secret#private"}]}}}
    assert sample_profile(data)["toolchain"] == {"endpoint:example.test/v1/chat": 1.5}


def test_prompt_exact_digest_compatible_with_bare_hash():
    left = prompt_profile([{"text_hash": "a" * 64}])
    right = prompt_profile([{"text_hash": "sha256:" + "a" * 64}])
    result = compare_prompts(left, right)
    assert result["score"] == 1 and result["matched_prompts"][0]["method"] == "exact_sha256"


def test_simhash_uses_real_hamming_distance_and_does_not_score_random_bits():
    left = prompt_profile([fuzzy(0xffffffffffffffff)])
    close = compare_prompts(left, prompt_profile([fuzzy(0xfffffffffffffffe)]))
    assert close["matched_prompts"][0]["hamming_distance"] == 1
    assert close["content_similarity"] == pytest.approx(.95 * 15 / 16)
    distant = compare_prompts(left, prompt_profile([fuzzy(0xffffffff00000000)]))
    assert distant["score"] == 0 and distant["matched_prompts"] == []


@pytest.mark.parametrize("bad_hash", ["simhash64:abc", "ssdeep:unknown", {"algorithm": "different", "value": "simhash64:ffffffffffffffff"},
                                      {"algorithm": SIMHASH_ALGORITHM, "value": "simhash64:0000000000000000"}])
def test_unknown_invalid_or_empty_fuzzy_hash_is_not_a_match(bad_hash):
    profile = prompt_profile([{"fuzzy_hash": bad_hash}])
    assert profile["records"] == []
    assert compare_prompts(profile, profile)["score"] is None


def test_prompt_matching_is_one_to_one_and_duplicate_invariant():
    a = {**fuzzy(0xffffffffffffffff), "text_hash": "a" * 64}
    b = {**fuzzy(0xffffffffffffffff), "text_hash": "b" * 64}
    c = {**fuzzy(0xffffffffffffffff), "text_hash": "c" * 64}
    left = prompt_profile([a, a])
    assert len(left["records"]) == 1
    result = compare_prompts(left, prompt_profile([b, c]))
    assert len(result["matched_prompts"]) == 1
    assert result["content_similarity"] == pytest.approx(.95 / 2)


def test_only_structure_is_weak_not_full_prompt_similarity():
    left = prompt_profile(structure={"role_definition": True, "code_only": False})
    right = prompt_profile(structure={"role_definition": True})
    result = compare_prompts(left, right)
    assert result["score"] == .2 and result["strength"] == "structure_only"
    assert result["content_similarity"] is None
    assert result["matched_structure"] == ["flag:role_definition"]


def test_real_legacy_special_token_key_is_supported():
    p = sample_profile({"features": {"prompt": {"special_tokens": [{"token": "[INST]"}]}}})
    assert p["prompt"]["structure"] == {"token:[inst]": .5}


@pytest.mark.parametrize("change,reason", [
    ({"language": "vbscript"}, "different_languages"),
    ({"parse_error": "bad syntax"}, "invalid_source_quality"),
    ({"recoverability": "recovered_source"}, "invalid_source_quality"),
    ({"recoverability": "strings_only"}, "invalid_source_quality"),
    ({"language": None}, "invalid_source_quality"),
    ({"language": "python"}, "invalid_source_quality"),
])
def test_code_quality_or_language_difference_is_not_zero_score(change, reason):
    a, b = sample(), sample("b")
    b["features"]["code_style"].update(change)
    result = compare(a, b)
    assert result["code_style_similarity"] is None
    assert result["details"]["groups"]["code_style"]["reason"] == reason


def test_proportional_but_different_code_statistics_are_not_identical():
    a = sample(metrics={"loc": 100, "function_count": 5, "mean_identifier_length": 5})
    b = sample("b", metrics={"loc": 1000, "function_count": 50, "mean_identifier_length": 50})
    result = compare(a, b)
    assert result["code_style_similarity"] == pytest.approx(.1)
    assert not any(x.startswith("code_style:") for x in result["common_features"])


def test_code_does_not_use_shared_zeros_or_single_metric_as_positive_evidence():
    a = sample(metrics={"loc": 100, "function_count": 0, "comment_ratio": 0})
    result = compare(a, copy.deepcopy(a))
    assert result["code_style_similarity"] is None
    assert result["details"]["groups"]["code_style"]["reason"] == "insufficient_shared_metrics"


def test_comparison_is_symmetric_finite_and_does_not_mutate_inputs():
    a, b = sample(), sample("b", metrics={"loc": 1000, "function_count": 50, "mean_identifier_length": 50})
    before = copy.deepcopy([a, b])
    left, right = compare(a, b), compare(b, a)
    assert left["overall_similarity"] == right["overall_similarity"]
    assert [a, b] == before
    json.dumps(left, allow_nan=False)


def test_empty_samples_are_singletons_and_api_explains_no_features(platform, monkeypatch):
    service, repo = platform
    put(repo, {"sample": {"sha256": "a" * 64}}, {"sample": {"sha256": "b" * 64}})
    assert service.similarity.rebuild()["cluster_count"] == 2
    normal = repo.sample_associations("a" * 64)
    assert normal["association_status"] == "no_features" and not normal["related_samples"]
    assert normal["association_summary"]["evaluated_pairs"] == 1
    assert "阈值" in normal["message"]
    from ai_signal_hub import main
    monkeypatch.setattr(main, "service", service)
    response = TestClient(main.app).get(f"/api/v1/samples/{'a' * 64}/associations?include_unmatched=true")
    assert response.status_code == 200
    pair = response.json()["related_samples"][0]
    assert pair["overall_similarity"] is None and pair["code_style_similarity"] is None
    assert not pair["same_cluster"]


def test_threshold_changes_clustering_not_candidate_visibility(platform):
    _, repo = platform
    a, b = sample(model=None, prompt=False), sample("b", model=None, prompt=False)
    put(repo, a, b)
    SampleSimilarityService(repo, distance_threshold=.45).rebuild()
    first = repo.sample_associations("a" * 64)["related_samples"][0]
    assert first["overall_similarity"] == .2 and not first["same_cluster"]
    SampleSimilarityService(repo, distance_threshold=.9).rebuild()
    second = repo.sample_associations("a" * 64)["related_samples"][0]
    assert second["overall_similarity"] == .2 and second["same_cluster"]


def test_corpus_outlier_does_not_change_existing_pair_and_raw_results_unchanged(platform):
    service, repo = platform
    a, b = sample(), sample("b", model="OTHER")
    put(repo, a, b)
    service.similarity.rebuild()
    before = repo.sample_associations("a" * 64)["related_samples"][0]["overall_similarity"]
    put(repo, sample("c", metrics={"loc": 10**20, "function_count": 10**10, "mean_identifier_length": 10**9}))
    service.similarity.rebuild()
    pair = next(r for r in repo.sample_associations("a" * 64, include_unmatched=True)["related_samples"] if r["related_sha256"] == "b" * 64)
    assert pair["overall_similarity"] == before
    assert repo.get_sample("a" * 64)["result_json"] == a
    assert repo.get_sample("b" * 64)["result_json"] == b
    repo.db.initialize()
    assert repo.sample_associations("a" * 64)["run"]["algorithm_version"] == ALGORITHM_VERSION


def test_stale_snapshot_rejected_without_destroying_current_relations(platform):
    service, repo = platform
    put(repo, sample(), sample("b"))
    run = service.similarity.rebuild()
    snapshot = repo.all_sample_results()
    put(repo, sample("c"))
    with pytest.raises(RuntimeError, match="计算期间"):
        repo.replace_sample_similarity(algorithm_version=ALGORITHM_VERSION, distance_threshold=.45,
                                       clusters=[], relations=[], expected_samples=snapshot)
    assert repo.sample_associations("a" * 64)["run"]["id"] == run["run_id"]


def test_failed_replacement_rolls_back_old_derived_records(platform):
    service, repo = platform
    put(repo, sample(), sample("b"))
    run = service.similarity.rebuild()
    with pytest.raises(sqlite3.IntegrityError):
        repo.replace_sample_similarity(algorithm_version=ALGORITHM_VERSION, distance_threshold=.45,
            clusters=[{"sample_id": "missing", "cluster_label": "C1", "cluster_size": 1}], relations=[])
    result = repo.sample_associations("a" * 64)
    assert result["run"]["id"] == run["run_id"] and len(result["related_samples"]) == 1


def test_legacy_results_without_diagnostics_require_rebuild(platform):
    _, repo = platform
    put(repo, sample())
    repo.replace_sample_similarity(algorithm_version="old", distance_threshold=.45,
        clusters=[{"sample_id": "a" * 64, "cluster_label": "C1", "cluster_size": 1}], relations=[])
    result = repo.sample_associations("a" * 64)
    assert result["association_status"] == "legacy_results"


def test_association_page_explains_missing_and_supports_null_scores(platform, monkeypatch):
    service, repo = platform
    put(repo, {"sample": {"sha256": "a" * 64}}, {"sample": {"sha256": "b" * 64}})
    service.similarity.rebuild()
    ui = Path(__file__).resolve().parents[1] / "ui"
    monkeypatch.syspath_prepend(str(ui))
    from ui_utils import api

    def get_json(base, path, params=()):
        if path == "/api/v1/samples":
            return repo.list_samples()
        return repo.sample_associations("a" * 64, include_unmatched=dict(params).get("include_unmatched") == "true")

    monkeypatch.setattr(api, "get_json", get_json)
    app = AppTest.from_file(ui / "app_pages" / "sample_associations.py")
    app.session_state["api_base_url"] = "http://test.invalid"
    app.run()
    assert not app.exception
    assert any("没有可用于" in item.value for item in app.info)
    app.checkbox[0].check().run()
    assert not app.exception
    assert len(app.dataframe) >= 2
    assert json.loads(app.dataframe[1].proto.columns)["code_style_similarity"]["label"] == "代码统计"


def test_old_running_api_cannot_rebuild_through_new_ui(monkeypatch):
    ui = Path(__file__).resolve().parents[1] / "ui"
    monkeypatch.syspath_prepend(str(ui))
    from ui_utils import api

    def get_json(base, path, params=()):
        if path == "/api/v1/samples":
            return [{"sha256": "a" * 64}]
        return {"cluster": {}, "related_samples": [], "interpretation": "legacy"}

    monkeypatch.setattr(api, "get_json", get_json)
    app = AppTest.from_file(ui / "app_pages" / "sample_associations.py")
    app.session_state["api_base_url"] = "http://test.invalid"
    app.run()
    assert not app.exception
    assert app.button[0].disabled
    assert any("重启" in item.value for item in app.warning)

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import yaml

from ai_signal_hub.config import Settings
from ai_signal_hub.legacy import LegacyAdapters
from ai_signal_hub.similarity import sample_profile
from aisig.classify import classify
from aisig.code_style import analyze_code_style
from aisig.toolchain import _matches, extract_python_call_evidence, extract_toolchain


def rules() -> dict:
    path = Settings().legacy_sample_project / "rules" / "llm_rules.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_model_rule_keeps_complete_gpt_identifier() -> None:
    data = b"gpt-4o-mini gpt-4-turbo"
    strings = [{"encoding": "ascii", "offset": 0, "value": data.decode()}]
    evidence = extract_toolchain(strings, rules(), {}, data)["evidence"]
    values = [item["value"] for item in evidence if item["type"] == "model_identifier"]
    assert values == ["gpt-4o-mini", "gpt-4-turbo"]


def test_string_matches_report_every_match_and_exact_encoded_offset() -> None:
    rule = [{"id": "token", "regex": "foo"}]
    ascii_hits = _matches(
        [{"encoding": "ascii", "offset": 10, "value": "xxfoo foo"}], rule, "marker"
    )
    utf16_hits = _matches(
        [{"encoding": "utf16le", "offset": 20, "value": "xxfoo foo"}], rule, "marker"
    )
    assert [item["offset"] for item in ascii_hits] == [12, 16]
    assert [item["offset"] for item in utf16_hits] == [24, 32]
    assert all(item["string_offset"] in {10, 20} for item in ascii_hits + utf16_hits)
    assert [item["match_char_offset"] for item in ascii_hits] == [2, 6]


def test_known_sdk_unknown_model_and_custom_service_stay_separate() -> None:
    text = """
from openai import OpenAI
client = OpenAI(base_url="https://gateway.example.invalid/v1")
answer = client.chat.completions.create(
    model="acme-nebula-v9",
    messages=[{"role": "user", "content": "Summarize the supplied record."}],
)
"""
    evidence = extract_python_call_evidence(text)
    model = next(item for item in evidence if item["type"] == "model_argument")
    endpoint = next(item for item in evidence if item["type"] == "service_endpoint")
    assert model["value"] == "acme-nebula-v9"
    assert model["normalized"]["model"] == "acme-nebula-v9"
    assert model["normalized"].get("vendor") is None
    assert endpoint["value"] == "https://gateway.example.invalid/v1"
    result = classify({"evidence": evidence}, {"embedded_prompts": []})
    assert result["model_attribution"]["model"] == "acme-nebula-v9"
    assert result["model_attribution"]["vendor"] is None
    assert result["llm_involvement"]["evidence_grade"] == "static_relation_supported"
    assert result["llm_involvement"]["runtime_observed"] is False


def test_unknown_http_endpoint_with_request_structure_is_discoverable() -> None:
    text = """
import requests
payload = {"engine": "fictional-router-2027", "messages": [{"role": "user", "content": "Classify this record."}]}
requests.post("https://private.example.invalid/infer", json=payload)
"""
    evidence = extract_python_call_evidence(text)
    assert any(item["type"] == "model_argument" and item["value"] == "fictional-router-2027" for item in evidence)
    assert any(item["type"] == "service_endpoint" and item["value"].startswith("https://private") for item in evidence)
    assert all(item["verification_status"] == "relation_verified" for item in evidence)


def test_ordinary_model_configuration_is_not_an_ai_call() -> None:
    text = 'config = {"model": "invoice-v2", "table": "orders"}\nprint(config)\n'
    assert extract_python_call_evidence(text) == []


def test_sdk_marker_does_not_attribute_model_vendor_or_claim_execution() -> None:
    evidence = [{
        "type": "sdk_marker",
        "value": "from openai import OpenAI",
        "normalized": {"sdk_name": "openai", "sdk_vendor": "OpenAI"},
        "confidence": 0.9,
        "verification_status": "location_verified",
    }]
    result = classify({"evidence": evidence}, {"embedded_prompts": []})
    assert result["model_attribution"]["vendor"] is None
    assert result["model_attribution"]["model"] is None
    assert result["llm_involvement"]["label"] != "confirmed"
    assert result["llm_involvement"]["evidence_grade"] == "marker_only"
    assert result["llm_involvement"]["runtime_observed"] is False
    assert result["llm_involvement"]["calibrated_probability"] is False


def test_ineligible_prompt_hash_is_excluded_from_similarity() -> None:
    digest = "sha256:" + "a" * 64
    result = {
        "features": {"prompt": {"embedded_prompts": [
            {"text_hash": digest, "comparison_eligible": False, "completeness": "excerpt_only"},
            {"text_hash": "sha256:" + "b" * 64, "comparison_eligible": True,
             "completeness": "complete_static_template"},
        ]}}
    }
    profile = sample_profile(result)["prompt"]
    assert profile["records"] == [{"exact": "sha256:" + "b" * 64, "fuzzy": None,
                                    "completeness": "complete_static_template"}]
    assert profile["excluded_ineligible"] == 1


def test_code_metrics_are_descriptive_and_record_representation() -> None:
    result = analyze_code_style("def run(value):\n    return value\n", "python", "original_source")
    assert result["status"] == "descriptive_metrics"
    assert result["representation"] == "original_source"
    assert result["ai_generated_detection"] == {
        "status": "not_supported",
        "heuristic_score": None,
    }


def test_adapter_reclassifies_once_after_all_enhancements(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("harmless fixture", encoding="utf-8")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    baseline = {
        "schema_version": "0.1",
        "sample": {"sha256": digest, "size": sample.stat().st_size, "file_type": "text",
                   "language": None, "recoverability": "unknown"},
        "features": {"toolchain": {"evidence": [{"type": "sdk_marker", "value": "sdk",
            "normalized": {"sdk_name": "fixture"}, "confidence": 0.8}]},
            "prompt": {"embedded_prompts": [], "structural_features": {}, "special_tokens": []},
            "code_style": {}, "recovery": {}},
        "classification": {"llm_involvement": {"label": "unknown"}, "model_attribution": {}},
        "errors": [],
    }

    def fake_analyze(_sample, out, _limits, _rules):
        out.mkdir(parents=True, exist_ok=True)
        (out / "result.json").write_text(json.dumps(baseline), encoding="utf-8")
        (out / "strings.jsonl").write_text("", encoding="utf-8")

    def fake_recovery(result, _data):
        updated = copy.deepcopy(result)
        updated["features"]["prompt"]["embedded_prompts"].append({
            "text": "A statically bound prompt component.", "comparison_eligible": True
        })
        return updated

    import aisig.cli
    import ai_signal_hub.prompt_recovery

    monkeypatch.setattr(aisig.cli, "analyze", fake_analyze)
    monkeypatch.setattr(ai_signal_hub.prompt_recovery, "recover_prompt_features", fake_recovery)
    called = []
    adapter = LegacyAdapters(Settings(data_dir=tmp_path / "data", sample_llm_enabled=False,
                                      static_tools_docker_enabled=False))
    monkeypatch.setattr(adapter, "_recover_packaged_toolchain", lambda result, data: called.append(True))
    result = adapter.analyze_sample(sample, tmp_path / "artifacts")
    assert called == [True]
    assert result["classification"]["llm_involvement"]["evidence_grade"] == "marker_only"
    assert result["classification"]["derivation_stage"] == "final"


def test_multiple_models_are_preserved_as_candidates() -> None:
    evidence = [
        {"type": "model_argument", "value": "private-alpha", "normalized": {"model": "private-alpha"},
         "verification_status": "relation_verified", "confidence": 0.9},
        {"type": "model_argument", "value": "private-beta", "normalized": {"model": "private-beta"},
         "verification_status": "relation_verified", "confidence": 0.9},
    ]
    result = classify({"evidence": evidence}, {"embedded_prompts": []})
    assert {item["model"] for item in result["model_candidates"]} == {"private-alpha", "private-beta"}


def test_similarity_keeps_sdk_and_model_vendor_separate() -> None:
    result = {"features": {"toolchain": {"evidence": [{
        "type": "model_argument", "value": "router-deployment",
        "normalized": {"model": "router-deployment", "sdk_vendor": "OpenAI", "sdk_name": "openai"},
    }]}}}
    facts = sample_profile(result)["toolchain"]
    assert "model:router-deployment" in facts
    assert "sdk_vendor:openai" in facts
    assert "vendor:openai" not in facts


def test_packaged_inner_toolchain_merges_with_existing_outer_evidence(tmp_path: Path, monkeypatch) -> None:
    import ai_signal_hub.prompt_recovery
    import aisig.toolchain

    monkeypatch.setattr(ai_signal_hub.prompt_recovery, "_pyinstaller_members",
                        lambda data: [("inner.pyc", 42, b"inner material")])
    monkeypatch.setattr(aisig.toolchain, "extract_toolchain", lambda *args: {"evidence": [{
        "type": "model_identifier", "value": "inner-model",
        "normalized": {"model": "inner-model"}, "source": "member", "offset": 2,
    }]})
    result = {"sample": {"sha256": "f" * 64}, "features": {
        "toolchain": {"evidence": [{"type": "sdk_marker", "value": "outer-sdk",
                                      "source": "outer", "offset": 1}]},
        "recovery": {},
    }}
    adapter = LegacyAdapters(Settings(data_dir=tmp_path / "data", sample_llm_enabled=False,
                                      static_tools_docker_enabled=False))
    adapter._recover_packaged_toolchain(result, b"prefixMEI\x0c\x0b\x0a\x0b\x0esuffix")
    values = {item["value"] for item in result["features"]["toolchain"]["evidence"]}
    assert values == {"outer-sdk", "inner-model"}
    assert result["features"]["recovery"]["static_toolchain"]["evidence_added"] == 1

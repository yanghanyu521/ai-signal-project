from __future__ import annotations

import copy
import hashlib
import json
from io import BytesIO

import httpx
import pytest

from ai_signal_hub import report_llm
from ai_signal_hub.report_quality import enforce_review, high_risk_paths
from ai_signal_hub.repository import _event_date
from conftest import empty_value, model_event, with_review


def reply(candidate):
    return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(candidate)}}]})


def run(service, text="TARGET possibly remains a proof of concept."):
    return service.analyze_report(BytesIO(text.encode()), "quality.txt", None, target_name="TARGET")


@pytest.mark.parametrize("failure", ["scope", "missing_binding", "missing_assertion", "unresolved"])
def test_semantic_gate_rejects_unresolved_or_uncovered_claims(platform, report_model, monkeypatch, failure):
    service, repo = platform
    calls = []

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        calls.append(body)
        candidate = model_event(body)
        if body["task"] == "extract":
            candidate["event"]["status"].update(value="proof_of_concept", evidence_ids=["e1"])
        else:
            review = candidate["review"]
            if failure == "scope":
                review["subject_bindings"][0].update(subject="OTHER", scope="other")
            elif failure == "missing_binding":
                review["subject_bindings"] = []
            elif failure == "missing_assertion":
                review["field_assertions"] = []
            else:
                review["verdict"] = "unresolved"
        return reply(candidate)
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    with pytest.raises(report_llm.ReportModelError, match="质量门禁"):
        run(service)
    assert len(calls) == 3  # extraction + review + one feedback repair
    assert calls[-1]["validation_feedback"]
    assert not repo.list_reports()


def test_nonexplicit_status_is_neutralized_with_audit(platform, report_model, monkeypatch):
    service, _ = platform

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        candidate = model_event(body)
        if body["task"] == "extract":
            candidate["event"]["status"].update(value="proof_of_concept", evidence_ids=["e1"])
        else:
            candidate["review"]["field_assertions"][0]["assertion_status"] = "possible"
        return reply(candidate)
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    result = run(service)["result_json"]
    assert result["events"][0]["status"]["value"] == "unknown"
    audit = result["extraction"]["quality_review"]
    assert audit["uncertainty_corrections"][0]["before"] == "proof_of_concept"
    assert audit["field_assertions"][0]["reviewed_value"] == "proof_of_concept"


def test_reported_prompt_cannot_stay_only_in_behavior(platform, report_model, monkeypatch):
    service, repo = platform

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        candidate = model_event(body)
        if body["task"] == "review":
            candidate["review"]["coverage_checks"]["prompts"] = {
                "has_evidence": True, "evidence_ids": candidate["event"]["identity"]["evidence_ids"],
                "explanation": "source describes embedded adversarial prompts"}
        return reply(candidate)
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    with pytest.raises(report_llm.ReportModelError, match="专用字段"):
        run(service, "TARGET contains hard-coded prompts to bypass LLM security analysis.")
    assert not repo.list_reports()


def test_uncertain_actor_is_withheld_not_confirmed_or_whole_report_rejected(platform, report_model, monkeypatch):
    service, _ = platform

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        candidate = model_event(body)
        if body["task"] == "extract":
            defs = body["response_schema"]["$defs"]
            actor = empty_value(defs["actor"], defs)
            actor.update(name="GROUP_A", aliases=["GROUP_B"], actor_type="state_sponsored", evidence_ids=["e1"])
            candidate["event"]["attribution"]["actors"] = [actor]
        else:
            for assertion in candidate["review"]["field_assertions"]:
                if assertion["path"].endswith("/name"):
                    assertion["assertion_status"] = "possible"
        return reply(candidate)
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    result = run(service, "TARGET may be associated with GROUP_A.")["result_json"]
    actor = result["events"][0]["attribution"]["actors"][0]
    assert actor["name"] == "unknown" and actor["aliases"] == [] and actor["actor_type"] == "unknown"
    audit = result["extraction"]["quality_review"]["uncertainty_corrections"]
    assert audit[0]["before"]["name"] == "GROUP_A"
    assert audit[0]["before"]["evidence_ids"][0].startswith("evidence:")


@pytest.mark.parametrize("initial_problem", ["null", "schema"])
def test_initial_missing_target_or_schema_problem_gets_independent_review(platform, report_model, monkeypatch, initial_problem):
    service, _ = platform
    tasks = []

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        tasks.append(body["task"])
        if body["task"] == "extract":
            if initial_problem == "null":
                return reply({"event": None})
            candidate = model_event(body)
            del candidate["event"]["outcomes"]
            return reply(candidate)
        assert body["validation_feedback"]
        corrected = model_event({**body, "task": "extract"})
        return reply(with_review(body, corrected))
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    result = run(service)["result_json"]
    assert tasks == ["extract", "review"]
    assert result["events"][0]["identity"]["event_name"] == "TARGET"
    assert result["extraction"]["quality_review"]["verdict"] == "pass"


def test_reviewer_corrects_cross_subject_and_completes_prompt(platform, report_model, monkeypatch):
    service, _ = platform

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        candidate = model_event(body)
        event = candidate["event"]
        if body["task"] == "extract":
            event["limitations"] = [{"type": "negative_evidence", "description": "OTHER cannot compromise a host.", "evidence_ids": ["e1"]}]
        else:
            assert len(body["blocks"]) == 2
            assert body["candidate"]["limitations"]
            event["limitations"] = []
            prompt = empty_value(body["response_schema"]["$defs"]["prompt"], body["response_schema"]["$defs"])
            prompt.update(availability="described_only", purpose="analysis evasion", evidence_ids=event["identity"]["evidence_ids"])
            event["ai_signals"]["prompts"] = [prompt]
            candidate = with_review(body, candidate)
            candidate["review"]["issues"] = ["Removed other subject; completed described prompt"]
        return reply(candidate)
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    result = run(service, "TARGET embeds prompts to evade analysis.\nOTHER cannot compromise a host.")["result_json"]
    assert not result["events"][0]["limitations"]
    assert result["events"][0]["ai_signals"]["prompts"][0]["availability"] == "described_only"
    assert result["extraction"]["quality_review"]["human_review_required"] is True


@pytest.mark.parametrize("excerpt,source,accepted", [
    ('uses "model-v1" today', 'uses " model-v1 " today', True),
    ('TARGET uses\nmodel', 'TARGET  uses model', True),
    ('TARGET uses model', 'TARGET does not use model', False),
    ('notused', 'not used', False),
    ('model-v2', 'model-v1', False),
])
def test_quote_repair_is_whitespace_only(excerpt, source, accepted):
    original = report_llm._locate_excerpt(excerpt, {"text": source})
    assert (original is not None) is accepted
    if accepted:
        assert original in source


@pytest.mark.parametrize("precision,date,expected", [
    ("year", "2026-01-01", "2026"), ("month", "2026-03-01", "2026-03"),
    ("day", "2026-03-12", "2026-03-12"), ("unknown", None, None),
    ("quarter", "2026-01-01", None), ("range", "2026-01-01", None),
])
def test_event_date_does_not_invent_month_or_use_publication(precision, date, expected):
    assert _event_date({"time": {"start": date, "precision": precision}}, "2026-09-02") == expected


def test_prompt_hash_normalization_and_comparison_are_non_mutating(platform, report_model, monkeypatch):
    service, _ = platform
    text = "TARGET prompt: Output only code."

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        candidate = model_event(body)
        if body["task"] == "extract":
            definitions = body["response_schema"]["$defs"]
            prompt = empty_value(definitions["prompt"], definitions)
            prompt.update(availability="full_text", text=text, evidence_ids=["e1"])
            candidate["event"]["ai_signals"]["prompts"] = [prompt]
        return reply(candidate)
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    result = run(service, text)["result_json"]
    digest = hashlib.sha256(text.encode()).hexdigest()
    assert result["events"][0]["ai_signals"]["prompts"][0]["text_hash"] == "sha256:" + digest
    sample = {"sample": {"sha256": "a" * 64}, "features": {"prompt": {"embedded_prompts": [{"text_hash": "sha256:" + digest}]}}}
    # Simulate a persisted historic bare report digest.
    result["events"][0]["ai_signals"]["prompts"][0]["text_hash"] = digest
    before = copy.deepcopy(result)
    compared = service.legacy.compare(result, sample, event_id=result["events"][0]["event_id"])
    assert any(c["signal_group"] == "prompt" and c["relation"] == "supports" for c in compared["comparisons"])
    assert result == before


def test_final_quote_comes_from_original_block_not_model_paraphrase(platform, report_model, monkeypatch):
    service, _ = platform

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        candidate = model_event(body)
        if body["task"] == "extract":
            candidate["event"]["evidence"][0]["excerpt"] = 'TARGET utilizes model-v1.'
        return reply(candidate)
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    result = run(service, 'TARGET uses " model-v1 ".')["result_json"]
    quality = result["extraction"]["quality_review"]
    assert quality["evidence_strategy"] == "verified_source_block"
    assert result["events"][0]["evidence"][0]["excerpt"] == 'TARGET uses " model-v1 ".'


def test_source_block_prefix_repair_requires_known_id_and_copies_source():
    blocks = [{"block_id": "block:abc", "text": "TARGET does NOT use AI."}]
    event = {"evidence": [{"evidence_id": "e1", "block_id": "abc"}]}
    audit = {}
    report_llm._bind_source_evidence(event, blocks, audit)
    assert event["evidence"][0]["excerpt"] == "TARGET does NOT use AI."
    assert audit["block_id_repairs"][0]["method"] == "verified_prefix_restore"
    with pytest.raises(report_llm.ReportModelError):
        report_llm._bind_source_evidence({"evidence": [{"block_id": "missing"}]}, blocks, {})


def test_review_capacity_failure_never_bypasses_gate(platform, report_model, monkeypatch):
    service, repo = platform

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        if body["task"] == "review":
            return httpx.Response(200, json={"choices": [{"finish_reason": "length"}]})
        return reply(model_event(body))
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    with pytest.raises(report_llm.ReportModelError, match="不跳过复核"):
        run(service)
    assert not repo.list_reports()


@pytest.mark.parametrize("source,user_aliases,model_aliases,accepted,origin", [
    ("target is a sample", [], [], True, "target_name"),
    ("报告称TARGET为恶意软件。", [], [], True, "target_name"),
    ("TARGETED is a different sample", [], [], False, None),
    ("OTHER is a sample", [], ["OTHER"], False, None),
    ("OTHER is a sample", ["OTHER"], [], True, "user_alias"),
    ("OTHER is a sample", ["TARGET"], ["OTHER"], False, None),
])
def test_target_anchor_never_uses_model_generated_aliases(source, user_aliases, model_aliases, accepted, origin):
    event = {"identity": {"event_name": "TARGET", "aliases": model_aliases, "evidence_ids": ["e1"]},
             "evidence": [{"evidence_id": "e1", "block_id": "b1", "excerpt": source},
                          {"evidence_id": "e2", "block_id": "b2", "excerpt": "TARGET is elsewhere"}]}
    target = {"name": "TARGET", "aliases": user_aliases}
    if accepted:
        audit = report_llm._target_identity_anchor(event, target)
        assert audit["origin"] == origin and audit["block_ids"] == ["b1"]
    else:
        with pytest.raises(report_llm.ReportModelError, match="身份引用原文"):
            report_llm._target_identity_anchor(event, target)


def test_false_target_with_invented_alias_fails_closed(platform, report_model, monkeypatch):
    service, repo = platform

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        candidate = model_event(body)
        candidate["event"]["identity"]["aliases"] = ["PromptLock"]
        return reply(candidate)

    monkeypatch.setattr(report_llm.httpx, "post", respond)
    with pytest.raises(report_llm.ReportModelError, match="身份引用原文"):
        run(service, "PromptLock uses a local model.")
    assert not repo.list_reports()

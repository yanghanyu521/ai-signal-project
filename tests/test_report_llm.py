from __future__ import annotations

import copy
import json
from io import BytesIO

import httpx
import pytest
from fastapi.testclient import TestClient

from ai_signal_hub import report_llm
from ai_signal_hub.legacy import _add_src
from conftest import empty_value, model_event, with_review, empty_review


def extract(service, text="TARGET is a defensive testing fixture."):
    return service.analyze_report(BytesIO(text.encode()), "fixture.txt", None, target_name="TARGET")


def response(event, finish="stop"):
    return httpx.Response(200, json={"choices": [{"finish_reason": finish, "message": {"content": json.dumps(event)}}]})


def test_full_text_has_no_rule_gate_or_14000_character_cutoff(platform, report_model, monkeypatch):
    service, _ = platform
    _add_src(service.settings.legacy_report_project)
    import report_extractor.event_pipeline_v3 as old

    def forbidden(*args, **kwargs):
        pytest.fail("Legacy report rule pipeline must not be called")
    for name in ("extract_report_events_v3", "discover_events", "build_target_context", "extract_event", "_llm_context"):
        monkeypatch.setattr(old, name, forbidden)
    text = "TARGET is mentioned only here.\n" + "ordinary neutral prose " * 1600 + "\nFINAL PARAGRAPH no repeated family name"
    saved = extract(service, text)
    assert len(report_model) == 2
    assert [b["text"] for b in report_model[0]["blocks"]] == [line.strip() for line in text.splitlines()]
    assert sum(len(b["text"]) for b in report_model[0]["blocks"]) > 14000
    meta = saved["result_json"]["extraction"]
    assert meta["mode"] == "llm_only"
    assert meta["input_strategy"] == "full_text"
    assert meta["rule_extraction"] is False
    assert meta["coverage"]["omitted_blocks"] == 0
    assert {e["name"] for e in meta["extractors"]} == {"document-parser", "llm-only-report-extractor", "llm-semantic-reviewer"}
    assert meta["review_status"] == "needs_review"


@pytest.mark.parametrize("reason", ["context", "length"])
def test_capacity_fallback_covers_all_text(platform, report_model, monkeypatch, reason):
    service, _ = platform
    calls = []
    leaves = []

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        calls.append(body)
        if len(calls) == 1:
            if reason == "context":
                return httpx.Response(400, json={"error": {"code": "context_length_exceeded"}})
            return response({}, "length")
        leaves.extend(body["blocks"])
        return response(model_event(body))
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    saved = extract(service, "\n".join(f"TARGET paragraph {i} " + "neutral prose " * 40 for i in range(8)))
    assert len(calls) == 4
    for original in calls[0]["blocks"]:
        assert any(b["block_id"] == original["block_id"] and b["text"] == original["text"] for b in leaves)
    meta = saved["result_json"]["extraction"]
    assert meta["input_strategy"] == "full_coverage_chunks"
    assert meta["coverage"]["completed_chunks"] == 2
    assert meta["coverage"]["omitted_blocks"] == 0


def test_large_single_block_split_preserves_boundaries():
    text = "".join(chr(0x4E00 + i) for i in range(3000))
    blocks = [{"block_id": "big", "text": text}, {"block_id": "small", "text": "tail"}]
    left, right = report_llm._split(blocks)
    for char in text:
        assert any(char in b["text"] for b in left + right)
    assert max(sum(len(b["text"]) for b in part) for part in (left, right)) < len(text)
    assert any(b["text"] == "tail" for b in right)


@pytest.mark.parametrize("mutation", ["block", "reference", "no_evidence", "other_target", "missing_field", "hash", "prompt"])
def test_invalid_model_evidence_never_enters_knowledge_base(platform, report_model, monkeypatch, mutation):
    service, repository = platform

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        result = model_event(body)
        event = result["event"]
        definitions = body["response_schema"]["$defs"]
        if mutation == "block":
            event["evidence"][0]["block_id"] = "invented_block"
        elif mutation == "reference":
            event["identity"]["evidence_ids"] = ["missing"]
        elif mutation == "no_evidence":
            event["identity"]["evidence_ids"] = []
        elif mutation == "other_target":
            event["identity"]["event_name"] = "UNRELATED"
        elif mutation == "missing_field":
            event.pop("outcomes", None)
        elif mutation == "hash":
            artifact = empty_value(definitions["artifact"], definitions)
            artifact.update(sha256=["a" * 64], evidence_ids=["e1"])
            event["artifacts"] = [artifact]
        else:
            prompt = empty_value(definitions["prompt"], definitions)
            prompt.update(availability="full_text", text="invented prompt", evidence_ids=["e1"])
            event["ai_signals"]["prompts"] = [prompt]
        return response(with_review(body, result))
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    with pytest.raises(report_llm.ReportModelError):
        extract(service)
    assert not repository.list_reports()


@pytest.mark.parametrize("status,expected_calls", [(401, 1), (403, 1), (429, 3), (500, 3), (400, 1)])
def test_http_failures_are_explicit_and_no_secret_echo(platform, report_model, monkeypatch, status, expected_calls):
    service, repository = platform
    calls = []

    def respond(*args, **kwargs):
        calls.append(1)
        return httpx.Response(status, json={"error": {"message": "private report and test-not-a-real-secret"}})
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    with pytest.raises(report_llm.ReportModelError) as error:
        extract(service)
    assert "private report" not in str(error.value)
    assert "test-not-a-real-secret" not in str(error.value)
    assert len(calls) == expected_calls
    assert not repository.list_reports()


def test_model_null_is_not_saved_as_success(platform, report_model, monkeypatch):
    service, repository = platform
    def null_response(*args, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        value = {"event": None}
        if body["task"] == "review":
            value["review"] = empty_review()
        return response(value)
    monkeypatch.setattr(report_llm.httpx, "post", null_response)
    with pytest.raises(ValueError, match="未在报告中找到"):
        extract(service)
    assert not repository.list_reports()


def test_request_limit_fails_whole_report(platform, report_model, monkeypatch):
    service, repository = platform
    monkeypatch.setenv("REPORT_LLM_MAX_REQUESTS", "1")
    monkeypatch.setattr(report_llm.httpx, "post", lambda *args, **kwargs: response({}, "length"))
    with pytest.raises(report_llm.ReportModelError, match="请求次数"):
        extract(service, "TARGET " * 500)
    assert not repository.list_reports()


def test_late_chunk_failure_does_not_save_partial_report(platform, report_model, monkeypatch):
    service, repository = platform
    calls = []

    def respond(url, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            return response({}, "length")
        if len(calls) == 2:
            return response(model_event(json.loads(kwargs["json"]["messages"][1]["content"])))
        return response({"event": {}})
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    with pytest.raises(report_llm.ReportModelError):
        extract(service, "TARGET first " * 100 + "\n" + "TARGET last " * 100)
    assert len(calls) == 5
    assert not repository.list_reports()


def test_every_event_field_is_kept_in_direct_model_output(platform, report_model, monkeypatch):
    service, _ = platform

    def respond(url, **kwargs):
        body = json.loads(kwargs["json"]["messages"][1]["content"])
        result = model_event(body)
        if body.get("task") == "review":
            return response(result)
        event = result["event"]
        definitions = body["response_schema"]["$defs"]
        event["time"].update(description="as reported", evidence_ids=["e1"])
        event["status"].update(value="experimental", evidence_ids=["e1"])
        event["ai_involvement"].update(roles=["code_generation"], evidence_ids=["e1"])
        for key, definition in [("artifacts", "artifact"), ("targets", "target"),
                                ("key_behaviors", "behavior"), ("outcomes", "outcome"), ("limitations", "limitation")]:
            item = empty_value(definitions[definition], definitions)
            item["evidence_ids"] = ["e1"]
            event[key] = [item]
        actor = empty_value(definitions["actor"], definitions)
        actor.update(name="researcher", evidence_ids=["e1"])
        event["attribution"]["actors"] = [actor]
        for key, definition in [("toolchain", "toolchain"), ("prompts", "prompt"), ("code_style", "codeStyle")]:
            item = empty_value(definitions[definition], definitions)
            item["evidence_ids"] = ["e1"]
            if key == "prompts":
                item["availability"] = "described_only"
            event["ai_signals"][key] = [item]
        return response(with_review(body, result))
    monkeypatch.setattr(report_llm.httpx, "post", respond)
    result = extract(service)["result_json"]["events"][0]
    assert all(result[key] for key in ("time", "status", "artifacts", "attribution", "targets", "ai_involvement", "key_behaviors", "outcomes", "limitations"))
    assert all(result["ai_signals"][key] for key in ("toolchain", "prompts", "code_style"))


def test_conflicting_scalars_are_not_silently_overwritten():
    a = {"status": {"value": "experimental", "evidence_ids": ["e1"]},
         "evidence": [{"evidence_id": "e1"}], "limitations": []}
    b = copy.deepcopy(a)
    b["status"]["value"] = "confirmed_intrusion"
    event, conflicts = report_llm._merge_events([a, b])
    assert event["status"]["value"] == "unknown"
    assert len(conflicts) == 1
    assert event["limitations"][0]["type"] == "cross_chunk_conflict"


def test_api_defaults_and_errors(platform, report_model, monkeypatch):
    from ai_signal_hub import main
    service, repository = platform
    monkeypatch.setattr(main, "service", service)
    client = TestClient(main.app)  # No production lifespan/database writes.
    files = {"file": ("report.txt", b"TARGET defensive fixture")}
    result = client.post("/api/v1/reports/analyze", files=files, data={"target_name": "TARGET"})
    assert result.status_code == 200
    assert result.json()["result_json"]["extraction"]["mode"] == "llm_only"
    assert len(report_model) == 2
    rejected = client.post("/api/v1/reports/analyze", files=files, data={"target_name": "TARGET", "use_llm": "false"})
    assert rejected.status_code == 400
    assert len(report_model) == 2
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("cc-api", raising=False)
    missing = client.post("/api/v1/reports/analyze", files=files, data={"target_name": "TARGET"})
    assert missing.status_code == 503
    assert len(repository.list_reports()) == 1
    failed_case = client.post("/api/v1/analysis-cases", files={"report_file": ("r.txt", b"TARGET")}, data={"target_name": "TARGET"})
    assert failed_case.status_code == 503
    assert repository.list_cases()[0]["status"] == "report_analysis_failed"
    assert not repository.get_case(repository.list_cases()[0]["id"])["reports"]


@pytest.mark.parametrize("base,expected", [("https://example.invalid", "https://example.invalid/chat/completions"),
    ("https://example.invalid/v1/", "https://example.invalid/v1/chat/completions"),
    ("https://example.invalid/v1/chat/completions", "https://example.invalid/v1/chat/completions")])
def test_endpoint_and_legacy_key_compatibility(monkeypatch, base, expected):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("cc-api", "test-legacy-key")
    monkeypatch.setenv("DEEPSEEK_BASE_URL", base)
    client = report_llm.ModelClient.from_env()
    assert client.endpoint == expected
    assert "test-legacy-key" not in repr(client)

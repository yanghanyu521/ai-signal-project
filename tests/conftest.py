from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest

from ai_signal_hub.config import Settings
from ai_signal_hub.database import Database
from ai_signal_hub.legacy import LegacyAdapters
from ai_signal_hub.repository import Repository
from ai_signal_hub.services import HubService


@pytest.fixture
def platform(tmp_path):
    project = Path(__file__).resolve().parents[1]
    settings = Settings(project_root=project, workspace_root=project.parent, data_dir=tmp_path / "data",
                        legacy_sample_project=project / "components" / "ai_signal_demo",
                        legacy_report_project=project / "components" / "report_extractor",
                        seed_data_dir=project / "components" / "seed_data",
                        max_upload_bytes=10 * 1024 * 1024)
    settings.ensure_directories()
    database = Database(settings.database_path)
    database.initialize()
    repository = Repository(database)
    return HubService(settings, repository, LegacyAdapters(settings)), repository


def empty_value(schema: dict, definitions: dict):
    """Test-only schema fixture builder, never an extraction implementation."""
    if "$ref" in schema:
        return empty_value(definitions[schema["$ref"].split("/")[-1]], definitions)
    if "enum" in schema:
        return "unknown" if "unknown" in schema["enum"] else schema["enum"][0]
    kind = schema.get("type")
    if isinstance(kind, list):
        return None if "null" in kind else ""
    if kind == "object":
        return {key: empty_value(value, definitions) for key, value in schema["properties"].items()}
    return {"array": [], "string": "", "boolean": False, "integer": 0}.get(kind)


def model_event(body: dict) -> dict:
    if body.get("task") == "review":
        if not body["candidate"]:
            return {"event": None, "review": empty_review()}
        if "invalid_candidates" in body["candidate"]:
            return {"event": body["candidate"]["invalid_candidates"][0]["event"],
                    "review": {**empty_review(), "verdict": "unresolved"}}
        return with_review(body, {"event": copy.deepcopy(body["candidate"])})
    definitions = body["response_schema"]["$defs"]
    event = empty_value(definitions["event"], definitions)
    block = next((b for b in body["blocks"] if body["target"]["name"].lower() in b["text"].lower()), body["blocks"][0])
    event["identity"].update(event_name=body["target"]["name"], evidence_ids=["e1"])
    event["evidence"] = [{"evidence_id": "e1", "block_id": block["block_id"], "excerpt": block["text"]}]
    model_block = next((b for b in body["blocks"] if "gemini-1.5-flash-latest" in b["text"]), None)
    if model_block:
        event["evidence"].append({"evidence_id": "e2", "block_id": model_block["block_id"], "excerpt": model_block["text"]})
        tool = empty_value(definitions["toolchain"], definitions)
        tool.update(model="gemini-1.5-flash-latest", raw_value="gemini-1.5-flash-latest",
                    purpose="self-modification", evidence_ids=["e2"])
        event["ai_signals"]["toolchain"] = [tool]
    return {"event": event}


def with_review(body: dict, candidate: dict) -> dict:
    """Mechanical simulated approval for transport tests; not a semantic judge."""
    from ai_signal_hub.report_quality import fact_objects, high_risk_paths
    if body.get("task") != "review" or candidate.get("event") is None:
        return candidate
    event = candidate["event"]
    if "excerpt" not in body["response_schema"]["$defs"]["evidence"]["properties"]:
        for evidence in event["evidence"]:
            evidence.pop("excerpt", None)
    objects = fact_objects(event)
    assertions = []
    for path in high_risk_paths(event):
        owner = next(obj for p, obj in sorted(objects.items(), key=lambda x: len(x[0]), reverse=True) if path.startswith(p + "/"))
        assertions.append({"path": path, "assertion_status": "explicit", "evidence_ids": owner["evidence_ids"], "explanation": "test fixture"})
    candidate["review"] = {"verdict": "pass", "issues": [],
        "subject_bindings": [{"path": path, "subject": body["target"]["name"], "scope": "target"} for path in objects],
        "field_assertions": assertions,
        "coverage_checks": {name: {"has_evidence": bool(items),
            "evidence_ids": sorted({ref for item in items for ref in item["evidence_ids"]}), "explanation": "fixture"}
            for name, items in {**event["ai_signals"], "artifacts": event["artifacts"], "negative_capabilities": event.get("limitations", [])}.items()}}
    return candidate


def empty_review():
    return {"verdict": "pass", "issues": [], "subject_bindings": [], "field_assertions": [],
            "coverage_checks": {name: {"has_evidence": False, "evidence_ids": [], "explanation": "fixture"}
                for name in ("toolchain", "prompts", "code_style", "artifacts", "negative_capabilities")}}


@pytest.fixture
def report_model(monkeypatch):
    """No real keys or external requests; exercise the actual parser and adapter."""
    from ai_signal_hub import report_llm

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-not-a-real-secret")
    monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://model.invalid/v1")
    monkeypatch.setenv("REPORT_LLM_MAX_REQUESTS", "32")
    monkeypatch.setattr(report_llm.time, "sleep", lambda _: None)
    calls = []

    def respond(url, *, json: dict, **kwargs):
        body = __import__("json").loads(json["messages"][1]["content"])
        calls.append(copy.deepcopy(body))
        candidate = model_event(body)
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": __import__("json").dumps(candidate)}}],
                                         "usage": {"prompt_tokens": 100, "completion_tokens": 50}})

    monkeypatch.setattr(report_llm.httpx, "post", respond)
    return calls

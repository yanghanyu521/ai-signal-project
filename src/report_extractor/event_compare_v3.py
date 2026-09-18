from __future__ import annotations

import re

from .utils import normalize_space, stable_id


def _canonical(value: str | None) -> str:
    text = normalize_space(value).lower().removesuffix("-latest")
    return re.sub(r"[^a-z0-9]", "", text)


def _model_match(sample_value: str, report_value: str) -> tuple[bool, str]:
    sample_key = _canonical(sample_value)
    report_key = _canonical(report_value)
    if sample_key == report_key:
        return True, "exact_model"
    # 报告有时只给出模型家族（如 Gemini），样本则能恢复到具体版本。
    # 只对明确的家族名称做前缀兼容，避免把任意子串误判为同一模型。
    generic_families = {"gemini", "gpt", "gptoss", "claude", "qwen"}
    if report_key in generic_families and sample_key.startswith(report_key):
        return True, "family_to_specific"
    if sample_key in generic_families and report_key.startswith(sample_key):
        return True, "family_to_specific"
    return False, "none"


def _sample_toolchain(sample: dict) -> dict[str, list[dict]]:
    result = {"models": [], "providers": [], "services": []}
    for index, evidence in enumerate(sample.get("features", {}).get("toolchain", {}).get("evidence", [])):
        normalized = evidence.get("normalized") or {}
        path = f"features.toolchain.evidence[{index}]"
        model = normalized.get("model") or normalized.get("model_identifier_raw") or (
            evidence.get("value") if evidence.get("type") in {"model_identifier", "model_argument"} else None
        )
        # SDK/service vendors are intentionally not model providers.
        provider = normalized.get("model_vendor") or (
            normalized.get("vendor") if evidence.get("type") == "model_identifier" else None
        )
        if model:
            result["models"].append({"value": str(model), "path": path})
        if provider:
            result["providers"].append({"value": str(provider), "path": path})
        if evidence.get("type") in {"api_endpoint", "endpoint", "service_endpoint", "sdk", "sdk_marker", "sdk_call", "api_or_sdk", "agent_marker"}:
            result["services"].append({"value": str(evidence.get("value") or ""), "path": path})
    attribution = sample.get("classification", {}).get("model_attribution", {})
    if attribution.get("model"):
        result["models"].append({"value": str(attribution["model"]), "path": "classification.model_attribution.model"})
    if attribution.get("vendor"):
        result["providers"].append({"value": str(attribution["vendor"]), "path": "classification.model_attribution.vendor"})
    for key in result:
        unique = {(item["value"], item["path"]): item for item in result[key]}
        result[key] = list(unique.values())
    return result


def _select_event(report: dict, *, event_id: str | None, sample_sha: str, sample_family: str | None) -> tuple[dict, dict]:
    events = report.get("events") or []
    if event_id:
        event = next((item for item in events if item.get("event_id") == event_id), None)
        if not event:
            raise ValueError(f"报告中不存在 event_id: {event_id}")
        for artifact in event.get("artifacts", []):
            if sample_sha in {value.lower() for value in artifact.get("sha256", [])}:
                return event, {"method": "sha256_exact", "confidence": 1.0, "artifact_id": artifact["artifact_id"], "propagation_allowed": True}
        return event, {"method": "manual_event_id", "confidence": 0.8, "artifact_id": None, "propagation_allowed": False}
    for event in events:
        for artifact in event.get("artifacts", []):
            if sample_sha in {value.lower() for value in artifact.get("sha256", [])}:
                return event, {"method": "sha256_exact", "confidence": 1.0, "artifact_id": artifact["artifact_id"], "propagation_allowed": True}
    if sample_family:
        family = normalize_space(sample_family).lower()
        for event in events:
            for artifact in event.get("artifacts", []):
                names = [artifact.get("family"), *artifact.get("aliases", [])]
                if family in {normalize_space(name).lower() for name in names if name}:
                    return event, {"method": "family_only", "confidence": 0.55, "artifact_id": artifact["artifact_id"], "propagation_allowed": False}
    raise ValueError("无法按SHA-256或家族关联报告事件；请显式提供event_id")


def _comparison(sample_sha: str, event_id: str, group: str, relation: str, sample_path: str | None, sample_value: object, report_path: str, report_value: object, evidence_ids: list[str], link: dict, notes: str) -> dict:
    return {
        "comparison_id": stable_id("comparison", sample_sha, event_id, group, report_path, relation),
        "signal_group": group, "relation": relation,
        "sample": {"path": sample_path, "value": sample_value},
        "report": {"path": report_path, "value": report_value, "evidence_ids": evidence_ids},
        "link_method": link["method"],
        "review_status": "not_reviewed" if link["propagation_allowed"] and relation == "supports" else "needs_review",
        "notes": notes,
    }


def compare_event_to_sample(report: dict, sample: dict, *, event_id: str | None = None, sample_family: str | None = None) -> dict:
    if report.get("schema_version") != "0.3":
        raise ValueError("比较器只接受v0.3 report_events.json")
    sample_sha = str(sample.get("sample", {}).get("sha256") or "").lower()
    if not re.fullmatch(r"[a-f0-9]{64}", sample_sha):
        raise ValueError("样本结果缺少有效SHA-256")
    event, link = _select_event(report, event_id=event_id, sample_sha=sample_sha, sample_family=sample_family)
    event_id_value = event["event_id"]
    tools = _sample_toolchain(sample)
    comparisons = []
    compared_report_models: set[str] = set()
    compared_report_providers: set[str] = set()
    for index, report_tool in enumerate(event["ai_signals"]["toolchain"]):
        model_key = _canonical(report_tool.get("model"))
        if report_tool.get("model") and model_key not in compared_report_models:
            compared_report_models.add(model_key)
            matches = [(item, _model_match(item["value"], report_tool["model"])[1]) for item in tools["models"] if _model_match(item["value"], report_tool["model"])[0]]
            matched, match_kind = matches[0] if matches else (None, "none")
            if matched:
                notes = "样本与报告的规范化模型标识一致" if match_kind == "exact_model" else "报告给出模型家族，样本给出兼容的具体模型版本"
                relation, path, value = "supports", matched["path"], matched["value"]
            elif tools["models"] and link["method"] == "sha256_exact":
                relation, path, value, notes = "contradicts", tools["models"][0]["path"], tools["models"][0]["value"], "精确哈希关联下具体模型不一致，需人工复核"
            else:
                relation, path, value, notes = "inconclusive", None, None, "报告给出模型，但样本没有可比的直接模型信号"
            comparisons.append(_comparison(sample_sha, event_id_value, "toolchain", relation, path, value, f"events.{event_id_value}.ai_signals.toolchain[{index}].model", report_tool["model"], report_tool["evidence_ids"], link, notes))
        provider_key = _canonical(report_tool.get("provider"))
        if report_tool.get("provider") and provider_key not in compared_report_providers:
            compared_report_providers.add(provider_key)
            matched = next((item for item in tools["providers"] if _canonical(item["value"]) == _canonical(report_tool["provider"]) or _canonical(item["value"]) in _canonical(report_tool["provider"]) or _canonical(report_tool["provider"]) in _canonical(item["value"])), None)
            comparisons.append(_comparison(sample_sha, event_id_value, "toolchain", "supports" if matched else "inconclusive", matched["path"] if matched else None, matched["value"] if matched else None, f"events.{event_id_value}.ai_signals.toolchain[{index}].provider", report_tool["provider"], report_tool["evidence_ids"], link, "样本与报告厂商一致" if matched else "样本没有可直接比较的厂商信号"))
        if report_tool.get("purpose"):
            comparisons.append(_comparison(sample_sha, event_id_value, "toolchain", "complements", "classification.llm_involvement", sample.get("classification", {}).get("llm_involvement"), f"events.{event_id_value}.ai_signals.toolchain[{index}].purpose", report_tool["purpose"], report_tool["evidence_ids"], link, "报告补充AI工具链在事件中的实际用途"))
    sample_prompt = sample.get("features", {}).get("prompt", {})
    embedded = [item for item in sample_prompt.get("embedded_prompts") or []
                if item.get("comparison_eligible") is not False]
    sample_structural = sample_prompt.get("structural_features") or {}
    for index, report_prompt in enumerate(event["ai_signals"]["prompts"]):
        exact = next((item for item in embedded
                      if (item.get("completeness") or "legacy_complete_text") not in {"window_excerpt", "excerpt_only", "description"}
                      and report_prompt.get("text_hash") and item.get("text_hash") == report_prompt["text_hash"]), None)
        if exact:
            relation, path, value, notes = "supports", "features.prompt.embedded_prompts", report_prompt["text_hash"], "报告和样本Prompt精确哈希一致"
        elif report_prompt["availability"] == "described_only":
            relation, path, value, notes = "complements", "features.prompt.structural_features", sample_structural, "报告只描述Prompt用途，作为静态Prompt结构的补充"
        else:
            expected = {key for key, value in report_prompt["structural_features"].items() if value}
            observed = {key for key, value in sample_structural.items() if value}
            relation = "supports" if expected and expected <= observed else "inconclusive"
            path, value, notes = "features.prompt.structural_features", sample_structural, "Prompt结构标记一致，仍需人工核对文本范围" if relation == "supports" else "Prompt片段或结构不足以确认一致"
        comparisons.append(_comparison(sample_sha, event_id_value, "prompt", relation, path, value, f"events.{event_id_value}.ai_signals.prompts[{index}]", {"availability": report_prompt["availability"], "purpose": report_prompt["purpose"], "text_hash": report_prompt["text_hash"]}, report_prompt["evidence_ids"], link, notes))
    for index, style in enumerate(event["ai_signals"]["code_style"]):
        comparisons.append(_comparison(sample_sha, event_id_value, "code_style", "complements", "features.code_style", sample.get("features", {}).get("code_style"), f"events.{event_id_value}.ai_signals.code_style[{index}]", style["observed_feature"], style["evidence_ids"], link, "报告描述代码生成机制或作者观察；不把样本侧描述性代码统计解释为AI生成概率"))
    context_facts = [
        ("event_context", "time", event["time"], event["time"]["evidence_ids"]),
        ("event_context", "status", event["status"], event["status"]["evidence_ids"]),
        ("event_context", "attribution", event["attribution"], [e for actor in event["attribution"]["actors"] for e in actor["evidence_ids"]]),
        ("event_context", "targets", event["targets"], [e for target in event["targets"] for e in target["evidence_ids"]]),
    ]
    for group, name, value, evidence_ids in context_facts:
        if value and evidence_ids:
            comparisons.append(_comparison(sample_sha, event_id_value, group, "complements", None, None, f"events.{event_id_value}.{name}", value, evidence_ids, link, "报告补充样本静态分析通常无法获得的事件信息"))
    return {
        "schema_version": "0.3", "sample_sha256": sample_sha,
        "report_id": report["report"]["report_id"], "event_id": event_id_value,
        "link": link, "comparisons": comparisons,
        "summary": {relation: sum(item["relation"] == relation for item in comparisons) for relation in ["supports", "contradicts", "complements", "inconclusive"]},
    }

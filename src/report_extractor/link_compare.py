from __future__ import annotations

import re

from .utils import normalize_space, stable_id


def _canonical_model(value: str | None) -> str:
    value = normalize_space(value).lower().replace("_", "-").replace(" ", "-")
    value = re.sub(r"-+", "-", value)
    return value.removesuffix("-latest")


def _sample_models(sample_result: dict) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for index, evidence in enumerate(sample_result.get("features", {}).get("toolchain", {}).get("evidence", [])):
        if evidence.get("type") != "model_identifier":
            continue
        normalized = evidence.get("normalized") or {}
        value = normalized.get("model") or normalized.get("family") or evidence.get("value")
        if value:
            values.append((f"features.toolchain.evidence[{index}]", str(value)))
    attribution = sample_result.get("classification", {}).get("model_attribution", {})
    value = attribution.get("model") or attribution.get("family")
    if value and str(value).lower() != "unknown":
        values.append(("classification.model_attribution", str(value)))
    return list(dict.fromkeys(values))


def _sample_providers(sample_result: dict) -> list[tuple[str, str]]:
    values = []
    for index, evidence in enumerate(sample_result.get("features", {}).get("toolchain", {}).get("evidence", [])):
        normalized = evidence.get("normalized") or {}
        provider = normalized.get("provider") or normalized.get("vendor")
        if provider:
            values.append((f"features.toolchain.evidence[{index}]", str(provider)))
    return list(dict.fromkeys(values))


def link_report_to_sample(report_result: dict, sample_result: dict, sample_family: str | None = None) -> dict:
    sha256 = str(sample_result.get("sample", {}).get("sha256") or "").lower()
    if not re.fullmatch(r"[a-f0-9]{64}", sha256):
        raise ValueError("样本结果缺少有效 SHA-256")
    entities = {entity["entity_id"]: entity for entity in report_result.get("entities", [])}
    exact_entities = [
        entity for entity in entities.values()
        if entity.get("entity_type") == "indicator" and entity.get("normalized_name", "").lower() == sha256
    ]
    family_entities = []
    if sample_family:
        family_norm = normalize_space(sample_family).lower()
        family_entities = [
            entity for entity in entities.values()
            if entity.get("entity_type") == "malware_family"
            and family_norm in {normalize_space(entity.get("name")).lower(), normalize_space(entity.get("normalized_name")).lower()}
        ]
    if exact_entities:
        method, confidence, propagation, target_entities = "sha256_exact", 1.0, True, exact_entities
    elif family_entities:
        method, confidence, propagation, target_entities = "family_only", 0.55, False, family_entities
    else:
        method, confidence, propagation, target_entities = "manual", 0.0, False, []
    link = {
        "sample_ref": {"sha256": sha256, "family": sample_family, "file_name": sample_result.get("sample", {}).get("file_name")},
        "report_entity_id": target_entities[0]["entity_id"] if target_entities else None,
        "link_method": method,
        "link_confidence": confidence,
        "propagation_allowed": propagation,
        "evidence_claim_ids": [],
    }
    comparisons = compare_signals(report_result, sample_result, link)
    return {"sample_links": [link], "cross_validation": comparisons}


def compare_signals(report_result: dict, sample_result: dict, link: dict) -> list[dict]:
    entities = {entity["entity_id"]: entity for entity in report_result.get("entities", [])}
    comparisons: list[dict] = []
    sample_sha = sample_result["sample"]["sha256"]
    sample_models = _sample_models(sample_result)
    sample_providers = _sample_providers(sample_result)
    relevant_subjects: set[str] = set()
    linked_entity_id = link.get("report_entity_id")
    if link.get("link_method") == "family_only" and linked_entity_id:
        relevant_subjects.add(linked_entity_id)
    elif link.get("link_method") == "sha256_exact" and linked_entity_id:
        for candidate in report_result.get("claims", []):
            if candidate.get("predicate") == "has_indicator" and candidate.get("object", {}).get("entity_id") == linked_entity_id:
                relevant_subjects.add(candidate.get("subject_id"))
    for claim in report_result.get("claims", []):
        if not relevant_subjects or claim.get("subject_id") not in relevant_subjects:
            continue
        obj_id = claim.get("object", {}).get("entity_id")
        obj_entity = entities.get(obj_id) if obj_id else None
        if claim.get("predicate") == "uses_model" and obj_entity:
            report_value = obj_entity.get("normalized_name") or obj_entity.get("name")
            report_model = _canonical_model(str(report_value))
            matched = [(path, value) for path, value in sample_models if _canonical_model(value) == report_model]
            if matched:
                relation = "supports"
                sample_path = matched[0][0]
                notes = f"样本与报告模型一致：{matched[0][1]} / {obj_entity.get('name')}"
            elif sample_models and link["link_method"] == "sha256_exact":
                relation = "contradicts"
                sample_path = sample_models[0][0]
                notes = f"精确哈希关联下模型不一致：样本={sample_models[0][1]}，报告={obj_entity.get('name')}"
            else:
                relation = "inconclusive"
                sample_path = sample_models[0][0] if sample_models else "classification.model_attribution"
                notes = "报告有模型声明，但样本无可比的同值信号或仅为弱关联"
        elif claim.get("predicate") == "uses_provider" and obj_entity:
            report_provider = normalize_space(obj_entity.get("normalized_name") or obj_entity.get("name")).lower()
            matched = [(path, value) for path, value in sample_providers if report_provider in value.lower() or value.lower() in report_provider]
            relation = "supports" if matched else "inconclusive"
            sample_path = matched[0][0] if matched else "features.toolchain.evidence"
            notes = "样本与报告服务商/API一致" if matched else "未找到可直接比较的服务商/API信号"
        elif claim.get("predicate") in {"has_ai_role", "has_autonomy_level", "has_ai_work_share", "has_operational_status"}:
            relation = "complements"
            sample_path = "classification.llm_involvement"
            notes = "报告补充静态样本通常无法独立确定的运行目的、自治或运营状态"
        else:
            continue
        comparisons.append(
            {
                "comparison_id": stable_id("comparison", sample_sha, claim["claim_id"], relation, sample_path),
                "sample_sha256": sample_sha,
                "sample_signal_path": sample_path,
                "report_claim_id": claim["claim_id"],
                "relation": relation,
                "decision": "auto" if link["propagation_allowed"] and relation != "contradicts" else "needs_review",
                "notes": notes,
            }
        )
    return comparisons

from __future__ import annotations

from typing import Any


def _score(item: dict[str, Any]) -> float:
    value = item.get("confidence")
    return float(value) if isinstance(value, (int, float)) else 0.0


def _is_attribution_eligible(item: dict[str, Any]) -> bool:
    explicit = item.get("attribution_eligible")
    if isinstance(explicit, bool):
        return explicit and item.get("role", "application") == "application"
    # Compatibility for v0.2 snapshots created before the explicit gate.
    # Only deterministic relation evidence is promoted; location-only LLM or
    # marker evidence remains ineligible.
    return (
        item.get("verification_status") == "relation_verified"
        and item.get("role", "application") == "application"
        and item.get("discovery_method") != "llm"
    )


def _model_candidate(item: dict[str, Any]) -> dict[str, Any]:
    normalized = item.get("normalized") or {}
    raw = item.get("raw_value") or item.get("value")
    model = normalized.get("model") or normalized.get("model_identifier_raw") or raw
    # Only model-identifier evidence can attribute a model vendor/family. SDK
    # and service providers intentionally never flow into these fields.
    vendor = normalized.get("model_vendor")
    family = normalized.get("model_family")
    if item.get("type") == "model_identifier":
        vendor = vendor or normalized.get("vendor")
        family = family or normalized.get("family")
    return {
        "vendor": vendor,
        "family": family or "unknown",
        "model": model,
        "raw_value": raw,
        "source_type": item.get("type"),
        "verification_status": item.get("verification_status", "unverified"),
        "verification": item.get("verification") or {},
        "role": item.get("role", "unknown"),
        "attribution_eligible": bool(item.get("attribution_eligible")),
    }


def classify(toolchain: dict[str, Any], prompt: dict[str, Any]) -> dict[str, Any]:
    """Derive a conservative static conclusion from the final evidence set.

    The legacy numeric confidence is retained for storage compatibility but is
    explicitly a rule strength, not a calibrated probability. No static result
    claims that a call was observed at runtime.
    """
    evidence = list(toolchain.get("evidence") or [])
    eligible = [
        item for item in evidence
        if _is_attribution_eligible(item)
    ]
    model_evidence = [
        item for item in eligible if item.get("type") in {"model_identifier", "model_argument"}
    ]
    relation_evidence = [
        item for item in eligible
        if (item.get("verification") or {}).get("relation") == "verified"
        or item.get("verification_status") == "relation_verified"
    ]
    prompt_evidence = list(prompt.get("embedded_prompts") or [])
    eligible_prompts = [
        item for item in prompt_evidence
        if _is_attribution_eligible(item)
        or (
            item.get("attribution_eligible") is None
            and item.get("call_binding") == "relation_verified"
            and item.get("role", "application") == "application"
        )
    ]
    has_prompt_candidate = bool(prompt_evidence or prompt.get("special_tokens"))
    analyzer_directives = [item for item in prompt_evidence if item.get("role") == "analyzer_directive"]

    if relation_evidence:
        grade = "static_relation_supported"
    elif evidence:
        grade = "marker_only"
    elif eligible_prompts:
        grade = "static_relation_supported"
    elif has_prompt_candidate:
        grade = "static_interaction_candidate"
    else:
        grade = "insufficient"

    # Keep the legacy label vocabulary readable by existing DB/UI consumers,
    # while evidence_grade carries the precise new semantics.
    label = "probable" if relation_evidence or eligible_prompts else "unknown"
    strongest = max(eligible, key=_score) if eligible else None
    heuristic_strength = _score(strongest) if strongest else (0.75 if eligible_prompts else 0.0)

    candidates = [_model_candidate(item) for item in model_evidence]
    candidates.sort(
        key=lambda item: (
            item["verification_status"] == "relation_verified",
            item["vendor"] is not None,
        ),
        reverse=True,
    )
    attribution = candidates[0] if candidates else {
        "vendor": None,
        "family": "unknown",
        "model": None,
        "raw_value": None,
        "source_type": None,
        "verification_status": "unverified",
        "verification": {},
        "role": "unknown",
        "attribution_eligible": False,
    }
    method = {
        "model_argument": "static_model_argument",
        "model_identifier": "model_identifier_mapping",
    }.get(attribution.get("source_type"), "unknown")
    model_attribution = {
        "vendor": attribution["vendor"],
        "family": attribution["family"],
        "model": attribution["model"],
        "model_identifier_raw": attribution["raw_value"],
        "decision_method": method,
        "attribution_status": (
            "rule_mapped" if attribution.get("vendor") else
            "raw_identifier_only" if attribution.get("model") else "unknown"
        ),
        "confidence": heuristic_strength if attribution.get("model") else 0.0,
        "confidence_semantics": "rule_strength_not_calibrated_probability",
        "calibrated_probability": False,
    }
    return {
        "llm_involvement": {
            "label": label,
            "evidence_grade": grade,
            "runtime_observed": False,
            "confidence": heuristic_strength,
            "confidence_semantics": "heuristic_strength_not_calibrated_probability",
            "calibrated_probability": False,
        },
        "model_attribution": model_attribution,
        "model_candidates": candidates,
        "evidence_summary": (relation_evidence or eligible_prompts or evidence or prompt_evidence)[:10],
        "analysis_targeting": {
            "detected": bool(analyzer_directives),
            "evidence": analyzer_directives[:10],
            "proves_model_use": False,
        },
    }

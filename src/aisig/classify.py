from __future__ import annotations

from typing import Any


def _score(item: dict[str, Any]) -> float:
    value = item.get("confidence")
    return float(value) if isinstance(value, (int, float)) else 0.0


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
        "role": item.get("role", "unknown"),
    }


def classify(toolchain: dict[str, Any], prompt: dict[str, Any]) -> dict[str, Any]:
    """Derive a conservative static conclusion from the final evidence set.

    The legacy numeric confidence is retained for storage compatibility but is
    explicitly a rule strength, not a calibrated probability. No static result
    claims that a call was observed at runtime.
    """
    evidence = list(toolchain.get("evidence") or [])
    model_evidence = [
        item for item in evidence if item.get("type") in {"model_identifier", "model_argument"}
    ]
    relation_evidence = [
        item for item in evidence if item.get("verification_status") == "relation_verified"
    ]
    prompt_evidence = list(prompt.get("embedded_prompts") or [])
    has_prompt = bool(prompt_evidence or prompt.get("special_tokens"))

    if relation_evidence:
        grade = "static_relation_supported"
    elif evidence:
        grade = "marker_only"
    elif has_prompt:
        grade = "static_interaction_candidate"
    else:
        grade = "insufficient"

    # Keep the legacy label vocabulary readable by existing DB/UI consumers,
    # while evidence_grade carries the precise new semantics.
    label = "unknown" if grade == "insufficient" else "probable"
    strongest = max(evidence, key=_score) if evidence else None
    heuristic_strength = _score(strongest) if strongest else (0.75 if has_prompt else 0.0)

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
        "role": "unknown",
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
        "evidence_summary": (relation_evidence or evidence or prompt_evidence)[:10],
    }

from __future__ import annotations

from typing import Any


def classify(toolchain: dict[str, Any], prompt: dict[str, Any]) -> dict[str, Any]:
    evidence = toolchain.get("evidence", [])
    models = [item for item in evidence if item["type"] == "model_identifier"]
    endpoints = [item for item in evidence if item["type"] == "endpoint"]
    sdks = [item for item in evidence if item["type"] == "sdk_marker"]
    ai_clis = [item for item in evidence if item["type"] == "ai_cli"]
    if models:
        best = max(models, key=lambda item: item["confidence"])
        normalized = best["normalized"]
        # Some rules intentionally identify a model family (for example GPT)
        # without duplicating every model version in YAML. The exact matched
        # identifier is still direct static evidence and should be preserved.
        model_name = normalized.get("model") or best["value"]
        return {
            "llm_involvement": {"label": "confirmed", "confidence": best["confidence"]},
            "model_attribution": {"vendor": normalized.get("vendor"), "family": normalized.get("family", "unknown"), "model": model_name, "decision_method": "direct_model_identifier", "confidence": best["confidence"]},
            "evidence_summary": [best],
        }
    if endpoints or sdks or ai_clis:
        best = max(endpoints + sdks + ai_clis, key=lambda item: item["confidence"])
        normalized = best["normalized"]
        method = "ai_cli_mapping" if best["type"] == "ai_cli" else "api_or_sdk_mapping"
        return {
            "llm_involvement": {"label": "confirmed", "confidence": best["confidence"]},
            "model_attribution": {"vendor": normalized.get("provider"), "family": normalized.get("family", "unknown"), "model": None, "decision_method": method, "confidence": best["confidence"]},
            "evidence_summary": [best],
        }
    # Prompt-pattern flags are meaningful only if a complete candidate passed
    # the natural-language gate. This avoids treating dependency strings inside
    # archives as attacker Prompt evidence.
    strong_prompt = bool(prompt.get("embedded_prompts")) or bool(prompt.get("special_tokens"))
    if strong_prompt:
        return {
            "llm_involvement": {"label": "probable", "confidence": 0.75},
            "model_attribution": {"vendor": None, "family": "unknown", "model": None, "decision_method": "unknown", "confidence": 0.0},
            "evidence_summary": prompt.get("embedded_prompts", [])[:3],
        }
    return {
        "llm_involvement": {"label": "unknown", "confidence": 0.0},
        "model_attribution": {"vendor": None, "family": "unknown", "model": None, "decision_method": "unknown", "confidence": 0.0},
        "evidence_summary": [],
    }

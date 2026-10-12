"""Typed AI-signal boundary shared by discovery and comparison."""
from __future__ import annotations

import re
from urllib.parse import urlsplit
from typing import Any


AI_SDKS = {"openai", "anthropic", "ollama", "google.generativeai", "google.genai",
           "google-generativeai", "langchain", "llama_index", "llama-index",
           "transformers", "huggingface_hub", "litellm", "cohere", "mistralai"}
AI_CLIS = {"claude", "codex", "gemini", "qwen", "ollama", "aider"}
AI_HOSTS = {"api.openai.com", "api.anthropic.com", "api.deepseek.com",
            "generativelanguage.googleapis.com", "api.cohere.ai", "api.mistral.ai",
            "openrouter.ai", "huggingface.co", "api-inference.huggingface.co"}
MODEL_PATTERN = re.compile(r"(?i)\b(?:gpt[-_\w.]*|claude[-_\w.]*|gemini[-_\w.]*|qwen[-_\w.]*|deepseek[-_\w.]*|llama[-_\w.]*)\b")
AI_CONTEXT = re.compile(
    r"(?i)\b(?:messages|chat\.completions|generate_content|completion|deployment|llm|"
    r"prompt|system_prompt|assistant|model_id|model_name|language.model|inference)\b"
)


def semantic_context_status(raw: str, context: str, *, relation_verified: bool = False) -> str:
    """Evidence tier, not an LLM self-assigned label.

    Unknown private selectors remain candidates when static context is weak.
    A verified call relation is stronger than a nearby keyword but neither is
    runtime proof. Generic `model=` assignments alone are insufficient.
    """
    if relation_verified:
        return "static_call_verified"
    if MODEL_PATTERN.search(raw):
        return "semantic_confirmed"
    if AI_CONTEXT.search(context) and re.search(r"(?i)\b(?:call|invoke|send|post|create|generate|request)\b", context):
        return "semantic_confirmed"
    return "candidate"


def is_ai_toolchain_fact(item: dict[str, Any]) -> bool:
    normalized = item.get("normalized") or item.get("normalized_value") or {}
    raw = str(item.get("raw_value") or item.get("value") or "").strip()
    kind = str(item.get("type") or "")
    verified = (item.get("verification_status") == "relation_verified"
                and item.get("role", "application") == "application")
    if item.get("discovery_method") == "llm":
        tier = item.get("semantic_confirmation_status")
        if tier == "candidate":
            return False
        if tier in {"semantic_confirmed", "static_call_verified"}:
            return True
        # Historical LLM records without a tier need independent corroboration.
        return bool(verified or MODEL_PATTERN.search(raw))
    if kind in {"model_identifier", "model_argument"}:
        model_value = raw or str(normalized.get("model") or normalized.get("model_identifier_raw") or "")
        return bool(model_value and (verified or MODEL_PATTERN.search(raw)
                                    or item.get("discovery_method") != "llm"))
    model = str(normalized.get("model_identifier_raw") or normalized.get("model") or "")
    if model and (MODEL_PATTERN.search(model) or verified or kind == "model_argument"):
        return True
    sdk_value = normalized.get("sdk_name") or (raw if kind in {"sdk_call", "sdk_marker"} else "")
    sdk = str(sdk_value).casefold().strip()
    if sdk in AI_SDKS or sdk.split(".")[0] in {"openai", "anthropic", "ollama", "cohere", "mistralai"}:
        return True
    if kind == "ai_cli" and raw.casefold() in AI_CLIS:
        return True
    endpoint_value = normalized.get("service_endpoint") or (
        raw if kind in {"endpoint", "service_endpoint"} else "")
    endpoint = str(endpoint_value)
    if endpoint:
        host = urlsplit(endpoint if "://" in endpoint else "https://" + endpoint).hostname
        if host and (host in AI_HOSTS or host.endswith(".openai.azure.com")):
            return True
        if verified and any(part in endpoint.casefold() for part in ("/chat/completions", "/generatecontent", "/v1/messages")):
            return True
    return False

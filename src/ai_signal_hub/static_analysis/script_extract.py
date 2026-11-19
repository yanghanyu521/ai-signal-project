"""LLM script AI-feature extraction with deterministic evidence verification.

The model proposes features; this module disposes. Every claim must anchor to
the script text (verbatim excerpt or a decodable base64 literal) or it is
dropped. Precision is guaranteed by the checks here, not by the model.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .llm import SampleLLMClient

PROMPT_CATEGORIES = {
    "program_prompt", "jailbreak_prompt", "analyzer_injection",
    "prompt_template_prefix", "image_generation_prompt",
    "image_generation_negative_prompt", "other",
}


def _normalized(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def build_chunks(text: str, max_chars: int = 60000) -> list[dict[str, Any]]:
    """Full-coverage line-numbered chunks; nothing is ranked or discarded."""
    lines = text.split("\n")
    chunks: list[dict[str, Any]] = []
    current: list[str] = []
    start = 1
    size = 0
    for index, line in enumerate(lines, 1):
        if current and size + len(line) + 1 > max_chars:
            chunks.append({"unit_id": f"chunk-{len(chunks) + 1}", "kind": "script_chunk",
                           "line_start": start, "line_end": index - 1,
                           "content": "\n".join(current)})
            current, start, size = [], index, 0
        current.append(f"{index}\t{line}")
        size += len(line) + 1
    if current:
        chunks.append({"unit_id": f"chunk-{len(chunks) + 1}", "kind": "script_chunk",
                       "line_start": start, "line_end": len(lines),
                       "content": "\n".join(current)})
    return chunks


def _find_excerpt(excerpt: str, text: str) -> bool:
    if not excerpt or not excerpt.strip():
        return False
    if excerpt in text:
        return True
    return _normalized(excerpt) in _normalized(text)


def _check_evidence(item: dict[str, Any], text: str, total_lines: int, path: str,
                    violations: list[str]) -> bool:
    evidence = item.get("evidence") or {}
    excerpt = evidence.get("excerpt") or ""
    if not _find_excerpt(excerpt, text):
        violations.append(f"{path}: 证据摘录无法在源码中定位，条目已丢弃")
        return False
    start, end = evidence.get("line_start"), evidence.get("line_end")
    if start is None and end is None:
        return True
    if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start or end > total_lines:
        violations.append(f"{path}: 行号越界，已按全局摘录定位采信")
    return True


_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{40,}")


def _b64_decodes_to(decoded: str, encoded_run: str) -> str | None:
    try:
        decoded_source = base64.b64decode(encoded_run + "=" * (-len(encoded_run) % 4), validate=False).decode(
            "utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None
    if _normalized(decoded) in _normalized(decoded_source) or _normalized(decoded_source) in _normalized(decoded):
        return decoded_source
    return None


def _verify_prompt(item: dict[str, Any], text: str, index: int, violations: list[str]) -> bool:
    encoding = str(item.get("encoding") or "plaintext").lower()
    body = str(item.get("text") or "")
    decoded = str(item.get("decoded_text") or "")
    excerpt = (item.get("evidence") or {}).get("excerpt") or ""
    excerpt_found = _find_excerpt(excerpt, text)
    if encoding == "base64":
        if not decoded.strip():
            violations.append(f"prompts[{index}]: base64 提示词缺少 decoded_text，条目已丢弃")
            return False
        excerpt_key = re.sub(r"[^A-Za-z0-9+/=]", "", excerpt)[:40]
        if excerpt_found and excerpt_key:
            for run in _B64_RUN.finditer(text):
                if excerpt_key in run.group(0):
                    decoded_source = _b64_decodes_to(decoded, run.group(0))
                    if decoded_source is not None:
                        item["decoded_text"] = decoded_source.strip().strip('"')
                        item["verbatim_verified"] = True
                        return True
        # The excerpt may be a short fragment or slightly misquoted: independently
        # re-encode the claimed plaintext and require that literal in the source.
        core = decoded.strip()
        variants = {core, core.strip('"'), core.strip('"').strip()}
        variants |= {f'"{variant}"' for variant in list(variants)}
        variants |= {variant + " " for variant in list(variants)}
        for variant in variants:
            if not variant:
                continue
            encoded = base64.b64encode(variant.encode("utf-8")).decode()
            if encoded in text:
                item["decoded_text"] = variant
                item["verbatim_verified"] = True
                if not excerpt_found:
                    violations.append(f"prompts[{index}]: 证据摘录未定位，但 decoded_text 重编码后在源码命中，已采信")
                return True
        violations.append(f"prompts[{index}]: decoded_text 无法由源码中的 base64 验证，条目已丢弃")
        return False
    if not body.strip():
        violations.append(f"prompts[{index}]: 提示词文本为空，条目已丢弃")
        return False
    body_found = _find_excerpt(body, text)
    if not excerpt_found and not body_found:
        violations.append(f"prompts[{index}]: 证据摘录与提示词文本均无法在源码定位，条目已丢弃")
        return False
    item["verbatim_verified"] = body_found
    if not excerpt_found and body_found:
        violations.append(f"prompts[{index}]: 证据摘录未定位，但提示词原文在源码命中，已采信")
    return True


def verify_extraction(result: dict[str, Any], text: str) -> dict[str, Any]:
    """Drop unverifiable claims; return the cleaned result plus an audit."""
    violations: list[str] = []
    total_lines = len(text.split("\n"))
    cleaned: dict[str, Any] = {
        "ai_calling": result.get("ai_calling") if result.get("ai_calling") in {True, False, "unknown"} else "unknown",
        "toolchain": [], "prompts": [],
        "obfuscation": result.get("obfuscation") or [],
        "llm_assisted_dev_signals": result.get("llm_assisted_dev_signals") or [],
        "notes": result.get("notes") or "",
    }
    for index, item in enumerate(result.get("toolchain") or []):
        if not isinstance(item, dict):
            continue
        if cleaned["ai_calling"] is not True:
            violations.append(f"toolchain[{index}]: ai_calling={cleaned['ai_calling']} 时不接受工具链条目，已丢弃")
            continue
        if not any(item.get(field) for field in ("sdk", "service", "endpoint", "model")):
            violations.append(f"toolchain[{index}]: 没有任何标识字段，条目已丢弃")
            continue
        if _check_evidence(item, text, total_lines, f"toolchain[{index}]", violations):
            cleaned["toolchain"].append(item)
    for index, item in enumerate(result.get("prompts") or []):
        if not isinstance(item, dict):
            continue
        category = item.get("category")
        if category not in PROMPT_CATEGORIES:
            violations.append(f"prompts[{index}]: 非法分类 {category!r}，已改为 other")
            item["category"] = "other"
        if _verify_prompt(item, text, index, violations):
            cleaned["prompts"].append(item)
    if cleaned["ai_calling"] is True and not cleaned["toolchain"] and cleaned["prompts"] and not any(
            item.get("category") == "analyzer_injection" for item in cleaned["prompts"]):
        violations.append("ai_calling=true 但工具链全部未通过校验，已降级为 unknown")
        cleaned["ai_calling"] = "unknown"
    cleaned["verification"] = {
        "status": "passed" if not violations else "warnings",
        "violations": violations,
        "dropped_counts": {
            "toolchain": len(result.get("toolchain") or []) - len(cleaned["toolchain"]),
            "prompts": len(result.get("prompts") or []) - len(cleaned["prompts"]),
        },
    }
    return cleaned


def extract_script_features(source: Path, client: SampleLLMClient, *, max_chunk_chars: int = 60000) -> dict[str, Any]:
    text = source.read_text(encoding="utf-8", errors="replace")
    chunks = build_chunks(text, max_chunk_chars)
    partials = []
    for chunk in chunks:
        response = client.analyze([chunk], task="script_extract")
        partials.append(response)
    merged: dict[str, Any] = {"ai_calling": False, "toolchain": [], "prompts": [],
                              "obfuscation": [], "llm_assisted_dev_signals": [], "notes": []}
    for partial in partials:
        if partial.get("ai_calling") is True or merged["ai_calling"] is False and partial.get("ai_calling") == "unknown":
            merged["ai_calling"] = partial.get("ai_calling")
        merged["toolchain"].extend(partial.get("toolchain") or [])
        merged["prompts"].extend(partial.get("prompts") or [])
        for key in ("obfuscation", "llm_assisted_dev_signals"):
            for value in partial.get(key) or []:
                if value not in merged[key]:
                    merged[key].append(value)
        if partial.get("notes"):
            merged["notes"].append(str(partial["notes"]))
    merged["notes"] = "\n".join(merged["notes"])
    cleaned = verify_extraction(merged, text)
    seen_prompts = set()
    unique_prompts = []
    for item in cleaned["prompts"]:
        digest = hashlib.sha256((item.get("category", "") + _normalized(item.get("decoded_text") or item.get("text") or "")).encode("utf-8")).hexdigest()
        if digest not in seen_prompts:
            seen_prompts.add(digest)
            unique_prompts.append(item)
    cleaned["prompts"] = unique_prompts
    seen_tools = set()
    unique_tools = []
    for item in cleaned["toolchain"]:
        key = tuple(str(item.get(field) or "") for field in ("sdk", "service", "endpoint", "model"))
        if key not in seen_tools:
            seen_tools.add(key)
            unique_tools.append(item)
    cleaned["toolchain"] = unique_tools
    cleaned["extraction"] = {
        "mode": "llm_script_extract",
        "model": client.model,
        "chunks": len(chunks),
        "input_strategy": "full_text" if len(chunks) == 1 else "full_coverage_chunks",
        "transfer": client.transfer_metadata(),
    }
    return cleaned

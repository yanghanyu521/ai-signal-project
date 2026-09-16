from __future__ import annotations

import json
import os
import re
import time
from typing import Iterable

import requests

from .utils import normalize_space, sha256_text, stable_id


ENTITY_TYPES = {
    "campaign", "threat_actor", "victim", "region", "malware_family", "sample", "artifact",
    "ai_model", "ai_provider", "agent_framework", "tool", "technique", "vulnerability", "indicator",
}
ENTITY_TYPE_MAP = {
    "malware": "malware_family", "threat-actor": "threat_actor", "threat_actor": "threat_actor",
    "platform": "tool", "software": "tool", "library": "tool", "script": "artifact",
    "file-format": "artifact", "architecture": "artifact", "programming-language": "artifact",
    "ip-address": "indicator", "concept": "technique",
}
PREDICATES = {
    "attributed_to", "associated_with_region", "targets", "uses_model", "uses_provider", "uses_agent",
    "uses_tool", "uses_prompt", "has_code_style_feature", "performs_technique", "has_operational_status",
    "has_ai_role", "has_autonomy_level", "has_human_role", "has_ai_work_share", "has_indicator",
    "has_artifact", "affects_platform", "observed_during", "limits_or_contradicts",
}
PREDICATE_MAP = {
    "has_hash": "has_indicator", "has_characteristic": "has_code_style_feature",
    "has_use_case": "has_ai_role", "uses_prompt_technique": "uses_prompt",
    "uses_prompt_role": "uses_prompt", "uses_llm_to": "has_ai_role", "uses_module": "uses_tool",
    "uploads_to": "uses_tool", "relies_on": "uses_tool", "uses": "uses_tool",
    "compiled_for": "affects_platform", "has_behaviour": "performs_technique",
    "has_function": "performs_technique", "generates": "performs_technique",
    "is_proof_of_concept": "has_operational_status", "has_deployment_evidence": "has_operational_status",
    "has_possible_objective": "has_ai_role", "embeds_keys": "has_artifact",
    "has_key_prefix": "has_artifact", "has_key_substring": "has_artifact",
    "has_endpoint": "has_artifact", "contains_samples": "has_artifact",
    "includes_guardrails": "limits_or_contradicts", "includes_guardrail": "limits_or_contradicts",
}
CLAIM_TYPE_MAP = {
    "observation": "direct_observation", "fact": "direct_observation", "finding": "direct_observation",
    "event": "direct_observation", "capability": "direct_observation", "technique": "direct_observation",
    "attribution": "author_assessment", "author_judgment": "author_assessment",
    "inference": "author_inference", "limitation": "limitation", "negative_evidence": "negative_evidence",
}
ASSERTION_MAP = {
    "confirmed": "asserted", "observed": "asserted", "reported": "asserted", "asserted": "asserted",
    "likely": "likely", "possible": "possible", "hypothesized": "possible", "speculative": "speculative",
    "negated": "denied", "denied": "denied", "unknown": "unknown",
}
AUTHOR_CONFIDENCE_MAP = {
    "high": "explicit_high", "medium": "explicit_medium", "low": "explicit_low",
    "explicit_high": "explicit_high", "explicit_medium": "explicit_medium", "explicit_low": "explicit_low",
    "implicit": "implicit", "not_stated": "not_stated",
}
PREDICATE_SUBJECT_TYPES = {
    "attributed_to": {"campaign", "malware_family", "sample", "artifact"},
    "associated_with_region": {"campaign", "threat_actor", "malware_family", "sample", "artifact"},
    "targets": {"campaign", "threat_actor", "malware_family", "sample", "artifact"},
    "uses_model": {"campaign", "threat_actor", "malware_family", "sample", "artifact"},
    "uses_provider": {"campaign", "threat_actor", "malware_family", "sample", "artifact"},
    "uses_agent": {"campaign", "threat_actor", "malware_family", "sample", "artifact"},
    "uses_tool": {"campaign", "threat_actor", "malware_family", "sample", "artifact"},
    "uses_prompt": {"campaign", "threat_actor", "malware_family", "sample", "artifact"},
    "has_code_style_feature": {"malware_family", "sample", "artifact"},
    "has_ai_role": {"campaign", "threat_actor", "malware_family", "sample", "artifact"},
    "has_autonomy_level": {"campaign", "threat_actor", "malware_family", "sample", "artifact"},
    "has_human_role": {"campaign", "threat_actor", "malware_family", "sample", "artifact"},
}
PREDICATE_OBJECT_TYPES = {
    "attributed_to": {"threat_actor"},
    "associated_with_region": {"region"},
    "targets": {"victim", "region"},
    "uses_model": {"ai_model"},
    "uses_provider": {"ai_provider"},
    "uses_agent": {"agent_framework", "tool"},
    "uses_tool": {"tool", "artifact"},
    "has_indicator": {"indicator"},
    "has_artifact": {"artifact", "sample"},
    "affects_platform": {"tool", "artifact"},
}
SURFACE_BOUND_PREDICATES = {"attributed_to", "associated_with_region", "targets", "uses_model", "uses_provider", "uses_agent"}
GENERIC_ACTORS = {"attacker", "attackers", "threat actor", "threat actors", "operator", "operators", "攻击者", "威胁行为者", "操作者"}
GENERIC_MODELS = {"model", "the model", "llm", "large language model", "ai", "threat actor", "dll", "rsa encryption", "encryption key", "gemini api", "ollama api", "hugging face api"}
GENERIC_TARGETS = {"user", "users", "wide range of users", "victim", "victims", "victim network or device", "用户", "受害者"}


SYSTEM_PROMPT = """你是威胁情报报告的结构化信息抽取器，不是事实补全器。
只能依据提供的报告片段输出原子声明，不得利用常识补充主体、地区、模型、哈希或事件关系。
必须区分直接观察、作者判断、推测、否定和未知。每条声明的 evidence_excerpt 必须是输入中精确连续出现的最小片段。
输出 JSON 对象，顶层只有 entities 和 claims。entities 包含 temp_id、entity_type、name、normalized_name；claims 包含 subject_temp_id、predicate、object_temp_id 或 value、claim_type、assertion_status、author_confidence、evidence_block_id、evidence_excerpt。
entity_type 只能是 campaign, threat_actor, victim, region, malware_family, sample, artifact, ai_model, ai_provider, agent_framework, tool, technique, vulnerability, indicator。
predicate 只能是 attributed_to, associated_with_region, targets, uses_model, uses_provider, uses_agent, uses_tool, uses_prompt, has_code_style_feature, performs_technique, has_operational_status, has_ai_role, has_autonomy_level, has_human_role, has_ai_work_share, has_indicator, has_artifact, affects_platform, observed_during, limits_or_contradicts。
claim_type 只能是 direct_observation, author_assessment, author_inference, methodology, limitation, negative_evidence；assertion_status 只能是 asserted, likely, possible, speculative, denied, unknown；author_confidence 只能是 explicit_high, explicit_medium, explicit_low, implicit, not_stated。
每个响应最多返回 30 条最重要声明，优先模型/API/Agent、AI角色、自治程度、威胁主体/地区、受害目标、样本哈希、运营状态、Prompt和代码风格；不要穷举文章中的一般性背景或每个重复哈希。不要输出解释。"""


def _chunks(blocks: list[dict], max_chars: int = 5000) -> Iterable[list[dict]]:
    current: list[dict] = []
    size = 0
    for block in blocks:
        text = block["text"]
        segments = [text[index:index + max_chars] for index in range(0, len(text), max_chars)] or [""]
        for segment in segments:
            item = {**block, "text": segment}
            item_size = len(segment) + 100
            if current and size + item_size > max_chars:
                yield current
                current = []
                size = 0
            current.append(item)
            size += item_size
    if current:
        yield current


def _parse_json_content(content: str) -> dict:
    content = content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1]
        content = content.rsplit("```", 1)[0]
    value = json.loads(content)
    if not isinstance(value, dict):
        raise ValueError("大模型响应不是 JSON 对象")
    return value


def _surface_mentioned(value: str, excerpt: str) -> bool:
    value_normalized = normalize_space(value).lower()
    excerpt_normalized = normalize_space(excerpt).lower()
    if value_normalized and value_normalized in excerpt_normalized:
        return True
    compact_value = "".join(character for character in value_normalized if character.isalnum())
    compact_excerpt = "".join(character for character in excerpt_normalized if character.isalnum())
    return len(compact_value) >= 4 and compact_value in compact_excerpt


def extract_with_deepseek(blocks: list[dict], *, model: str | None = None, base_url: str | None = None, timeout: int = 60, max_retries: int = 3) -> dict:
    api_key = os.environ.get("cc-api")
    if not api_key:
        raise RuntimeError("未设置环境变量 cc-api")
    model = model or os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
    base_url = (base_url or os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")).rstrip("/")
    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/v1/chat/completions"
    all_entities: list[dict] = []
    all_claims: list[dict] = []
    chunk_errors: list[dict] = []
    for chunk_number, chunk in enumerate(_chunks(blocks), start=1):
        user_content = json.dumps(
            {"blocks": [{"block_id": block["block_id"], "text": block["text"]} for block in chunk]},
            ensure_ascii=False,
        )
        payload = {
            "model": model,
            "temperature": 0.0,
            "max_tokens": 8192,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
        }
        last_error: Exception | None = None
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    endpoint,
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json=payload,
                    timeout=timeout,
                )
                if response.status_code in {401, 403}:
                    raise RuntimeError(f"DeepSeek 鉴权失败: HTTP {response.status_code}")
                response.raise_for_status()
                choice = response.json()["choices"][0]
                if choice.get("finish_reason") not in {None, "stop"}:
                    raise ValueError(f"大模型响应未完整结束: finish_reason={choice.get('finish_reason')}")
                content = choice["message"]["content"]
                result = _parse_json_content(content)
                # DeepSeek 在每个分块中都会从 e1/s1 等临时 ID 重新编号。
                # 合并前加分块命名空间，否则后一个分块会覆盖前一分块的实体映射。
                namespace = f"chunk{chunk_number}:"
                for entity in result.get("entities") or []:
                    item = dict(entity)
                    item["temp_id"] = namespace + normalize_space(str(item.get("temp_id") or ""))
                    all_entities.append(item)
                for claim in result.get("claims") or []:
                    item = dict(claim)
                    item["subject_temp_id"] = namespace + normalize_space(str(item.get("subject_temp_id") or ""))
                    if item.get("object_temp_id") is not None:
                        item["object_temp_id"] = namespace + normalize_space(str(item.get("object_temp_id") or ""))
                    all_claims.append(item)
                last_error = None
                break
            except (requests.RequestException, KeyError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt + 1 < max_retries:
                    time.sleep(2 ** attempt)
        if last_error:
            chunk_errors.append({
                "chunk": chunk_number,
                "error_type": type(last_error).__name__,
                "message": str(last_error),
            })
    return {"model": model, "entities": all_entities, "claims": all_claims, "chunk_errors": chunk_errors}


def validate_and_convert_llm(
    document_id: str,
    blocks: list[dict],
    candidate: dict,
    *,
    allowed_subject_names: list[str] | None = None,
) -> dict:
    block_map = {block["block_id"]: block for block in blocks}
    entity_map: dict[str, dict] = {}
    entities: list[dict] = []
    warnings: list[str] = []
    allowed_subject_keys = {
        re.sub(r"[^a-z0-9]", "", normalize_space(value).lower())
        for value in allowed_subject_names or []
        if value
    }
    for item in candidate.get("entities") or []:
        temp_id = normalize_space(str(item.get("temp_id") or ""))
        raw_entity_type = normalize_space(str(item.get("entity_type") or "")).lower()
        entity_type = ENTITY_TYPE_MAP.get(raw_entity_type, raw_entity_type)
        name = normalize_space(str(item.get("name") or ""))
        normalized = normalize_space(str(item.get("normalized_name") or name)).lower()
        if not temp_id or entity_type not in ENTITY_TYPES or not name:
            warnings.append(f"丢弃字段不完整或类型不受支持的 LLM 实体: {raw_entity_type or 'missing'}")
            continue
        entity = {
            "entity_id": stable_id("entity", entity_type, normalized),
            "entity_type": entity_type,
            "name": name,
            "normalized_name": normalized,
            "aliases": [],
            "attributes": {"candidate_source": "deepseek"},
        }
        entity_map[temp_id] = entity
        entities.append(entity)
    claims: list[dict] = []
    for item in candidate.get("claims") or []:
        subject = entity_map.get(normalize_space(str(item.get("subject_temp_id") or "")))
        block = block_map.get(normalize_space(str(item.get("evidence_block_id") or "")))
        excerpt = normalize_space(str(item.get("evidence_excerpt") or ""))
        raw_predicate = normalize_space(str(item.get("predicate") or "")).lower()
        predicate = PREDICATE_MAP.get(raw_predicate, raw_predicate)
        if not subject or not block or not excerpt or excerpt not in block["text"]:
            warnings.append("丢弃无主体、无证据块或证据不能精确匹配的 LLM 声明")
            continue
        if predicate not in PREDICATES:
            warnings.append(f"丢弃不受支持的 LLM 谓词: {raw_predicate or 'missing'}")
            continue
        if allowed_subject_keys:
            subject_key = re.sub(r"[^a-z0-9]", "", subject["name"].lower())
            if not any(subject_key == key or subject_key.startswith(key) or key.startswith(subject_key) for key in allowed_subject_keys):
                warnings.append(f"丢弃非目标事件主体的 LLM 声明: {subject['name']}")
                continue
        object_entity = entity_map.get(normalize_space(str(item.get("object_temp_id") or "")))
        if not object_entity and item.get("value") is None:
            warnings.append("丢弃没有可用宾语或值的 LLM 声明")
            continue
        allowed_subject_types = PREDICATE_SUBJECT_TYPES.get(predicate)
        if allowed_subject_types is not None and subject["entity_type"] not in allowed_subject_types:
            warnings.append(f"丢弃主体类型与谓词不兼容的 LLM 声明: {predicate}/{subject['entity_type']}")
            continue
        allowed_object_types = PREDICATE_OBJECT_TYPES.get(predicate)
        if object_entity and allowed_object_types is not None and object_entity["entity_type"] not in allowed_object_types:
            warnings.append(f"丢弃宾语类型与谓词不兼容的 LLM 声明: {predicate}/{object_entity['entity_type']}")
            continue
        if predicate == "targets" and object_entity is None:
            warnings.append("丢弃没有具名victim/region宾语的targets声明")
            continue
        object_surface = normalize_space(str(object_entity["name"] if object_entity else item.get("value") or ""))
        if predicate in SURFACE_BOUND_PREDICATES and not _surface_mentioned(object_surface, excerpt):
            warnings.append(f"丢弃关键宾语未在证据片段出现的 LLM 声明: {predicate}")
            continue
        if predicate == "attributed_to":
            if object_surface.lower() in GENERIC_ACTORS or re.search(r"\b(?:financially motivated|malicious|unknown)\s+actors?\b", object_surface, re.I):
                warnings.append("丢弃泛称攻击者归因")
                continue
            if re.search(r"\bunattributed to (?:a )?specific threat actor\b|\b(?:discovered|reported|published|researched|analyzed)\s+by\b|由.+?(?:发现|报告|发布|研究|分析)", excerpt, re.I):
                warnings.append("丢弃把报告发现者/研究者误作攻击归因的声明")
                continue
        if predicate == "targets" and object_surface.lower() in GENERIC_TARGETS:
            warnings.append("丢弃非具名或过于泛化的目标实体")
            continue
        if predicate == "uses_model" and (
            object_surface.lower() in GENERIC_MODELS
            or re.search(r"\b(?:less|more|advanced|less advanced|capable)\s+(?:capable\s+)?model\b", object_surface, re.I)
        ):
            warnings.append("丢弃泛化或明显非模型的uses_model声明")
            continue
        if predicate == "uses_provider" and (re.search(r"\.(?:py|js|exe|dll)(?:\s|\(|$)", object_surface, re.I) or "malware" in object_surface.lower()):
            warnings.append("丢弃文件/恶意软件被误作AI服务商的声明")
            continue
        if predicate == "performs_technique":
            if re.search(r"\.(?:py|js|exe|dll|ps1)(?:\s|\(|$)", object_surface, re.I):
                warnings.append("丢弃文件名被误作攻击技术的声明")
                continue
            if re.search(rf"(?:group|actor|operators?|组织|团伙|攻击者).{{0,30}}{re.escape(object_surface)}", excerpt, re.I):
                warnings.append("丢弃威胁行为体名称被误作攻击技术的声明")
                continue
        object_value = {"entity_id": object_entity["entity_id"]} if object_entity else {"value": item.get("value"), "unit": None}
        start = block["text"].find(excerpt)
        raw_claim_type = normalize_space(str(item.get("claim_type") or "")).lower()
        claim_type = CLAIM_TYPE_MAP.get(raw_claim_type, raw_claim_type)
        if claim_type not in {"direct_observation", "author_assessment", "author_inference", "methodology", "limitation", "negative_evidence"}:
            claim_type = "author_assessment"
        assertion_status = ASSERTION_MAP.get(normalize_space(str(item.get("assertion_status") or "")).lower(), "unknown")
        author_confidence = AUTHOR_CONFIDENCE_MAP.get(normalize_space(str(item.get("author_confidence") or "")).lower(), "not_stated")
        claims.append(
            {
                "claim_id": stable_id("claim", subject["entity_id"], item.get("predicate"), str(object_value), block["block_id"], excerpt),
                "subject_id": subject["entity_id"],
                "predicate": predicate,
                "object": object_value,
                "claim_type": claim_type,
                "assertion_status": assertion_status,
                "author_confidence": author_confidence,
                "extractor_confidence": 0.75,
                "evidence": [{
                    "document_id": document_id,
                    "block_id": block["block_id"],
                    "section": block.get("section"),
                    "locator": {"page": block.get("page"), "paragraph": block.get("paragraph"), "char_start": start, "char_end": start + len(excerpt), "table": block.get("table")},
                    "excerpt": excerpt,
                    "excerpt_sha256": sha256_text(excerpt),
                }],
            }
        )
    return {"entities": entities, "claims": claims, "warnings": warnings}

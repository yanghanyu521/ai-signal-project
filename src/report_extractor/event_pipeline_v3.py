from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

from .llm import extract_with_deepseek, validate_and_convert_llm
from .parsers import parse_document
from .utils import SHA256_RE, normalize_space, sha256_bytes, sha256_text, stable_id, write_json


ROLE_WORDS = {
    "Reverse Shell": "reverse_shell", "Dropper": "dropper", "Ransomware": "ransomware",
    "Data Miner": "data_miner", "Credential Stealer": "credential_stealer",
    "implant": "implant", "malware generator": "malware_generator", "AI agent": "agent",
}
LANGUAGES = ["VBScript", "PowerShell", "Python", "JavaScript", "Golang", "Go", "Lua"]
MONTHS = {name.lower(): index for index, name in enumerate(
    ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"], 1
)}
MODEL_RULES = [
    (r"gemini-1\.5-flash-latest", "Google", "Gemini", "gemini-1.5-flash-latest", "Gemini API", "cloud_api"),
    (r"Qwen2\.5-Coder-32B-Instruct", "Alibaba/Qwen", "Qwen", "Qwen2.5-Coder-32B-Instruct", "Hugging Face API", "cloud_api"),
    (r"\bGPT-4\b", "OpenAI", "GPT", "GPT-4", "Chat Completions API", "cloud_api"),
    (r"\bgpt-3\.5-turbo\b", "OpenAI", "GPT", "gpt-3.5-turbo", "Chat Completions API", "cloud_api"),
    # 中文正文中模型名前一个字符通常是汉字，Python 的 \b 会把汉字也视为
    # word character，因此这里使用 ASCII 边界，避免漏掉“的gpt-oss-20b模型”。
    (r"(?<![A-Za-z0-9])gpt-oss\s*[-: ]\s*20b(?![A-Za-z0-9])", "OpenAI", "GPT-OSS", "gpt-oss-20b", "Ollama API", "local_model"),
    (r"\bClaude Code\b", "Anthropic", "Claude", "Claude Code", None, "unknown"),
]
SERVICE_RULES = [
    (r"Gemini(?:'s)? API|Google Gemini API", "Google", "Gemini", "Gemini API", "cloud_api"),
    (r"Hugging Face API|API for Hugging Face", "Hugging Face", None, "Hugging Face API", "cloud_api"),
    (r"OpenAI chat completions API", "OpenAI", "GPT", "Chat Completions API", "cloud_api"),
    (r"on-host installed AI CLI tools", None, None, "AI CLI", "on_host_cli"),
    (r"\bOllama API\b", None, "GPT-OSS", "Ollama API", "local_model"),
]
EXCLUDED_NAMES = {"LLM", "API", "GTIG", "MCP", "AI", "CVE", "MOF", "CERT-UA", "NCSA", "ICT"}


def _candidate_name(value: str) -> str:
    return normalize_space(value).strip("'\"‘’“”.,:;()[]")


def discover_events(blocks: list[dict], title: str | None = None, *, target_event: dict | None = None) -> list[dict]:
    """依据报告内容建立事件索引；目标提示只有在正文精确命中时才生效。"""
    found: dict[str, dict] = {}

    def add(name: str, block: dict, aliases: list[str] | None = None, hint: str | None = None) -> None:
        name = _candidate_name(name)
        if len(name) < 4 or name.upper() in EXCLUDED_NAMES:
            return
        key = re.sub(r"[^a-z0-9]", "", name.lower())
        item = found.setdefault(key, {"name": name, "aliases": [], "anchor_block_ids": [], "hints": [], "first_index": block["index"]})
        for alias in aliases or []:
            alias = _candidate_name(alias)
            if alias and alias.lower() != item["name"].lower() and alias not in item["aliases"]:
                item["aliases"].append(alias)
        if block["block_id"] not in item["anchor_block_ids"]:
            item["anchor_block_ids"].append(block["block_id"])
        if hint and hint not in item["hints"]:
            item["hints"].append(hint)
        item["first_index"] = min(item["first_index"], block["index"])

    for block in blocks:
        text = block.get("text", "")
        for match in re.finditer(r"\b([A-Z][A-Z0-9-]{3,30})\s+(Reverse Shell|Dropper|Ransomware|Data Miner|Credential Stealer)\b", text):
            add(match.group(1), block, hint=match.group(2))
        for match in re.finditer(r"\b([A-Z][A-Z0-9-]{3,30})\s+is\s+(?:an?\s+)?(?:experimental\s+)?(reverse shell|dropper|ransomware|data miner|credential stealer|malware)\b", text, re.I):
            add(match.group(1), block, hint=match.group(2))
        for match in re.finditer(r"\b(?:tracked as|designated|dubbed)\s+[‘'\"]?([A-Z][A-Za-z0-9-]{3,30})", text, re.I):
            prefix = text[max(0, match.start() - 40):match.start()]
            if re.search(r"\b(?:group|actor|operators?)\s+$", prefix, re.I):
                continue
            add(match.group(1), block)
        for match in re.finditer(r"\b(GTG-\d{3,6})\b", text):
            add(match.group(1), block, hint="campaign")
        alias_match = re.search(r"track as\s+([A-Z][A-Z0-9-]+).*?reported.*?as\s+([A-Z][A-Z0-9-]+)", text, re.I)
        if alias_match:
            add(alias_match.group(1), block, aliases=[alias_match.group(2)], hint="malware")
        if re.search(r"Targeted With\s+([A-Z][A-Za-z0-9-]+)\s+AI Agent", text, re.I):
            agent = re.search(r"Targeted With\s+([A-Z][A-Za-z0-9-]+)\s+AI Agent", text, re.I).group(1)
            add(f"{agent} intrusion", block, aliases=[agent], hint="intrusion")
        if block.get("kind") == "heading":
            slash = re.search(r"([A-Z][A-Za-z0-9-]+)/([A-Z][A-Z0-9-]{3,})", text)
            if slash:
                add(slash.group(2), block, aliases=[slash.group(1)], hint="malware")
            for token in re.findall(r"\b[A-Z][a-z]+(?:[A-Z][A-Za-z0-9]*)+\b", text):
                if re.search(r"prompt|terminal|malware|ransom", token, re.I):
                    add(token, block, hint="malware")

    # PDF表格可能把“家族名”和“Credential Stealer”等角色拆成相邻块。
    uppercase_occurrences: dict[str, list[tuple[int, dict]]] = {}
    for index, block in enumerate(blocks):
        for token in re.findall(r"\b[A-Z][A-Z0-9-]{4,30}\b", block.get("text", "")):
            if token not in EXCLUDED_NAMES and not re.fullmatch(r"APT\d+|UAC-\d+|T\d+", token):
                uppercase_occurrences.setdefault(token, []).append((index, block))
    for token, occurrences in uppercase_occurrences.items():
        if len(occurrences) < 2:
            continue
        if not re.search(r"PROMPT|SHELL$|VAULT$|LOCK$|STEAL$|FLUX$|MAL$", token, re.I):
            continue
        neighborhood = " ".join(
            blocks[pos]["text"] for index, _ in occurrences for pos in range(max(0, index - 2), min(len(blocks), index + 3))
        )
        if re.search(r"malware|dropper|ransomware|data miner|credential stealer|reverse shell|AI prompt|LLM", neighborhood, re.I):
            add(token, occurrences[0][1], hint="malware")

    # 批量样本对照可以提供目标家族提示，但提示本身不是报告事实。
    # 只有报告正文或章节精确出现目标名称/别名时，才把它加入事件候选。
    if target_event:
        target_name = _candidate_name(str(target_event.get("name") or ""))
        target_aliases = [_candidate_name(str(value)) for value in target_event.get("aliases", []) if value]
        target_terms = [value for value in [target_name, *target_aliases] if value]
        matched_aliases: list[str] = []
        for block in blocks:
            haystacks = [block.get("text", ""), block.get("section") or ""]
            matched_terms = [
                term for term in target_terms
                if any(re.search(rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", text, re.I) for text in haystacks)
            ]
            if not matched_terms:
                continue
            matched_aliases.extend(term for term in matched_terms if term.lower() != target_name.lower())
            add(
                target_name,
                block,
                aliases=list(dict.fromkeys([*target_aliases, *matched_aliases])),
                hint=str(target_event.get("hint") or "target_family"),
            )

    candidates = sorted(found.values(), key=lambda item: item["first_index"])
    # 文中明确的 aka/also known as 关系用于合并别名候选。
    for block in blocks:
        text = block.get("text", "")
        for match in re.finditer(r"([A-Z][A-Za-z0-9-]{3,})\s*\(\s*(?:aka|also known as)\s+([A-Z][A-Za-z0-9-]{3,})", text, re.I):
            a, b = match.group(1), match.group(2)
            related = [item for item in candidates if item["name"].lower() in {a.lower(), b.lower()}]
            if related:
                canonical = next((item for item in related if item["name"].isupper()), related[0])
                other = b if canonical["name"].lower() == a.lower() else a
                if other not in canonical["aliases"]:
                    canonical["aliases"].append(other)
                for item in related:
                    if item is not canonical:
                        canonical["anchor_block_ids"].extend(item["anchor_block_ids"])
                        candidates.remove(item)
    return candidates


def _event_context(blocks: list[dict], candidate: dict, *, full: bool) -> list[dict]:
    if full:
        return blocks
    terms = [candidate["name"], *candidate.get("aliases", [])]
    # 对 "Hermes intrusion" 也使用单词 Hermes 搜索。
    terms.extend(candidate["name"].split()[:1])
    pattern = re.compile("|".join(re.escape(term) for term in terms if term), re.I)
    positions: set[int] = set()
    for index, block in enumerate(blocks):
        if pattern.search(block.get("text", "")) or pattern.search(block.get("section") or ""):
            positions.update(range(max(0, index - 12), min(len(blocks), index + 13)))
    return [blocks[index] for index in sorted(positions)]


def build_event_contexts(blocks: list[dict], candidates: list[dict]) -> dict[str, list[dict]]:
    """按正文中最近的事件锚点分配块，避免多事件报告的邻近污染。"""
    if not candidates:
        return {}
    patterns: list[re.Pattern[str]] = []
    positions: list[list[int]] = []
    for candidate in candidates:
        terms = [candidate["name"], *candidate.get("aliases", []), candidate["name"].split()[0]]
        pattern = re.compile("|".join(re.escape(term) for term in dict.fromkeys(terms) if term), re.I)
        patterns.append(pattern)
        positions.append([
            index for index, block in enumerate(blocks)
            if pattern.search(block.get("text", "")) or pattern.search(block.get("section") or "")
        ])
    if len(candidates) == 1:
        hits = positions[0]
        if not hits:
            return {candidates[0]["name"]: blocks}
        start = max(0, min(hits) - 10)
        summary_positions = [index for index, block in enumerate(blocks) if normalize_space(block.get("section")).lower() == "summary"]
        # HTML研究文章通常在Summary后拼接相关文章；PDF无章节时保留全文以覆盖后续技术细节。
        end = max(summary_positions) + 1 if summary_positions else len(blocks)
        return {candidates[0]["name"]: blocks[start:end]}
    assigned: dict[str, list[dict]] = {candidate["name"]: [] for candidate in candidates}
    for index, block in enumerate(blocks):
        section_matches = [i for i, pattern in enumerate(patterns) if pattern.search(block.get("section") or "")]
        text_matches = [i for i, pattern in enumerate(patterns) if pattern.search(block.get("text", ""))]
        owners = section_matches or text_matches
        if len(owners) == 1:
            assigned[candidates[owners[0]]["name"]].append(block)
            continue
        if len(owners) > 1:
            # 同一汇总表/总览句提到多个事件时不用于事件专属字段。
            continue
        block_page = block.get("page")
        distances = []
        for hits in positions:
            same_page = [pos for pos in hits if block_page is not None and blocks[pos].get("page") == block_page]
            pool = same_page or hits
            penalty = 0 if same_page or block_page is None else 1_000
            distances.append(penalty + min((abs(index - pos) for pos in pool), default=10_000))
        nearest = min(distances)
        if nearest <= 15 and distances.count(nearest) == 1:
            assigned[candidates[distances.index(nearest)]["name"]].append(block)
    return assigned


def build_target_context(blocks: list[dict], candidate: dict, all_candidates: list[dict] | None = None) -> list[dict]:
    """只保留目标事件名称附近的局部证据，抑制长篇多案例报告的跨事件污染。

    连续出现的目标名称通常位于技术分析主体，允许向两侧扩展 3 个块；孤立的
    摘要或附录命中仅扩展 1 个块。目标名称本身出现的块始终保留。
    """
    terms = list(dict.fromkeys([candidate["name"], *candidate.get("aliases", [])]))
    pattern = re.compile(
        "|".join(rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])" for term in terms if term),
        re.I,
    )
    other_terms = list(dict.fromkeys(
        value
        for item in all_candidates or []
        if item is not candidate
        for value in [item["name"], *item.get("aliases", [])]
        if value
    ))
    candidate_groups = [
        (item["name"].lower(), list(dict.fromkeys([item["name"], *item.get("aliases", [])])))
        for item in all_candidates or [candidate]
    ]
    all_terms = list(dict.fromkeys(term for _, group_terms in candidate_groups for term in group_terms if term))

    def mentioned_events(text: str) -> set[str]:
        return {
            event_key
            for event_key, group_terms in candidate_groups
            if any(re.search(rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", text, re.I) for term in group_terms if term)
        }

    hits = [index for index, block in enumerate(blocks) if pattern.search(block.get("text", ""))]
    if not hits:
        return []
    clusters: list[list[int]] = []
    for index in hits:
        if clusters and index - clusters[-1][-1] <= 3:
            clusters[-1].append(index)
        else:
            clusters.append([index])
    # GTIG 等报告把每个家族名作为独立块，后续块直到下一个家族名都属于该行。
    exact_markers: dict[int, str] = {}
    for index, block in enumerate(blocks):
        text_key = normalize_space(block.get("text", "")).lower()
        for term in all_terms:
            if text_key == normalize_space(term).lower():
                exact_markers[index] = term
                break

    selected: set[int] = set()
    for cluster in clusters:
        target_markers = [index for index in cluster if index in exact_markers and exact_markers[index].lower() in {term.lower() for term in terms}]
        has_other_markers = any(term.lower() not in {value.lower() for value in terms} for term in exact_markers.values())
        if target_markers and has_other_markers:
            start = min(target_markers)
            next_marker = min((index for index in exact_markers if index > start), default=len(blocks))
            selected.update(range(start, next_marker))
        else:
            left_radius, right_radius = (1, 3) if len(cluster) > 1 else (1, 1)
            selected.update(range(max(0, cluster[0] - left_radius), min(len(blocks), cluster[-1] + right_radius + 1)))

    cleaned = []
    target_keys = {term.lower() for term in terms}
    target_event_key = candidate["name"].lower()
    for index in sorted(selected):
        block = blocks[index]
        mentions = mentioned_events(block.get("text", ""))
        # 同一总览段或合并表格同时提到多个事件，不作为任何单一目标事件的证据。
        if len(mentions) > 1:
            continue
        if mentions and target_event_key not in mentions:
            continue
        if index in exact_markers and exact_markers[index].lower() not in target_keys:
            continue
        cleaned.append(block)
    return cleaned


def _excerpt(block: dict, match: re.Match[str], limit: int = 700) -> str:
    text = block["text"]
    if len(text) <= limit:
        return text
    start = max(0, match.start() - limit // 3)
    end = min(len(text), start + limit)
    return text[max(0, end - limit):end].strip()


def _evidence(event: dict, block: dict, match: re.Match[str]) -> str:
    excerpt = _excerpt(block, match)
    evidence_id = stable_id("evidence", block["block_id"], excerpt)
    if not any(item["evidence_id"] == evidence_id for item in event["evidence"]):
        event["evidence"].append({
            "evidence_id": evidence_id, "block_id": block["block_id"], "page": block.get("page"),
            "section": block.get("section"), "excerpt": excerpt, "excerpt_sha256": sha256_text(excerpt),
        })
    return evidence_id


def _find(context: list[dict], pattern: str) -> tuple[dict, re.Match[str]] | None:
    regex = re.compile(pattern, re.I | re.S)
    for block in context:
        match = regex.search(block.get("text", ""))
        if match:
            return block, match
    return None


def _add_unique(items: list[dict], item: dict, keys: tuple[str, ...]) -> None:
    for existing in items:
        if all(existing.get(key) == item.get(key) for key in keys):
            existing["evidence_ids"] = list(dict.fromkeys(existing["evidence_ids"] + item["evidence_ids"]))
            return
    items.append(item)


def _infer_event_type(text: str, hints: list[str]) -> str:
    value = f"{text} {' '.join(hints)}".lower()
    if any(hint.lower() == "intrusion" for hint in hints):
        return "intrusion"
    if "cyber espionage" in value:
        return "cyber_espionage"
    if ("android" in value or "安卓" in value) and ("malware" in value or "恶意软件" in value):
        return "malware_operation"
    has_ransomware = "ransomware" in value or "勒索软件" in value
    has_reverse_shell = "reverse shell" in value or "反向 shell" in value or "反向shell" in value
    if has_ransomware and has_reverse_shell:
        return "malware_operation"
    if has_ransomware:
        return "ransomware"
    if any(word in value for word in ["malware", "dropper", "data miner", "credential stealer", "reverse shell", "恶意软件", "恶意程序"]):
        return "malware_operation"
    if "intrusion" in value or "compromise multiple systems" in value:
        return "intrusion"
    if "proof of concept" in value or "proof-of-concept" in value:
        return "proof_of_concept"
    return "unknown"


def _extract_time(event: dict, context: list[dict]) -> dict:
    pattern = r"\b(?:(early|mid|late)[ -])?(January|February|March|April|May|June|July|August|September|October|November|December)\s+(20\d{2})\b"
    hit = _find(context, pattern)
    if not hit:
        return {"start": None, "end": None, "precision": "unknown", "description": None, "evidence_ids": []}
    block, match = hit
    month, year = MONTHS[match.group(2).lower()], int(match.group(3))
    return {"start": f"{year:04d}-{month:02d}", "end": None, "precision": "month", "description": match.group(0), "evidence_ids": [_evidence(event, block, match)]}


def _extract_status(event: dict, context: list[dict], event_terms: list[str]) -> dict:
    rules = [
        (r"proof[- ]of[- ]concept|(?<![A-Za-z0-9])PoC(?![A-Za-z0-9])|概念验证", "proof_of_concept"),
        (r"live operations|observed in operations|in the wild|used during a ransomware attack", "observed_in_operations"),
        (r"development or testing phase|research and development phase", "development_or_testing"),
        (r"experimental", "experimental"),
        (r"successful intrusions|compromise multiple systems|confirmed intrusion", "confirmed_intrusion"),
    ]
    term_pattern = re.compile("|".join(re.escape(term) for term in event_terms if term), re.I)
    name_positions = [block.get("index", index) for index, block in enumerate(context) if term_pattern.search(block.get("text", ""))]

    def grounded(hit: tuple[dict, re.Match[str]]) -> bool:
        block, match = hit
        text = block.get("text", "")
        term_matches = list(term_pattern.finditer(text))
        if term_matches:
            return min(abs(match.start() - term.start()) for term in term_matches) <= 220
        block_index = block.get("index")
        return len(text) <= 400 and block_index is not None and min((abs(block_index - index) for index in name_positions), default=10_000) <= 3

    observed_hit = _find(context, r"\bObserved\b")
    operations_hit = _find(context, r"\bin operations\b")
    if observed_hit and operations_hit and grounded(observed_hit) and grounded(operations_hit):
        return {"value": "observed_in_operations", "evidence_ids": list(dict.fromkeys([_evidence(event, *observed_hit), _evidence(event, *operations_hit)]))}
    for pattern, value in rules:
        hit = _find(context, pattern)
        if hit and grounded(hit):
            if value == "observed_in_operations":
                before = hit[0]["text"][max(0, hit[1].start() - 60):hit[1].start()].lower()
                whole = hit[0]["text"].lower()
                if re.search(r"not |not being|as opposed to|does not|without", before) or "does not" in whole:
                    continue
            return {"value": value, "evidence_ids": [_evidence(event, *hit)]}
    return {"value": "unknown", "evidence_ids": []}


def _purpose(text: str) -> tuple[str | None, str | None]:
    lower = text.lower()
    if "rewrite" in lower or "self-modification" in lower or "regeneration" in lower:
        return "self_rewriting", "execution"
    if "command" in lower and "generate" in lower:
        return "command_generation", "execution"
    if "ransomware code" in lower or "lua scripts" in lower:
        return "malicious_code_generation", "execution"
    if "search" in lower and ("secret" in lower or "token" in lower):
        return "secret_discovery", "post_compromise"
    if "orchestrat" in lower or "sub-agent" in lower:
        return "attack_orchestration", "full_attack_lifecycle"
    if "enumerat" in lower or "travers" in lower:
        return "post_compromise_operations", "post_compromise"
    return None, None


def _extract_toolchain(event: dict, context: list[dict], aliases: list[str]) -> list[dict]:
    items: list[dict] = []
    for pattern, provider, family, model, service, deployment in MODEL_RULES:
        hit = _find(context, pattern)
        if not hit:
            continue
        block, match = hit
        purpose, stage = _purpose(block["text"])
        _add_unique(items, {"raw_value": match.group(0), "provider": provider, "family": family, "model": model, "service": service, "endpoint": None, "sdk_or_library": None, "agent_or_protocol": None, "deployment": deployment, "purpose": purpose, "stage": stage, "evidence_ids": [_evidence(event, block, match)]}, ("provider", "model", "service"))
    for pattern, provider, family, service, deployment in SERVICE_RULES:
        hit = _find(context, pattern)
        if not hit:
            continue
        block, match = hit
        existing_service = next((item for item in items if item.get("service") == service and item.get("provider") == provider), None)
        if existing_service:
            existing_service["evidence_ids"] = list(dict.fromkeys([*existing_service["evidence_ids"], _evidence(event, block, match)]))
            continue
        purpose, stage = _purpose(block["text"])
        _add_unique(items, {"raw_value": match.group(0), "provider": provider, "family": family, "model": None, "service": service, "endpoint": None, "sdk_or_library": None, "agent_or_protocol": None, "deployment": deployment, "purpose": purpose, "stage": stage, "evidence_ids": [_evidence(event, block, match)]}, ("provider", "model", "service"))
    mcp = _find(context, r"Model Context Protocol\s*\(MCP\)|\bMCP tools\b")
    if mcp:
        _add_unique(items, {"raw_value": mcp[1].group(0), "provider": None, "family": None, "model": None, "service": None, "endpoint": None, "sdk_or_library": None, "agent_or_protocol": "MCP", "deployment": "unknown", "purpose": "attack_orchestration", "stage": "full_attack_lifecycle", "evidence_ids": [_evidence(event, *mcp)]}, ("agent_or_protocol", "purpose"))
    agent_term = aliases[0] if aliases else None
    if agent_term:
        hit = _find(context, rf"{re.escape(agent_term)}.*(?:autonomous AI agent|YOLO mode)")
        if hit:
            _add_unique(items, {"raw_value": agent_term, "provider": None, "family": None, "model": None, "service": None, "endpoint": None, "sdk_or_library": None, "agent_or_protocol": agent_term, "deployment": "unknown", "purpose": "post_compromise_operations", "stage": "post_compromise", "evidence_ids": [_evidence(event, *hit)]}, ("agent_or_protocol", "purpose"))
    if not items:
        generic = _find(context, r"\bLLMs?\b|large language model")
        if generic:
            purpose, stage = _purpose(generic[0]["text"])
            items.append({"raw_value": generic[1].group(0), "provider": None, "family": "LLM", "model": None, "service": None, "endpoint": None, "sdk_or_library": None, "agent_or_protocol": None, "deployment": "unknown", "purpose": purpose, "stage": stage, "evidence_ids": [_evidence(event, *generic)]})
    return items


def _prompt_structural(text: str) -> dict:
    lower = text.lower()
    return {
        "role_definition": bool(re.search(r"act as|you are|persona", lower)),
        "output_only": bool(re.search(r"output only|only (?:the )?output", lower)),
        "code_only": bool(re.search(r"only (?:the )?code|code itself", lower)),
        "single_line_command": bool(re.search(r"one-line|single-line|one line", lower)),
        "self_modification": bool(re.search(r"rewrite.*(?:source code|malware)|self-modif|regenerat", lower)),
        "evasion": bool(re.search(r"evasion|evade|bypass detection|obfuscat", lower)),
        "jailbreak": bool(re.search(r"jailbreak|ignore previous|bypass safeguards", lower)),
        "safety_framing": bool(re.search(r"authorized|research|ctf|educational", lower)),
    }


def _extract_prompts(event: dict, context: list[dict], toolchain: list[dict]) -> list[dict]:
    candidates = []
    for block in context:
        text = block.get("text", "")
        if "prompt" not in text.lower() or not re.search(r"output|generate|rewrite|act as|command|bypass|YOLO|persona|leverages", text, re.I):
            continue
        match = re.search(r"prompt", text, re.I)
        if not match:
            continue
        structural = _prompt_structural(text)
        purpose, _ = _purpose(text)
        if not purpose:
            if structural["evasion"]:
                purpose = "analysis_evasion"
            elif "collect" in text.lower():
                purpose = "data_collection"
        constraints = [name for name, present in structural.items() if present and name in {"output_only", "code_only", "single_line_command", "role_definition"}]
        target_model = next((item["model"] for item in toolchain if item.get("model")), None)
        effectiveness = "succeeded" if re.search(r"blindly executed|then executes|able to induce|logs show", text, re.I) else "unknown"
        _add_unique(candidates, {"availability": "described_only", "text": None, "text_hash": None, "fuzzy_hash": None, "purpose": purpose, "structural_features": structural, "constraints": constraints, "target_model": target_model, "effectiveness": effectiveness, "evidence_ids": [_evidence(event, block, match)]}, ("purpose", "target_model"))
        if len(candidates) >= 4:
            break
    return candidates


def _extract_code_style(event: dict, context: list[dict]) -> list[dict]:
    rules = [
        (r"metamorphic script|self-modification|rewrite the malware's entire source code", "运行时自我重写/变形机制", "报告将其描述为持续变化或自我重写设计"),
        (r"decomposed complex multi-stage attacks", "编排器—子代理任务分解", "复杂攻击被拆分为离散技术任务"),
        (r"incomplete features are commented out|function.*commented out", "存在被注释或未完成的功能", "实现状态可能仍处于研发阶段"),
    ]
    items = []
    for pattern, feature, assessment in rules:
        hit = _find(context, pattern)
        if hit:
            _add_unique(items, {"observed_feature": feature, "feature_location": hit[0].get("section"), "report_assessment": assessment, "generation_assessment": "not_claimed", "alternative_explanation": None, "evidence_ids": [_evidence(event, *hit)]}, ("observed_feature",))
    return items


def _extract_artifacts(event: dict, candidate: dict, context: list[dict], event_type: str) -> list[dict]:
    artifacts: list[dict] = []
    names = [candidate["name"], *candidate.get("aliases", [])]
    if event_type in {"malware_operation", "ransomware", "proof_of_concept"} or any(hint.lower() in " ".join(ROLE_WORDS).lower() for hint in candidate.get("hints", [])):
        artifacts.append({"artifact_id": stable_id("artifact", event["event_id"], candidate["name"]), "family": candidate["name"], "aliases": candidate.get("aliases", []), "sha256": [], "file_names": [], "role": None, "language": None, "file_type": None, "packer": None, "scope": "family", "evidence_ids": list(event["identity"]["evidence_ids"])})
    implant = _find(context, r"(?:implant|payload).*?(?:refers to as|named)\s+[\"']?([A-Z][A-Za-z0-9-]{3,})")
    if implant:
        family = implant[1].group(1)
        artifacts.append({"artifact_id": stable_id("artifact", event["event_id"], family), "family": family, "aliases": [], "sha256": [], "file_names": [], "role": "implant", "language": None, "file_type": None, "packer": None, "scope": "artifact_only", "evidence_ids": [_evidence(event, *implant)]})
    for artifact in artifacts:
        terms = [artifact["family"], *artifact["aliases"]]
        for block in context:
            if not any(term and re.search(re.escape(term), block.get("text", ""), re.I) for term in terms):
                continue
            hashes = [value.lower() for value in SHA256_RE.findall(block["text"])]
            if hashes:
                artifact["sha256"].extend(hashes)
                artifact["scope"] = "sample_set" if len(hashes) > 1 else "exact_sample"
                match = re.search(re.escape(hashes[0]), block["text"], re.I)
                if match:
                    artifact["evidence_ids"].append(_evidence(event, block, match))
        joined = " ".join(block["text"] for block in context[:80])
        for label, role in ROLE_WORDS.items():
            if re.search(rf"{re.escape(artifact['family'] or '')}.{{0,80}}{re.escape(label)}|{re.escape(label)}.{{0,80}}{re.escape(artifact['family'] or '')}", joined, re.I):
                artifact["role"] = role
                break
        for language in LANGUAGES:
            if re.search(rf"(?:written|compiled) in {re.escape(language)}", joined, re.I):
                artifact["language"] = "Go" if language == "Golang" else language
                break
        if "PyInstaller" in joined:
            artifact["packer"] = "PyInstaller"
        artifact["sha256"] = list(dict.fromkeys(artifact["sha256"]))
        artifact["evidence_ids"] = list(dict.fromkeys(artifact["evidence_ids"]))
    return artifacts


def _extract_attribution(event: dict, context: list[dict], candidate: dict) -> dict:
    actors = []
    hit = _find(context, r"(?:Russian government-backed actor\s+)?(APT\d+)(?:\s*\(aka\s+([A-Z][A-Z0-9-]+)\))?")
    if hit:
        actors.append({"name": hit[1].group(1), "aliases": [hit[1].group(2)] if hit[1].group(2) else [], "actor_type": "state_sponsored" if "government-backed" in hit[0]["text"].lower() else "unknown", "country_or_region": "Russia" if "Russian" in hit[0]["text"] else None, "confidence": "high" if "government-backed" in hit[0]["text"].lower() else "not_stated", "basis": ["report_author_assessment"], "limitations": [], "evidence_ids": [_evidence(event, *hit)]})
    hit = _find(context, r"high confidence.*?Chinese state-sponsored group")
    if hit:
        actors.append({"name": candidate["name"], "aliases": candidate.get("aliases", []), "actor_type": "state_sponsored", "country_or_region": "China", "confidence": "high", "basis": ["report_author_assessment"], "limitations": [], "evidence_ids": [_evidence(event, *hit)]})
    hit = _find(context, r"(?:operators? are part of a )?group tracked as\s+([A-Z][A-Za-z0-9-]{3,30})")
    if hit:
        _add_unique(actors, {"name": hit[1].group(1), "aliases": [], "actor_type": "cybercrime", "country_or_region": None, "confidence": "not_stated", "basis": ["report_author_assessment"], "limitations": [], "evidence_ids": [_evidence(event, *hit)]}, ("name",))
    return {"actors": actors}


def _extract_targets(event: dict, context: list[dict]) -> list[dict]:
    items = []
    rules = [
        (r"malware against Ukraine|against Ukraine", None, None, "Ukraine", "targeted"),
        (r"targeting Thailand's Ministry of Finance|Thailand's Ministry of Finance Targeted", "Thailand Ministry of Finance", "government/public finance", "Thailand", "compromised"),
        (r"(?:targeted\s+)?roughly 30 entities", "roughly 30 entities", "technology and government among others", None, "targeted"),
        (r"主要针对阿根廷用户|针对阿根廷用户", "阿根廷用户", None, "Argentina", "targeted"),
    ]
    for pattern, name, sector, region, status in rules:
        hit = _find(context, pattern)
        if hit:
            _add_unique(items, {"name": name, "sector": sector, "country_or_region": region, "status": status, "evidence_ids": [_evidence(event, *hit)]}, ("name", "country_or_region"))
    return items


def _extract_involvement(event: dict, context: list[dict]) -> dict:
    joined = " ".join(block["text"] for block in context)
    roles, stages, evidence_ids = [], [], []
    rules = [
        (r"rewrite.*(?:source code|malware)|self-modification|regeneration", "self_rewriter", "execution"),
        (r"generate(?:s|d)? commands|commands for execution", "command_generator", "execution"),
        (r"autonomous AI agent|autonomous penetration testing orchestrators", "autonomous_operator", "post_compromise"),
        (r"bypass detection|evasion", "analysis_evasion", "analysis_evasion"),
    ]
    for pattern, role, stage in rules:
        hit = _find(context, pattern)
        if hit:
            roles.append(role); stages.append(stage); evidence_ids.append(_evidence(event, *hit))
    autonomy = "unattended" if re.search(r"unattended|YOLO mode", joined, re.I) else ("human_on_loop" if re.search(r"80-90%|minimal human oversight", joined, re.I) else "unknown")
    output = "blindly_executed" if re.search(r"blindly executed|then executes the commands", joined, re.I) else ("saved_to_file" if re.search(r"saved? (?:to|the new)|saving the new", joined, re.I) else "unknown")
    human_role = "目标选择与高层决策" if re.search(r"targets selected by human|human operators", joined, re.I) else None
    return {"roles": list(dict.fromkeys(roles)), "stages": list(dict.fromkeys(stages)), "autonomy_level": autonomy, "human_role": human_role, "output_handling": output, "evidence_ids": list(dict.fromkeys(evidence_ids))}


def _extract_behaviors_outcomes_limitations(event: dict, context: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    behaviors, outcomes, limitations = [], [], []
    behavior_rules = [
        (r"Startup folder.*persistence", "persistence", "将重写后的版本保存到启动目录建立持久化"),
        (r"removable drives.*network shares", "propagation", "复制到可移动驱动器和网络共享"),
        (r"filesystem reconnaissance.*data exfiltration", "execution", "执行文件系统侦察、数据外传和文件加密"),
        (r"blindly executed locally|executes the commands.*sends the collected data", "execution", "执行LLM生成的本地命令并外传结果"),
        (r"enumerating ministry hosts.*traversing files", "post_compromise", "枚举主机、遍历文件并收集相邻主机信息"),
        (r"reconnaissance, vulnerability discovery, exploitation, lateral movement", "full_attack_lifecycle", "覆盖侦察、漏洞发现与利用、横向移动、凭据收集和外传"),
    ]
    for pattern, stage, description in behavior_rules:
        hit = _find(context, pattern)
        if hit:
            _add_unique(behaviors, {"stage": stage, "behavior": description, "evidence_ids": [_evidence(event, *hit)]}, ("behavior",))
    outcome_rules = [
        (r"compromise multiple systems", "confirmed_intrusion", "在目标网络中攻陷多个系统"),
        (r"validated a handful of successful intrusions", "confirmed_intrusion", "确认少量目标被成功入侵"),
        (r"data exfiltration|exfiltrated", "data_exfiltration", "报告描述了数据外传"),
    ]
    for pattern, kind, description in outcome_rules:
        hit = _find(context, pattern)
        if hit:
            _add_unique(outcomes, {"type": kind, "status": "confirmed", "description": description, "evidence_ids": [_evidence(event, *hit)]}, ("type", "description"))
    limitation_rules = [
        (r"does not demonstrate an ability to compromise|does not have the ability to compromise", "capability_not_observed", "当前状态未展示攻陷受害网络或设备的能力"),
        (r"function.*commented out|incomplete features are commented out", "feature_not_active", "部分功能被注释或尚未完成"),
        (r"initial access was.*not.*evident", "initial_access_unknown", "无法从报告材料确定初始访问方式"),
        (r"do not have evidence confirming or denying VShell", "tool_use_unconfirmed", "无法确认或否认VShell是否用于目标"),
        (r"frequently overstated.*fabricated data|hallucination", "model_reliability", "模型会夸大或编造结果，需要人工验证"),
        (r"stolen API tokens|keys were leaked", "credential_origin", "API凭据可能被盗或来自泄露"),
    ]
    for pattern, kind, description in limitation_rules:
        hit = _find(context, pattern)
        if hit:
            _add_unique(limitations, {"type": kind, "description": description, "evidence_ids": [_evidence(event, *hit)]}, ("type", "description"))
    return behaviors, outcomes, limitations


def extract_event(candidate: dict, blocks: list[dict], report_id: str, *, context: list[dict] | None = None) -> dict:
    context = context if context is not None else _event_context(blocks, candidate, full=False)
    event_id = stable_id("event", report_id, candidate["name"])
    event = {"event_id": event_id, "identity": {}, "time": {}, "status": {}, "artifacts": [], "attribution": {"actors": []}, "targets": [], "ai_involvement": {}, "ai_signals": {"toolchain": [], "prompts": [], "code_style": []}, "key_behaviors": [], "outcomes": [], "limitations": [], "evidence": []}
    name_pattern = "|".join(re.escape(value) for value in [candidate["name"], *candidate.get("aliases", []), candidate["name"].split()[0]])
    name_hits = []
    for block in context:
        match = re.search(name_pattern, block.get("text", ""), re.I)
        if match:
            explicit = bool(re.search(r"identified|discovered|observed|detected|tracked as|named|发现|识别|检测|观察|命名", block["text"], re.I))
            name_hits.append((1 if explicit else 0, -block.get("index", 0), block, match))
    best_name_hit = max(name_hits, default=None, key=lambda item: (item[0], item[1]))
    name_hit = (best_name_hit[2], best_name_hit[3]) if best_name_hit else None
    identity_evidence = [_evidence(event, *name_hit)] if name_hit else []
    context_text = " ".join(block["text"] for block in context)
    event_type = _infer_event_type(context_text, candidate.get("hints", []))
    event["identity"] = {"event_name": candidate["name"], "aliases": candidate.get("aliases", []), "event_type": event_type, "evidence_ids": identity_evidence}
    event["time"] = _extract_time(event, context)
    event["status"] = _extract_status(event, context, [candidate["name"], *candidate.get("aliases", [])])
    event["artifacts"] = _extract_artifacts(event, candidate, context, event_type)
    event["attribution"] = _extract_attribution(event, context, candidate)
    event["targets"] = _extract_targets(event, context)
    event["ai_involvement"] = _extract_involvement(event, context)
    event["ai_signals"]["toolchain"] = _extract_toolchain(event, context, candidate.get("aliases") or [candidate["name"].split()[0]])
    event["ai_signals"]["prompts"] = _extract_prompts(event, context, event["ai_signals"]["toolchain"])
    event["ai_signals"]["code_style"] = _extract_code_style(event, context)
    event["key_behaviors"], event["outcomes"], event["limitations"] = _extract_behaviors_outcomes_limitations(event, context)
    return event


def _date_value(raw: str | None) -> dict:
    raw = normalize_space(raw) or None
    if not raw:
        return {"value": None, "precision": "unknown", "raw": None}
    iso = re.search(r"(20\d{2})[-/]([01]?\d)[-/]([0-3]?\d)", raw)
    if iso:
        return {"value": f"{int(iso.group(1)):04d}-{int(iso.group(2)):02d}-{int(iso.group(3)):02d}", "precision": "day", "raw": raw}
    year = re.search(r"(20\d{2})", raw)
    return {"value": year.group(1) if year else None, "precision": "year" if year else "unknown", "raw": raw}


def _validate_evidence(result: dict, blocks: list[dict]) -> list[str]:
    block_map = {block["block_id"]: block for block in blocks}
    errors = []
    for event in result["events"]:
        evidence_ids = {item["evidence_id"] for item in event["evidence"]}
        for evidence in event["evidence"]:
            block = block_map.get(evidence["block_id"])
            if not block or evidence["excerpt"] not in block["text"]:
                errors.append(f"{event['identity']['event_name']}: evidence不能回指原文")
        refs = [event["identity"]["evidence_ids"], event["time"]["evidence_ids"], event["status"]["evidence_ids"], event["ai_involvement"]["evidence_ids"]]
        for key in ["artifacts", "targets", "key_behaviors", "outcomes", "limitations"]:
            refs.extend(item["evidence_ids"] for item in event[key])
        refs.extend(actor["evidence_ids"] for actor in event["attribution"]["actors"])
        for key in ["toolchain", "prompts", "code_style"]:
            refs.extend(item["evidence_ids"] for item in event["ai_signals"][key])
        for group in refs:
            for ref in group:
                if ref not in evidence_ids:
                    errors.append(f"{event['identity']['event_name']}: evidence引用不存在 {ref}")
    return errors


def _llm_context(context: list[dict], limit: int = 14000) -> list[dict]:
    priorities = []
    pattern = re.compile(
        r"AI|LLM|model|prompt|API|agent|actor|target|victim|intrusion|malware|ransomware|country|region|autonom|limitation|unable|not observed|"
        r"模型|提示词|智能体|攻击者|威胁组织|目标|受害者|入侵|恶意软件|勒索软件|国家|地区|自治|归因|限制|无法|未观察|确认|可能",
        re.I,
    )
    for block in context:
        score = 2 if pattern.search(block.get("text", "")) else 0
        score += 1 if block.get("kind") in {"heading", "table"} else 0
        priorities.append((score, block["index"], block))
    chosen, size = [], 0
    for _, _, block in sorted(priorities, key=lambda item: (-item[0], item[1])):
        cost = len(block["text"]) + 100
        if chosen and size + cost > limit:
            continue
        chosen.append(block); size += cost
        if size >= limit:
            break
    return sorted(chosen, key=lambda block: block["index"])


def _merge_llm_event(event: dict, converted: dict) -> int:
    entities = {entity["entity_id"]: entity for entity in converted.get("entities", [])}
    added = 0
    for claim in converted.get("claims", []):
        evidence = claim.get("evidence", [None])[0]
        if not evidence:
            continue
        excerpt = evidence["excerpt"]
        evidence_id = stable_id("evidence", evidence["block_id"], excerpt)
        if not any(item["evidence_id"] == evidence_id for item in event["evidence"]):
            event["evidence"].append({"evidence_id": evidence_id, "block_id": evidence["block_id"], "page": evidence["locator"].get("page"), "section": evidence.get("section"), "excerpt": excerpt, "excerpt_sha256": sha256_text(excerpt)})
        obj = claim.get("object", {})
        entity = entities.get(obj.get("entity_id")) if obj.get("entity_id") else None
        value = normalize_space(str(entity.get("name") if entity else obj.get("value") or ""))
        if not value:
            continue
        predicate = claim.get("predicate")
        if predicate == "uses_model":
            if re.search(r"\bGPT[- ]?4\b", value, re.I):
                value = "GPT-4"
            elif re.search(r"\bgpt[- ]?3\.5[- ]turbo\b", value, re.I):
                value = "gpt-3.5-turbo"
            elif re.search(r"\bgpt[- ]?oss[- : ]?20b\b", value, re.I):
                value = "gpt-oss-20b"
            value_key = re.sub(r"[^a-z0-9]", "", value.lower())
            existing = next((item for item in event["ai_signals"]["toolchain"] if re.sub(r"[^a-z0-9]", "", str(item.get("model") or "").lower()) == value_key), None)
            if existing:
                existing["evidence_ids"] = list(dict.fromkeys([*existing["evidence_ids"], evidence_id]))
            else:
                event["ai_signals"]["toolchain"].append({"raw_value": value, "provider": None, "family": None, "model": value, "service": None, "endpoint": None, "sdk_or_library": None, "agent_or_protocol": None, "deployment": "unknown", "purpose": None, "stage": None, "evidence_ids": [evidence_id]})
            added += 1
        elif predicate == "uses_provider":
            if re.search(r"\bOpenAI\b", value, re.I):
                value = "OpenAI"
            elif re.search(r"\bGoogle(?: Gemini)?\b", value, re.I):
                value = "Google"
            elif re.search(r"\bHugging\s*Face\b", value, re.I):
                value = "Hugging Face"
            value_key = re.sub(r"[^a-z0-9]", "", value.lower())
            existing = next((item for item in event["ai_signals"]["toolchain"] if re.sub(r"[^a-z0-9]", "", str(item.get("provider") or "").lower()) == value_key), None)
            if existing:
                existing["evidence_ids"] = list(dict.fromkeys([*existing["evidence_ids"], evidence_id]))
            else:
                event["ai_signals"]["toolchain"].append({"raw_value": value, "provider": value, "family": None, "model": None, "service": None, "endpoint": None, "sdk_or_library": None, "agent_or_protocol": None, "deployment": "unknown", "purpose": None, "stage": None, "evidence_ids": [evidence_id]})
            added += 1
        elif predicate == "uses_agent":
            value_key = re.sub(r"[^a-z0-9]", "", value.lower())
            service_match = next((item for item in event["ai_signals"]["toolchain"] if re.sub(r"[^a-z0-9]", "", str(item.get("service") or "").lower()) == value_key), None)
            if service_match and value.lower().endswith("api"):
                service_match["evidence_ids"] = list(dict.fromkeys([*service_match["evidence_ids"], evidence_id]))
            else:
                _add_unique(event["ai_signals"]["toolchain"], {"raw_value": value, "provider": None, "family": None, "model": None, "service": None, "endpoint": None, "sdk_or_library": None, "agent_or_protocol": value, "deployment": "unknown", "purpose": None, "stage": None, "evidence_ids": [evidence_id]}, ("agent_or_protocol", "purpose"))
            added += 1
        elif predicate == "attributed_to":
            actor = {"name": value, "aliases": [], "actor_type": "unknown", "country_or_region": None, "confidence": {"explicit_high": "high", "explicit_medium": "medium", "explicit_low": "low"}.get(claim.get("author_confidence"), "not_stated"), "basis": ["report_author_assessment"], "limitations": [], "evidence_ids": [evidence_id]}
            if re.fullmatch(r"UAC-\d+", value, re.I):
                apt_actor = next((item for item in event["attribution"]["actors"] if re.fullmatch(r"APT\d+", item.get("name", ""), re.I)), None)
                if apt_actor:
                    apt_actor["aliases"] = list(dict.fromkeys([*apt_actor.get("aliases", []), value]))
                    apt_actor["evidence_ids"] = list(dict.fromkeys([*apt_actor["evidence_ids"], evidence_id]))
                else:
                    _add_unique(event["attribution"]["actors"], actor, ("name",))
            else:
                _add_unique(event["attribution"]["actors"], actor, ("name",))
            added += 1
        elif predicate == "targets":
            target = {"name": value if entity and entity.get("entity_type") == "victim" else None, "sector": None, "country_or_region": value if entity and entity.get("entity_type") == "region" else None, "status": "targeted", "evidence_ids": [evidence_id]}
            value_key = "".join(character for character in value.lower() if character.isalnum())
            existing = next((
                item for item in event["targets"]
                if value_key and value_key in {
                    "".join(character for character in str(item.get("name") or "").lower() if character.isalnum()),
                    "".join(character for character in str(item.get("country_or_region") or "").lower() if character.isalnum()),
                }
            ), None)
            if existing:
                existing_region_key = "".join(character for character in str(existing.get("country_or_region") or "").lower() if character.isalnum())
                target_name_key = "".join(character for character in str(target.get("name") or "").lower() if character.isalnum())
                if target_name_key != existing_region_key:
                    existing["name"] = existing.get("name") or target.get("name")
                existing["country_or_region"] = existing.get("country_or_region") or target.get("country_or_region")
                existing["evidence_ids"] = list(dict.fromkeys([*existing["evidence_ids"], evidence_id]))
            else:
                event["targets"].append(target)
            added += 1
        elif predicate == "has_ai_role":
            event["ai_involvement"]["roles"] = list(dict.fromkeys([*event["ai_involvement"]["roles"], value])); event["ai_involvement"]["evidence_ids"] = list(dict.fromkeys([*event["ai_involvement"]["evidence_ids"], evidence_id])); added += 1
        elif predicate == "has_autonomy_level":
            normalized = value.lower().replace("-", "_").replace(" ", "_")
            event["ai_involvement"]["autonomy_level"] = normalized if normalized in {"advisory", "human_in_loop", "human_on_loop", "unattended"} else event["ai_involvement"]["autonomy_level"]
            event["ai_involvement"]["evidence_ids"] = list(dict.fromkeys([*event["ai_involvement"]["evidence_ids"], evidence_id])); added += 1
        elif predicate == "has_human_role":
            event["ai_involvement"]["human_role"] = value; event["ai_involvement"]["evidence_ids"] = list(dict.fromkeys([*event["ai_involvement"]["evidence_ids"], evidence_id])); added += 1
        elif predicate == "uses_prompt":
            _add_unique(event["ai_signals"]["prompts"], {"availability": "described_only", "text": None, "text_hash": None, "fuzzy_hash": None, "purpose": value, "structural_features": {"role_definition": False, "output_only": False, "code_only": False, "single_line_command": False, "self_modification": False, "evasion": False, "jailbreak": False, "safety_framing": False}, "constraints": [], "target_model": None, "effectiveness": "unknown", "evidence_ids": [evidence_id]}, ("purpose", "target_model")); added += 1
        elif predicate == "has_code_style_feature":
            _add_unique(event["ai_signals"]["code_style"], {"observed_feature": value, "feature_location": evidence.get("section"), "report_assessment": None, "generation_assessment": "unknown", "alternative_explanation": None, "evidence_ids": [evidence_id]}, ("observed_feature",)); added += 1
        elif predicate == "performs_technique":
            _add_unique(event["key_behaviors"], {"stage": None, "behavior": value, "evidence_ids": [evidence_id]}, ("behavior",)); added += 1
        elif predicate == "limits_or_contradicts":
            _add_unique(event["limitations"], {"type": "llm_extracted_limitation", "description": value, "evidence_ids": [evidence_id]}, ("type", "description")); added += 1
    return added


def extract_report_events_v3(source_path: str | Path, *, canonical_url: str | None = None, output_dir: str | Path | None = None, schema_path: str | Path | None = None, use_llm: bool = False, target_event: dict | None = None) -> dict:
    source = Path(source_path)
    digest = sha256_bytes(source.read_bytes())
    report_id = stable_id("report", canonical_url or source.name, digest)
    parsed = parse_document(source, report_id)
    blocks = parsed["blocks"]
    candidates = discover_events(blocks, parsed.get("title"), target_event=target_event)
    contexts = build_event_contexts(blocks, candidates)
    if target_event:
        target_terms = {
            normalize_space(str(value)).lower()
            for value in [target_event.get("name"), *target_event.get("aliases", [])]
            if value
        }
        for candidate in candidates:
            candidate_terms = {
                normalize_space(str(value)).lower()
                for value in [candidate["name"], *candidate.get("aliases", [])]
                if value
            }
            if target_terms & candidate_terms:
                contexts[candidate["name"]] = build_target_context(blocks, candidate, candidates)
    events = [extract_event(candidate, blocks, report_id, context=contexts.get(candidate["name"], [])) for candidate in candidates]
    report = {
        "report_id": report_id, "title": parsed.get("title") or source.stem,
        "publisher": urlsplit(canonical_url).hostname if canonical_url else None,
        "publication_date": _date_value(parsed.get("publication_date")), "url": canonical_url,
        "file_name": source.name, "content_type": parsed["content_type"], "language": parsed.get("language"),
        "content_sha256": digest,
    }
    result = {"schema_version": "0.3", "report": report, "events": events, "extraction": {"pipeline_version": "0.3", "extractors": [{"name": "document-parser", "version": parsed["content_type"]}, {"name": "deterministic-event-index", "version": "0.3"}, {"name": "evidence-field-rules", "version": "0.3"}], "validation_status": "passed", "review_status": "not_reviewed", "errors": []}}
    llm_candidates = {}
    llm_validated = {}
    if use_llm:
        llm_models = set()
        llm_events = events
        if target_event:
            target_terms = {
                normalize_space(str(value)).lower()
                for value in [target_event.get("name"), *target_event.get("aliases", [])]
                if value
            }
            llm_events = [
                event for event in events
                if target_terms & {
                    normalize_space(str(value)).lower()
                    for value in [event["identity"]["event_name"], *event["identity"].get("aliases", [])]
                    if value
                }
            ]
        for event in llm_events:
            name = event["identity"]["event_name"]
            try:
                candidate = extract_with_deepseek(_llm_context(contexts.get(name, [])))
                llm_candidates[name] = candidate
                if candidate.get("model"):
                    llm_models.add(candidate["model"])
                event_aliases = [name, *event["identity"].get("aliases", [])]
                converted = validate_and_convert_llm(
                    report_id,
                    contexts.get(name, []),
                    candidate,
                    allowed_subject_names=event_aliases,
                )
                llm_validated[name] = converted
                added = _merge_llm_event(event, converted)
                for warning in converted["warnings"]:
                    result["extraction"]["errors"].append({"stage": "llm_validation", "event": name, "message": warning, "recoverable": True})
                for chunk_error in candidate.get("chunk_errors", []):
                    result["extraction"]["errors"].append({"stage": "llm_extraction", "event": name, "message": chunk_error["message"], "recoverable": True})
                if added:
                    result["extraction"]["review_status"] = "needs_review"
            except Exception as exc:
                result["extraction"]["errors"].append({"stage": "llm_extraction", "event": name, "message": str(exc), "recoverable": True})
        result["extraction"]["extractors"].append({"name": "deepseek-event-enrichment", "version": ",".join(sorted(llm_models)) or "configured-model"})
    errors = _validate_evidence(result, blocks)
    if schema_path:
        schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
        errors.extend(error.message for error in Draft202012Validator(schema).iter_errors(result))
    if errors:
        result["extraction"]["validation_status"] = "failed"
        result["extraction"]["errors"].extend({"stage": "validation", "message": message} for message in errors)
    elif result["extraction"]["errors"]:
        result["extraction"]["validation_status"] = "warnings"
    if output_dir:
        out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
        write_json(out / "report.json", report); write_json(out / "blocks.json", blocks); write_json(out / "event_index.json", candidates)
        if llm_candidates:
            write_json(out / "llm_candidates.json", llm_candidates)
        if llm_validated:
            write_json(out / "llm_validated_claims.json", llm_validated)
        write_json(out / "report_events.json", result)
    return result

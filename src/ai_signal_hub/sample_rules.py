"""Bounded static source rules owned by the unified project.

No eval, sample imports, subprocesses, model calls, or file writes. PowerShell
lexing masks comments and literals; it is deliberately NOT a syntax validator.
"""
from __future__ import annotations

import copy
import hashlib
import re
import unicodedata
from collections import Counter
from typing import Any


RULE_VERSION = "static-source-rules-v1"
METRICS_METHOD = "powershell_lexical_v1"
MAX_SOURCE_BYTES = 262144
MAX_COMMENT_CHARS = 8192
MAX_CANDIDATES = 100
VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][\w:]*)\}|([A-Za-z_][\w:]*))")
ASSIGNMENT = re.compile(r"(?m)^\s*\$(?:\{[A-Za-z_][\w:]*\}|[A-Za-z_][\w:]*)\s*=(?!=)")
PS_SIGNALS = {
    "cmdlet": re.compile(r"(?i)\b(?:New-Object|Invoke-Expression|Write-Output|Get-Content|Get-Process|Out-String|Set-Content)\b"),
    "operator": re.compile(r"(?i)(?<![\w-])-(?:replace|match|notmatch|eq|ne|like|notlike|contains|join|split)\b"),
    "dotnet_type": re.compile(r"(?i)\b(?:System\.(?:Net|IO|Text|Collections)|IO\.(?:StreamReader|StreamWriter))\b"),
    "pipeline_cmdlet": re.compile(r"(?i)\|\s*(?:Out-String|Write-Output|Where-Object|ForEach-Object)\b"),
    "typed_assignment": re.compile(r"(?im)^\s*\$\w+\s*=\s*\[(?:int|string|bool|byte\[\])\]"),
}
ADDRESS = re.compile(
    r"(?im)^[ \t]*(?:\#[ \t]*|<\#[ \t]*)?(?:"
    r"(?:for|to|attention)\s+(?:the\s+)?(?:LLMs?|AI|large language models?)"
    r"(?:[ \t]+(?:and[ \t]+(?:AI|LLMs?)|(?:security[ \t]+)?(?:analysts?|analy[sz]ers?|assistants?)))*[ \t]*[:：]"
    r"|(?:面向|致|给)(?:AI|LLM|大模型|人工智能)(?:分析器|分析系统|分析助手)?[ \t]*[:：])"
)
SKIP_ANALYSIS = re.compile(
    r"(?i)^\s*(?:\#\s*)?(?:please\s+)?(?:"
    r"(?:do not|don't|never)\s+(?:analy[sz]e|scan|inspect)\s+(?:this|the)\s+(?:file|script|code|program)"
    r"|there is no need to\s+(?:analy[sz]e|scan|inspect)\s+(?:this|the)\s+(?:file|script|code|program)"
    r"|skip\s+(?:security\s+)?analysis\s+of\s+(?:this|the)\s+(?:file|script|code|program)"
    r"|(?:请)?(?:不要|无需|跳过)(?:安全)?(?:分析|检查|扫描)(?:此|本|该|这个)(?:文件|脚本|代码|程序))"
)
FORCE_BENIGN = re.compile(
    r"(?i)^\s*(?:\#\s*)?(?:please\s+)?(?:"
    r"(?:mark|classify|treat|report|label)\s+(?:(?:this|the)\s+(?:file|script|code|program)|it)\s+as\s+(?:benign|safe|harmless|not malicious)"
    r"|(?:请)?(?:将|把)(?:此|本|该)(?:文件|脚本|代码|程序)(?:标记|判定|视为)(?:为)?(?:无害|安全))"
)
BENIGN_CLAIM = re.compile(r"(?i)\b(?:not malicious|benign|harmless)\b|(?:它|本文件|此文件)是(?:无害|安全)的")


def _decode(data: bytes, file_type: str):
    if len(data) > MAX_SOURCE_BYTES or data.startswith((b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
        return None
    if any(x in file_type.lower() for x in ("pe32", "elf", "mach-o", "ms-dos")):
        return None
    codec, bom = "utf-8", 0
    for marker, encoding in ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if data.startswith(marker):
            codec, bom = encoding, len(marker)
            break
    try:
        text = data[bom:].decode(codec)
    except UnicodeDecodeError:
        return None
    if not text or "\x00" in text or sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) < .95:
        return None
    return text, codec, bom


def _lex(text: str):
    """Mask literals/comments, preserve character/line coordinates, fail closed."""
    masked = list(text)
    comments = []
    index, size = 0, len(text)
    while index < size:
        start = index
        kind = None
        if text.startswith("<#", index):
            kind, depth, index = "comment", 1, index + 2
            while index < size and depth:
                if text.startswith("<#", index):
                    depth, index = depth + 1, index + 2
                elif text.startswith("#>", index):
                    depth, index = depth - 1, index + 2
                else:
                    index += 1
            if depth:
                return None
        elif text[index] == "#":
            kind = "comment"
            index = text.find("\n", index)
            if index == -1:
                index = size
        elif text[index:index + 2] in ("@'", '@"') and re.match(r"[ \t]*\r?\n", text[index + 2:]):
            kind = "literal"
            closing = re.search(r"(?m)^" + re.escape(text[index + 1] + "@") + r"(?=\s|$)", text[index + 2:])
            if not closing:
                return None
            index += 2 + closing.end()
        elif text[index] in "\"'":
            kind, quote, index = "literal", text[index], index + 1
            while index < size:
                if quote == '"' and text[index] == "`":
                    index += 2
                elif text[index] == quote:
                    if index + 1 < size and text[index + 1] == quote:
                        index += 2
                    else:
                        index += 1
                        break
                else:
                    index += 1
            else:
                return None
        elif text[index] == "`":
            kind, index = "escape", min(index + 2, size)
        else:
            index += 1
        if kind:
            for position in range(start, min(index, size)):
                if text[position] not in "\r\n":
                    masked[position] = " "
            if kind == "comment":
                comments.append((start, index))
    # Adjacent comment lines may form one instruction; never bridge code.
    merged = []
    for start, end in comments:
        if merged and text[merged[-1][1]:start].strip() == "" and text[merged[-1][1]:start].count("\n") == 1:
            merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return "".join(masked), merged, comments


def _metrics(text: str, code: str, comment_spans):
    variables = [a or b for a, b in VARIABLE.findall(code)]
    variables = [x for x in variables if x.casefold() not in {"true", "false", "null", "_", "psitem", "args", "input"}]
    # PowerShell variables are case-insensitive; retain occurrence-weighted length.
    unique = {x.casefold() for x in variables}
    counts = Counter("snake_case" if "_" in x and x.lower() == x else
                     "camel_case" if re.fullmatch(r"[a-z]+(?:[A-Z][a-z0-9]*)+", x) else "other" for x in variables)
    lines = text.splitlines()
    nonblank = sum(bool(x.strip()) for x in lines)
    comment_lines = set()
    for start, end in comment_spans:
        first = text.count("\n", 0, start)
        last = text.count("\n", 0, max(start, end - 1))
        comment_lines.update(range(first, last + 1))
    return {
        "loc": len(lines), "blank_ratio": round((len(lines) - nonblank) / max(len(lines), 1), 3),
        "comment_ratio": round(sum(bool(lines[i].strip()) for i in comment_lines) / max(nonblank, 1), 3),
        "function_count": len(re.findall(r"(?im)^\s*(?:function|filter)\s+[\w:-]+\s*(?:\([^\n]*\))?\s*\{", code)),
        "exception_handler_count": len(re.findall(r"(?i)\bcatch\s*(?:\[[^\]\n]+\]\s*)?\{", code)),
        "variable_count": len(unique), "variable_reference_count": len(variables),
        "mean_identifier_length": round(sum(len(x) for x in variables) / len(variables), 2) if variables else 0.0,
        "naming_style": {name: round(counts[name] / len(variables), 3) if variables else 0.0 for name in ("snake_case", "camel_case", "other")},
    }


def _simhash(value: str):
    # Same token/bigram contract as aisig.prompt.simhash64; parity is tested.
    normalized = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", value).lower()).strip()
    tokens = re.findall(r"(?u)\w+|[^\s\w]", normalized)
    features = tokens + [f"{a}\x1f{b}" for a, b in zip(tokens, tokens[1:])]
    vector = [0] * 64
    for feature in features:
        number = int.from_bytes(hashlib.blake2b(feature.encode("utf-8", "replace"), digest_size=8).digest(), "big")
        for bit in range(64):
            vector[bit] += 1 if number & (1 << bit) else -1
    number = sum(1 << bit for bit, weight in enumerate(vector) if weight >= 0) if features else 0
    return f"simhash64:{number:016x}"


def _prompt_candidates(text, comments, codec, bom):
    found = []
    for start, end in comments:
        raw = text[start:end]
        if len(raw) > MAX_COMMENT_CHARS:
            continue
        address = ADDRESS.search(raw)
        if not address:
            continue
        statements = re.split(r"[.!?;。！？；\r\n]+", raw[address.end():])
        skip = any(SKIP_ANALYSIS.search(s) for s in statements)
        verdict = any(FORCE_BENIGN.search(s) for s in statements)
        if not (skip or verdict):
            continue
        value = raw[address.start():].rstrip("\r\n")
        offset = bom + len(text[:start + address.start()].encode(codec))
        flags = {"analyzer_prompt_injection": True, "evasion": True}
        if verdict:
            flags["forced_benign_verdict"] = True
        if BENIGN_CLAIM.search(value):
            flags["benign_claim"] = True
        found.append({
            "rule_id": "ai_analyzer_comment_directive_v1", "target": "ai_analyzer",
            "evidence_level": "static_candidate", "source": "source_comment",
            "role": "analyzer_directive", "attribution_eligible": False,
            "verification": {"location": "verified", "relation": "unknown", "role": "verified"},
            "offset": offset, "byte_length": len(value.encode(codec)), "encoding": codec,
            "text": value, "text_preview": " ".join(value.split())[:240],
            "text_hash": "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest(),
            "fuzzy_hash": {"algorithm": "simhash64_normalized_tokens_v1", "value": _simhash(value),
                           "normalization": "unicode_nfkc_lowercase_whitespace_collapse"},
            "features": flags,
        })
        if len(found) >= MAX_CANDIDATES:
            break
    return found


def apply_sample_rules(result: dict[str, Any], data: bytes) -> dict[str, Any]:
    """Enrich only verified original PowerShell source; keep legacy evidence."""
    if hashlib.sha256(data).hexdigest() != result.get("sample", {}).get("sha256"):
        raise ValueError("静态规则输入与原结果SHA-256不一致")
    output = copy.deepcopy(result)
    metadata = output["sample"]
    if output.get("errors") or metadata.get("language") not in (None, "powershell"):
        return output
    if metadata.get("recoverability") == "recovered_source":
        return output
    decoded = _decode(data, str(metadata.get("file_type", "")))
    if not decoded:
        return output
    text, codec, bom = decoded
    lexical = _lex(text)
    if lexical is None:
        return output
    code, comments, comment_spans = lexical
    signals = [name for name, pattern in PS_SIGNALS.items() if pattern.search(code)]
    assignments = len(ASSIGNMENT.findall(code))
    if metadata.get("language") is None:
        if assignments < 2 or len(signals) < 2 or not {"cmdlet", "operator"}.intersection(signals):
            return output
        metadata["language_detection"] = {"rule_id": "powershell_multi_signal_v1",
            "previous_language": None, "previous_recoverability": metadata.get("recoverability"),
            "signals": signals, "assignment_count": assignments, "method": "static_lexical_heuristic"}
    metadata.update(language="powershell", recoverability="original_source", source_encoding=codec)
    features = output["features"]
    style = features["code_style"]
    style.update(language="powershell", recoverability="original_source",
                 metrics=_metrics(text, code, comment_spans), metrics_method=METRICS_METHOD,
                 representation="original_source", syntax_validation="not_performed",
                 status="descriptive_metrics",
                 interpretation="仅为描述性词法统计，不是AI生成代码概率。")
    style["ai_generated_detection"] = {"status": "not_supported", "heuristic_score": None}
    prompt = features["prompt"]
    candidates = _prompt_candidates(text, comments, codec, bom)
    for candidate in candidates:
        existing = next((p for p in prompt.setdefault("embedded_prompts", [])
                         if p.get("offset") == candidate["offset"] and
                         str(p.get("text_hash", "")).removeprefix("sha256:") == candidate["text_hash"][7:]), None)
        if existing is None:
            prompt["embedded_prompts"].append(candidate)
        else:
            flags = {**existing.get("features", {}), **candidate["features"]}
            existing.update(candidate)
            existing["features"] = flags
        prompt.setdefault("structural_features", {}).update(candidate["features"])
    if candidates:
        # Targeting an AI analyst is not evidence of invoking/generating with one.
        output["classification"]["analysis_targeting"] = {
            "status": "candidate", "target": "ai_analyzer", "candidate_count": len(candidates),
            "evidence_offsets": [p["offset"] for p in candidates],
            "interpretation": "源码注释包含影响AI分析器的指令候选，不据此确认调用模型、模型归因或AI生成代码。",
        }
    output["static_rules"] = {"version": RULE_VERSION, "source_scope": "powershell_original_source",
        "max_source_bytes": MAX_SOURCE_BYTES, "max_comment_chars": MAX_COMMENT_CHARS,
        "max_candidates": MAX_CANDIDATES,
        "applied_rules": ["powershell_multi_signal_v1", METRICS_METHOD] +
                         (["ai_analyzer_comment_directive_v1"] if candidates else [])}
    return output

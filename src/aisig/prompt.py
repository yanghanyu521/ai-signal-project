from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Any


def normalize_prompt_template(value: str) -> str:
    """Normalize non-semantic formatting before generating a fuzzy template hash."""
    normalized = unicodedata.normalize("NFKC", value).lower()
    return re.sub(r"\s+", " ", normalized).strip()


def simhash64(value: str) -> str:
    """Return a deterministic 64-bit SimHash for a normalized prompt template.

    SimHash is used here rather than ssdeep because embedded prompts are often
    short. It tolerates case/whitespace differences and supports future
    similarity comparison through Hamming distance without an external binary.
    """
    normalized = normalize_prompt_template(value)
    tokens = re.findall(r"(?u)\w+|[^\s\w]", normalized)
    features = tokens + [f"{left}\x1f{right}" for left, right in zip(tokens, tokens[1:])]
    if not features:
        return "simhash64:0000000000000000"
    vector = [0] * 64
    for feature in features:
        digest = hashlib.blake2b(feature.encode("utf-8", "replace"), digest_size=8).digest()
        number = int.from_bytes(digest, "big")
        for bit in range(64):
            vector[bit] += 1 if number & (1 << bit) else -1
    result = sum(1 << bit for bit, weight in enumerate(vector) if weight >= 0)
    return f"simhash64:{result:016x}"


def simhash_hamming_distance(left: str, right: str) -> int:
    """Return the bit distance between two `simhash64:<hex>` values."""
    prefix = "simhash64:"
    if not left.startswith(prefix) or not right.startswith(prefix):
        raise ValueError("both fuzzy hashes must use the simhash64:<hex> format")
    return (int(left[len(prefix):], 16) ^ int(right[len(prefix):], 16)).bit_count()


def extract_prompt_features(
    strings: list[dict[str, Any]],
    rules: dict[str, Any],
    max_candidates: int,
    raw_data: bytes | None = None,
) -> dict[str, Any]:
    compiled = {name: re.compile(pattern) for name, pattern in rules.get("prompt_patterns", {}).items()}
    structure_patterns = {
        name: re.compile(pattern)
        for name, pattern in rules.get("prompt_structure_patterns", {}).items()
    }
    tokens = rules.get("special_tokens", [])
    prompts: list[dict[str, Any]] = []
    aggregate = {name: False for name in compiled}
    found_tokens: list[dict[str, Any]] = []
    structural_artifacts: list[dict[str, Any]] = []
    for item in strings:
        value = item["value"]
        matched = {name: bool(pattern.search(value)) for name, pattern in compiled.items()}
        for token in tokens:
            if token.lower() in value.lower():
                found_tokens.append({"token": token, "offset": item["offset"], "source": f"strings:{item['encoding']}"})
        for name, pattern in structure_patterns.items():
            match = pattern.search(value)
            if match:
                structural_artifacts.append({
                    "type": name,
                    "value": match.group(0),
                    "offset": item["offset"],
                    "source": f"strings:{item['encoding']}",
                    "evidence_level": "strong_indirect",
                })
        natural_language = len(value) >= 32 and (" " in value or any(matched.values()))
        if natural_language and any(matched.values()) and len(prompts) < max_candidates:
            for name, result in matched.items():
                aggregate[name] = aggregate[name] or result
            prompts.append({
                "offset": item["offset"],
                "source": f"strings:{item['encoding']}",
                "text_hash": "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest(),
                "fuzzy_hash": {
                    "algorithm": "simhash64_normalized_tokens_v1",
                    "value": simhash64(value),
                    "normalization": "unicode_nfkc_lowercase_whitespace_collapse",
                },
                "text_preview": " ".join(value.split())[:240],
                "features": {name: value_ for name, value_ in matched.items() if value_},
            })
    # 常规字符串导出有数量上限。二进制中的 Go 类型名、JSON 字段等很可能
    # 排在截断点之后，所以对“短而精确”的结构标记和特殊 Token 再做一次原始
    # 字节扫描。这里不从原始字节拼接自然语言，避免把二进制碎片误作 Prompt。
    if raw_data:
        raw_text = raw_data.decode("latin-1", errors="ignore")
        for name, pattern in structure_patterns.items():
            for match in pattern.finditer(raw_text):
                structural_artifacts.append({
                    "type": name,
                    "value": match.group(0),
                    "offset": match.start(),
                    "source": "raw_byte_scan",
                    "evidence_level": "strong_indirect",
                })
        for token in tokens:
            for match in re.finditer(re.escape(token), raw_text, flags=re.IGNORECASE):
                found_tokens.append({"token": token, "offset": match.start(), "source": "raw_byte_scan"})
    # 同一结构字段可因符号表、类型信息等重复出现。按位置和值去重，
    # 同时保留其来源，便于人工区分“结构存在”与“完整 Prompt 已恢复”。
    deduplicated_artifacts: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for item in structural_artifacts:
        key = (item["type"], item["offset"], item["value"])
        if key not in seen:
            seen.add(key)
            deduplicated_artifacts.append(item)
    return {
        "embedded_prompts": prompts,
        "structural_features": aggregate,
        "structural_artifacts": deduplicated_artifacts,
        "special_tokens": found_tokens,
    }

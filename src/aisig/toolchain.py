from __future__ import annotations

import re
from typing import Any


def _matches(strings: list[dict[str, Any]], rules: list[dict[str, Any]], evidence_type: str) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for rule in rules:
        pattern = re.compile(rule["regex"])
        for item in strings:
            match = pattern.search(item["value"])
            if not match:
                continue
            evidence.append({
                "type": evidence_type,
                "rule_id": rule.get("id"),
                "value": match.group(0),
                "normalized": {key: rule.get(key) for key in ("vendor", "family", "model", "provider") if rule.get(key) is not None},
                "source": f"strings:{item['encoding']}",
                "offset": item["offset"],
                "confidence": rule.get("confidence", 0.90),
                "evidence_level": "direct" if evidence_type in {"model_identifier", "endpoint"} else "strong_indirect",
            })
    return evidence


def _raw_matches(data: bytes, rules: list[dict[str, Any]], evidence_type: str) -> list[dict[str, Any]]:
    """Scan raw bytes for direct ASCII-compatible evidence that may occur after string caps.

    This is byte inspection only; it neither loads nor executes the supplied sample.
    """
    text = data.decode("latin-1", errors="ignore")
    evidence: list[dict[str, Any]] = []
    for rule in rules:
        match = re.search(rule["regex"], text)
        if not match:
            continue
        evidence.append({
            "type": evidence_type,
            "rule_id": rule.get("id"),
            "value": match.group(0),
            "normalized": {key: rule.get(key) for key in ("vendor", "family", "model", "provider") if rule.get(key) is not None},
            "source": "raw_byte_scan",
            "offset": match.start(),
            "confidence": rule.get("confidence", 0.90),
            "evidence_level": "direct" if evidence_type in {"model_identifier", "endpoint"} else "strong_indirect",
        })
    return evidence


def extract_toolchain(strings: list[dict[str, Any]], rules: dict[str, Any], metadata: dict[str, Any], raw_data: bytes) -> dict[str, Any]:
    evidence = _matches(strings, rules.get("models", []), "model_identifier")
    evidence += _matches(strings, rules.get("endpoints", []), "endpoint")
    evidence += _matches(strings, rules.get("sdk_patterns", []), "sdk_marker")
    evidence += _matches(strings, rules.get("ai_cli_patterns", []), "ai_cli")
    # The conventional string export has a size cap. Direct model/API evidence
    # must not be lost merely because it occurs later in a packed binary.
    evidence += _raw_matches(raw_data, rules.get("models", []), "model_identifier")
    evidence += _raw_matches(raw_data, rules.get("endpoints", []), "endpoint")
    evidence += _raw_matches(raw_data, rules.get("sdk_patterns", []), "sdk_marker")
    evidence += _raw_matches(raw_data, rules.get("ai_cli_patterns", []), "ai_cli")
    deduplicated: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for item in evidence:
        key = (item["type"], item["offset"], item["value"])
        if key not in seen:
            seen.add(key)
            deduplicated.append(item)
    return {
        "source_language": metadata.get("language"),
        "file_type": metadata.get("file_type"),
        "packaging_candidates": ["PyInstaller"] if any("PyInstaller" in item["value"] for item in strings) else [],
        "evidence": deduplicated,
    }

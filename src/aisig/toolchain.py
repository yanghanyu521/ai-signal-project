from __future__ import annotations

import ast
import re
from typing import Any

from .python_graph import PythonStaticGraph


MAX_MATCHES_PER_RULE = 256
MODEL_KEYS = {"model", "model_name", "engine", "deployment", "deployment_name"}
INPUT_KEYS = {"messages", "prompt", "contents", "input"}
def _normalized(rule: dict[str, Any], evidence_type: str) -> dict[str, Any]:
    value = {
        key: rule[key]
        for key in (
            "vendor", "family", "model", "provider", "sdk_name", "sdk_vendor",
            "service_provider", "model_vendor", "model_family",
        )
        if rule.get(key) is not None
    }
    if evidence_type == "model_identifier":
        if "vendor" in value:
            value.setdefault("model_vendor", value["vendor"])
        if "family" in value:
            value.setdefault("model_family", value["family"])
    elif evidence_type == "endpoint" and "provider" in value:
        value.setdefault("service_provider", value["provider"])
    elif evidence_type == "sdk_marker":
        # Legacy rules used provider/family for SDKs. Preserve those keys for
        # old readers, but expose an explicit SDK identity and never treat it
        # as proof of the model vendor.
        value.setdefault("sdk_vendor", value.get("provider"))
        value.setdefault("sdk_name", rule.get("id") or "unknown")
    return value


def _encoded_position(value: str, char_offset: int, encoding: str) -> int:
    codec = {"ascii": "ascii", "utf16le": "utf-16le"}.get(encoding, "utf-8")
    return len(value[:char_offset].encode(codec, errors="replace"))


def _matches(strings: list[dict[str, Any]], rules: list[dict[str, Any]], evidence_type: str) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for rule in rules:
        pattern = re.compile(rule["regex"])
        match_count = 0
        for item in strings:
            for match in pattern.finditer(item["value"]):
                if match_count >= MAX_MATCHES_PER_RULE:
                    break
                relative = _encoded_position(item["value"], match.start(), item["encoding"])
                evidence.append({
                    "type": evidence_type,
                    "rule_id": rule.get("id"),
                    "value": match.group(0),
                    "raw_value": match.group(0),
                    "normalized": _normalized(rule, evidence_type),
                    "source": f"strings:{item['encoding']}",
                    "offset": item["offset"] + relative,
                    "string_offset": item["offset"],
                    "match_char_offset": match.start(),
                    "match_byte_offset": relative,
                    "byte_length": len(match.group(0).encode(
                        "utf-16le" if item["encoding"] == "utf16le" else "ascii",
                        errors="replace",
                    )),
                    "confidence": rule.get("confidence", 0.90),
                    "confidence_semantics": "rule_strength_not_calibrated_probability",
                    "discovery_method": "rule",
                    "verification_status": "location_verified",
                    "verification": {"location": "verified", "relation": "unknown", "role": "unknown"},
                    "attribution_eligible": False,
                    "role": "unknown",
                    "evidence_level": "marker_only",
                })
                match_count += 1
            if match_count >= MAX_MATCHES_PER_RULE:
                break
    return evidence


def _raw_matches(data: bytes, rules: list[dict[str, Any]], evidence_type: str) -> list[dict[str, Any]]:
    """Scan raw bytes for direct ASCII-compatible evidence that may occur after string caps.

    This is byte inspection only; it neither loads nor executes the supplied sample.
    """
    text = data.decode("latin-1", errors="ignore")
    evidence: list[dict[str, Any]] = []
    for rule in rules:
        for index, match in enumerate(re.finditer(rule["regex"], text)):
            if index >= MAX_MATCHES_PER_RULE:
                break
            evidence.append({
                "type": evidence_type,
                "rule_id": rule.get("id"),
                "value": match.group(0),
                "raw_value": match.group(0),
                "normalized": _normalized(rule, evidence_type),
                "source": "raw_byte_scan",
                "offset": match.start(),
                "byte_length": match.end() - match.start(),
                "confidence": rule.get("confidence", 0.90),
                "confidence_semantics": "rule_strength_not_calibrated_probability",
                "discovery_method": "rule",
                "verification_status": "location_verified",
                "verification": {"location": "verified", "relation": "unknown", "role": "unknown"},
                "attribution_eligible": False,
                "role": "unknown",
                "evidence_level": "marker_only",
            })
    return evidence


def _source_location(node: ast.AST, lines: list[str]) -> dict[str, Any]:
    line = getattr(node, "lineno", None)
    column = getattr(node, "col_offset", None)
    byte_offset = None
    if isinstance(line, int) and isinstance(column, int) and 1 <= line <= len(lines):
        byte_offset = sum(len(item.encode("utf-8")) for item in lines[: line - 1])
        byte_offset += len(lines[line - 1].encode("utf-8")[:column])
    return {
        "line": line,
        "end_line": getattr(node, "end_lineno", line),
        "column": column,
        "byte_offset": byte_offset,
        "coordinate_system": "python_utf8_source",
    }


def extract_python_call_evidence(text: str) -> list[dict[str, Any]]:
    """Extract statically bound model/service facts without executing source.

    A model-like dictionary by itself is intentionally ignored. Facts are only
    emitted when tied to a known AI SDK call or to an HTTP request carrying both
    an input structure and a model/deployment selector.
    """
    try:
        graph = PythonStaticGraph(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    nodes = graph.nodes
    lines = text.splitlines(keepends=True)

    evidence: list[dict[str, Any]] = []
    for call in (node for node in nodes if isinstance(node, ast.Call)):
        name = graph.call_name(call)
        sdk = graph.client_for_call(call)
        known_sdk_call = graph.is_known_ai_call(call)
        keyword_nodes = {kw.arg.casefold(): kw.value for kw in call.keywords if kw.arg}
        payload_node = keyword_nodes.get("json") or keyword_nodes.get("data")
        payload = graph.dict_items(payload_node)
        request_keys = set(keyword_nodes) | set(payload)
        generic_http = name.endswith((".post", ".request")) and bool(request_keys & INPUT_KEYS) and bool(request_keys & MODEL_KEYS)
        if not known_sdk_call and not generic_http:
            continue

        call_location = _source_location(call, lines)
        role = "application"
        common = {
            "discovery_method": "structure",
            "verification_status": "relation_verified",
            "verification": {"location": "verified", "relation": "verified", "role": "verified"},
            "attribution_eligible": True,
            "evidence_level": "static_relation_supported",
            "role": role,
            "call_site": {"callee": name, **call_location},
            "confidence": 1.0,
            "confidence_semantics": "deterministic_static_relation_not_runtime_probability",
        }
        for key in MODEL_KEYS:
            node = keyword_nodes.get(key)
            values = [(value, node) for value in graph.static_values(node)] if node is not None else []
            values.extend(payload.get(key, []))
            for value, source_node in values:
                if isinstance(value, str) and value.strip() and source_node is not None:
                    evidence.append({
                        **common,
                        "type": "model_argument",
                        "value": value,
                        "raw_value": value,
                        "normalized": {"model": value, "model_identifier_raw": value},
                        "source": "python_ast",
                        "source_location": _source_location(source_node, lines),
                        "argument_name": key,
                    })
        endpoint_node = call.args[0] if generic_http and call.args else keyword_nodes.get("url")
        endpoints = graph.static_values(endpoint_node)
        if not endpoints and sdk:
            endpoint_node = sdk.get("base_url_node")
            endpoints = graph.static_values(endpoint_node)
        for endpoint in endpoints:
            if isinstance(endpoint, str) and endpoint.strip():
                evidence.append({
                    **common,
                    "type": "service_endpoint",
                    "value": endpoint,
                    "raw_value": endpoint,
                    "normalized": {"endpoint": endpoint, "service_endpoint": endpoint, "service_provider": None},
                    "source": "python_ast",
                    "source_location": _source_location(endpoint_node or call, lines),
                })
        if sdk:
            evidence.append({
                **common,
                "type": "sdk_call",
                "value": sdk["sdk_name"],
                "raw_value": sdk["sdk_name"],
                "normalized": {"sdk_name": sdk["sdk_name"], "sdk_vendor": sdk["sdk_vendor"]},
                "source": "python_ast",
                "source_location": call_location,
            })
    deduplicated = []
    seen = set()
    for item in evidence:
        location = item.get("source_location") or {}
        key = (item["type"], item["value"], location.get("line"), item.get("argument_name"))
        if key not in seen:
            seen.add(key)
            deduplicated.append(item)
    return deduplicated


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

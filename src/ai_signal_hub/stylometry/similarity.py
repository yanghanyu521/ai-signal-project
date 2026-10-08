"""Comparable, explainable distance between deterministic code fingerprints."""
from __future__ import annotations

from typing import Any


def _overlap(a: dict[str, float], b: dict[str, float]) -> float:
    keys = set(a) | set(b)
    denominator = sum(max(a.get(k, 0), b.get(k, 0)) for k in keys)
    return sum(min(a.get(k, 0), b.get(k, 0)) for k in keys) / denominator if denominator else 0.0


def compare_fingerprints(left: dict[str, Any] | None, right: dict[str, Any] | None) -> dict[str, Any]:
    def unavailable(reason: str) -> dict[str, Any]:
        return {"status": "not_comparable", "score": None, "reason": reason,
                "components": [], "shared_indicators": []}

    if not left or not right:
        return unavailable("missing_fingerprint")
    if left.get("asset_kind") != "code" or right.get("asset_kind") != "code":
        return unavailable("different_asset_kind")
    if left.get("language") != right.get("language"):
        return unavailable("different_languages")
    if left.get("source_kind") != "original_source" or right.get("source_kind") != "original_source":
        return unavailable("invalid_source_quality")
    if left.get("fingerprint_version") != right.get("fingerprint_version"):
        return unavailable("different_fingerprint_versions")
    if left.get("information_status") != "comparable" or right.get("information_status") != "comparable":
        return unavailable("low_information")
    a, b = left.get("metrics") or {}, right.get("metrics") or {}
    components: list[dict[str, Any]] = []
    for key in ("blank_ratio", "comment_ratio", "comment_tokens_per_code_token",
                "mean_identifier_length", "branch_ratio", "loop_ratio", "exception_ratio"):
        x, y = a.get(key), b.get(key)
        if isinstance(x, (int, float)) and isinstance(y, (int, float)):
            if x == y == 0:
                continue
            components.append({"metric": key, "score": round(min(x, y) / max(x, y), 6),
                               "left": x, "right": y, "kind": "scalar"})
    for key in ("naming_style", "indent_distribution", "token_unigrams", "token_bigrams",
                "ast_node_distribution", "ast_pattern_distribution"):
        x, y = a.get(key), b.get(key)
        if isinstance(x, dict) and isinstance(y, dict) and x and y:
            shared = sorted(k for k in set(x) & set(y) if min(x[k], y[k]) > 0)
            components.append({"metric": key, "score": round(_overlap(x, y), 6),
                               "shared_values": shared[:20], "kind": "distribution"})
    if len(components) < 3:
        return unavailable("insufficient_shared_metrics")
    score = round(sum(item["score"] for item in components) / len(components), 6)
    shared = [{"metric": item["metric"], "values": item.get("shared_values", []),
               "score": item["score"]} for item in components if item["score"] > 0]
    return {"status": "comparable", "score": score,
            "method": "normalized_style_metric_overlap_v1", "components": components,
            "shared_indicators": shared,
            "same_content": left.get("content_hash") == right.get("content_hash"),
            "same_structure": bool(left.get("structure_hash") and
                                   left.get("structure_hash") == right.get("structure_hash")),
            "near_duplicate_warning": left.get("content_hash") == right.get("content_hash"),
            "missing_features": sorted((set(a) ^ set(b)) & {
                "ast_node_distribution", "ast_pattern_distribution", "comment_ratio", "naming_style"}),
            "interpretation": "风格指标接近；未校准为AI生成或模型来源概率"}

"""Evidence-aware pair scores; no corpus scaling or synthetic sample features."""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

import numpy as np
from scipy.optimize import linear_sum_assignment
from sklearn.cluster import AgglomerativeClustering

from .repository import Repository


ALGORITHM_VERSION = "ai-signal-evidence-pairwise-v2.1"
GROUP_WEIGHTS = {"toolchain": 0.5, "prompt": 0.3, "code_style": 0.2}
SIMHASH_ALGORITHM = "simhash64_normalized_tokens_v1"
SIMHASH_MAX_DISTANCE = 8
STRUCTURE_ONLY_CAP = 0.2
TOOL_WEIGHTS = {"vendor": 1.0, "family": 1.5, "model": 2.0,
                "sdk": 1.0, "endpoint": 1.5, "ai_cli": 1.0}
SCALARS = ("loc", "function_count", "mean_identifier_length", "blank_ratio",
           "comment_ratio", "exception_handler_ratio")


def _token(value: Any) -> str:
    return str(value).strip().casefold()


def _meaningful(value: Any) -> bool:
    return isinstance(value, str) and _token(value) not in {
        "", "unknown", "none", "null", "n/a", "na", "—", "-"}


def _number(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value) and value >= 0


def _tool_features(result: dict) -> dict[str, float]:
    facts: dict[str, float] = {}

    def add(kind, value):
        if _meaningful(value):
            facts[f"{kind}:{_token(value)}"] = TOOL_WEIGHTS[kind]

    for evidence in result.get("features", {}).get("toolchain", {}).get("evidence", []) or []:
        normalized = evidence.get("normalized") or {}
        for key in ("vendor", "provider", "family", "model"):
            add("vendor" if key == "provider" else key, normalized.get(key))
        kind, value = evidence.get("type"), evidence.get("value")
        if kind in {"sdk_marker", "ai_cli"}:
            add("sdk" if kind == "sdk_marker" else kind, value)
        elif kind == "endpoint" and _meaningful(value):
            # Never propagate credentials/query arguments into comparison labels.
            parsed = urlsplit(value if "://" in value else "https://" + value)
            if parsed.hostname:
                add("endpoint", parsed.hostname + parsed.path)
    attribution = result.get("classification", {}).get("model_attribution", {})
    for key in ("vendor", "family", "model"):
        add(key, attribution.get(key))
    return facts


def _exact_hash(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    digest = value.strip().lower().removeprefix("sha256:")
    return "sha256:" + digest if re.fullmatch(r"[a-f0-9]{64}", digest) else None


def _fuzzy_hash(value: Any) -> int | None:
    if isinstance(value, dict):
        if value.get("algorithm") != SIMHASH_ALGORITHM:
            return None
        value = value.get("value")
    if not isinstance(value, str) or not re.fullmatch(r"simhash64:[a-fA-F0-9]{16}", value):
        return None
    number = int(value.split(":", 1)[1], 16)
    # The legacy extractor uses zero for an empty token sequence.
    return number if number else None


def _prompt_profile(result: dict) -> dict:
    prompt = result.get("features", {}).get("prompt", {})
    records = {}
    invalid = 0
    for item in prompt.get("embedded_prompts", []) or []:
        exact, fuzzy = _exact_hash(item.get("text_hash")), _fuzzy_hash(item.get("fuzzy_hash"))
        if item.get("fuzzy_hash") and fuzzy is None:
            invalid += 1
        if exact or fuzzy is not None:
            key = exact or f"simhash64:{fuzzy:016x}"
            # Repeated copies of a prompt must not inflate overlap.
            if key not in records or (records[key]["fuzzy"] is None and fuzzy is not None):
                records[key] = {"exact": exact, "fuzzy": fuzzy}
    structure = {f"flag:{key}": 1.0 for key, value in (prompt.get("structural_features") or {}).items()
                 if value is True}
    for item in prompt.get("special_tokens", []) or []:
        token = item.get("token", item.get("value")) if isinstance(item, dict) else item
        if _meaningful(token):
            structure[f"token:{_token(token)}"] = 0.5
    return {"records": [records[key] for key in sorted(records)], "structure": structure,
            "ignored_fuzzy_hashes": invalid}


def _code_profile(result: dict) -> dict:
    style = result.get("features", {}).get("code_style", {})
    language = style.get("language")
    source = style.get("recoverability")
    metrics = style.get("metrics") or {}
    reason = None
    if style.get("parse_error"):
        reason = "parse_error"
    elif source != "original_source":
        reason = "not_original_source"
    elif not _meaningful(language):
        reason = "unknown_language"
    elif not metrics:
        reason = "missing_metrics"
    elif _token(language) == "python" and not metrics.get("ast_node_counts"):
        reason = "python_ast_unavailable"
    clean = {}
    for key in SCALARS:
        value = metrics.get(key)
        if _number(value) and (key not in {"blank_ratio", "comment_ratio"} or value <= 1):
            clean[key] = float(value)
    for key in ("naming_style", "ast_node_counts"):
        histogram = metrics.get(key)
        if isinstance(histogram, dict):
            values = {name: float(value) for name, value in histogram.items()
                      if _number(value) and value > 0 and (key != "naming_style" or value <= 1)}
            if values:
                total = sum(values.values())
                clean[key] = {name: value / total for name, value in values.items()}
    if reason is None and len(clean) < 3:
        reason = "insufficient_metrics"
    return {"language": _token(language) if _meaningful(language) else None,
            "source_kind": source, "metrics": clean, "reason": reason,
            "metrics_method": style.get("metrics_method") or "legacy_code_statistics_v1",
            "available": reason is None,
            "excluded_recovered_layers": len(style.get("recovered_layers") or []),
            "method": "ast_and_statistics" if language == "python" else "text_statistics_only"}


def sample_profile(result: dict) -> dict:
    return {"toolchain": _tool_features(result), "prompt": _prompt_profile(result), "code_style": _code_profile(result)}


def extract_feature_groups(result: dict[str, Any]) -> dict[str, dict]:
    """Compatibility diagnostic view, not a global vectorizer input."""
    profile = sample_profile(result)
    prompt = dict(profile["prompt"]["structure"])
    for item in profile["prompt"]["records"]:
        prompt[item["exact"] or f"simhash64:{item['fuzzy']:016x}"] = 1.0
    return {"toolchain": profile["toolchain"], "prompt": prompt,
            "code_style": profile["code_style"]["metrics"] if profile["code_style"]["available"] else {}}


def _jaccard(left: dict[str, float], right: dict[str, float]) -> float:
    keys = set(left) | set(right)
    denominator = sum(max(left.get(k, 0), right.get(k, 0)) for k in keys)
    return sum(min(left.get(k, 0), right.get(k, 0)) for k in keys) / denominator if denominator else 0.0


def _unavailable(reason: str, **details) -> dict:
    return {"score": None, "status": "not_comparable", "reason": reason, **details}


def compare_toolchain(left: dict, right: dict) -> dict:
    if not left or not right:
        return _unavailable("missing_toolchain_evidence", left_count=len(left), right_count=len(right))
    return {"score": _jaccard(left, right), "status": "comparable", "method": "weighted_jaccard",
            "matched_facts": sorted(set(left) & set(right)), "left_count": len(left), "right_count": len(right)}


def _prompt_pair(left: dict, right: dict) -> tuple[float, str, int | None]:
    if left["exact"] and left["exact"] == right["exact"]:
        return 1.0, "exact_sha256", None
    if left["fuzzy"] is not None and right["fuzzy"] is not None:
        distance = (left["fuzzy"] ^ right["fuzzy"]).bit_count()
        # Random 64-bit hashes have about 32 different bits: never score 50%.
        score = 0.95 * (1 - distance / 16) if distance <= SIMHASH_MAX_DISTANCE else 0.0
        return score, "simhash64_hamming", distance
    return 0.0, "no_content_match", None


def compare_prompts(left: dict, right: dict) -> dict:
    a, b = left["records"], right["records"]
    structure_available = bool(left["structure"] and right["structure"])
    structure = _jaccard(left["structure"], right["structure"]) if structure_available else None
    matches = []
    content = None
    if a and b:
        scores = np.array([[_prompt_pair(x, y)[0] for y in b] for x in a])
        rows, cols = linear_sum_assignment(-scores)
        content = float(scores[rows, cols].sum() / max(len(a), len(b)))
        for i, j in zip(rows, cols, strict=True):
            score, method, distance = _prompt_pair(a[i], b[j])
            if score:
                matches.append({"left_index": int(i), "right_index": int(j), "score": score,
                                "method": method, "hamming_distance": distance})
    if content is None and structure is None:
        return _unavailable("missing_comparable_prompt_evidence", left_count=len(a), right_count=len(b))
    if content is not None:
        score = content if structure is None else 0.8 * content + 0.2 * structure
    else:
        score = STRUCTURE_ONLY_CAP * structure
    return {"score": score, "status": "comparable", "method": "one_to_one_hash_and_structure",
            "strength": "content" if content is not None and content > 0 else ("structure_only" if structure else "no_match"),
            "content_comparable": content is not None,
            "content_similarity": content, "structure_similarity": structure,
            "left_count": len(a), "right_count": len(b), "matched_prompts": matches,
            "matched_structure": sorted(set(left["structure"]) & set(right["structure"])),
            "simhash_max_distance": SIMHASH_MAX_DISTANCE,
            "ignored_fuzzy_hashes": left["ignored_fuzzy_hashes"] + right["ignored_fuzzy_hashes"]}


def compare_code_style(left: dict, right: dict) -> dict:
    if not left["available"] or not right["available"]:
        return _unavailable("invalid_source_quality", left_reason=left["reason"], right_reason=right["reason"])
    if left["language"] != right["language"]:
        return _unavailable("different_languages", left_language=left["language"], right_language=right["language"])
    if left["metrics_method"] != right["metrics_method"]:
        return _unavailable("different_metric_methods", left_method=left["metrics_method"], right_method=right["metrics_method"])
    a, b = left["metrics"], right["metrics"]
    components = []
    comparable_count = 0
    for key in sorted(set(a) | set(b)):
        x, y = a.get(key), b.get(key)
        if x is None or y is None:
            score, status = 0.0, "one_side_missing"
        elif isinstance(x, dict) and isinstance(y, dict):
            score, status = _jaccard(x, y), "comparable"
            comparable_count += 1
        elif _number(x) and _number(y):
            if x == y == 0:
                continue  # Shared absence is not positive similarity evidence.
            score, status = min(x, y) / max(x, y), "comparable"
            comparable_count += 1
        else:
            continue
        components.append({"metric": key, "left": x, "right": y, "score": score, "status": status})
    if comparable_count < 3:
        return _unavailable("insufficient_shared_metrics", comparable_metric_count=comparable_count)
    return {"score": sum(item["score"] for item in components) / len(components), "status": "comparable",
            "method": "relative_numeric_and_histogram_overlap", "language": left["language"],
            "source_kind": "original_source", "components": components,
            "interpretation": "代码统计特征接近，不是代码语义、同源或AI生成概率"}


def _weights(weights: dict | None) -> dict[str, float]:
    values = dict(GROUP_WEIGHTS if weights is None else weights)
    if set(values) != set(GROUP_WEIGHTS) or any(not _number(v) for v in values.values()) or sum(values.values()) <= 0:
        raise ValueError("三组权重必须为有限非负数且总和大于零")
    total = sum(values.values())
    if not math.isfinite(total):
        raise ValueError("权重总和必须为有限数")
    return {key: value / total for key, value in values.items()}


def compare_profiles(left: dict, right: dict, weights: dict | None = None) -> dict:
    weights = _weights(weights)
    groups = {"toolchain": compare_toolchain(left["toolchain"], right["toolchain"]),
              "prompt": compare_prompts(left["prompt"], right["prompt"]),
              "code_style": compare_code_style(left["code_style"], right["code_style"])}
    coverage = sum(weights[group] for group, detail in groups.items() if detail["score"] is not None)
    contributions = {group: weights[group] * (detail["score"] or 0.0) for group, detail in groups.items()}
    total = sum(contributions.values())
    common = ["toolchain:" + fact for fact in groups["toolchain"].get("matched_facts", [])]
    common += ["prompt:" + fact for fact in groups["prompt"].get("matched_structure", [])]
    common += ["prompt:" + match["method"] for match in groups["prompt"].get("matched_prompts", [])]
    # Do not call the mere existence of a metric a shared feature.
    common += ["code_style:equal:" + part["metric"] for part in groups["code_style"].get("components", [])
               if part["status"] == "comparable" and part["score"] == 1.0]
    return {"overall_similarity": total if coverage else None,
            **{group + "_similarity": detail["score"] for group, detail in groups.items()},
            "common_features": list(dict.fromkeys(common)),
            "details": {"status": "comparable" if coverage else "not_comparable", "groups": groups,
                        "weights": weights, "contributions": contributions, "comparable_weight": coverage,
                        "conditional_similarity": total / coverage if coverage else None,
                        "fusion": "fixed_weight_sum_missing_contributes_zero"}}


def profile_diagnostics(profile: dict) -> dict:
    prompt_count = len(profile["prompt"]["records"]) + len(profile["prompt"]["structure"])
    code = profile["code_style"]
    groups = {
        "toolchain": {"available": bool(profile["toolchain"]), "count": len(profile["toolchain"]),
                      "reason": None if profile["toolchain"] else "missing_toolchain_evidence"},
        "prompt": {"available": bool(prompt_count), "count": prompt_count,
                   "reason": None if prompt_count else "missing_prompt_evidence",
                   "ignored_fuzzy_hashes": profile["prompt"]["ignored_fuzzy_hashes"]},
        "code_style": {key: code[key] for key in ("available", "reason", "language", "source_kind", "metrics_method", "excluded_recovered_layers")},
    }
    groups["code_style"]["count"] = len(code["metrics"]) if code["available"] else 0
    return {"status": "available" if any(item["available"] for item in groups.values()) else "no_features", "groups": groups}


class SampleSimilarityService:
    def __init__(self, repository: Repository, distance_threshold: float = 0.45, weights: dict | None = None):
        if not _number(distance_threshold) or not 0 < distance_threshold < 1:
            raise ValueError("聚类距离阈值必须大于0且小于1")
        self.repository = repository
        self.distance_threshold = distance_threshold
        self.weights = _weights(weights)

    def rebuild(self) -> dict[str, Any]:
        samples = self.repository.all_sample_results()
        if not samples:
            return {"algorithm_version": ALGORITHM_VERSION, "sample_count": 0, "cluster_count": 0}
        shas = [item["sha256"] for item in samples]
        profiles = [sample_profile(item["result_json"]) for item in samples]
        distances = np.ones((len(samples), len(samples)))
        np.fill_diagonal(distances, 0.0)
        relations = []
        for left in range(len(samples)):
            for right in range(left + 1, len(samples)):
                result = compare_profiles(profiles[left], profiles[right], self.weights)
                score = result["overall_similarity"] or 0.0
                distances[left, right] = distances[right, left] = max(0.0, 1 - score)
                relations.append({"source_sample_id": shas[left], "target_sample_id": shas[right], **result})
        if len(samples) == 1:
            raw_labels = np.array([0])
        else:
            raw_labels = AgglomerativeClustering(n_clusters=None, metric="precomputed", linkage="average",
                                                distance_threshold=self.distance_threshold).fit_predict(distances)
        members = {}
        for sha, label in zip(shas, raw_labels, strict=True):
            members.setdefault(int(label), []).append(sha)
        label_map = {label: f"C{index:03d}" for index, label in enumerate(sorted(members, key=lambda k: min(members[k])), 1)}
        labels = {sha: label_map[int(label)] for sha, label in zip(shas, raw_labels, strict=True)}
        sizes = Counter(labels.values())
        for relation in relations:
            relation["same_cluster"] = labels[relation["source_sample_id"]] == labels[relation["target_sample_id"]]
        run = self.repository.replace_sample_similarity(
            algorithm_version=ALGORITHM_VERSION, distance_threshold=self.distance_threshold,
            clusters=[{"sample_id": sha, "cluster_label": labels[sha], "cluster_size": sizes[labels[sha]],
                       "details": profile_diagnostics(profile)} for sha, profile in zip(shas, profiles, strict=True)],
            relations=relations, expected_samples=samples, details={"weights": self.weights, "distance": "1-fixed_weight_similarity",
                "linkage": "average", "simhash_max_distance": SIMHASH_MAX_DISTANCE,
                "structure_only_cap": STRUCTURE_ONLY_CAP, "corpus_scaling": False,
                "synthetic_features": False, "threshold_calibration": "engineering_default_not_benchmark_calibrated"})
        return {**run, "weights": self.weights, "interpretation": "证据候选关联，不是同源、同模型或AI生成概率"}

    def associations(self, sha256: str, limit: int = 10, include_unmatched: bool = False) -> dict[str, Any]:
        return self.repository.sample_associations(sha256, limit, include_unmatched=include_unmatched)

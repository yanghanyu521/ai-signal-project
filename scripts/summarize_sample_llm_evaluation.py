from __future__ import annotations

import argparse
import base64
import csv
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8-sig")
        return
    fieldnames = list(rows[0])
    seen = set(fieldnames)
    for row in rows[1:]:
        for key in row:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _label(snapshot: dict[str, Any]) -> str:
    return str((((snapshot.get("classification") or {}).get("llm_involvement") or {}).get("label")) or "unknown")


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction) - 1))
    return float(ordered[index])


def _reason(item: dict[str, Any]) -> str:
    for key in ("reason", "rejection_reason", "error", "verification_status"):
        if item.get(key):
            return str(item[key])
    return "unknown"


def _semantic_triage(fact: dict[str, Any]) -> tuple[str, str]:
    group = str(fact.get("signal_group") or "unknown")
    raw = str(fact.get("raw_value") or "")
    lowered = raw.lower().strip()
    normalized = fact.get("normalized_value") or {}
    if group == "toolchain":
        if normalized.get("model_identifier_raw"):
            return "ai_relevant_candidate", "explicit_model_or_cli_identifier"
        sdk = str(normalized.get("sdk_name") or "").lower()
        if sdk == "openai":
            return "ai_relevant_candidate", "known_ai_sdk"
        endpoint = str(normalized.get("service_endpoint") or raw).lower()
        if "router.huggingface.co/" in endpoint and any(
            marker in endpoint for marker in ("chat/completions", "images/generations")
        ):
            return "ai_relevant_candidate", "known_ai_service_route"
        return "non_ai_or_misclassified", "generic_sdk_endpoint_ioc_or_build_component"
    if group == "prompt":
        if "there is no need to analyze this file" in lowered:
            return "non_ai_or_misclassified", "analyzer_directive_not_application_prompt"
        if lowered == "what should not be on the image":
            return "non_ai_or_misclassified", "ui_label_not_prompt_content"
        compact = "".join(raw.split())
        try:
            decoded = base64.b64decode(compact, validate=True) if len(compact) >= 80 else b""
        except (ValueError, TypeError):
            decoded = b""
        if decoded and sum(32 <= byte < 127 for byte in decoded) / len(decoded) >= 0.8:
            return "needs_normalization", "base64_prompt_not_decoded"
        return "ai_relevant_candidate", "instruction_or_role_text"
    if group == "code_observation":
        ai_markers = (
            "llm_query", "['choices'][0]['message']['content']", '"role": "user"',
            '"role":"user"', "generating image with prompt", "authorization tokens",
            "llm_api_url", "image_api_url", "exec(complete_str)", "exec (complete_str",
            "f .write (complete_str",
        )
        if any(marker in lowered for marker in ai_markers):
            return "ai_relevant_candidate", "ai_request_response_or_generated_code_flow"
        if lowered in {"exec(", "exec (", "api_url", "os.system(filename)", "malicious="}:
            return "needs_manual_review", "generic_marker_requires_relation_context"
        return "non_ai_or_misclassified", "generic_code_or_malware_behavior"
    return "needs_manual_review", "unknown_signal_group"


def main() -> None:
    parser = argparse.ArgumentParser(description="汇总45样本规则与LLM隔离评估产物")
    parser.add_argument("evaluation_dir", type=Path)
    args = parser.parse_args()
    root = args.evaluation_dir.resolve()
    comparisons = json.loads((root / "comparison_summary.json").read_text(encoding="utf-8"))

    sample_rows: list[dict[str, Any]] = []
    family_rows: dict[str, Counter] = defaultdict(Counter)
    transitions = Counter()
    limitations = Counter()
    errors = Counter()
    rejection_reasons = Counter()
    fact_groups = Counter()
    representations = Counter()
    tool_runs = Counter()
    duration_values: list[float] = []
    request_values: list[int] = []
    token_values: list[int] = []
    issue_samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    semantic_triage: list[dict[str, Any]] = []
    semantic_counts = Counter()
    semantic_by_group: dict[str, Counter] = defaultdict(Counter)
    delta_totals = Counter()
    audit_totals = Counter()

    for comparison in comparisons:
        sha256 = comparison["sha256"]
        family = comparison["family"]
        old = comparison["old_rule"]
        new = comparison["v07_llm"]
        run = new["run"]
        budget = run.get("budget") or {}
        usage = budget.get("provider_usage") or {}
        result_path = root / "samples" / sha256 / "v07_llm" / "result.json"
        materials_path = root / "samples" / sha256 / "v07_llm" / "static_materials.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        static_run = result["features"]["static_analysis"]["run"]
        materials = json.loads(materials_path.read_text(encoding="utf-8"))
        old_label, new_label = _label(old), _label(new)
        transitions[(old_label, new_label)] += 1
        duration = float(comparison.get("duration_seconds") or 0)
        requests = int(budget.get("requests") or 0)
        tokens = int(usage.get("total_tokens") or 0)
        facts = new.get("llm_facts") or []
        eligible = sum(fact.get("attribution_eligible") is True for fact in facts)
        rejected = static_run.get("rejected_facts") or []
        old_to_new = comparison.get("old_to_v07_llm") or {}
        for key, values in old_to_new.items():
            delta_totals[key] += len(values or [])
        for key, value in (comparison.get("llm_fact_audit") or {}).items():
            if isinstance(value, int):
                audit_totals[key] += value
        groups = Counter(str(fact.get("signal_group") or "unknown") for fact in facts)
        fact_groups.update(groups)
        for fact in facts:
            decision, reason = _semantic_triage(fact)
            group = str(fact.get("signal_group") or "unknown")
            semantic_counts[decision] += 1
            semantic_by_group[group][decision] += 1
            semantic_triage.append({
                "family": family,
                "sha256": sha256,
                "fact_id": fact.get("fact_id"),
                "signal_group": group,
                "raw_value": fact.get("raw_value"),
                "normalized_value": fact.get("normalized_value") or {},
                "attribution_eligible": fact.get("attribution_eligible") is True,
                "triage": decision,
                "triage_reason": reason,
                "review_status": "heuristic_initial_review",
            })
        limitations.update(run.get("limitations") or [])
        for error in static_run.get("errors") or []:
            errors[(str(error.get("stage") or "primary"), str(error.get("error") or "unknown"))] += 1
        for item in rejected:
            rejection_reasons[_reason(item)] += 1
        for representation in ((run.get("coverage") or {}).get("material_coverage") or {}).get("representations", []) or []:
            representations[str(representation)] += 1
        for tool_run in materials.get("tool_runs", []) or []:
            tool_runs[(str(tool_run.get("tool") or "unknown"), str(tool_run.get("status") or "unknown"))] += 1
        duration_values.append(duration)
        request_values.append(requests)
        token_values.append(tokens)

        row = {
            "family": family,
            "sha256": sha256,
            "size_bytes": comparison.get("size_bytes"),
            "old_label": old_label,
            "new_label": new_label,
            "llm_status": run.get("status"),
            "duration_seconds": duration,
            "requests": requests,
            "total_tokens": tokens,
            "old_toolchain": len(old.get("toolchain") or []),
            "new_toolchain": len(new.get("toolchain") or []),
            "old_prompts": len(old.get("prompts") or []),
            "new_prompts": len(new.get("prompts") or []),
            "toolchain_added": len(old_to_new.get("toolchain_added") or []),
            "toolchain_missing": len(old_to_new.get("toolchain_missing") or []),
            "prompt_added": len(old_to_new.get("prompt_added") or []),
            "prompt_missing": len(old_to_new.get("prompt_missing") or []),
            "llm_facts": len(facts),
            "eligible_llm_facts": eligible,
            "llm_toolchain_facts": groups.get("toolchain", 0),
            "llm_prompt_facts": groups.get("prompt", 0),
            "llm_code_observations": groups.get("code_observation", 0),
            "rejected_facts": len(rejected),
            "limitations": "|".join(run.get("limitations") or []),
            "errors": len(static_run.get("errors") or []),
        }
        sample_rows.append(row)
        family_counter = family_rows[family]
        for key in (
            "old_toolchain", "new_toolchain", "old_prompts", "new_prompts", "toolchain_added",
            "toolchain_missing", "prompt_added", "prompt_missing", "llm_facts", "eligible_llm_facts",
            "llm_toolchain_facts", "llm_prompt_facts", "llm_code_observations", "rejected_facts",
            "requests", "total_tokens",
        ):
            family_counter[key] += int(row[key] or 0)
        family_counter["samples"] += 1
        family_counter[f"status_{run.get('status') or 'missing'}"] += 1
        family_counter[f"old_{old_label}"] += 1
        family_counter[f"new_{new_label}"] += 1

        issue_base = {"family": family, "sha256": sha256, "status": run.get("status"),
                      "requests": requests, "total_tokens": tokens, "llm_facts": len(facts)}
        if not facts:
            issue_samples["zero_llm_facts"].append(issue_base)
        if run.get("status") in {"partial", "failed", "unsupported"}:
            issue_samples["incomplete_or_unsupported"].append(issue_base)
        if old_label == "confirmed" and new_label == "unknown":
            issue_samples["old_confirmed_new_unknown"].append(issue_base)
        if len(old.get("toolchain") or []) and not len(new.get("toolchain") or []):
            issue_samples["old_toolchain_new_empty"].append(issue_base)
        if len(old.get("prompts") or []) and not len(new.get("prompts") or []):
            issue_samples["old_prompts_new_empty"].append(issue_base)
        if requests >= 5 or tokens >= 100_000:
            issue_samples["high_cost"].append(issue_base)
        if rejected:
            issue_samples["has_rejected_facts"].append({**issue_base, "rejected_facts": len(rejected)})
        if len(facts) >= 15:
            issue_samples["high_fact_count"].append(issue_base)

    family_matrix = []
    for family, values in sorted(family_rows.items()):
        family_matrix.append({"family": family, **dict(values)})
    completed = len(comparisons)
    summary = {
        "generated_at": _now(),
        "evaluation_dir": str(root),
        "samples": completed,
        "families": len(family_rows),
        "label_transitions": {f"{old}->{new}": count for (old, new), count in sorted(transitions.items())},
        "performance": {
            "duration_seconds_total": round(sum(duration_values), 3),
            "duration_seconds_median": round(statistics.median(duration_values), 3) if duration_values else 0,
            "duration_seconds_p95": round(_percentile(duration_values, 0.95), 3),
            "duration_seconds_max": round(max(duration_values), 3) if duration_values else 0,
            "requests_total": sum(request_values),
            "requests_median": statistics.median(request_values) if request_values else 0,
            "requests_max": max(request_values) if request_values else 0,
            "samples_requests_ge_5": sum(value >= 5 for value in request_values),
            "tokens_total": sum(token_values),
            "tokens_median": statistics.median(token_values) if token_values else 0,
            "tokens_max": max(token_values) if token_values else 0,
            "samples_tokens_ge_100k": sum(value >= 100_000 for value in token_values),
        },
        "old_feature_records": {
            "toolchain": sum(int(row["old_toolchain"]) for row in sample_rows),
            "prompts": sum(int(row["old_prompts"]) for row in sample_rows),
        },
        "new_feature_records": {
            "toolchain": sum(int(row["new_toolchain"]) for row in sample_rows),
            "prompts": sum(int(row["new_prompts"]) for row in sample_rows),
        },
        "exact_value_deltas": dict(sorted(delta_totals.items())),
        "llm_fact_groups": dict(sorted(fact_groups.items())),
        "llm_fact_audit": dict(sorted(audit_totals.items())),
        "limitations": dict(limitations.most_common()),
        "errors": [{"stage": stage, "error": error, "count": count}
                   for (stage, error), count in errors.most_common()],
        "rejection_reasons": dict(rejection_reasons.most_common()),
        "semantic_triage": {
            "method": "conservative_heuristic_initial_review_not_ground_truth",
            "counts": dict(sorted(semantic_counts.items())),
            "by_group": {group: dict(sorted(values.items()))
                         for group, values in sorted(semantic_by_group.items())},
        },
        "material_representations": dict(representations.most_common()),
        "static_tool_runs": [{"tool": tool, "status": status, "count": count}
                             for (tool, status), count in tool_runs.most_common()],
        "issue_counts": {key: len(value) for key, value in sorted(issue_samples.items())},
    }
    _write_json(root / "analysis_summary.json", summary)
    _write_json(root / "issue_samples.json", dict(sorted(issue_samples.items())))
    _write_json(root / "semantic_triage.json", semantic_triage)
    _write_csv(root / "tables" / "sample_matrix.csv", sample_rows)
    _write_csv(root / "tables" / "family_matrix.csv", family_matrix)
    print(json.dumps({
        "samples": completed,
        "families": len(family_rows),
        "analysis_summary": str(root / "analysis_summary.json"),
        "sample_matrix": str(root / "tables" / "sample_matrix.csv"),
        "issue_counts": summary["issue_counts"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()

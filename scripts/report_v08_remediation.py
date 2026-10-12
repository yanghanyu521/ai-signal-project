"""Evidence-bounded four-way comparison; candidate counts are not accuracy."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _group(sample: dict) -> str:
    fmt = sample.get("format")
    if fmt in {"pe", "elf", "mach_o", "apk", "dex", "python_bytecode"}:
        return "binary_or_package"
    if fmt == "text" and sample.get("recoverability") == "original_source":
        return "script_source"
    return "other_or_unresolved"


def _stats(result: dict) -> dict:
    features = result.get("features") or {}
    tools = (features.get("toolchain") or {}).get("evidence") or []
    prompts = (features.get("prompt") or {}).get("embedded_prompts") or []
    generation = features.get("code_generation_signals") or {}
    static = features.get("static_analysis") or {}
    run = static.get("run") or {}
    coverage = run.get("coverage") or {}
    recovery = coverage.get("recovery_coverage") or {}
    main_usage = (run.get("budget") or {}).get("provider_usage") or {}
    style = generation.get("semantic_analysis") or {}
    style_usage = style.get("provider_usage") or {}
    return {
        "toolchain_candidates": len(tools), "prompt_candidates": len(prompts),
        "relation_verified_tools": sum(item.get("verification_status") == "relation_verified" for item in tools),
        "relation_verified_prompts": sum(item.get("call_binding") == "relation_verified" for item in prompts),
        "fingerprint": generation.get("fingerprint") is not None,
        "style_observations": len(generation.get("style_indicators") or []),
        "style_rejected_text_asset": (style.get("rejection_reasons") or {}).get("text_asset_not_code_style", 0),
        "style_status": style.get("status"), "style_source_units": style.get("source_units_total"),
        "style_considered_units": style.get("source_units_considered"),
        "llm_status": run.get("status"), "main_requests": (run.get("budget") or {}).get("requests", 0),
        "style_requests": style.get("requests", 0),
        "main_tokens": main_usage.get("total_tokens"), "style_tokens": style_usage.get("total_tokens"),
        "main_elapsed_seconds": run.get("elapsed_seconds"), "style_elapsed_seconds": style.get("elapsed_seconds"),
        "strings_discovered": recovery.get("strings_discovered"),
        "strings_retained": recovery.get("strings_retained"),
        "strings_rejected_by_limit": recovery.get("strings_rejected_by_limit"),
        "bytes_scanned": recovery.get("bytes_scanned") or recovery.get("member_bytes_scanned"),
        "string_units_indexed": coverage.get("string_units_indexed"),
        "string_units_screened": coverage.get("string_units_screened"),
        "string_analysis_rate": coverage.get("string_analysis_rate"),
        "member_rejected_by_limit": recovery.get("members_rejected_by_limit"),
    }


def compare(v07: Path, v08_old: Path, post: Path) -> dict:
    manifest = _read(post / "manifest.json")
    if len(manifest) != 45:
        raise ValueError("Post-run manifest must contain 45 samples")
    rows = []
    for item in manifest:
        sha = item["sha256"]
        paths = {
            "v07_rule": v07 / "samples" / sha / "old_rule_result.json",
            "v07_llm": v07 / "samples" / sha / "v07_llm" / "result.json",
            "v08_pre": v08_old / "samples" / sha / "v08" / "result.json",
            "v08_post": post / "samples" / sha / "v08" / "result.json",
        }
        results = {key: _read(path) for key, path in paths.items()}
        current = results["v08_post"]
        sample = current.get("sample") or results["v08_pre"].get("sample") or {}
        row = {"sha256": sha, "family": item.get("family"), "group": _group(sample),
               "same_sha_across_versions": all(
                   result.get("sample", {}).get("sha256") == sha for result in results.values() if result),
               "versions_present": {key: bool(result) for key, result in results.items()},
               "versions": {key: _stats(result) if result else None for key, result in results.items()},
               "accuracy_status": "pending_human_adjudication"}
        rows.append(row)
    grouped = {}
    for group in ("script_source", "binary_or_package", "other_or_unresolved"):
        subset = [row for row in rows if row["group"] == group]
        totals = {}
        for version in ("v07_rule", "v07_llm", "v08_pre", "v08_post"):
            stats = [row["versions"][version] for row in subset if row["versions"][version]]
            totals[version] = {key: sum((entry.get(key) or 0) for entry in stats)
                               for key in ("toolchain_candidates", "prompt_candidates",
                                           "relation_verified_tools", "relation_verified_prompts",
                                           "fingerprint", "style_observations", "style_rejected_text_asset",
                                           "main_requests", "style_requests", "main_tokens", "style_tokens",
                                           "main_elapsed_seconds", "style_elapsed_seconds",
                                           "strings_discovered", "strings_retained", "strings_rejected_by_limit",
                                           "bytes_scanned", "string_units_indexed", "string_units_screened")}
            totals[version]["result_files"] = len(stats)
            totals[version]["llm_statuses"] = dict(Counter(entry.get("llm_status") for entry in stats))
        grouped[group] = {"samples": len(subset), "versions": totals}
    return {"schema_version": "v08-remediation-comparison/1.0", "expected_samples": 45,
            "post_result_files": sum(row["versions_present"]["v08_post"] for row in rows),
            "same_sha_across_available_versions": all(row["same_sha_across_versions"] for row in rows),
            "groups": grouped, "rows": rows,
            "correct_candidates": None, "missed_candidates": None,
            "wrong_relation_upgrades": None, "style_label_accuracy": None,
            "limitation": "Accuracy and complete recall require adjudicated gold standard and independent miss audit."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v07", type=Path, required=True)
    parser.add_argument("--v08-pre", type=Path, required=True)
    parser.add_argument("--post", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.v07, args.v08_pre, args.post)
    output = args.post / "comparison_summary.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"post_result_files": result["post_result_files"],
                      "same_sha": result["same_sha_across_available_versions"],
                      "groups": {key: value["samples"] for key, value in result["groups"].items()}},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()

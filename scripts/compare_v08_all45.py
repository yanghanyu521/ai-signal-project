"""Resumable, isolated v0.8 static reanalysis of the historical 45 samples.

Never executes a sample, changes the knowledge database, or invokes Docker.
The optional DeepSeek transfer uses the existing remote-redacted sample policy.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import io
import json
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ai_signal_hub.config import Settings
from ai_signal_hub.legacy import LegacyAdapters
from compare_sample_llm_runs import _atomic_json, _delta, _now, _sha256_file, _snapshot


PROJECT = Path(__file__).resolve().parents[1]
HISTORICAL = PROJECT / "data/evaluations/20260920_all45_llm_v07"
DEFAULT_OUTPUT = PROJECT / "data/evaluations/20261008_all45_v08_full"
EXECUTABLE_FORMATS = {"pe", "elf", "mach_o", "apk", "dex", "python_bytecode"}


def _group(sample: dict[str, Any]) -> str:
    fmt = sample.get("format")
    if fmt in EXECUTABLE_FORMATS:
        return "executable_or_package"
    if fmt == "text" and sample.get("recoverability") == "original_source":
        return "script_source"
    return "other_or_unresolved"


def _settings() -> Settings:
    return Settings(
        project_root=PROJECT, workspace_root=PROJECT.parent,
        data_dir=PROJECT / "data",
        legacy_sample_project=PROJECT / "components/ai_signal_demo",
        legacy_report_project=PROJECT / "components/report_extractor",
        seed_data_dir=PROJECT / "components/seed_data",
        sample_llm_enabled=True,
        sample_llm_allow_remote=True,
        sample_llm_transfer_policy="remote_redacted",
        sample_llm_mode="coverage",
        sample_llm_max_requests=128,
        sample_llm_max_reasoning_rounds=4,
        sample_llm_max_queries_per_round=8,
        sample_llm_max_context_units=32,
        static_tools_docker_enabled=False,
    )


def _run_one(spec: dict[str, Any], output: Path, settings: Settings) -> dict[str, Any]:
    sha = spec["sha256"]
    sample_path = Path(spec["selected_path"])
    if not sample_path.is_file() or _sha256_file(sample_path) != sha:
        raise ValueError(f"source_missing_or_hash_mismatch:{sha}")
    old_path = HISTORICAL / "samples" / sha / "old_rule_result.json"
    if not old_path.is_file():
        raise FileNotFoundError(f"historical_rule_result_missing:{sha}")
    old = json.loads(old_path.read_text(encoding="utf-8"))
    sample_dir = output / "samples" / sha
    sample_dir.mkdir(parents=True, exist_ok=True)
    _atomic_json(sample_dir / "historical_rule_result.json", old)
    started = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        current = LegacyAdapters(settings).analyze_sample(sample_path, sample_dir / "v08")
    seconds = round(time.perf_counter() - started, 3)
    sample = current.get("sample") or {}
    features = current.get("features") or {}
    generation = features.get("code_generation_signals") or {}
    run = ((features.get("static_analysis") or {}).get("run") or {})
    budget = run.get("budget") or {}
    old_snapshot, new_snapshot = _snapshot(old), _snapshot(current)
    llm_facts = [fact for fact in features.get("facts") or [] if fact.get("discovery_method") == "llm"]
    record = {
        "family": spec["family"], "sha256": sha, "sample_format": sample.get("format"),
        "language": sample.get("language"), "recoverability": sample.get("recoverability"),
        "group": _group(sample), "size_bytes": sample.get("size"), "duration_seconds": seconds,
        "old_rule": old_snapshot, "v08": new_snapshot,
        "old_rule_to_v08": _delta(old_snapshot, new_snapshot),
        "v08_extra": {
            "schema_version": current.get("schema_version"),
            "toolchain_records": len((features.get("toolchain") or {}).get("evidence") or []),
            "prompt_records": len((features.get("prompt") or {}).get("embedded_prompts") or []),
            "llm_fact_count": len(llm_facts),
            "eligible_llm_fact_count": sum(item.get("attribution_eligible") is True for item in llm_facts),
            "llm_fact_groups": dict(Counter(item.get("signal_group", "unknown") for item in llm_facts)),
            "fingerprint_available": generation.get("fingerprint") is not None,
            "local_profile_count": len(generation.get("local_profiles") or []),
            "member_source_profile_count": len(generation.get("member_source_profiles") or []),
            "style_indicator_count": len(generation.get("style_indicators") or []),
            "generation_artifact_count": len(generation.get("generation_artifacts") or []),
            "style_semantic_status": (generation.get("semantic_analysis") or {}).get("status"),
            "analysis_status": generation.get("analysis_status"),
            "llm_run_status": run.get("status"), "llm_requests": budget.get("requests", 0),
            "provider_usage": budget.get("provider_usage") or {},
            "limitations": run.get("limitations") or [], "errors": run.get("errors") or [],
            "docker_tool_runs": len(((features.get("static_analysis") or {}).get("materials") or {}).get("tool_runs") or []),
        },
    }
    _atomic_json(sample_dir / "comparison.json", record)
    return {"state": "completed", "completed_at": _now(), "duration_seconds": seconds,
            "group": record["group"], "llm_status": run.get("status"),
            "requests": budget.get("requests", 0), "llm_facts": len(llm_facts)}


def _aggregate(specs: list[dict[str, Any]], output: Path) -> dict[str, Any]:
    rows = []
    states = Counter()
    for spec in specs:
        base = output / "samples" / spec["sha256"]
        status_path = base / "status.json"
        status = json.loads(status_path.read_text(encoding="utf-8")) if status_path.is_file() else {}
        states[status.get("state", "pending")] += 1
        comparison = base / "comparison.json"
        if status.get("state") == "completed" and comparison.is_file():
            rows.append(json.loads(comparison.read_text(encoding="utf-8")))
    groups: dict[str, Counter] = defaultdict(Counter)
    family_groups: dict[str, Counter] = defaultdict(Counter)
    table = []
    for item in rows:
        old, new, extra = item["old_rule"], item["v08"], item["v08_extra"]
        group = item["group"]
        counter = groups[group]
        counter["samples"] += 1
        counter["old_toolchain"] += len(old["toolchain"])
        counter["v08_toolchain"] += len(new["toolchain"])
        counter["old_prompt"] += len(old["prompts"])
        counter["v08_prompt"] += len(new["prompts"])
        counter["old_toolchain_positive_samples"] += bool(old["toolchain"])
        counter["v08_toolchain_positive_samples"] += bool(new["toolchain"])
        counter["old_prompt_positive_samples"] += bool(old["prompts"])
        counter["v08_prompt_positive_samples"] += bool(new["prompts"])
        counter["llm_facts"] += extra["llm_fact_count"]
        counter["eligible_llm_facts"] += extra["eligible_llm_fact_count"]
        counter["fingerprints"] += extra["fingerprint_available"]
        counter["local_profiles"] += extra["local_profile_count"]
        counter["member_source_profiles"] += extra["member_source_profile_count"]
        counter["style_indicators"] += extra["style_indicator_count"]
        counter["generation_artifacts"] += extra["generation_artifact_count"]
        counter["requests"] += extra["llm_requests"]
        counter["docker_tool_runs"] += extra["docker_tool_runs"]
        family_groups[item["family"]][group] += 1
        table.append({
            "family": item["family"], "sha256": item["sha256"], "group": group,
            "format": item["sample_format"], "language": item["language"],
            "old_toolchain": len(old["toolchain"]), "v08_toolchain": len(new["toolchain"]),
            "old_prompt": len(old["prompts"]), "v08_prompt": len(new["prompts"]),
            "toolchain_added": len(item["old_rule_to_v08"]["toolchain_added"]),
            "toolchain_missing": len(item["old_rule_to_v08"]["toolchain_missing"]),
            "prompt_added": len(item["old_rule_to_v08"]["prompt_added"]),
            "prompt_missing": len(item["old_rule_to_v08"]["prompt_missing"]),
            "llm_status": extra["llm_run_status"], "llm_facts": extra["llm_fact_count"],
            "eligible_llm_facts": extra["eligible_llm_fact_count"],
            "fingerprint": extra["fingerprint_available"],
            "local_profiles": extra["local_profile_count"],
            "member_source_profiles": extra["member_source_profile_count"],
            "style_semantic_status": extra["style_semantic_status"],
            "requests": extra["llm_requests"], "duration_seconds": item["duration_seconds"],
        })
    table_dir = output / "tables"
    table_dir.mkdir(parents=True, exist_ok=True)
    columns = list(table[0]) if table else []
    if columns:
        with (table_dir / "sample_matrix.csv").open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(table)
    summary = {
        "generated_at": _now(), "expected_samples": len(specs),
        "states": dict(states), "completed_samples": len(rows),
        "groups": {key: dict(value) for key, value in sorted(groups.items())},
        "family_group_counts": {key: dict(value) for key, value in sorted(family_groups.items())},
        "llm_statuses": dict(Counter(item["v08_extra"]["llm_run_status"] for item in rows)),
        "style_semantic_statuses": dict(Counter(item["v08_extra"]["style_semantic_status"] for item in rows)),
        "sample_matrix": "tables/sample_matrix.csv",
    }
    _atomic_json(output / "aggregate_summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=HISTORICAL / "manifest.json")
    parser.add_argument("--max-samples", type=int)
    parser.add_argument("--sha", action="append", help="repeat to recheck selected manifest SHA-256 values")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--retry-failed", action="store_true")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if output == HISTORICAL.resolve() or HISTORICAL.resolve() in output.parents:
        raise ValueError("v0.8 output must not overwrite the historical v0.7 directory")
    if (PROJECT / "data").resolve() not in output.parents:
        raise ValueError("output must be a separate directory under project data/")
    specs = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.sha:
        selected = {value.lower() for value in args.sha}
        specs = [spec for spec in specs if spec["sha256"].lower() in selected]
        if len(specs) != len(selected):
            raise ValueError("one or more selected SHA-256 values are absent from the manifest")
    if args.max_samples is not None:
        specs = specs[:max(0, args.max_samples)]
    settings = _settings()
    if not settings.sample_llm_api_key:
        raise RuntimeError("missing SAMPLE_LLM_API_KEY / DEEPSEEK_API_KEY / cc-api")
    if any(not Path(spec["selected_path"]).is_file() for spec in specs):
        raise FileNotFoundError("manifest contains missing original samples")
    output.mkdir(parents=True, exist_ok=True)
    metadata = {
        "schema_version": "v08-all45-run/1.0", "created_at": _now(),
        "manifest": str(args.manifest.resolve()), "historical_baseline": str(HISTORICAL),
        "expected_samples": len(specs), "model": settings.sample_llm_model,
        "provider_host": urlparse(settings.sample_llm_base_url).hostname,
        "transfer_policy": settings.sample_llm_transfer_policy,
        "llm_enabled": True, "docker_enabled": False, "total_token_budget": None,
        "database_modified": False, "sample_execution": False,
    }
    _atomic_json(output / "run_metadata.json", metadata)
    _atomic_json(output / "manifest.json", specs)
    print(json.dumps({"preflight": "ok", "samples": len(specs),
                      "model": settings.sample_llm_model,
                      "transfer_policy": settings.sample_llm_transfer_policy,
                      "docker_enabled": False}, ensure_ascii=False), flush=True)
    if args.preflight_only:
        _aggregate(specs, output)
        return
    for index, spec in enumerate(specs, 1):
        sample_dir = output / "samples" / spec["sha256"]
        status_path = sample_dir / "status.json"
        existing = json.loads(status_path.read_text(encoding="utf-8")) if status_path.is_file() else {}
        if existing.get("state") == "completed" and (sample_dir / "comparison.json").is_file():
            print(json.dumps({"index": index, "state": "skipped_completed", "sha256": spec["sha256"][:12]}), flush=True)
            continue
        if existing.get("state") == "failed" and not args.retry_failed:
            print(json.dumps({"index": index, "state": "skipped_failed", "sha256": spec["sha256"][:12]}), flush=True)
            continue
        sample_dir.mkdir(parents=True, exist_ok=True)
        _atomic_json(status_path, {"state": "running", "started_at": _now()})
        try:
            status = _run_one(spec, output, settings)
        except Exception as exc:
            status = {"state": "failed", "failed_at": _now(), "error_type": type(exc).__name__,
                      "error": str(exc)}
            (sample_dir / "traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
        _atomic_json(status_path, status)
        print(json.dumps({"index": index, "total": len(specs), "family": spec["family"],
                          "sha256": spec["sha256"][:12], **status}, ensure_ascii=False), flush=True)
        _aggregate(specs, output)
    summary = _aggregate(specs, output)
    print(json.dumps({"run_complete": True, "states": summary["states"],
                      "completed_samples": summary["completed_samples"]}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()

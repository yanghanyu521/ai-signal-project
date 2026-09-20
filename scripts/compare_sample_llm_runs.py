from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sqlite3
import time
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ai_signal_hub.config import Settings
from ai_signal_hub.legacy import LegacyAdapters


PROJECT = Path(__file__).resolve().parents[1]


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _append_event(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"timestamp": _now(), **event}, ensure_ascii=False) + "\n")


def _parse_sample(value: str) -> dict[str, Any]:
    try:
        family, sha256, raw_path = value.split("::", 2)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("样本参数格式必须是 FAMILY::SHA256::PATH") from exc
    if len(sha256) != 64 or any(char not in "0123456789abcdefABCDEF" for char in sha256):
        raise argparse.ArgumentTypeError("SHA-256 必须是64位十六进制")
    return {
        "family": family,
        "sha256": sha256.lower(),
        "selected_path": str(Path(raw_path).resolve()),
        "matching_paths": [str(Path(raw_path).resolve())],
    }


def _settings(*, docker_tools: bool) -> Settings:
    return Settings(
        project_root=PROJECT,
        workspace_root=PROJECT.parent,
        data_dir=PROJECT / "data",
        legacy_sample_project=PROJECT / "components" / "ai_signal_demo",
        legacy_report_project=PROJECT / "components" / "report_extractor",
        seed_data_dir=PROJECT / "components" / "seed_data",
        sample_llm_enabled=True,
        sample_llm_allow_remote=True,
        sample_llm_transfer_policy="remote_redacted",
        sample_llm_mode="coverage",
        sample_llm_max_requests=128,
        sample_llm_max_reasoning_rounds=4,
        sample_llm_max_queries_per_round=8,
        sample_llm_max_context_units=32,
        static_tools_docker_enabled=docker_tools,
    )


def _database_rows(database: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT sha256, source_case, original_name, size_bytes, file_type, result_json "
            "FROM samples ORDER BY source_case, sha256"
        ).fetchall()
    finally:
        connection.close()
    return [dict(row) for row in rows]


def _read_baseline(database: Path, sha256: str) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True)
    try:
        row = connection.execute("SELECT result_json FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
    finally:
        connection.close()
    if not row:
        raise ValueError(f"知识库中不存在样本 {sha256}")
    return json.loads(row[0])


def _discover_database_samples(database: Path, samples_root: Path) -> list[dict[str, Any]]:
    rows = _database_rows(database)
    targets = {str(row["sha256"]).lower() for row in rows}
    matches: dict[str, list[Path]] = defaultdict(list)
    for path in sorted(samples_root.rglob("*")):
        if not path.is_file():
            continue
        digest = _sha256_file(path)
        if digest in targets:
            matches[digest].append(path.resolve())
    specs = []
    for row in rows:
        sha256 = str(row["sha256"]).lower()
        candidates = sorted(
            matches.get(sha256, []),
            key=lambda path: (path.name.lower() != sha256, len(str(path)), str(path).lower()),
        )
        specs.append({
            "family": row.get("source_case") or "unknown",
            "sha256": sha256,
            "original_name": row.get("original_name"),
            "database_size_bytes": row.get("size_bytes"),
            "database_file_type": row.get("file_type"),
            "selected_path": str(candidates[0]) if candidates else None,
            "matching_paths": [str(path) for path in candidates],
        })
    return specs


def _tool_values(result: dict[str, Any], *, eligible_only: bool = False) -> list[dict[str, Any]]:
    records = []
    for item in ((result.get("features") or {}).get("toolchain") or {}).get("evidence", []) or []:
        if eligible_only and item.get("attribution_eligible") is not True:
            continue
        records.append({
            "type": item.get("type"),
            "raw_value": item.get("raw_value") or item.get("value"),
            "normalized": item.get("normalized") or {},
            "source": item.get("source"),
            "discovery_method": item.get("discovery_method"),
            "verification_status": item.get("verification_status"),
            "role": item.get("role"),
            "attribution_eligible": item.get("attribution_eligible"),
        })
    return records


def _prompt_values(result: dict[str, Any], *, eligible_only: bool = False) -> list[dict[str, Any]]:
    records = []
    for item in ((result.get("features") or {}).get("prompt") or {}).get("embedded_prompts", []) or []:
        if eligible_only and item.get("attribution_eligible") is not True:
            continue
        records.append({
            "text": item.get("text") or item.get("text_preview"),
            "text_hash": item.get("text_hash") or item.get("evidence_text_hash"),
            "source": item.get("source"),
            "discovery_method": item.get("discovery_method"),
            "completeness": item.get("completeness"),
            "call_binding": item.get("call_binding"),
            "role": item.get("role"),
            "attribution_eligible": item.get("attribution_eligible"),
        })
    return records


def _model_values(tools: list[dict[str, Any]]) -> list[str]:
    values = set()
    for item in tools:
        normalized = item.get("normalized") or {}
        if item.get("type") in {"model_argument", "model_identifier"}:
            value = normalized.get("model") or normalized.get("model_identifier_raw") or item.get("raw_value")
            if value:
                values.add(str(value))
    return sorted(values)


def _snapshot(result: dict[str, Any]) -> dict[str, Any]:
    tools = _tool_values(result)
    eligible_tools = _tool_values(result, eligible_only=True)
    prompts = _prompt_values(result)
    eligible_prompts = _prompt_values(result, eligible_only=True)
    static = ((result.get("features") or {}).get("static_analysis") or {})
    run = static.get("run") or {}
    facts = (result.get("features") or {}).get("facts", []) or []
    llm_facts = [fact for fact in facts if fact.get("discovery_method") == "llm"]
    return {
        "schema_version": result.get("schema_version"),
        "classification": result.get("classification") or {},
        "toolchain": tools,
        "eligible_toolchain": eligible_tools,
        "models": _model_values(tools),
        "eligible_models": _model_values(eligible_tools),
        "prompts": prompts,
        "eligible_prompts": eligible_prompts,
        "prompt_compositions": (((result.get("features") or {}).get("prompt") or {}).get("compositions") or []),
        "llm_facts": llm_facts,
        "code_generation_observations": (((result.get("features") or {}).get("code_generation_signals") or {}).get("observations") or []),
        "materials": static.get("materials") or {},
        "run": {
            "status": run.get("status"),
            "coverage": run.get("coverage") or {},
            "budget": run.get("budget") or {},
            "llm_transfer": run.get("llm_transfer"),
            "errors": run.get("errors") or [],
            "limitations": run.get("limitations") or [],
            "query_audit": run.get("query_audit") or [],
        },
    }


def _texts(records: list[dict[str, Any]]) -> set[str]:
    return {str(item["text"]) for item in records if item.get("text")}


def _raw(records: list[dict[str, Any]]) -> set[str]:
    return {str(item["raw_value"]) for item in records if item.get("raw_value")}


def _delta(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_tools, right_tools = _raw(left["toolchain"]), _raw(right["toolchain"])
    left_prompts, right_prompts = _texts(left["prompts"]), _texts(right["prompts"])
    return {
        "toolchain_added": sorted(right_tools - left_tools),
        "toolchain_missing": sorted(left_tools - right_tools),
        "prompt_added": sorted(right_prompts - left_prompts),
        "prompt_missing": sorted(left_prompts - right_prompts),
        "model_added": sorted(set(right["models"]) - set(left["models"])),
        "model_missing": sorted(set(left["models"]) - set(right["models"])),
    }


def _audit_llm_facts(result: dict[str, Any], materials_path: Path) -> dict[str, Any]:
    facts = [fact for fact in (result.get("features") or {}).get("facts", []) or []
             if fact.get("discovery_method") == "llm"]
    materials = json.loads(materials_path.read_text(encoding="utf-8")) if materials_path.is_file() else {}
    units = {unit.get("unit_id"): unit for unit in materials.get("units", []) or []}
    counts = Counter()
    groups = Counter()
    for fact in facts:
        raw = str(fact.get("raw_value") or "")
        source_ids = fact.get("source_unit_ids") or []
        selected = [units[source_id] for source_id in source_ids if source_id in units]
        location = fact.get("source_location") or {}
        location_unit = units.get(location.get("unit_id"))
        content = (location_unit or {}).get("content") or ""
        offset = location.get("unit_char_offset")
        expected_hash = "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
        counts["source_units_exist"] += int(len(selected) == len(source_ids) and bool(source_ids))
        counts["raw_exact_in_source"] += int(bool(raw) and any(raw in (unit.get("content") or "") for unit in selected))
        counts["hash_matches"] += int(fact.get("evidence_text_hash") == expected_hash)
        counts["offset_matches"] += int(
            isinstance(offset, int) and bool(raw) and content[offset:offset + len(raw)] == raw
        )
        counts["eligible"] += int(fact.get("attribution_eligible") is True)
        counts["needs_review"] += int(fact.get("semantic_review_status") == "needs_review")
        groups[str(fact.get("signal_group") or "unknown")] += 1
    return {"total": len(facts), **dict(counts), "groups": dict(sorted(groups.items()))}


def _label(snapshot: dict[str, Any]) -> str:
    return str((((snapshot.get("classification") or {}).get("llm_involvement") or {}).get("label")) or "unknown")


def _aggregate(specs: list[dict[str, Any]], output: Path) -> dict[str, Any]:
    comparisons, failures, sample_states = [], [], []
    for spec in specs:
        sample_dir = output / "samples" / spec["sha256"]
        status_path = sample_dir / "status.json"
        status = json.loads(status_path.read_text(encoding="utf-8")) if status_path.is_file() else {"state": "pending"}
        sample_states.append({"sha256": spec["sha256"], "family": spec["family"], **status})
        comparison_path = sample_dir / "comparison.json"
        if status.get("state") == "completed" and comparison_path.is_file():
            comparisons.append(json.loads(comparison_path.read_text(encoding="utf-8")))
        elif status.get("state") == "failed":
            failures.append({"sha256": spec["sha256"], "family": spec["family"], **status})
    old_labels = Counter(_label(item["old_rule"]) for item in comparisons)
    new_labels = Counter(_label(item["v07_llm"]) for item in comparisons)
    llm_statuses = Counter(item["v07_llm"]["run"].get("status") or "missing" for item in comparisons)
    fact_groups = Counter()
    audit_totals = Counter()
    provider_usage = Counter()
    family_summary: dict[str, Counter] = defaultdict(Counter)
    for item in comparisons:
        snapshot = item["v07_llm"]
        for fact in snapshot["llm_facts"]:
            fact_groups[str(fact.get("signal_group") or "unknown")] += 1
        for key, value in (item.get("llm_fact_audit") or {}).items():
            if isinstance(value, int):
                audit_totals[key] += value
        budget = snapshot["run"].get("budget") or {}
        provider_usage.update({key: int(value) for key, value in (budget.get("provider_usage") or {}).items()
                               if isinstance(value, (int, float))})
        family = family_summary[item["family"]]
        family["samples"] += 1
        family["old_tools"] += len(item["old_rule"]["toolchain"])
        family["new_tools"] += len(snapshot["toolchain"])
        family["old_prompts"] += len(item["old_rule"]["prompts"])
        family["new_prompts"] += len(snapshot["prompts"])
        family["llm_facts"] += len(snapshot["llm_facts"])
        family["eligible_llm_facts"] += sum(fact.get("attribution_eligible") is True for fact in snapshot["llm_facts"])
    summary = {
        "generated_at": _now(),
        "expected_samples": len(specs),
        "completed_samples": len(comparisons),
        "failed_samples": len(failures),
        "pending_samples": len(specs) - len(comparisons) - len(failures),
        "old_label_distribution": dict(sorted(old_labels.items())),
        "new_label_distribution": dict(sorted(new_labels.items())),
        "llm_run_status_distribution": dict(sorted(llm_statuses.items())),
        "old_toolchain_records": sum(len(item["old_rule"]["toolchain"]) for item in comparisons),
        "new_toolchain_records": sum(len(item["v07_llm"]["toolchain"]) for item in comparisons),
        "old_prompt_records": sum(len(item["old_rule"]["prompts"]) for item in comparisons),
        "new_prompt_records": sum(len(item["v07_llm"]["prompts"]) for item in comparisons),
        "llm_fact_groups": dict(sorted(fact_groups.items())),
        "llm_fact_audit": dict(sorted(audit_totals.items())),
        "provider_usage": dict(sorted(provider_usage.items())),
        "families": {family: dict(values) for family, values in sorted(family_summary.items())},
    }
    _atomic_json(output / "comparison_summary.json", comparisons)
    _atomic_json(output / "failures.json", failures)
    _atomic_json(output / "sample_states.json", sample_states)
    _atomic_json(output / "aggregate_summary.json", summary)
    return summary


def _run_sample(spec: dict[str, Any], database: Path, output: Path, settings: Settings) -> dict[str, Any]:
    sha256 = spec["sha256"]
    family = spec["family"]
    path_value = spec.get("selected_path")
    if not path_value:
        raise FileNotFoundError(f"没有找到 {sha256} 的原始样本")
    path = Path(path_value)
    actual_sha = _sha256_file(path)
    if actual_sha != sha256:
        raise ValueError(f"{family} SHA-256不一致：{actual_sha}")
    sample_dir = output / "samples" / sha256
    sample_dir.mkdir(parents=True, exist_ok=True)
    baseline = _read_baseline(database, sha256)
    _atomic_json(sample_dir / "old_rule_result.json", baseline)
    started = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        hybrid = LegacyAdapters(settings).analyze_sample(path, sample_dir / "v07_llm")
    elapsed = time.perf_counter() - started
    old_snapshot = _snapshot(baseline)
    hybrid_snapshot = _snapshot(hybrid)
    audit = _audit_llm_facts(hybrid, sample_dir / "v07_llm" / "static_materials.json")
    comparison = {
        "family": family,
        "sha256": sha256,
        "source_path": str(path),
        "size_bytes": path.stat().st_size,
        "duration_seconds": round(elapsed, 3),
        "old_rule": old_snapshot,
        "v07_llm": hybrid_snapshot,
        "old_to_v07_llm": _delta(old_snapshot, hybrid_snapshot),
        "llm_fact_audit": audit,
    }
    _atomic_json(sample_dir / "comparison.json", comparison)
    status = {
        "state": "completed",
        "completed_at": _now(),
        "duration_seconds": round(elapsed, 3),
        "llm_status": hybrid_snapshot["run"].get("status"),
        "requests": (hybrid_snapshot["run"].get("budget") or {}).get("requests", 0),
        "llm_facts": len(hybrid_snapshot["llm_facts"]),
    }
    _atomic_json(sample_dir / "status.json", status)
    return status


def main() -> None:
    parser = argparse.ArgumentParser(description="隔离比较知识库旧规则结果与v0.7+LLM样本静态分析")
    parser.add_argument("--database", type=Path, default=PROJECT / "data" / "knowledge.db")
    parser.add_argument("--output-dir", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sample", action="append", type=_parse_sample)
    source.add_argument("--all-from-database", action="store_true")
    parser.add_argument("--samples-root", type=Path, default=PROJECT.parent / "恶意样本文件")
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--docker-tools", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--max-samples", type=int)
    args = parser.parse_args()

    database = args.database.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    specs = (_discover_database_samples(database, args.samples_root.resolve())
             if args.all_from_database else list(args.sample or []))
    if args.max_samples is not None:
        specs = specs[:max(0, args.max_samples)]
    settings = _settings(docker_tools=args.docker_tools)
    if not settings.sample_llm_api_key:
        raise RuntimeError("未检测到SAMPLE_LLM_API_KEY或cc-api")

    metadata = {
        "schema_version": "1.0",
        "created_at": _now(),
        "analysis_method": "v0.7 deterministic static analysis + DeepSeek semantic extraction",
        "database": str(database),
        "database_sha256": _sha256_file(database),
        "samples_root": str(args.samples_root.resolve()),
        "expected_samples": len(specs),
        "model": settings.sample_llm_model,
        "provider_host": urlparse(settings.sample_llm_base_url).hostname,
        "transfer_policy": settings.sample_llm_transfer_policy,
        "remote_allowed": settings.sample_llm_allow_remote,
        "total_token_budget": None,
        "max_requests_per_sample": settings.sample_llm_max_requests,
        "docker_tools_enabled": args.docker_tools,
        "jadx_image": settings.jadx_docker_image if args.docker_tools else None,
        "ghidra_image": settings.ghidra_docker_image if args.docker_tools else None,
        "knowledge_database_modified": False,
    }
    _atomic_json(output / "run_metadata.json", metadata)
    _atomic_json(output / "manifest.json", specs)
    print(json.dumps({
        "preflight": "ok",
        "samples": len(specs),
        "missing_sources": sum(not spec.get("selected_path") for spec in specs),
        "duplicate_sources": sum(len(spec.get("matching_paths") or []) > 1 for spec in specs),
        "model": settings.sample_llm_model,
        "transfer_policy": settings.sample_llm_transfer_policy,
        "docker_tools": args.docker_tools,
        "key_present": True,
    }, ensure_ascii=False), flush=True)
    if args.preflight_only:
        _aggregate(specs, output)
        return

    events_path = output / "run_events.jsonl"
    for index, spec in enumerate(specs, start=1):
        sample_dir = output / "samples" / spec["sha256"]
        status_path = sample_dir / "status.json"
        existing = json.loads(status_path.read_text(encoding="utf-8")) if status_path.is_file() else {}
        if args.resume and existing.get("state") == "completed" and (sample_dir / "comparison.json").is_file():
            print(json.dumps({"index": index, "total": len(specs), "family": spec["family"],
                              "sha256": spec["sha256"][:12], "state": "skipped_completed"},
                             ensure_ascii=False), flush=True)
            continue
        if args.resume and existing.get("state") == "failed" and not args.retry_failed:
            print(json.dumps({"index": index, "total": len(specs), "family": spec["family"],
                              "sha256": spec["sha256"][:12], "state": "skipped_failed"},
                             ensure_ascii=False), flush=True)
            continue
        sample_dir.mkdir(parents=True, exist_ok=True)
        _atomic_json(status_path, {"state": "running", "started_at": _now()})
        _append_event(events_path, {"event": "sample_started", "index": index, "sha256": spec["sha256"],
                                    "family": spec["family"]})
        try:
            status = _run_sample(spec, database, output, settings)
            _append_event(events_path, {"event": "sample_completed", "index": index,
                                        "sha256": spec["sha256"], "family": spec["family"], **status})
            print(json.dumps({"index": index, "total": len(specs), "family": spec["family"],
                              "sha256": spec["sha256"][:12], **status}, ensure_ascii=False), flush=True)
        except Exception as exc:  # Keep the 45-sample run resumable and auditable.
            failed = {"state": "failed", "failed_at": _now(), "error_type": type(exc).__name__,
                      "error": str(exc)}
            _atomic_json(status_path, failed)
            (sample_dir / "traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
            _append_event(events_path, {"event": "sample_failed", "index": index,
                                        "sha256": spec["sha256"], "family": spec["family"], **failed})
            print(json.dumps({"index": index, "total": len(specs), "family": spec["family"],
                              "sha256": spec["sha256"][:12], **failed}, ensure_ascii=False), flush=True)
        _aggregate(specs, output)
    summary = _aggregate(specs, output)
    print(json.dumps({"run_complete": True, **summary}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()

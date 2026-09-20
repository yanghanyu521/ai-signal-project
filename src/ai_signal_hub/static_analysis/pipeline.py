from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from .llm import SampleLLMClient
from .materials import MaterialIndex, build_material_index, split_large_units
from .query import StaticQueryService


def _estimate_tokens(text: str) -> int:
    # Conservative scheduling estimate only; actual provider usage is retained.
    return max(1, (len(text.encode("utf-8")) + 2) // 3)


def _batch_units(units: list[Any], max_input_tokens: int) -> list[list[Any]]:
    """Pack analysis units into requests without imposing a run-wide token budget."""
    # Keep room for the system prompt, JSON envelope and an optional context-query
    # response. Oversized units have already been split before this is called.
    target = max(512, max_input_tokens - min(8192, max_input_tokens // 4))
    batches: list[list[Any]] = []
    current: list[Any] = []
    current_tokens = 0
    for unit in units:
        estimate = _estimate_tokens(json.dumps(unit.as_dict(include_content=True), ensure_ascii=False))
        if current and current_tokens + estimate > target:
            batches.append(current)
            current = []
            current_tokens = 0
        current.append(unit)
        current_tokens += estimate
    if current:
        batches.append(current)
    return batches


def _fact_id(group: str, raw: str, unit_ids: list[str]) -> str:
    value = json.dumps([group, raw, sorted(unit_ids)], ensure_ascii=False)
    return "fact:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def _anchor_matches(anchor: dict[str, Any], group: str, raw: str, units: list[Any]) -> bool:
    if anchor.get("signal_group") != group or anchor.get("raw_value") != raw:
        return False
    verification = anchor.get("verification") or {}
    if verification.get("relation") != "verified" and anchor.get("verification_status") != "relation_verified":
        return False
    location = anchor.get("source_location") or {}
    line = location.get("line")
    if not isinstance(line, int):
        return False
    return any(
        isinstance(unit.location.get("source_lines"), list)
        and len(unit.location["source_lines"]) >= 2
        and isinstance(unit.location["source_lines"][0], int)
        and unit.location["source_lines"][0] <= line <= unit.location["source_lines"][1]
        for unit in units
    )


def _validate_facts(
    response: dict[str, Any], index: MaterialIndex,
    relation_anchors: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    units = {unit.unit_id: unit for unit in index.units}
    accepted, rejected = [], []
    for candidate in response.get("facts") or []:
        if not isinstance(candidate, dict):
            rejected.append({"reason": "fact_not_object"})
            continue
        group = candidate.get("signal_group")
        raw = candidate.get("raw_value")
        ids = candidate.get("source_unit_ids") or []
        if group not in {"toolchain", "prompt", "code_observation"} or not isinstance(raw, str) or not raw:
            rejected.append({"reason": "invalid_fact_shape", "candidate": candidate})
            continue
        if not isinstance(ids, list) or not ids or any(unit_id not in units for unit_id in ids):
            rejected.append({"reason": "invalid_source_reference", "candidate": candidate})
            continue
        containing = [units[unit_id] for unit_id in ids if raw in units[unit_id].content]
        if not containing:
            rejected.append({"reason": "raw_value_not_in_material", "candidate": candidate})
            continue
        first = containing[0]
        char_offset = first.content.find(raw)
        line_start = first.location.get("source_lines", [None])[0]
        source_line = line_start + first.content[:char_offset].count("\n") if isinstance(line_start, int) else None
        normalized = candidate.get("normalized_value") if isinstance(candidate.get("normalized_value"), dict) else {}
        # SDK identity never becomes model identity without a separately cited value.
        if not normalized.get("model_identifier_raw"):
            normalized.pop("model_vendor", None)
            normalized.pop("model_family", None)
        elif normalized.get("model_identifier_raw") != raw:
            normalized["model_identifier_raw"] = raw
        material_text = "\n".join(units[unit_id].content for unit_id in ids)
        for key in ("model_vendor", "model_family", "sdk_name", "sdk_vendor", "service_provider", "service_endpoint"):
            value = normalized.get(key)
            if isinstance(value, str) and value not in material_text:
                normalized.pop(key, None)
        if group == "toolchain" and not any(
            isinstance(normalized.get(key), str) and normalized[key].strip()
            for key in ("model_identifier_raw", "model_vendor", "model_family", "sdk_name",
                        "sdk_vendor", "service_provider", "service_endpoint")
        ):
            rejected.append({"reason": "toolchain_fact_has_no_typed_identity", "candidate": candidate})
            continue
        raw_limitations = candidate.get("limitations")
        limitations = (
            [raw_limitations] if isinstance(raw_limitations, str) and raw_limitations.strip()
            else [str(item) for item in raw_limitations if str(item).strip()]
            if isinstance(raw_limitations, list)
            else ["semantic_interpretation_not_deterministically_verified"]
        )
        if not limitations:
            limitations = ["semantic_interpretation_not_deterministically_verified"]
        proposed_role = candidate.get("role") if candidate.get("role") in {
            "application", "dependency", "example", "analysis_helper", "analyzer_directive", "unknown"
        } else "unknown"
        material_roles = {unit.probable_role for unit in containing}
        role = next(iter(material_roles)) if len(material_roles) == 1 else "unknown"
        role_state = "verified" if role != "unknown" else "unknown"
        relation_verified = any(
            _anchor_matches(anchor, group, raw, containing) for anchor in (relation_anchors or [])
        )
        relation_state = "verified" if relation_verified else "candidate"
        attribution_eligible = bool(
            group in {"toolchain", "prompt"}
            and relation_verified and role_state == "verified" and role == "application"
        )
        fact = {
            "fact_id": _fact_id(group, raw, ids), "signal_group": group,
            "raw_value": raw, "normalized_value": normalized,
            "source_unit_ids": ids,
            "source_location": {"unit_id": first.unit_id, "line": source_line,
                                "unit_char_offset": char_offset},
            "evidence_text_hash": "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "discovery_method": "llm",
            "verification_status": "relation_verified" if relation_verified else "location_verified",
            "verification": {"location": "verified", "relation": relation_state, "role": role_state},
            "attribution_eligible": attribution_eligible,
            # A model cannot mark its own interpretation as human-reviewed.
            "semantic_review_status": "needs_review",
            "limitations": limitations,
            "role": role,
            "proposed_role": proposed_role,
        }
        accepted.append(fact)
    return accepted, rejected


def _query_context(
    response: dict[str, Any], service: StaticQueryService, max_queries: int, *,
    round_number: int, seen_queries: set[str], seen_unit_ids: set[str],
    max_context_units: int,
) -> tuple[list[dict], list[dict]]:
    results, audit = [], []
    for item in (response.get("queries") or [])[:max_queries]:
        if not isinstance(item, dict):
            continue
        name, arguments = str(item.get("name") or ""), item.get("arguments") or {}
        arguments = arguments if isinstance(arguments, dict) else {}
        query_key = json.dumps([name, arguments], ensure_ascii=False, sort_keys=True)
        source_unit_id = arguments.get("unit_id")
        if query_key in seen_queries:
            audit.append({"round": round_number, "source_unit_id": source_unit_id,
                          "query": name, "arguments": arguments, "result_unit_ids": [],
                          "status": "duplicate", "reason": "query_already_executed"})
            continue
        seen_queries.add(query_key)
        result = service.execute(name, arguments)
        new_units = []
        if result.get("status") == "ok":
            for unit in result.get("units") or []:
                unit_id = unit.get("unit_id")
                if not isinstance(unit_id, str) or unit_id in seen_unit_ids:
                    continue
                if len(seen_unit_ids) >= max_context_units:
                    break
                seen_unit_ids.add(unit_id)
                new_units.append(unit)
            if new_units:
                results.append({**result, "units": new_units})
        audit.append({"round": round_number, "source_unit_id": source_unit_id,
                      "query": name, "arguments": arguments,
                      "result_unit_ids": [unit["unit_id"] for unit in new_units],
                      "status": result.get("status"), "reason": result.get("reason")})
    return results, audit


def run_static_analysis(
    data: bytes, sample: dict[str, Any], artifact_dir: Path, *,
    llm_client: SampleLLMClient | None = None, mode: str = "coverage",
    max_input_tokens: int = 64000, max_requests: int = 128,
    max_reasoning_rounds: int = 4, max_queries_per_round: int = 8,
    max_context_units: int = 32,
    recovered_index: MaterialIndex | None = None,
    relation_anchors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if mode not in {"coverage", "budgeted"}:
        raise ValueError("SAMPLE_LLM_MODE 只能是 coverage 或 budgeted")
    index = recovered_index or build_material_index(data, sample)
    per_unit_limit = max(512, max_input_tokens - min(8192, max_input_tokens // 4))
    index = split_large_units(index, per_unit_limit)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    material_path = artifact_dir / "static_materials.json"
    material_path.write_text(json.dumps({
        **index.public_summary(),
        "units": [unit.as_dict(include_content=True) for unit in index.units],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    recovery_coverage = dict(index.recovery_coverage or {})
    if not recovery_coverage:
        recovery_coverage = {
            "artifacts_discovered": 1,
            "artifacts_recovered": int(bool(index.units)),
            "artifacts_failed": int(index.status == "failed"),
        }
    relation_keys = {"calls", "callers", "definitions", "resources", "strings", "previous", "next"}
    relation_count = sum(
        len(values) for unit in index.units for key, values in unit.references.items()
        if key in relation_keys
    )
    material_coverage = {
        "units_indexed": len(index.units),
        "representations": sorted({unit.representation for unit in index.units}),
        "roles": {role: sum(unit.probable_role == role for unit in index.units)
                  for role in sorted({unit.probable_role for unit in index.units})},
    }
    relation_coverage = {
        "resolved_relations": relation_count,
        "units_with_relations": sum(any(unit.references.get(key) for key in relation_keys)
                                    for unit in index.units),
        "xrefs_available": bool(index.capabilities.get("xrefs")),
        "dataflow_available": bool(index.capabilities.get("dataflow")),
    }
    run = {
        "schema_version": "static-analysis-run/1.0", "mode": mode,
        "status": "unavailable" if llm_client is None else ("unsupported" if not index.units else "completed"),
        "index_status": index.status, "material_artifact": str(material_path.resolve()),
        "coverage": {"indexed_units": len(index.units), "screened_units": 0,
                     "cached_units": 0, "failed_units": 0, "unprocessed_unit_ids": [],
                     "recovery_coverage": recovery_coverage,
                     "material_coverage": material_coverage,
                     "relation_coverage": relation_coverage},
        "budget": {"configured_total_token_budget": None, "estimated_tokens_used": 0,
                   "max_input_tokens_per_request": max_input_tokens,
                   "provider_usage": {}, "requests": 0, "max_requests": max_requests,
                   "max_reasoning_rounds": max_reasoning_rounds,
                   "max_queries_per_round": max_queries_per_round,
                   "max_context_units": max_context_units},
        "facts": [], "rejected_facts": [], "query_audit": [], "errors": [],
        "llm_transfer": llm_client.transfer_metadata() if llm_client is not None and hasattr(llm_client, "transfer_metadata") else None,
        "limitations": list(index.limitations),
    }
    if llm_client is None:
        run["limitations"].append("sample_llm_disabled")
        run["coverage"]["unprocessed_unit_ids"] = [unit.unit_id for unit in index.units]
        return {"materials": index.public_summary(), "run": run}
    query_service = StaticQueryService(index)
    start = time.monotonic()
    batches = _batch_units(index.units, max_input_tokens)
    processed_units = 0
    for batch in batches:
        payloads = [unit.as_dict(include_content=True) for unit in batch]
        estimate = _estimate_tokens(json.dumps(payloads, ensure_ascii=False))
        if run["budget"]["requests"] >= max_requests:
            run["status"] = "partial"
            run["coverage"]["unprocessed_unit_ids"] = [item.unit_id for item in index.units[processed_units:]]
            break
        try:
            response = llm_client.analyze(payloads)
            run["budget"]["requests"] += 1
            run["budget"]["estimated_tokens_used"] += estimate
            run["coverage"]["screened_units"] += len(batch)
            for key, value in (response.get("usage") or {}).items():
                if isinstance(value, (int, float)):
                    run["budget"]["provider_usage"][key] = run["budget"]["provider_usage"].get(key, 0) + value
            combined_facts = list(response.get("facts") or [])
            seen_queries: set[str] = set()
            seen_context_ids = {unit.unit_id for unit in batch}
            context: list[dict[str, Any]] = []
            current_response = response
            for round_number in range(1, max_reasoning_rounds + 1):
                new_context, audit = _query_context(
                    current_response, query_service, max_queries_per_round,
                    round_number=round_number, seen_queries=seen_queries,
                    seen_unit_ids=seen_context_ids, max_context_units=max_context_units,
                )
                run["query_audit"].extend(audit)
                if not new_context or run["budget"]["requests"] >= max_requests:
                    break
                context.extend(new_context)
                context_estimate = _estimate_tokens(json.dumps(context, ensure_ascii=False))
                try:
                    followup = llm_client.analyze(payloads, context)
                    run["budget"]["requests"] += 1
                    run["budget"]["estimated_tokens_used"] += context_estimate
                    for key, value in (followup.get("usage") or {}).items():
                        if isinstance(value, (int, float)):
                            run["budget"]["provider_usage"][key] = run["budget"]["provider_usage"].get(key, 0) + value
                    combined_facts.extend(followup.get("facts") or [])
                    current_response = followup
                except Exception as exc:
                    run["errors"].append({"unit_ids": [unit.unit_id for unit in batch],
                                          "stage": "context_followup",
                                          "error": f"{type(exc).__name__}: {exc}"})
                    run["status"] = "partial"
                    break
            facts, rejected = _validate_facts({"facts": combined_facts}, index, relation_anchors)
            run["facts"].extend(facts)
            run["rejected_facts"].extend(rejected)
        except Exception as exc:
            run["coverage"]["failed_units"] += len(batch)
            run["errors"].append({"unit_ids": [unit.unit_id for unit in batch],
                                  "error": f"{type(exc).__name__}: {exc}"})
            run["status"] = "partial"
        finally:
            processed_units += len(batch)
    if run["errors"] and run["coverage"]["screened_units"] == 0:
        run["status"] = "failed"
    if llm_client is not None and hasattr(llm_client, "transfer_metadata"):
        run["llm_transfer"] = llm_client.transfer_metadata()
    run["elapsed_seconds"] = round(time.monotonic() - start, 4)
    return {"materials": index.public_summary(), "run": run}

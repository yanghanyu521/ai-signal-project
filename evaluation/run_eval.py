from __future__ import annotations

import argparse
import contextlib
import io
import json
import shutil
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

from ai_signal_hub.config import Settings
from ai_signal_hub.legacy import LegacyAdapters
from ai_signal_hub.static_analysis.docker_tools import DockerStaticTools


ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _analyze_source(case: dict[str, Any], fixture: Path, work: Path) -> tuple[dict[str, Any], float]:
    sample_path = fixture
    if case["category"] in {"dependency", "example"}:
        sample_path = work / f"{case['id']}.zip"
        member = ("vendor/sdk.py" if case["category"] == "dependency" else "examples/readme.py")
        with zipfile.ZipFile(sample_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(member, fixture.read_bytes())
    settings = Settings(
        project_root=PROJECT, workspace_root=PROJECT.parent, data_dir=work / "data",
        legacy_sample_project=PROJECT / "components" / "ai_signal_demo",
        legacy_report_project=PROJECT / "components" / "report_extractor",
        seed_data_dir=PROJECT / "components" / "seed_data",
        sample_llm_enabled=False, sample_llm_allow_remote=False,
        sample_llm_transfer_policy="local_only", static_tools_docker_enabled=False,
    )
    started = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        result = LegacyAdapters(settings).analyze_sample(sample_path, work / f"artifacts-{case['id']}")
    return result, time.perf_counter() - started


def _eligible_values(result: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    features = result.get("features") or {}
    tools = [item for item in (features.get("toolchain") or {}).get("evidence", []) or []
             if item.get("attribution_eligible") is True and item.get("role") == "application"]
    prompts = [item for item in (features.get("prompt") or {}).get("embedded_prompts", []) or []
               if item.get("attribution_eligible") is True and item.get("role") == "application"]
    return tools, prompts


def run() -> dict[str, Any]:
    cases = json.loads((ROOT / "annotations" / "cases.json").read_text(encoding="utf-8"))
    totals = {key: 0 for key in (
        "model_tp", "model_fp", "model_fn", "vendor_false", "vendor_predictions",
        "prompt_tp", "prompt_fp", "prompt_fn", "bound_prompts", "eligible_prompts",
        "hard_negative_hits", "hard_negative_total", "role_errors", "role_checks",
        "valid_citations", "citations", "valid_relations", "relations", "failures",
        "requests", "tokens",
    )}
    latencies: list[float] = []
    details = []
    with tempfile.TemporaryDirectory(prefix="ai-signal-eval-") as directory:
        work = Path(directory)
        for case in cases:
            fixture = ROOT / "fixtures" / case["fixture"]
            if case["category"] == "binary_decompiled":
                output = work / "ghidra"
                output.mkdir()
                shutil.copyfile(fixture, output / "ghidra.jsonl")
                index = DockerStaticTools._read_ghidra(output, {"sha256": "b" * 64})
                resolved_calls = sum(len(unit.references.get("calls", [])) for unit in index.units)
                string_refs = sum(len(unit.references.get("callers", [])) for unit in index.units
                                  if unit.kind == "string")
                passed = (resolved_calls >= case["expected_resolved_calls"] and
                          string_refs >= case["expected_string_references"])
                totals["failures"] += int(not passed)
                details.append({"id": case["id"], "category": case["category"], "passed": passed,
                                "resolved_calls": resolved_calls, "string_references": string_refs})
                continue

            result, latency = _analyze_source(case, fixture, work)
            latencies.append(latency)
            tools, prompts = _eligible_values(result)
            detected_models = {
                str(item.get("value") or item.get("raw_value")) for item in tools
                if item.get("type") in {"model_argument", "model_identifier"}
                or (item.get("normalized") or {}).get("model")
            }
            expected_models = set(case.get("expected_models") or [])
            expected_toolchains = set(case.get("expected_toolchains") or [])
            detected_prompts = {str(item.get("text") or "") for item in prompts if item.get("text")}
            expected_prompts = set(case.get("expected_prompt_components") or [])
            totals["model_tp"] += len(detected_models & expected_models)
            totals["model_fp"] += len(detected_models - expected_models)
            totals["model_fn"] += len(expected_models - detected_models)
            totals["prompt_tp"] += len(detected_prompts & expected_prompts)
            totals["prompt_fp"] += len(detected_prompts - expected_prompts)
            totals["prompt_fn"] += len(expected_prompts - detected_prompts)

            expected_vendors = set(case.get("expected_model_vendors") or [])
            vendors = {(item.get("normalized") or {}).get("model_vendor") for item in tools}
            vendors.discard(None)
            totals["vendor_predictions"] += len(vendors)
            totals["vendor_false"] += len(vendors - expected_vendors)
            totals["eligible_prompts"] += len(prompts)
            totals["bound_prompts"] += sum(item.get("call_binding") == "relation_verified" for item in prompts)

            all_values = detected_models | detected_prompts
            hard_negatives = set(case.get("hard_negative_values") or [])
            totals["hard_negative_total"] += len(hard_negatives)
            totals["hard_negative_hits"] += len(all_values & hard_negatives)

            expected_role = case.get("expected_role")
            if expected_role == "application":
                for item in [*tools, *prompts]:
                    totals["role_checks"] += 1
                    totals["role_errors"] += int(item.get("role") != "application")
            elif expected_role in {"dependency", "example"}:
                units = (((result.get("features") or {}).get("static_analysis") or {})
                         .get("materials") or {}).get("units") or []
                totals["role_checks"] += 1
                totals["role_errors"] += int(not any(unit.get("probable_role") == expected_role for unit in units))

            source_text = fixture.read_text(encoding="utf-8")
            for item in [*tools, *prompts]:
                raw = item.get("raw_value") or item.get("value") or item.get("text")
                totals["citations"] += 1
                totals["valid_citations"] += int(isinstance(raw, str) and raw in source_text)
                if item.get("verification_status") == "relation_verified" or item.get("call_binding") == "relation_verified":
                    totals["relations"] += 1
                    totals["valid_relations"] += int(
                        raw in expected_models or raw in expected_prompts or raw in expected_toolchains
                    )

            run = ((result.get("features") or {}).get("static_analysis") or {}).get("run") or {}
            budget = run.get("budget") or {}
            totals["requests"] += int(budget.get("requests") or 0)
            totals["tokens"] += int((budget.get("provider_usage") or {}).get("total_tokens") or 0)
            failed = bool(result.get("errors")) or run.get("status") == "failed"
            totals["failures"] += int(failed)
            targeting = (result.get("classification") or {}).get("analysis_targeting", {}).get("detected", False)
            if case.get("expected_analysis_targeting") is True:
                totals["role_checks"] += 1
                totals["role_errors"] += int(not targeting)
            targeting_ok = case.get("expected_analysis_targeting") is not True or targeting
            passed = (not failed and detected_models == expected_models and not (all_values & hard_negatives)
                      and targeting_ok)
            details.append({
                "id": case["id"], "category": case["category"], "passed": passed,
                "expected_models": sorted(expected_models), "detected_models": sorted(detected_models),
                "expected_prompt_components": sorted(expected_prompts),
                "detected_prompt_components": sorted(detected_prompts),
                "analysis_targeting": targeting,
            })

    source_case_count = len(cases) - 1
    metrics = {
        "model_identifier_precision": _ratio(totals["model_tp"], totals["model_tp"] + totals["model_fp"]),
        "model_identifier_recall": _ratio(totals["model_tp"], totals["model_tp"] + totals["model_fn"]),
        "model_vendor_false_attribution_rate": _ratio(totals["vendor_false"], totals["vendor_predictions"]),
        "prompt_component_precision": _ratio(totals["prompt_tp"], totals["prompt_tp"] + totals["prompt_fp"]),
        "prompt_component_recall": _ratio(totals["prompt_tp"], totals["prompt_tp"] + totals["prompt_fn"]),
        "prompt_call_binding_precision": _ratio(totals["bound_prompts"], totals["eligible_prompts"]),
        "decoy_false_positive_rate": _ratio(totals["hard_negative_hits"], totals["hard_negative_total"]),
        "role_error_rate": _ratio(totals["role_errors"], totals["role_checks"]),
        "citation_validity_rate": _ratio(totals["valid_citations"], totals["citations"]),
        "relation_verified_precision": _ratio(totals["valid_relations"], totals["relations"]),
        "analysis_failure_rate": _ratio(totals["failures"], len(cases)),
        "average_requests": round(totals["requests"] / source_case_count, 6),
        "average_tokens": round(totals["tokens"] / source_case_count, 6),
        "average_latency": round(sum(latencies) / len(latencies), 6) if latencies else None,
    }
    return {"schema_version": "ai-signal-evaluation/1.0", "case_count": len(cases),
            "metrics": metrics, "details": details,
            "limitations": ["synthetic_harmless_fixtures", "llm_disabled_for_baseline",
                            "binary_case_uses_saved_decompiler_export"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()

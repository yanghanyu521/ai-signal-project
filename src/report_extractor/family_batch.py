from __future__ import annotations

import csv
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

from jsonschema import Draft202012Validator

from .event_compare_v3 import compare_event_to_sample
from .event_pipeline_v3 import extract_report_events_v3
from .evidence_strength import build_field_assessments
from .utils import read_json, write_json


FAMILY_ALIASES = {
    "LAMEHUG": ["PROMPTSTEAL", "LameHug"],
    "PROMPTSTEAL": ["LAMEHUG", "LameHug"],
    "QUIETVAULT": ["QuietVault"],
    "PROMPTLOCK": ["PromptLock"],
    "PROMPTSPY": ["PromptSpy"],
    "MALTERMINAL": ["MalTerminal"],
    "SLOPOLY": ["Slopoly"],
}


def _family_key(value: str | None) -> str:
    text = str(value or "").split("（", 1)[0].split("(", 1)[0]
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _canonical_family(value: str) -> str:
    key = _family_key(value)
    names = {
        "fruitshell": "FRUITSHELL",
        "lamehug": "LAMEHUG",
        "malterminal": "MalTerminal",
        "promptflux": "PROMPTFLUX",
        "promptsteal": "PROMPTSTEAL",
        "promptlock": "PromptLock",
        "promptspy": "PromptSpy",
        "quietvault": "QUIETVAULT",
        "slopoly": "SLOPOLY",
    }
    return names.get(key, value.strip())


def _target_spec(family: str) -> dict:
    aliases = FAMILY_ALIASES.get(family.upper(), [])
    return {"name": family, "aliases": list(dict.fromkeys(aliases)), "hint": "target_family"}


def _event_names(event: dict) -> set[str]:
    values = [event.get("identity", {}).get("event_name"), *event.get("identity", {}).get("aliases", [])]
    return {_family_key(value) for value in values if value}


def select_target_event(report: dict, family: str, aliases: list[str]) -> tuple[dict, str]:
    target_key = _family_key(family)
    alias_keys = {_family_key(value) for value in aliases}
    for event in report.get("events", []):
        if _family_key(event.get("identity", {}).get("event_name")) == target_key:
            return event, "identity_exact"
    for event in report.get("events", []):
        names = _event_names(event)
        if target_key in names or names & alias_keys:
            return event, "identity_alias"
    for event in report.get("events", []):
        for artifact in event.get("artifacts", []):
            names = [artifact.get("family"), *artifact.get("aliases", [])]
            if target_key in {_family_key(value) for value in names if value}:
                return event, "artifact_family"
    raise ValueError(f"报告中未找到目标家族事件: {family}")


def _read_sample_rows(sample_csv: Path) -> list[dict]:
    with sample_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    seen = set()
    unique = []
    for row in rows:
        sha256 = str(row.get("SHA-256") or "").lower()
        if not re.fullmatch(r"[a-f0-9]{64}", sha256) or sha256 in seen:
            continue
        seen.add(sha256)
        row["canonical_family"] = _canonical_family(str(row.get("来源/案例") or ""))
        unique.append(row)
    return unique


def _main_report(family_dir: Path) -> Path:
    reports = sorted(family_dir.glob("*.html"))
    if len(reports) != 1:
        raise ValueError(f"{family_dir.name}目录应有且仅有1份主HTML，实际{len(reports)}份")
    return reports[0]


def _load_llm_claims(output_dir: Path, event_name: str) -> list[dict]:
    path = output_dir / "llm_validated_claims.json"
    if not path.exists():
        return []
    content = read_json(path)
    return list((content.get(event_name) or {}).get("claims") or [])


def _profile(
    family: str,
    aliases: list[str],
    final_report: dict,
    target_event: dict,
    method: str,
    deterministic_event: dict,
    llm_claims: list[dict],
    *,
    use_llm: bool,
    schema: dict,
) -> dict:
    excluded = [
        {"event_id": event["event_id"], "event_name": event["identity"]["event_name"]}
        for event in final_report.get("events", [])
        if event["event_id"] != target_event["event_id"]
    ]
    profile = {
        "profile_version": "0.1",
        "family": family,
        "report": final_report["report"],
        "selection": {
            "target_family": family,
            "target_aliases": aliases,
            "event_id": target_event["event_id"],
            "event_name": target_event["identity"]["event_name"],
            "method": method,
            "excluded_events": excluded,
        },
        "event": target_event,
        "field_assessments": build_field_assessments(
            target_event,
            llm_claims=llm_claims,
            deterministic_event=deterministic_event,
        ),
        "extraction": {
            "report_validation_status": final_report["extraction"]["validation_status"],
            "llm_enabled": use_llm,
            "profile_validation_status": "passed",
            "errors": [],
        },
    }
    errors = [error.message for error in Draft202012Validator(schema).iter_errors(profile)]
    if errors:
        profile["extraction"]["profile_validation_status"] = "failed"
        profile["extraction"]["errors"] = errors
    return profile


def _sample_evidence_context(sample: dict, path: str | None) -> dict:
    if not path:
        return {"evidence_levels": [], "max_confidence": None}
    evidence = []
    match = re.fullmatch(r"features\.toolchain\.evidence\[(\d+)\]", path)
    if match:
        items = sample.get("features", {}).get("toolchain", {}).get("evidence", [])
        index = int(match.group(1))
        if index < len(items):
            evidence.append(items[index])
    elif path.startswith("classification.model_attribution"):
        evidence.extend(sample.get("classification", {}).get("evidence_summary", []))
    elif path.startswith("features.prompt"):
        evidence.extend(sample.get("features", {}).get("prompt", {}).get("embedded_prompts", []))
        evidence.extend(sample.get("features", {}).get("prompt", {}).get("structural_artifacts", []))
    levels = sorted({str(item.get("evidence_level")) for item in evidence if item.get("evidence_level")})
    confidences = [float(item["confidence"]) for item in evidence if isinstance(item.get("confidence"), (int, float))]
    return {"evidence_levels": levels, "max_confidence": max(confidences) if confidences else None}


def _report_assessments(comparison: dict, assessments: list[dict]) -> list[dict]:
    report_data = comparison.get("report", {})
    evidence_ids = set(report_data.get("evidence_ids") or [])
    report_path = str(report_data.get("path") or "")
    suffix = re.sub(r"^events\.[^.]+\.", "event.", report_path)
    matches = []
    for assessment in assessments:
        if not evidence_ids.intersection(assessment.get("evidence_ids", [])):
            continue
        field_path = assessment.get("field_path", "")
        if suffix.startswith(field_path) or field_path.startswith(suffix) or not suffix:
            matches.append({
                key: assessment[key]
                for key in ["assessment_id", "field_path", "claim_type", "assertion_status", "author_confidence", "extractor_method", "extractor_confidence", "evidence_strength", "rationale"]
            })
    if matches:
        return matches
    return [
        {
            key: assessment[key]
            for key in ["assessment_id", "field_path", "claim_type", "assertion_status", "author_confidence", "extractor_method", "extractor_confidence", "evidence_strength", "rationale"]
        }
        for assessment in assessments
        if evidence_ids.intersection(assessment.get("evidence_ids", []))
    ]


def _enrich_comparison(result: dict, sample: dict, profile: dict) -> dict:
    for comparison in result.get("comparisons", []):
        report_assessments = _report_assessments(comparison, profile["field_assessments"])
        comparison["evidence_strength"] = {
            "sample": _sample_evidence_context(sample, comparison.get("sample", {}).get("path")),
            "report": report_assessments,
        }
        if any(
            item["evidence_strength"] in {"weak", "unknown"} or item["assertion_status"] != "asserted"
            for item in report_assessments
        ):
            comparison["review_status"] = "needs_review"
    result["evidence_model"] = {
        "sample": "使用样本静态结果自身的evidence_level/confidence",
        "report": "使用目标事件profile的多维字段证据评估",
    }
    return result


def _write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "sample_sha256", "family", "report_status", "event_name", "event_id", "link_method",
        "supports", "contradicts", "complements", "inconclusive", "review_status", "comparison_file", "error",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_family_batch(
    sample_csv: str | Path,
    reports_root: str | Path,
    output_dir: str | Path,
    *,
    use_llm: bool = False,
    event_schema_path: str | Path,
    profile_schema_path: str | Path,
) -> dict:
    sample_csv = Path(sample_csv).resolve()
    sample_root = sample_csv.parent.parent.resolve()
    reports_root = Path(reports_root).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    event_schema_path = Path(event_schema_path).resolve()
    profile_schema = json.loads(Path(profile_schema_path).read_text(encoding="utf-8"))
    rows = _read_sample_rows(sample_csv)
    rows_by_family: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        rows_by_family[row["canonical_family"]].append(row)

    family_results = []
    comparison_rows = []
    aggregate = Counter()
    api_available = bool(os.environ.get("cc-api"))
    for family in sorted(rows_by_family, key=str.lower):
        family_out = output_dir / family
        family_out.mkdir(parents=True, exist_ok=True)
        family_rows = rows_by_family[family]
        aliases = _target_spec(family)["aliases"]
        family_result = {"family": family, "sample_count": len(family_rows), "status": "pending", "errors": []}
        try:
            family_dir = next((path for path in reports_root.iterdir() if path.is_dir() and _family_key(path.name) == _family_key(family)), None)
            if not family_dir:
                raise FileNotFoundError(f"缺少家族报告目录: {family}")
            report_path = _main_report(family_dir)
            deterministic_out = family_out / "report_deterministic"
            enriched_out = family_out / "report_enriched"
            deterministic = extract_report_events_v3(
                report_path,
                output_dir=deterministic_out,
                schema_path=event_schema_path,
                target_event=_target_spec(family),
            )
            deterministic_event, _ = select_target_event(deterministic, family, aliases)
            if use_llm:
                final_report = extract_report_events_v3(
                    report_path,
                    output_dir=enriched_out,
                    schema_path=event_schema_path,
                    use_llm=True,
                    target_event=_target_spec(family),
                )
                final_out = enriched_out
            else:
                final_report = deterministic
                final_out = deterministic_out
            target_event, method = select_target_event(final_report, family, aliases)
            llm_claims = _load_llm_claims(final_out, target_event["identity"]["event_name"])
            profile = _profile(
                family,
                aliases,
                final_report,
                target_event,
                method,
                deterministic_event,
                llm_claims,
                use_llm=use_llm,
                schema=profile_schema,
            )
            write_json(family_out / "target_event_profile.json", profile)
            relation_counts = Counter()
            review_counts = Counter()
            compare_dir = family_out / "comparisons"
            compare_dir.mkdir(parents=True, exist_ok=True)
            for row in family_rows:
                sha256 = row["SHA-256"].lower()
                relative_result = Path(str(row["结果位置"]).replace("/", os.sep))
                sample_result_path = (sample_root / relative_result).resolve()
                if not sample_result_path.is_relative_to(sample_root):
                    raise ValueError(f"样本结果路径越界: {relative_result}")
                sample = read_json(sample_result_path)
                if str(sample.get("sample", {}).get("sha256") or "").lower() != sha256:
                    raise ValueError(f"样本结果SHA-256不匹配: {sha256}")
                comparison = compare_event_to_sample(final_report, sample, event_id=target_event["event_id"], sample_family=family)
                comparison = _enrich_comparison(comparison, sample, profile)
                comparison_path = compare_dir / f"{sha256}.json"
                write_json(comparison_path, comparison)
                relation_counts.update(comparison["summary"])
                review = "needs_review" if any(item["review_status"] == "needs_review" for item in comparison["comparisons"]) else "not_reviewed"
                review_counts[review] += 1
                comparison_rows.append({
                    "sample_sha256": sha256,
                    "family": family,
                    "report_status": final_report["extraction"]["validation_status"],
                    "event_name": target_event["identity"]["event_name"],
                    "event_id": target_event["event_id"],
                    "link_method": comparison["link"]["method"],
                    **comparison["summary"],
                    "review_status": review,
                    "comparison_file": str(comparison_path.relative_to(output_dir)),
                    "error": "",
                })
            strength_counts = Counter(item["evidence_strength"] for item in profile["field_assessments"])
            family_result.update({
                "status": "ok",
                "report_file": str(report_path),
                "report_validation_status": final_report["extraction"]["validation_status"],
                "target_event": profile["selection"],
                "field_assessments": len(profile["field_assessments"]),
                "evidence_strengths": dict(strength_counts),
                "comparison_summary": dict(relation_counts),
                "review_summary": dict(review_counts),
            })
            aggregate.update(relation_counts)
        except Exception as exc:
            family_result["status"] = "failed"
            family_result["errors"].append(f"{type(exc).__name__}: {exc}")
            for row in family_rows:
                comparison_rows.append({
                    "sample_sha256": row["SHA-256"].lower(), "family": family, "report_status": "failed",
                    "event_name": "", "event_id": "", "link_method": "", "supports": 0, "contradicts": 0,
                    "complements": 0, "inconclusive": 0, "review_status": "needs_review", "comparison_file": "",
                    "error": family_result["errors"][-1],
                })
        family_results.append(family_result)

    summary = {
        "batch_version": "0.1",
        "inputs": {"sample_csv": str(sample_csv), "reports_root": str(reports_root)},
        "llm": {"requested": use_llm, "api_key_available": api_available},
        "samples": {
            "total": len(rows),
            "compared": sum(row["report_status"] != "failed" for row in comparison_rows),
            "failed": sum(row["report_status"] == "failed" for row in comparison_rows),
        },
        "families": family_results,
        "comparison_summary": {key: aggregate.get(key, 0) for key in ["supports", "contradicts", "complements", "inconclusive"]},
    }
    write_json(output_dir / "batch_summary.json", summary)
    _write_csv(output_dir / "sample_comparison_summary.csv", comparison_rows)
    return summary

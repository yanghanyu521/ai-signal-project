"""Audit private rerun completeness and exact source anchors, not semantic truth."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import jsonschema


PROJECT = Path(__file__).resolve().parents[1]


def audit(output: Path) -> dict:
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    schema = json.loads((PROJECT / "components/ai_signal_demo/schemas/result.schema.json").read_text(encoding="utf-8"))
    totals = Counter()
    issues = []
    for spec in manifest:
        sha = spec["sha256"]
        base = output / "samples" / sha / "v08"
        try:
            status = json.loads((base / "status.json").read_text(encoding="utf-8"))
            result = json.loads((base / "result.json").read_text(encoding="utf-8"))
            materials = json.loads((base / "static_materials.json").read_text(encoding="utf-8"))
            jsonschema.validate(result, schema)
            if (status.get("status") != "completed"
                    or status.get("analysis_status") not in {"completed", "unsupported"}
                    or result.get("sample", {}).get("sha256") != sha):
                raise ValueError("result_or_status_incomplete")
            if hashlib.sha256(Path(spec["selected_path"]).read_bytes()).hexdigest() != sha:
                raise ValueError("original_sha_changed")
            units = {unit["unit_id"]: unit for unit in materials.get("units") or []}
            facts = [fact for fact in result.get("features", {}).get("facts") or []
                     if fact.get("discovery_method") == "llm"]
            for fact in facts:
                raw = fact.get("raw_value")
                location = fact.get("source_location") or {}
                unit = units.get(location.get("unit_id"))
                offset = location.get("unit_char_offset")
                valid = bool(unit and isinstance(raw, str) and isinstance(offset, int)
                             and unit.get("content", "")[offset:offset + len(raw)] == raw
                             and fact.get("evidence_text_hash") == "sha256:" + hashlib.sha256(raw.encode()).hexdigest())
                totals["llm_facts"] += 1
                totals["llm_facts_exact_source"] += valid
                if not valid:
                    issues.append({"sha256": sha, "reason": "llm_fact_anchor_invalid",
                                   "fact_id": fact.get("fact_id")})
                entries = (unit or {}).get("location", {}).get("string_entries") or []
                if entries and valid:
                    matching = next((entry for entry in entries if entry["start_char"] <= offset
                                     and offset + len(raw) <= entry["end_char"]), None)
                    if matching is None:
                        issues.append({"sha256": sha, "reason": "string_fact_crosses_entry"})
                    else:
                        prefix = unit["content"][matching["start_char"]:offset]
                        codec = {"ascii": "ascii", "utf8": "utf-8", "utf16le": "utf-16le",
                                 "utf16be": "utf-16be", "utf16le_cjk": "utf-16le",
                                 "utf16be_cjk": "utf-16be"}.get(matching["encoding"], "utf-8")
                        expected = matching["file_offset"] + len(prefix.encode(codec, errors="replace"))
                        if location.get("file_offset") != expected:
                            issues.append({"sha256": sha, "reason": "string_file_offset_invalid"})
            generation = result.get("features", {}).get("code_generation_signals") or {}
            for observation in generation.get("style_indicators") or []:
                if observation.get("verification") != "exact_source_match":
                    continue
                raw = observation.get("raw_value")
                loc = observation.get("source_location") or {}
                unit = units.get(loc.get("unit_id"))
                offset = loc.get("unit_char_offset")
                valid = bool(unit and isinstance(raw, str) and isinstance(offset, int)
                             and unit.get("content", "")[offset:offset + len(raw)] == raw)
                totals["style_observations"] += 1
                totals["style_exact_source"] += valid
                if not valid:
                    issues.append({"sha256": sha, "reason": "style_anchor_invalid"})
            totals["completed_samples"] += 1
            totals[f"llm_status:{status.get('analysis_status')}"] += 1
        except Exception as exc:
            issues.append({"sha256": sha, "reason": f"{type(exc).__name__}:{exc}"})
    return {"schema_version": "v08-remediation-audit/1.0", "expected_samples": len(manifest),
            "totals": dict(totals), "issue_count": len(issues), "issues": issues,
            "semantic_truth_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.output_dir)
    (args.output_dir / "quality_audit.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"expected": result["expected_samples"], "issue_count": result["issue_count"],
                      **result["totals"]}, ensure_ascii=False))
    if result["issue_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

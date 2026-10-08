"""Check completeness and evidence invariants for the isolated 45-sample run."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import jsonschema


PROJECT = Path(__file__).resolve().parents[1]


def audit(output: Path) -> dict:
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    schema = json.loads((PROJECT / "components/ai_signal_demo/schemas/result.schema.json").read_text(encoding="utf-8"))
    totals = Counter()
    problems = []
    semantic_review_flags = []
    for spec in manifest:
        sha = spec["sha256"]
        base = output / "samples" / sha
        try:
            status = json.loads((base / "status.json").read_text(encoding="utf-8"))
            result = json.loads((base / "v08/result.json").read_text(encoding="utf-8"))
            comparison = json.loads((base / "comparison.json").read_text(encoding="utf-8"))
            materials = json.loads((base / "v08/static_materials.json").read_text(encoding="utf-8"))
            jsonschema.validate(result, schema)
            if status.get("state") != "completed" or result["sample"]["sha256"] != sha:
                raise ValueError("incomplete_or_wrong_sample")
            if hashlib.sha256(Path(spec["selected_path"]).read_bytes()).hexdigest() != sha:
                raise ValueError("source_hash_changed")
            units = {unit["unit_id"]: unit for unit in materials.get("units") or []}
            facts = [item for item in (result.get("features") or {}).get("facts") or []
                     if item.get("discovery_method") == "llm"]
            for item in facts:
                raw = item.get("raw_value") or ""
                ids = item.get("source_unit_ids") or []
                loc = item.get("source_location") or {}
                unit = units.get(loc.get("unit_id"))
                offset = loc.get("unit_char_offset")
                valid = bool(raw and ids and all(uid in units for uid in ids) and unit
                             and isinstance(offset, int)
                             and unit.get("content", "")[offset:offset + len(raw)] == raw
                             and item.get("evidence_text_hash") == "sha256:" + hashlib.sha256(raw.encode()).hexdigest())
                totals["llm_facts"] += 1
                totals["llm_facts_valid"] += valid
                if not valid:
                    problems.append({"sha256": sha, "reason": "llm_fact_source_mismatch",
                                     "fact_id": item.get("fact_id")})
            generation = (result.get("features") or {}).get("code_generation_signals") or {}
            prompts = [str(prompt.get("text") or "") for prompt in
                       ((result.get("features") or {}).get("prompt") or {}).get("embedded_prompts") or []]
            for item in generation.get("style_indicators") or []:
                if item.get("verification") != "exact_source_match":
                    continue
                raw = item.get("raw_value") or ""
                loc = item.get("source_location") or {}
                unit = units.get(loc.get("unit_id"))
                offset = loc.get("unit_char_offset")
                valid = bool(raw and unit and isinstance(offset, int)
                             and unit.get("content", "")[offset:offset + len(raw)] == raw)
                totals["llm_style_observations"] += 1
                totals["llm_style_observations_valid"] += valid
                if not valid:
                    problems.append({"sha256": sha, "reason": "style_source_mismatch"})
                if item.get("label") == "dialogue_residue" and any(
                    len(prompt) >= 8 and (prompt in raw or raw in prompt) for prompt in prompts
                ):
                    semantic_review_flags.append({"sha256": sha, "label": item.get("label"),
                                                  "reason": "overlaps_application_prompt"})
                if item.get("label") == "generation_claim" and not re.search(
                    r"(?i)(?:generated\s+(?:by|with)\s+(?:an?\s+)?(?:ai|llm|chatgpt|gpt|claude)|"
                    r"(?:ai|llm)[ -]generated)", raw
                ):
                    semantic_review_flags.append({"sha256": sha, "label": item.get("label"),
                                                  "reason": "no_explicit_ai_code_generation_claim"})
            if comparison["group"] == "executable_or_package" and generation.get("fingerprint") is not None:
                problems.append({"sha256": sha, "reason": "binary_file_fingerprint"})
            if comparison["v08_extra"].get("docker_tool_runs"):
                problems.append({"sha256": sha, "reason": "docker_used"})
            totals["completed_samples"] += 1
        except Exception as exc:
            problems.append({"sha256": sha, "reason": f"{type(exc).__name__}:{exc}"})
    return {"audit_version": "v08-all45-evidence/1.0", "expected_samples": len(manifest),
            "totals": dict(totals), "problem_count": len(problems), "problems": problems,
            "semantic_review_flag_count": len(semantic_review_flags),
            "semantic_review_flag_reasons": dict(Counter(item["reason"] for item in semantic_review_flags)),
            "semantic_review_flags": semantic_review_flags}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    result = audit(output)
    (output / "quality_audit.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"expected": result["expected_samples"], **result["totals"],
                      "problems": result["problem_count"],
                      "semantic_review_flags": result["semantic_review_flag_reasons"]}, ensure_ascii=False))
    if result["problem_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

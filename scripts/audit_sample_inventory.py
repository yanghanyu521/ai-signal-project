"""Read-only inventory of stored sample evidence; never re-analyzes payloads."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime
from pathlib import Path

from ai_signal_hub.config import Settings
from ai_signal_hub.similarity import ALGORITHM_VERSION, sample_profile
from rebuild_similarity import readonly, save


def audit(batch):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", batch):
        raise ValueError("Use a single batch name")
    settings = Settings()
    output = settings.data_dir / "evaluations" / batch
    if output.exists():
        raise ValueError("Refusing to overwrite an audit")
    with closing(readonly(settings.database_path)) as con:
        con.execute("BEGIN")
        rows = list(con.execute("SELECT * FROM samples ORDER BY source_case,sha256"))
        runs = [dict(r) for r in con.execute("SELECT * FROM sample_cluster_runs")]
        tables = {r[0]: con.execute('SELECT COUNT(*) FROM "' + r[0].replace('"', '""') + '"').fetchone()[0]
                  for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        report_rows = [dict(r) for r in con.execute("SELECT * FROM reports")]
        relation_counts = dict(con.execute("SELECT same_cluster,COUNT(*) FROM sample_relations GROUP BY same_cluster"))
    records = []
    for row in rows:
        data = json.loads(row["result_json"])
        sample, features = data.get("sample", {}), data.get("features", {})
        tool, prompt, code = (features.get(k, {}) for k in ("toolchain", "prompt", "code_style"))
        profile = sample_profile(data)
        artifact = Path(row["artifact_path"]).resolve() if row["artifact_path"] else None
        string_count, max_string, truncated_strings = None, None, None
        if artifact and artifact.is_relative_to(settings.workspace_root.resolve()) and (artifact / "strings.jsonl").is_file():
            lengths = [len(json.loads(line).get("value", "")) for line in (artifact / "strings.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            string_count, max_string, truncated_strings = len(lengths), max(lengths, default=0), sum(x == 4096 for x in lengths)
        entry = {"sha256": row["sha256"], "family": row["source_case"], "updated_at": row["updated_at"],
                 "file_type": sample.get("file_type"), "language": sample.get("language"),
                 "recoverability": sample.get("recoverability"), "size": sample.get("size"),
                 "errors": data.get("errors", []), "status": row["status"], "artifact_path": row["artifact_path"],
                 "artifact_result_exists": bool(artifact and (artifact / "result.json").is_file()),
                 "toolchain_evidence": len(tool.get("evidence", [])), "toolchain_types": dict(Counter(x.get("type") for x in tool.get("evidence", []))),
                 "toolchain_sources": dict(Counter(x.get("source") for x in tool.get("evidence", []))),
                 "packaging_candidates": tool.get("packaging_candidates", []),
                 "prompt_candidates": len(prompt.get("embedded_prompts", [])),
                 "prompt_sources": dict(Counter(x.get("source") for x in prompt.get("embedded_prompts", []))),
                 "prompt_flags": [k for k,v in prompt.get("structural_features", {}).items() if v is True],
                 "prompt_artifacts": len(prompt.get("structural_artifacts", [])),
                 "prompt_artifact_types": dict(Counter(x.get("type") for x in prompt.get("structural_artifacts", []))),
                 "special_tokens": len(prompt.get("special_tokens", [])),
                 "code_metrics": list((code.get("metrics") or {}).keys()), "code_parse_error": code.get("parse_error"),
                 "code_method": code.get("metrics_method", "legacy_code_statistics_v1"),
                 "recovered_layers": code.get("recovered_layers", []), "recovery": features.get("recovery", {}),
                 "toolchain_available": bool(profile["toolchain"]), "prompt_available": bool(profile["prompt"]["records"] or profile["prompt"]["structure"]),
                 "code_available": profile["code_style"]["available"], "code_unavailable_reason": profile["code_style"]["reason"],
                 "rules_version": data.get("static_rules", {}).get("version"),
                 "string_count": string_count, "max_string_chars": max_string, "strings_at_char_cap": truncated_strings,
                 "stored_llm_label": row["llm_label"], "stored_model": row["model_name"],
                 "result_sha256": hashlib.sha256(row["result_json"].encode()).hexdigest()}
        entry["any_raw_feature"] = bool(entry["toolchain_evidence"] or entry["prompt_candidates"] or entry["prompt_flags"] or entry["prompt_artifacts"] or entry["special_tokens"] or entry["code_metrics"] or entry["recovered_layers"])
        entry["any_comparison_feature"] = entry["toolchain_available"] or entry["prompt_available"] or entry["code_available"]
        records.append(entry)
    predicates = {
        "total": lambda x: True, "analysis_errors": lambda x: bool(x["errors"]),
        "any_raw_feature": lambda x: x["any_raw_feature"], "any_comparison_feature": lambda x: x["any_comparison_feature"],
        "toolchain": lambda x: bool(x["toolchain_evidence"]), "prompt": lambda x: bool(x["prompt_candidates"]),
        "prompt_structure_only": lambda x: not x["prompt_candidates"] and bool(x["prompt_flags"] or x["prompt_artifacts"] or x["special_tokens"]),
        "code_raw": lambda x: bool(x["code_metrics"]), "code_qualified": lambda x: x["code_available"],
        "code_parse_error": lambda x: bool(x["code_parse_error"]),
        "toolchain_without_prompt": lambda x: bool(x["toolchain_evidence"]) and not x["prompt_candidates"],
        "recovered_layers": lambda x: bool(x["recovered_layers"]),
        "all_three_comparison_groups": lambda x: x["toolchain_available"] and x["prompt_available"] and x["code_available"],
    }
    family = defaultdict(list)
    for r in records:
        family[r["family"]].append(r)
    totals = {name: sum(fn(x) for x in records) for name,fn in predicates.items()}
    families = {name: {key: sum(fn(x) for x in items) for key,fn in predicates.items()} for name,items in family.items()}
    result = {"captured_at": datetime.now().astimezone().isoformat(), "database_path": str(settings.database_path),
              "algorithm_used_for_availability": ALGORITHM_VERSION, "totals": totals, "families": families,
              "tables": tables, "runs": runs, "relations_by_same_cluster": relation_counts,
              "reports": [{k: r[k] for k in ("id", "title", "created_at", "updated_at") if k in r} for r in report_rows],
              "sample_snapshot_digest": hashlib.sha256("\n".join(x["sha256"] + ":" + x["result_sha256"] for x in records).encode()).hexdigest(),
              "records": records}
    output.mkdir(parents=True)
    save(output / "inventory.json", result)
    print(json.dumps({k:v for k,v in result.items() if k not in ("records", "reports")}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True)
    audit(parser.parse_args().batch)

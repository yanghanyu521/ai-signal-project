"""Isolated static regression for the known FruitShell file; no DB mutations."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from contextlib import closing
from pathlib import Path

from ai_signal_hub.config import Settings
from ai_signal_hub.legacy import LegacyAdapters
from ai_signal_hub.sample_rules import RULE_VERSION
from ai_signal_hub.similarity import ALGORITHM_VERSION, compare_profiles, profile_diagnostics, sample_profile
from rebuild_similarity import fingerprints, readonly, save


SHA256 = "f8f5e0440c57c7deffd75ca33e2511867039796aa803e7ef847396a379188a7d"


def component_hashes(settings):
    paths = {
        "src/aisig/ingest.py": settings.project_root / "src" / "aisig" / "ingest.py",
        "src/aisig/code_style.py": settings.project_root / "src" / "aisig" / "code_style.py",
        "src/aisig/prompt.py": settings.project_root / "src" / "aisig" / "prompt.py",
        "components/ai_signal_demo/rules/llm_rules.yaml": settings.legacy_sample_project / "rules" / "llm_rules.yaml",
    }
    return {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}


def evaluate(batch: str):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", batch):
        raise ValueError("Batch must be one directory name")
    settings = Settings()
    sample = settings.workspace_root / "恶意样本文件" / "AI_signal" / "fruitshell" / SHA256
    if hashlib.sha256(sample.read_bytes()).hexdigest() != SHA256:
        raise ValueError("FruitShell SHA-256 mismatch")
    output = settings.data_dir / "evaluations" / batch
    if output.exists():
        raise ValueError("Evaluation batch exists; choose a new name")
    before = fingerprints(settings.database_path)
    old_code = component_hashes(settings)
    with closing(readonly(settings.database_path)) as connection:
        rows = list(connection.execute("SELECT sha256,source_case,result_json FROM samples ORDER BY sha256"))
    original = next(json.loads(row["result_json"]) for row in rows if row["sha256"] == SHA256)
    output.mkdir(parents=True)
    result = LegacyAdapters(settings).analyze_sample(sample, output / "artifacts")
    profile = sample_profile(result)
    comparisons = [{"related_sha256": row["sha256"], "source_case": row["source_case"],
                    **compare_profiles(profile, sample_profile(json.loads(row["result_json"])))}
                   for row in rows if row["sha256"] != SHA256]
    after = fingerprints(settings.database_path)
    current_code = component_hashes(settings)
    if before != after or old_code != current_code or hashlib.sha256(sample.read_bytes()).hexdigest() != SHA256:
        raise RuntimeError("Protected database, sample, or bundled component code changed during evaluation")
    prompts = result["features"]["prompt"]["embedded_prompts"]
    if result["sample"]["language"] != "powershell" or not profile["code_style"]["available"] or len(prompts) != 1:
        raise RuntimeError("FruitShell regression failed; inspect isolated artifacts")
    prompt = prompts[0]
    if not prompt.get("features", {}).get("analyzer_prompt_injection"):
        raise RuntimeError("Expected analyzer-directed evidence missing")
    summary = {"sample_sha256": SHA256, "rules_version": RULE_VERSION, "algorithm_version": ALGORITHM_VERSION,
        "database_unchanged": True, "sample_unchanged": True, "component_source_unchanged": True,
        "old_language": original["sample"]["language"], "new_language": result["sample"]["language"],
        "metrics": result["features"]["code_style"]["metrics"], "prompt_count": len(prompts),
        "prompt_evidence": {key: prompt[key] for key in ("offset", "byte_length", "features", "target", "text_hash")},
        "toolchain_evidence_count": len(result["features"]["toolchain"]["evidence"]),
        "classification": result["classification"], "feature_availability": profile_diagnostics(profile),
        "comparison_count": len(comparisons),
        "positive_pair_count": sum((item["overall_similarity"] or 0) > 1e-6 for item in comparisons),
        "comparable_code_pairs": sum(item["code_style_similarity"] is not None for item in comparisons),
        "protected_database_fingerprints": before, "component_source_fingerprints": old_code,
        "implementation_fingerprints": {name: hashlib.sha256((settings.project_root / "src/ai_signal_hub" / name).read_bytes()).hexdigest()
                                        for name in ("sample_rules.py", "legacy.py", "similarity.py")},
        "production_applied": False}
    save(output / "comparisons.json", comparisons)
    save(output / "summary.json", summary)
    print(json.dumps({key: value for key, value in summary.items() if "fingerprints" not in key and key != "classification"}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True)
    evaluate(parser.parse_args().batch)

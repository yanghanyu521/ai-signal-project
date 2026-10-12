"""Evaluate style reproducibility, formatting robustness and weak family-neighbor proxy.

LLM label accuracy requires a separate human-reviewed style label sheet.
No model-of-origin accuracy is calculated.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ai_signal_hub.stylometry.similarity import compare_fingerprints
from .adjudicate import read_csv


def _results(root: Path) -> dict[str, dict]:
    out = {}
    manifest_path = root / "manifest.json"
    families = {item["sha256"]: item.get("family") for item in
                json.loads(manifest_path.read_text(encoding="utf-8"))} if manifest_path.is_file() else {}
    for path in (root / "samples").glob("*/v08/result.json"):
        try:
            sha = path.parent.parent.name
            out[sha] = json.loads(path.read_text(encoding="utf-8"))
            out[sha]["family"] = families.get(sha)
        except (OSError, ValueError):
            continue
    return out


def _fp(result: dict) -> dict | None:
    return (result.get("features", {}).get("code_generation_signals") or {}).get("fingerprint")


def evaluate_style(base: dict[str, dict], repeat: dict[str, dict] | None = None,
                   formatted: dict[str, dict] | None = None,
                   labels: list[dict] | None = None) -> dict:
    comparable = {sha: _fp(result) for sha, result in base.items() if _fp(result)}
    def agreement(other: dict[str, dict] | None) -> dict:
        if other is None:
            return {"matched": None, "compared": 0, "rate": None}
        pairs = [(fp, _fp(other[sha])) for sha, fp in comparable.items()
                 if sha in other and _fp(other[sha])]
        matched = sum(left.get("metrics") == right.get("metrics") for left, right in pairs)
        return {"matched": matched, "compared": len(pairs),
                "rate": round(matched / len(pairs), 6) if pairs else None}

    repeatability = agreement(repeat)
    format_pairs = [(fp, _fp(formatted[sha])) for sha, fp in comparable.items()
                    if formatted and sha in formatted and _fp(formatted[sha])]
    format_robustness = {"same_normalized_ast": sum(
        left.get("normalized_ast_hash") == right.get("normalized_ast_hash")
        and bool(left.get("normalized_ast_hash")) for left, right in format_pairs),
        "compared": len(format_pairs)}
    format_robustness["rate"] = (round(format_robustness["same_normalized_ast"] / len(format_pairs), 6)
                                  if format_pairs else None)

    neighbors = []
    for sha, fp in comparable.items():
        ranked = sorted((score["score"], other_sha) for other_sha, other in comparable.items()
                        if other_sha != sha and (score := compare_fingerprints(fp, other))["status"] == "comparable")
        if ranked:
            neighbors.append((sha, ranked[-1][1]))
    families = {sha: result.get("family") or result.get("sample", {}).get("family") for sha, result in base.items()}
    family_checked = [(sha, other) for sha, other in neighbors if families.get(sha) and families.get(other)]
    family_hits = sum(families[sha] == families[other] for sha, other in family_checked)
    neighbor_metric = {"retrievable": len(neighbors), "family_labeled_pairs": len(family_checked),
                       "top1_same_family_proxy": round(family_hits / len(family_checked), 6)
                       if family_checked else None,
                       "limitation": "Malware family is only a weak retrieval proxy, not code generator identity."}
    usable = [row for row in (labels or []) if row.get("adjudication_result") in {"agreed", "resolved"}
              and row.get("label_correct") in {"yes", "no"}]
    label_accuracy = {"correct": sum(row["label_correct"] == "yes" for row in usable),
                      "reviewed": len(usable),
                      "accuracy": round(sum(row["label_correct"] == "yes" for row in usable) / len(usable), 6)
                      if usable else None}
    return {"schema_version": "style-evaluation/1.0", "base_samples": len(base),
            "source_fingerprints": len(comparable), "deterministic_repeatability": repeatability,
            "formatting_robustness": format_robustness, "nearest_neighbor": neighbor_metric,
            "llm_label_accuracy": label_accuracy,
            "generator_model_identification_accuracy": None,
            "limitations": ["No generator-model ground truth in the 45-sample corpus."]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--repeat", type=Path)
    parser.add_argument("--formatted", type=Path)
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate_style(_results(args.base), _results(args.repeat) if args.repeat else None,
                            _results(args.formatted) if args.formatted else None,
                            read_csv(args.labels) if args.labels else None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"base_samples": result["base_samples"],
                      "source_fingerprints": result["source_fingerprints"]}))


if __name__ == "__main__":
    main()

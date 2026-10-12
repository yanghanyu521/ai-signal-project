"""Compute adjudicated candidate-pool metrics without inventing complete recall."""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from .adjudicate import read_csv


VERSIONS = ("v07_rule", "v07_llm", "v08_pre", "v08_post")


def _score(rows: list[dict], version: str) -> dict:
    usable = [row for row in rows if row.get("true_ai_feature") in {"yes", "no"}
              and row.get("adjudication_result") in {"agreed", "resolved"}]
    pending = len(rows) - len(usable)
    predicted = [row for row in usable if version in row.get("candidate_versions", "").split("|")]
    tp = sum(row["true_ai_feature"] == "yes" for row in predicted)
    fp = sum(row["true_ai_feature"] == "no" for row in predicted)
    fn = sum(row["true_ai_feature"] == "yes" and row not in predicted for row in usable)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall) if precision + recall else 0.0) \
        if precision is not None and recall is not None else None
    relation_rows = [row for row in predicted if "relation_verified" in row.get("predicted_call_relation", "")]
    relation_labeled = [row for row in relation_rows if row.get("static_call_verified") in {"yes", "no"}]
    return {"tp": tp, "fp": fp, "fn_candidate_pool": fn, "pending_labels": pending,
            "precision": round(precision, 6) if precision is not None else None,
            "recall_candidate_pool": round(recall, 6) if recall is not None else None,
            "f1_candidate_pool": round(f1, 6) if f1 is not None else None,
            "call_relation_correct": sum(row["static_call_verified"] == "yes" for row in relation_labeled),
            "call_relation_wrong_upgrade": sum(row["static_call_verified"] == "no" for row in relation_labeled),
            "call_relation_pending": len(relation_rows) - len(relation_labeled)}


def evaluate(rows: list[dict], *, independent_miss_search_complete: bool = False) -> dict:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        for key in ("all", f"feature:{row.get('feature_category')}",
                    f"kind:{row.get('sample_kind')}", f"family:{row.get('family')}",
                    f"model:{row.get('model_familiarity')}"):
            groups[key].append(row)
    metrics = {group: {version: _score(items, version) for version in VERSIONS}
               for group, items in sorted(groups.items())}
    complete = bool(independent_miss_search_complete and all(
        row.get("true_ai_feature") in {"yes", "no"} and
        row.get("adjudication_result") in {"agreed", "resolved"} for row in rows))
    return {"schema_version": "gold-evaluation/1.0", "sample_count": len({row.get("sha256") for row in rows}),
            "candidate_count": len(rows), "recall_scope": "complete_evidence" if complete else "candidate_pool_only",
            "independent_miss_search_complete": independent_miss_search_complete,
            "metrics": metrics,
            "limitations": ([] if complete else ["No full recall: independent miss search and complete adjudication required."])}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adjudicated", type=Path, required=True)
    parser.add_argument("--miss-audit", type=Path, help="Independent miss audit JSON with explicit complete=true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    miss = json.loads(args.miss_audit.read_text(encoding="utf-8")) if args.miss_audit else {}
    if miss.get("complete") and (miss.get("unreviewed_regions") or miss.get("unresolved_candidates")):
        raise ValueError("miss audit cannot be complete with unreviewed or unresolved evidence")
    result = evaluate(read_csv(args.adjudicated),
                      independent_miss_search_complete=miss.get("complete") is True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"sample_count": result["sample_count"], "recall_scope": result["recall_scope"]}))


if __name__ == "__main__":
    main()

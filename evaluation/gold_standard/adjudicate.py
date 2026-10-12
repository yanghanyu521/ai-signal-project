"""Join independent reviewer sheets; never turn disagreement into a negative."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from .build_queue import FIELDS


LABEL_FIELDS = ("true_ai_feature", "static_call_verified", "prompt_role", "model_familiarity")
ALLOWED = {
    "true_ai_feature": {"yes", "no", "uncertain"},
    "static_call_verified": {"yes", "no", "uncertain"},
    "prompt_role": {"program_prompt", "jailbreak_prompt", "analyzer_injection", "ordinary_text", "uncertain", "not_applicable"},
    "model_familiarity": {"known", "unknown", "uncertain", "not_applicable"},
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def adjudicate(first: list[dict], second: list[dict]) -> tuple[list[dict], list[dict]]:
    left = {row["evidence_id"]: row for row in first}
    right = {row["evidence_id"]: row for row in second}
    if set(left) != set(right) or len(left) != len(first) or len(right) != len(second):
        raise ValueError("Reviewer sheets must contain the same unique evidence IDs")
    resolved, conflicts = [], []
    for evidence_id in sorted(left):
        a, b = left[evidence_id], right[evidence_id]
        if not a.get("annotator") or not b.get("annotator") or a["annotator"] == b["annotator"]:
            raise ValueError(f"Two distinct named annotators required: {evidence_id}")
        row = dict(a)
        differences = []
        for field in LABEL_FIELDS:
            av, bv = a.get(field, "").strip(), b.get(field, "").strip()
            if av and av not in ALLOWED[field] or bv and bv not in ALLOWED[field]:
                raise ValueError(f"Invalid {field}: {evidence_id}")
            if not av or not bv or av != bv or av == "uncertain":
                differences.append(field)
                row[field] = "uncertain"
            else:
                row[field] = av
        row["annotator"] = f"{a['annotator']}|{b['annotator']}"
        row["adjudication_result"] = "pending" if differences else "agreed"
        row["adjudicator"] = ""
        resolved.append(row)
        if differences:
            conflicts.append({"evidence_id": evidence_id, "fields": differences,
                              "first": {key: a.get(key, "") for key in differences},
                              "second": {key: b.get(key, "") for key in differences}})
    return resolved, conflicts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows, conflicts = adjudicate(read_csv(args.first), read_csv(args.second))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    args.output.with_suffix(".conflicts.json").write_text(
        json.dumps(conflicts, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"rows": len(rows), "conflicts": len(conflicts)}, ensure_ascii=False))


if __name__ == "__main__":
    main()

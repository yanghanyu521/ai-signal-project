"""Build a deduplicated, evidence-located annotation queue from saved runs.

Output contains raw malicious-sample evidence. Write it under ignored `data/`.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


FIELDS = [
    "evidence_id", "sha256", "family", "sample_kind", "feature_category",
    "raw_value", "source_location", "candidate_versions", "candidate_types",
    "predicted_call_relation", "predicted_prompt_role", "model_familiarity",
    "true_ai_feature", "static_call_verified", "prompt_role", "annotator",
    "adjudication_result", "adjudicator", "notes",
]
VERSIONS = {
    "v07_rule": ("v07", "old_rule_result.json"),
    "v07_llm": ("v07", "v07_llm/result.json"),
    "v08_pre": ("v08", "v08/result.json"),
    "v08_post": ("post", "v08/result.json"),
}


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _kind(item: dict) -> str:
    value = str(item.get("database_file_type") or item.get("original_name") or "").casefold()
    if any(ext in value for ext in ("python", ".py", "javascript", ".js", "powershell", ".ps1", "script")):
        return "script"
    if any(ext in value for ext in ("pe", "exe", "dll", "apk", "dex", "elf", "zip", "binary")):
        return "binary"
    return "other"


def _candidates(result: dict):
    features = result.get("features") or {}
    for item in (features.get("toolchain") or {}).get("evidence") or []:
        raw = item.get("raw_value") or item.get("value")
        if isinstance(raw, str) and raw.strip():
            yield "toolchain", raw, item
    for item in (features.get("prompt") or {}).get("embedded_prompts") or []:
        raw = item.get("text") or item.get("raw_value")
        if isinstance(raw, str) and raw.strip():
            yield "prompt", raw, item


def build_queue(v07: Path, v08: Path, post: Path | None = None) -> list[dict]:
    manifests = [_read(root / "manifest.json") for root in (v07, v08, post) if root]
    inventory = {item["sha256"]: item for manifest in manifests for item in manifest if item.get("sha256")}
    found: dict[str, dict] = {}
    for sha, sample in sorted(inventory.items()):
        for version, (root_key, relative) in VERSIONS.items():
            root = {"v07": v07, "v08": v08, "post": post}[root_key]
            if root is None:
                continue
            for category, raw, item in _candidates(_read(root / "samples" / sha / relative)):
                location = item.get("source_location") or {}
                if not location:
                    location = {key: item[key] for key in ("offset", "line", "source", "member_path") if key in item}
                # Same literal at distinct locations is distinct evidence;
                # the same literal found by multiple versions is one queue row.
                locator = json.dumps(location, ensure_ascii=False, sort_keys=True)
                key = hashlib.sha256(json.dumps([sha, category, raw, locator],
                                                   ensure_ascii=False).encode()).hexdigest()
                if key not in found:
                    found[key] = {field: "" for field in FIELDS}
                    found[key].update(evidence_id=key[:24], sha256=sha,
                                      family=sample.get("family") or "",
                                      sample_kind=_kind(sample), feature_category=category,
                                      raw_value=raw, source_location=locator,
                                      model_familiarity="unknown")
                    found[key]["_versions"] = set()
                    found[key]["_types"] = set()
                    found[key]["_relations"] = set()
                    found[key]["_roles"] = set()
                row = found[key]
                row["_versions"].add(version)
                row["_types"].add(str(item.get("type") or item.get("source") or "unknown"))
                row["_relations"].add(str(item.get("verification_status") or item.get("call_binding") or "unknown"))
                row["_roles"].add(str(item.get("prompt_role") or item.get("role") or "unknown"))
    for row in found.values():
        for key, column in (("_versions", "candidate_versions"), ("_types", "candidate_types"),
                            ("_relations", "predicted_call_relation"), ("_roles", "predicted_prompt_role")):
            row[column] = "|".join(sorted(row.pop(key)))
    return sorted(found.values(), key=lambda row: (row["sha256"], row["feature_category"], row["evidence_id"]))


def write_queue(rows: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    output.with_suffix(".json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v07", type=Path, required=True)
    parser.add_argument("--v08", type=Path, required=True)
    parser.add_argument("--post", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = build_queue(args.v07, args.v08, args.post)
    if not rows:
        raise SystemExit("No candidate data found; check all result directories.")
    write_queue(rows, args.output)
    print(json.dumps({"rows": len(rows), "sha256_count": len({row["sha256"] for row in rows}),
                      "output": str(args.output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()

"""Independent blinded review queue from unhit source regions and strings.

This samples material without using AI rules. It is not an exhaustive audit,
and therefore cannot by itself establish full recall.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from aisig.string_extract import scan_strings
from .adjudicate import read_csv


def build_miss_queue(manifest: list[dict], candidates: list[dict], *, per_sample: int = 200) -> tuple[list[dict], dict]:
    known_values = {(row["sha256"], row["raw_value"]) for row in candidates}
    known_locations = set()
    for row in candidates:
        try:
            location = json.loads(row.get("source_location") or "{}")
        except ValueError:
            continue
        if isinstance(location, dict) and not location.get("member_path"):
            offset = location.get("offset", location.get("file_offset"))
            if isinstance(offset, int):
                known_locations.add((row["sha256"], row["raw_value"], offset))
    queue = []
    inventory = {"samples_checked": 0, "sha_mismatch": [], "missing_files": [],
                 "unhit_regions_discovered": 0, "unhit_regions_queued": 0,
                 "strings_rejected_by_scan_limit": 0, "complete": False}
    for sample in manifest:
        sha = sample["sha256"]
        path = Path(sample.get("selected_path") or "")
        if not path.is_file():
            inventory["missing_files"].append(sha)
            continue
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            inventory["sha_mismatch"].append(sha)
            continue
        inventory["samples_checked"] += 1
        strings, coverage = scan_strings(data, 100_000, 4096)
        inventory["strings_rejected_by_scan_limit"] += coverage["strings_rejected_by_limit"]
        regions = [
            ("unhit_string", item["value"], f"byte:{item['offset']}:{item['encoding']}")
            for item in strings if (sha, item["value"], item["offset"]) not in known_locations
        ]
        if any(path.name.lower().endswith(ext) for ext in (".py", ".js", ".mjs", ".ps1")):
            text = data.decode("utf-8-sig", errors="replace")
            for start in range(0, len(text.splitlines()), 20):
                raw = "\n".join(text.splitlines()[start:start + 20])
                if raw.strip() and not any(value in raw for candidate_sha, value in known_values if candidate_sha == sha):
                    regions.append(("unhit_source_region", raw, f"line:{start + 1}-{start + 20}"))
        inventory["unhit_regions_discovered"] += len(regions)
        # Uniform, deterministic hash sample across byte/line positions, not a
        # model/rule-driven ranking. Keep the bound explicit in audit metadata.
        selected = sorted(regions, key=lambda item: hashlib.sha256(
            f"{sha}:{item[2]}:{item[1]}".encode()).hexdigest())[:per_sample]
        for category, raw, location in selected:
            queue.append({"evidence_id": hashlib.sha256(
                f"{sha}:{category}:{location}:{raw}".encode()).hexdigest()[:24],
                "sha256": sha, "region_kind": category, "raw_value": raw,
                "source_location": location, "true_ai_feature": "",
                "feature_category": "", "annotator": "", "adjudication_result": ""})
        inventory["unhit_regions_queued"] += len(selected)
    inventory["unreviewed_regions"] = inventory["unhit_regions_discovered"]
    return queue, inventory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--candidate-queue", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--per-sample", type=int, default=200)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    rows, audit = build_miss_queue(manifest, read_csv(args.candidate_queue), per_sample=args.per_sample)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]) if rows else [
            "evidence_id", "sha256", "region_kind", "raw_value", "source_location",
            "true_ai_feature", "feature_category", "annotator", "adjudication_result"])
        writer.writeheader()
        writer.writerows(rows)
    args.output.with_suffix(".audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    print(json.dumps(audit, ensure_ascii=False))


if __name__ == "__main__":
    main()

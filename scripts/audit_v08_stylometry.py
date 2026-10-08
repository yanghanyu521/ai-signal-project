"""Read-only v0.7→v0.8 code-style eligibility audit; never executes a sample.

This deliberately disables LLM and does not compare extraction accuracy: the
historical 45 malware samples have no verified generator labels.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from aisig.ingest import collect_metadata_from_data
from aisig.string_extract import source_text
from ai_signal_hub.stylometry.fingerprint import build_code_generation_signals


def audit(manifest: Path, historical_samples: Path) -> dict:
    records = json.loads(manifest.read_text(encoding="utf-8"))
    results = []
    for record in records:
        sha = record["sha256"]
        path = Path(record["selected_path"])
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError(f"SHA-256 mismatch: {sha}")
        metadata = collect_metadata_from_data(raw, path.name, len(raw))
        text, _ = source_text(raw, metadata["language"])
        generation = build_code_generation_signals(
            text, metadata["language"], metadata["recoverability"], sha)
        old_path = historical_samples / sha / "v07_llm" / "result.json"
        old = json.loads(old_path.read_text(encoding="utf-8")) if old_path.is_file() else {}
        old_style = (old.get("features") or {}).get("code_style") or {}
        results.append({
            "family": record["family"], "sha256": sha, "format": metadata["format"],
            "language": metadata["language"], "source_kind": metadata["recoverability"],
            "v07_code_style_status": old_style.get("status", "missing"),
            "v08_fingerprint_status": generation["analysis_status"]["status"],
            "v08_fingerprint_available": generation["fingerprint"] is not None,
            "v08_local_profiles": len(generation["local_profiles"]),
            "v08_generation_artifacts": len(generation["generation_artifacts"]),
            "v08_generator_model_hypothesis": generation["source_hypotheses"]["generator_model_hypothesis"],
        })
    return {
        "audit_version": "v08-stylometry-readonly/1.0", "sample_count": len(results),
        "scope": "deterministic_source_eligibility_only_no_llm_no_accuracy_claim",
        "counts": {
            "format": dict(Counter(item["format"] for item in results)),
            "source_kind": dict(Counter(item["source_kind"] for item in results)),
            "v07_style_status": dict(Counter(item["v07_code_style_status"] for item in results)),
            "v08_fingerprint_status": dict(Counter(item["v08_fingerprint_status"] for item in results)),
            "v08_fingerprint_available": sum(item["v08_fingerprint_available"] for item in results),
            "v08_local_profiles": sum(item["v08_local_profiles"] for item in results),
        },
        "samples": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--historical-samples", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    output = audit(args.manifest, args.historical_samples)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(output["counts"], ensure_ascii=False))


if __name__ == "__main__":
    main()

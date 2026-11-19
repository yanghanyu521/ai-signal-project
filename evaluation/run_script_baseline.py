"""Score sample-side LLM extraction results against evaluation/script_baseline.

Reads result.json artifacts (features.llm_script_extraction) and checks the
structured baseline: ai_calling, model identifiers, endpoints, prompt counts,
base64-decoded prompt content, and hallucination rules. Natural-language
must_find/must_not_claim notes in the baseline remain human-review items;
only mechanically checkable expectations are scored here.

Usage:
    python evaluation/run_script_baseline.py --results-dir data/artifacts/samples \
        --output evaluation/script_baseline_metrics.json
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

BASELINE_DIR = Path(__file__).resolve().parent / "script_baseline"


def _normalized(text: str) -> str:
    # Source literals may carry escaped backslashes (C:\\path vs C:\path) and
    # literal \n / \r escape sequences where the model emits real newlines.
    value = str(text or "").replace("\\\\", "\\")
    value = value.replace("\\n", " ").replace("\\r", " ")
    # Unicode punctuation variants (non-breaking hyphen etc.) vs ASCII.
    for char in "‐‑‒–—―−":
        value = value.replace(char, "-")
    return re.sub(r"\s+", " ", value).strip().casefold()


def _load_baseline() -> list[dict]:
    samples = []
    for path in sorted(BASELINE_DIR.glob("*.json")):
        if path.name in {"report_side.json", "script_baseline_metrics.json"}:
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for sample in data["samples"]:
            sample["family"] = data["family"]
            samples.append(sample)
    by_sha = {sample["sha256"]: sample for sample in samples}
    for sample in samples:
        reference = sample.get("same_as")
        if reference and reference in by_sha:
            for key in ("toolchain", "prompts", "ai_calling", "obfuscation"):
                sample.setdefault(key, by_sha[reference].get(key))
    return samples


def _expected_model(entry: dict) -> str | None:
    model = entry.get("model")
    if not model:
        return None
    return re.split(r"\s*\(", str(model), 1)[0].strip()


def _extraction(result_path: Path) -> dict | None:
    if not result_path.is_file():
        return None
    result = json.loads(result_path.read_text(encoding="utf-8"))
    record = (result.get("features") or {}).get("llm_script_extraction")
    return record if isinstance(record, dict) else None


def score_sample(sample: dict, record: dict | None) -> dict:
    findings = []
    if record is None:
        return {"sha256": sample["sha256"], "status": "missing_result", "findings": findings}
    if record.get("status") != "completed":
        return {"sha256": sample["sha256"], "status": record.get("status"), "findings": findings}
    expected_calling = sample.get("ai_calling")
    actual_calling = record.get("ai_calling")
    calling_ok = (
        (expected_calling is True and actual_calling is True)
        or (expected_calling is False and actual_calling is False)
        or (expected_calling == "not_statically_confirmable" and actual_calling in {"unknown", False})
    )
    if not calling_ok:
        findings.append({"check": "ai_calling", "expected": expected_calling, "actual": actual_calling})
    actual_models = {_normalized(item.get("model")) for item in record.get("toolchain") or []}
    actual_endpoints = " ".join(str(item.get("endpoint") or "") for item in record.get("toolchain") or [])
    for entry in sample.get("toolchain") or []:
        model = _expected_model(entry)
        if model and _normalized(model) not in actual_models:
            findings.append({"check": "model_missing", "expected": model, "actual": sorted(actual_models)})
        endpoint = entry.get("endpoint")
        if endpoint:
            base = endpoint.split("?")[0]
            if base not in actual_endpoints:
                findings.append({"check": "endpoint_missing", "expected": base})
    if expected_calling == "not_statically_confirmable":
        if record.get("toolchain") or record.get("prompts"):
            findings.append({"check": "hallucination_on_obfuscated",
                             "actual": f"{len(record.get('toolchain') or [])} toolchain + {len(record.get('prompts') or [])} prompts"})
    if expected_calling is False and record.get("toolchain"):
        findings.append({"check": "hallucination_toolchain_on_negative",
                         "actual": [item.get("model") or item.get("sdk") for item in record["toolchain"]]})
    expected_prompts = sample.get("prompts") or []
    actual_prompts = record.get("prompts") or []
    actual_prompt_texts = [
        _normalized(item.get("decoded_text") or item.get("text")) for item in actual_prompts
    ]
    for prompt in expected_prompts:
        expected_text = prompt.get("text") or prompt.get("decoded_text")
        if expected_text and not any(_normalized(expected_text) in actual or actual in _normalized(expected_text)
                                     for actual in actual_prompt_texts if actual):
            if prompt.get("items") or prompt.get("key_elements"):
                continue
            findings.append({"check": "prompt_missing", "expected": prompt.get("id")})
    if sample["family"] == "FRUITSHELL":
        if not any(item.get("category") == "analyzer_injection" for item in actual_prompts):
            findings.append({"check": "analyzer_injection_not_classified"})
    return {
        "sha256": sample["sha256"], "family": sample["family"], "status": "scored",
        "findings": findings,
        "counts": {"expected_prompts": len(expected_prompts), "actual_prompts": len(actual_prompts)},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=BASELINE_DIR.parent / "script_baseline_metrics.json")
    args = parser.parse_args()
    samples = _load_baseline()
    details = [score_sample(sample, _extraction(args.results_dir / sample["sha256"] / "result.json"))
               for sample in samples]
    scored = [item for item in details if item["status"] == "scored"]
    metrics = {
        "baseline_version": "1.0",
        "results_dir": str(args.results_dir),
        "total_samples": len(samples),
        "scored": len(scored),
        "missing_or_not_completed": len(samples) - len(scored),
        "clean_samples": sum(not item["findings"] for item in scored),
        "finding_counts": {},
        "details": details,
    }
    for item in scored:
        for finding in item["findings"]:
            metrics["finding_counts"][finding["check"]] = metrics["finding_counts"].get(finding["check"], 0) + 1
    args.output.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in metrics.items() if key != "details"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

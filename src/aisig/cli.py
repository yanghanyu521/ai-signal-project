from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from .classify import classify
from .apk_recovery import is_apk, merge_apk_features, recover_and_analyze_apk
from .code_style import analyze_code_style
from .ingest import collect_metadata
from .pyinstaller_recovery import is_pyinstaller, merge_recovered_features, recover_and_analyze_pyinstaller
from .prompt import extract_prompt_features
from .report import write_artifacts
from .string_extract import extract_strings, source_text
from .toolchain import extract_python_call_evidence, extract_toolchain

PROJECT_ROOT = Path(__file__).resolve().parents[2]
COMPONENT_ROOT = PROJECT_ROOT / "components" / "ai_signal_demo"


def _config(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def analyze(sample: Path, out: Path, limits: Path, rules: Path) -> None:
    """Read and statically analyze SAMPLE; no execution, emulation, import, or network access occurs."""
    errors: list[dict[str, str]] = []
    config = _config(limits)
    rule_set = _config(rules)
    try:
        metadata, data = collect_metadata(sample, config["max_file_bytes"])
        strings = extract_strings(data, config["max_strings"], config["max_string_chars"])
        text, encoding = source_text(data, metadata["language"])
        toolchain = extract_toolchain(strings, rule_set, metadata, data)
        if text is not None and metadata.get("language") == "python":
            existing = toolchain.setdefault("evidence", [])
            seen = {(item.get("type"), item.get("value"), item.get("offset"),
                     (item.get("source_location") or {}).get("line")) for item in existing}
            for item in extract_python_call_evidence(text):
                key = (item.get("type"), item.get("value"), item.get("offset"),
                       (item.get("source_location") or {}).get("line"))
                if key not in seen:
                    existing.append(item)
                    seen.add(key)
        prompt = extract_prompt_features(strings, rule_set, config["max_prompt_candidates"], data)
        if encoding:
            metadata["source_encoding"] = encoding
        code_style = analyze_code_style(text, metadata["language"], metadata["recoverability"])
        recovery: dict[str, Any] = {"pyinstaller": {"status": "not_detected"}, "apk": {"status": "not_detected"}}
        if config.get("pyinstaller_recovery_enabled", True) and is_pyinstaller(strings, data, toolchain):
            recovered = recover_and_analyze_pyinstaller(sample, config, rule_set)
            recovery["pyinstaller"] = {key: value for key, value in recovered.items() if key != "features"}
            toolchain, prompt, code_style = merge_recovered_features(toolchain, prompt, code_style, recovered)
        if config.get("apk_member_scan_enabled", True) and is_apk(sample, metadata):
            recovered_apk = recover_and_analyze_apk(sample, config, rule_set)
            recovery["apk"] = {key: value for key, value in recovered_apk.items() if key != "features"}
            toolchain, prompt = merge_apk_features(toolchain, prompt, recovered_apk)
        classification = classify(toolchain, prompt)
    except Exception as exc:  # ensures malformed inputs yield machine-readable output
        errors.append({"stage": "analysis", "message": f"{type(exc).__name__}: {exc}"})
        metadata = {"sha256": "0" * 64, "size": sample.stat().st_size, "file_type": "analysis_error", "language": None, "recoverability": "unknown"}
        strings, toolchain, prompt, code_style = [], {"evidence": []}, {"embedded_prompts": [], "structural_features": {}, "special_tokens": []}, {"status": "unavailable", "representation": "unknown", "metrics": {}, "ai_generated_detection": {"status": "not_supported", "heuristic_score": None}}
        recovery = {"pyinstaller": {"status": "not_run"}, "apk": {"status": "not_run"}}
        classification = {"llm_involvement": {"label": "unknown", "confidence": 0.0}, "model_attribution": {"vendor": None, "family": "unknown", "model": None, "decision_method": "unknown", "confidence": 0.0}, "evidence_summary": []}
    result = {"schema_version": "0.2", "sample": metadata, "features": {"toolchain": toolchain, "prompt": prompt, "code_style": code_style, "recovery": recovery}, "classification": classification, "errors": errors}
    write_artifacts(out, result, strings, COMPONENT_ROOT / "schemas" / "result.schema.json")
    print(json.dumps({"sha256": metadata["sha256"], "out": str(out), "classification": classification}, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Static-only AI signal attribution demo. Never executes samples.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subcommands.add_parser("analyze", help="Read and statically analyze a file")
    analyze_parser.add_argument("--sample", required=True, type=Path, help="Path to a readable file; it is never executed")
    analyze_parser.add_argument("--out", required=True, type=Path, help="Artifact directory")
    analyze_parser.add_argument("--limits", type=Path, default=COMPONENT_ROOT / "configs" / "limits.yaml")
    analyze_parser.add_argument("--rules", type=Path, default=COMPONENT_ROOT / "rules" / "llm_rules.yaml")
    args = parser.parse_args()
    if args.command == "analyze":
        if not args.sample.is_file():
            parser.error(f"--sample must name a readable file: {args.sample}")
        analyze(args.sample, args.out, args.limits, args.rules)


if __name__ == "__main__":
    main()

"""Run script-side LLM extraction over the 19-sample manual baseline.

Calls the real configured model (SAMPLE_LLM_* / DEEPSEEK_* env) and stores
features.llm_script_extraction into data/artifacts/samples/<sha256>/result.json
so evaluation/run_script_baseline.py can score the outcome. Samples are read
from an external root supplied on the command line; nothing is executed.

Example:
    python scripts/run_baseline_samples.py --sample-root /path/to/恶意样本文件 --only 4c73717d933f f8f5e0440c57
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from dotenv import load_dotenv

load_dotenv(PROJECT / ".env")

from ai_signal_hub.config import Settings
from ai_signal_hub.static_analysis.llm import SampleLLMClient
from ai_signal_hub.static_analysis.script_extract import extract_script_features


def baseline_samples() -> list[dict]:
    samples = []
    for path in sorted((PROJECT / "evaluation" / "script_baseline").glob("*.json")):
        if path.name == "report_side.json":
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for sample in data["samples"]:
            sample["family"] = data["family"]
            samples.append(sample)
    return samples


def locate(root: Path, sha256: str) -> Path | None:
    exact = [candidate for candidate in root.rglob(sha256) if candidate.is_file()]
    if exact:
        return exact[0]
    for candidate in root.rglob(f"{sha256[:12]}*"):
        if candidate.is_file() and candidate.suffix.lower() not in {".zip", ".rar", ".7z", ".gz"}:
            return candidate
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-root", type=Path, required=True)
    parser.add_argument("--only", nargs="*", default=[])
    parser.add_argument("--max-chunk-chars", type=int, default=60000)
    parser.add_argument("--output-root", type=Path, default=PROJECT / "data" / "artifacts" / "samples")
    args = parser.parse_args()

    settings = Settings()
    client = SampleLLMClient(
        base_url=settings.sample_llm_base_url,
        model=settings.sample_llm_model,
        api_key=settings.sample_llm_api_key,
        allow_remote=settings.sample_llm_allow_remote,
        transfer_policy=settings.sample_llm_transfer_policy,
        timeout_seconds=settings.sample_llm_timeout_seconds,
        max_output_tokens=settings.sample_llm_max_output_tokens,
    )
    summary = []
    for sample in baseline_samples():
        sha256 = sample["sha256"]
        if args.only and not any(sha256.startswith(prefix) for prefix in args.only):
            continue
        source = locate(args.sample_root, sha256)
        if source is None:
            print(f"[skip] {sample['family']} {sha256[:12]} not found", flush=True)
            continue
        started = time.time()
        print(f"[run ] {sample['family']} {sha256[:12]} ({source.stat().st_size} bytes)", flush=True)
        try:
            record = {"status": "completed", **extract_script_features(
                source, client, max_chunk_chars=args.max_chunk_chars)}
        except Exception as exc:
            record = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
        artifact = args.output_root / sha256
        artifact.mkdir(parents=True, exist_ok=True)
        result_path = artifact / "result.json"
        result = {"sample": {"sha256": sha256}, "features": {}}
        if result_path.is_file():
            result = json.loads(result_path.read_text(encoding="utf-8"))
        result.setdefault("features", {})["llm_script_extraction"] = record
        result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        verification = record.get("verification") or {}
        print(f"[done] {sha256[:12]} status={record['status']} "
              f"ai_calling={record.get('ai_calling')} toolchain={len(record.get('toolchain') or [])} "
              f"prompts={len(record.get('prompts') or [])} violations={len(verification.get('violations') or [])} "
              f"elapsed={time.time() - started:.1f}s", flush=True)
        if record["status"] != "completed":
            print(f"       error={record.get('error')}", flush=True)
        summary.append({"sha256": sha256, "family": sample["family"], "status": record["status"]})
    print(json.dumps({"total": len(summary),
                      "completed": sum(item["status"] == "completed" for item in summary),
                      "failed": sum(item["status"] == "failed" for item in summary)}, indent=2), flush=True)


if __name__ == "__main__":
    main()

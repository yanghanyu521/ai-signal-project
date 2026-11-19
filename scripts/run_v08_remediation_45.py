"""Resumable, SHA-checked, isolated static rerun of the 45-sample manifest.

Never executes a sample or writes to the main knowledge-base database.
All outputs (including raw evidence) must remain in ignored private data/.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from ai_signal_hub.config import Settings
from ai_signal_hub.legacy import LegacyAdapters


PROJECT = Path(__file__).resolve().parents[1]
PRIVATE = (PROJECT / "data" / "evaluations").resolve()


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def run(manifest_path: Path, output: Path, *, max_samples: int | None = None,
        start_index: int = 0, end_index: int = 45, worker: bool = False,
        force: bool = False) -> dict:
    output = output.resolve()
    if not output.is_relative_to(PRIVATE):
        raise ValueError("Raw sample output must stay under private data/evaluations/")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if len(manifest) != 45 or len({item["sha256"] for item in manifest}) != 45:
        raise ValueError("Expected exactly 45 distinct SHA-256 records")
    settings = Settings(
        project_root=PROJECT, workspace_root=PROJECT.parent, data_dir=output / "runtime",
        legacy_sample_project=PROJECT / "components" / "ai_signal_demo",
        legacy_report_project=PROJECT / "components" / "report_extractor",
        seed_data_dir=PROJECT / "components" / "seed_data",
        sample_llm_enabled=True, sample_llm_allow_remote=True,
        sample_llm_transfer_policy="remote_redacted", static_tools_docker_enabled=False,
    )
    if not settings.sample_llm_api_key:
        raise ValueError("DeepSeek key unavailable (expected system variable cc-api)")
    adapter = LegacyAdapters(settings)
    if not worker:
        _write(output / "manifest.json", manifest)
        _write(output / "run_metadata.json", {
            "schema_version": "v08-remediation-run/1.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "expected_samples": len(manifest), "model": settings.sample_llm_model,
            "provider_host": "api.deepseek.com", "transfer_policy": "remote_redacted",
            "max_requests_per_sample": settings.sample_llm_max_requests,
            "total_token_budget": None, "sample_execution": False,
            "knowledge_base_modified": False,
        })
    completed = failed = skipped = 0
    for number, item in enumerate(manifest, 1):
        if not start_index <= number - 1 < end_index:
            continue
        if max_samples is not None and completed + failed >= max_samples:
            break
        sha = item["sha256"]
        target = output / "samples" / sha / "v08"
        result_file = target / "result.json"
        previous_status = target / "status.json"
        completed_before = (result_file.is_file() and previous_status.is_file() and
                            _completed(previous_status))
        if completed_before and not force:
            skipped += 1
            continue
        path = Path(item["selected_path"])
        if not path.is_file():
            _write(target / "status.json", {"status": "missing_sample", "sha256": sha})
            failed += 1
            print(f"[{number}/45] {sha[:12]} missing_sample", flush=True)
            continue
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            _write(target / "status.json", {"status": "sha_mismatch", "sha256": sha})
            failed += 1
            print(f"[{number}/45] {sha[:12]} sha_mismatch", flush=True)
            continue
        started = time.monotonic()
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                result = adapter.analyze_sample(path, target)
            run_info = result.get("features", {}).get("static_analysis", {}).get("run", {})
            analysis_status = run_info.get("status")
            status = {"status": "completed" if analysis_status in {"completed", "unsupported"} else "incomplete",
                      "sha256": sha, "analysis_status": analysis_status,
                      "elapsed_seconds": round(time.monotonic() - started, 3),
                      "llm_requests": run_info.get("budget", {}).get("requests"),
                      "provider_usage": run_info.get("budget", {}).get("provider_usage", {}),
                      "string_analysis_rate": run_info.get("coverage", {}).get("string_analysis_rate")}
            _write(target / "status.json", status)
            if status["status"] == "completed":
                completed += 1
            else:
                failed += 1
            print(f"[{number}/45] {sha[:12]} {status['analysis_status']} "
                  f"requests={status['llm_requests']} elapsed={status['elapsed_seconds']}s", flush=True)
        except Exception as exc:
            _write(target / "status.json", {"status": "failed", "sha256": sha,
                                            "error_type": type(exc).__name__})
            failed += 1
            print(f"[{number}/45] {sha[:12]} failed:{type(exc).__name__}", flush=True)
    return {"expected": 45, "completed_this_run": completed, "failed_this_run": failed,
            "skipped_existing": skipped, "result_files": sum(
                (output / "samples" / item["sha256"] / "v08" / "status.json").is_file()
                and _completed(output / "samples" / item["sha256"] / "v08" / "status.json")
                for item in manifest)}


def _completed(path: Path) -> bool:
    status = json.loads(path.read_text(encoding="utf-8"))
    return status.get("status") == "completed" and status.get("analysis_status") in {"completed", "unsupported"}


def reconcile_statuses(manifest_path: Path, output: Path) -> dict[str, int]:
    """Repair old runner bookkeeping from saved results; never calls the LLM."""
    output = output.resolve()
    if not output.is_relative_to(PRIVATE):
        raise ValueError("Raw sample output must stay under private data/evaluations/")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if len(manifest) != 45 or len({item["sha256"] for item in manifest}) != 45:
        raise ValueError("Expected exactly 45 distinct SHA-256 records")
    counts = {"completed": 0, "incomplete": 0, "missing": 0}
    for item in manifest:
        base = output / "samples" / item["sha256"] / "v08"
        status_file, result_file = base / "status.json", base / "result.json"
        if not status_file.is_file() or not result_file.is_file():
            counts["missing"] += 1
            continue
        status = json.loads(status_file.read_text(encoding="utf-8"))
        result = json.loads(result_file.read_text(encoding="utf-8"))
        if result.get("sample", {}).get("sha256") != item["sha256"]:
            counts["missing"] += 1
            continue
        analysis_status = result.get("features", {}).get("static_analysis", {}).get("run", {}).get("status")
        status["analysis_status"] = analysis_status
        status["status"] = "completed" if analysis_status in {"completed", "unsupported"} else "incomplete"
        _write(status_file, status)
        counts[status["status"]] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-samples", type=int)
    parser.add_argument("--start-index", type=int, default=0, help="inclusive zero-based manifest index")
    parser.add_argument("--end-index", type=int, default=45, help="exclusive zero-based manifest index")
    parser.add_argument("--worker", action="store_true", help="do not rewrite shared manifest or metadata")
    parser.add_argument("--force", action="store_true", help="reanalyze selected indices even if already complete")
    parser.add_argument("--reconcile-only", action="store_true", help="repair saved statuses without LLM calls")
    args = parser.parse_args()
    if args.reconcile_only:
        print(json.dumps(reconcile_statuses(args.manifest, args.output), ensure_ascii=False))
        return
    if not 0 <= args.start_index <= args.end_index <= 45:
        parser.error("Require 0 <= start-index <= end-index <= 45")
    print(json.dumps(run(args.manifest, args.output, max_samples=args.max_samples,
                         start_index=args.start_index, end_index=args.end_index,
                         worker=args.worker, force=args.force), ensure_ascii=False))


if __name__ == "__main__":
    main()

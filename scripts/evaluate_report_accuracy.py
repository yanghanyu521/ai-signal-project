"""Isolated, explicitly invoked live evaluation; never writes knowledge.db."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from ai_signal_hub.config import Settings
from ai_signal_hub.legacy import LegacyAdapters, _add_src
from ai_signal_hub.report_llm import ModelClient, ReportModelError


PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT / "data" / "evaluations" / "20260902_llm_accuracy"
FAMILIES = ["FRUITSHELL", "LAMEHUG", "MalTerminal", "PROMPTFLUX", "PromptLock", "PromptSpy", "PROMPTSTEAL", "QUIETVAULT", "SLOPOLY"]


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def source(family):
    files = list((PROJECT.parent / "恶意样本报告" / family).glob("*.html"))
    if len(files) != 1:
        raise ValueError("Expected exactly one source HTML")
    return files[0]


def prepare(families):
    _add_src(Settings().legacy_report_project)
    from report_extractor.parsers import parse_document
    manifest = []
    for family in families:
        path = source(family)
        parsed = parse_document(path, f"evaluation:{family}")
        output = ROOT / "sources" / family
        write(output / "parsed.json", parsed)
        output.joinpath("parsed_text.txt").write_text("\n\n".join(
            f"[{b['index']}] [{b['block_id']}] {b['text']}" for b in parsed["blocks"]), encoding="utf-8")
        manifest.append({"family": family, "source": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "blocks": len(parsed["blocks"]), "characters": sum(len(b["text"]) for b in parsed["blocks"]), "title": parsed["title"]})
    write(ROOT / "source_manifest.json", manifest)
    print(json.dumps([{k: item[k] for k in ("family", "blocks", "characters")} for item in manifest]), flush=True)


def run(families, batch):
    if batch in {"", ".", ".."} or any(char in batch for char in '/\\:'):
        raise ValueError("--batch must be a single directory name")
    settings = Settings()
    client = ModelClient.from_env()
    # Initialize legacy imports before starting worker threads.
    _add_src(settings.legacy_report_project)
    from report_extractor.parsers import parse_document  # noqa: F401
    output = ROOT / batch
    if output.exists() and any(output.iterdir()):
        raise ValueError("Batch directory is not empty: choose a new --batch")
    output.mkdir(parents=True, exist_ok=True)
    if (output / "summary.json").exists():
        raise ValueError("Batch already exists: choose a new --batch; do not overwrite evaluation")
    rows = []

    def one(family):
        start = time.monotonic()
        row = {"family": family, "model": client.model, "source": str(source(family))}
        try:
            result = LegacyAdapters(settings).analyze_report(source(family), output / family, target_name=family)
            row.update(status="passed", extraction=result["extraction"],
                       evidence_count=len(result["events"][0]["evidence"]))
        except (ReportModelError, ValueError) as exc:
            row.update(status="failed", error_type=type(exc).__name__, message=str(exc))
        except Exception as exc:
            row.update(status="failed", error_type=type(exc).__name__, message="Unexpected error; inspect local artifacts")
        row["elapsed_seconds"] = round(time.monotonic() - start, 2)
        write(output / family / "evaluation_status.json", row)
        print(json.dumps({k: row[k] for k in ("family", "status", "elapsed_seconds")}, ensure_ascii=True), flush=True)
        return row

    with ThreadPoolExecutor(max_workers=3) as pool:
        for future in as_completed([pool.submit(one, family) for family in families]):
            rows.append(future.result())
            write(output / "summary.json", {"created_at": datetime.now(timezone.utc).isoformat(),
                "production_code_sha256": hashlib.sha256((PROJECT / "src/ai_signal_hub/report_llm.py").read_bytes()).hexdigest(),
                "quality_code_sha256": hashlib.sha256((PROJECT / "src/ai_signal_hub/report_quality.py").read_bytes()).hexdigest(),
                "model": client.model, "max_output_tokens": client.max_tokens, "timeout_seconds": client.timeout,
                "families": sorted(rows, key=lambda row: row["family"]), "knowledge_db_written": False})


def negative(batch="negative_control"):
    if batch in {"", ".", ".."} or any(char in batch for char in '/\\:'):
        raise ValueError("--batch must be a single directory name")
    output = ROOT / batch
    if (output / "evaluation_status.json").exists():
        raise ValueError("Negative-control run already exists")
    target = "EVAL_NONEXISTENT_FAMILY_9B7C"
    try:
        result = LegacyAdapters(Settings()).analyze_report(source("PromptLock"), output, target_name=target)
        row = {"status": "false_positive", "target": target, "events": len(result["events"])}
    except ValueError as exc:
        row = {"status": "correct_no_target" if "未在报告中找到" in str(exc) else "other_failure", "target": target, "message": str(exc)}
    except ReportModelError as exc:
        status = "correct_target_anchor_rejection" if "目标名称/用户别名未出现在身份引用原文中" in str(exc) else "model_failure"
        row = {"status": status, "target": target, "message": str(exc)}
    write(output / "evaluation_status.json", row)
    print(json.dumps(row, ensure_ascii=True), flush=True)


def check_connection():
    client = ModelClient.from_env()
    try:
        response = httpx.get(client.endpoint.removesuffix('/chat/completions') + '/models',
                            headers={'Authorization': 'Bearer ' + client.api_key}, timeout=10, follow_redirects=False)
        print(json.dumps({'http_status': response.status_code}))
    except httpx.HTTPError as exc:
        print(json.dumps({'error_type': type(exc).__name__}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "run", "negative", "check"])
    parser.add_argument("--families", nargs="+", choices=FAMILIES, default=FAMILIES)
    parser.add_argument("--batch", default="baseline")
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.families)
    elif args.action == "run":
        run(args.families, args.batch)
    elif args.action == "negative":
        negative("negative_control" if args.batch == "baseline" else args.batch)
    else:
        check_connection()

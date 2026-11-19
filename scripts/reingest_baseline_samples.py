"""Re-ingest the 19 baseline scripts through the full service pipeline.

Runs aisig deterministic analysis + bounded semantic pass + the new verified
LLM script extraction, and upserts into the production knowledge database.
Semantic LLM budget is capped per sample; script extraction is separate.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

os.environ.setdefault("SAMPLE_LLM_MAX_REQUESTS", "4")
os.environ.setdefault("SAMPLE_LLM_MAX_REASONING_ROUNDS", "1")
os.environ.setdefault("SAMPLE_LLM_MAX_QUERIES_PER_ROUND", "4")

from dotenv import load_dotenv

load_dotenv(PROJECT / ".env")

from ai_signal_hub.config import Settings
from ai_signal_hub.database import Database
from ai_signal_hub.legacy import LegacyAdapters
from ai_signal_hub.repository import Repository
from ai_signal_hub.services import HubService

EXTENSIONS = {"python": ".py", "javascript": ".js", "powershell": ".ps1", "vbscript": ".vbs"}


def locate(root: Path, sha256: str) -> Path | None:
    exact = [p for p in root.rglob(sha256) if p.is_file()]
    if exact:
        return exact[0]
    for candidate in root.rglob(f"{sha256[:12]}*"):
        if candidate.is_file() and candidate.suffix.lower() not in {".zip", ".rar", ".7z", ".gz"}:
            return candidate
    return None


def main() -> None:
    root = Path(sys.argv[1])
    settings = Settings()
    settings.ensure_directories()
    database = Database(settings.database_path)
    database.initialize()
    service = HubService(settings, Repository(database), LegacyAdapters(settings))

    samples = []
    for path in sorted((PROJECT / "evaluation" / "script_baseline").glob("*.json")):
        if path.name == "report_side.json":
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for sample in data["samples"]:
            sample["family"] = data["family"]
            sample["language"] = data["language"]
            samples.append(sample)

    summary = []
    for sample in samples:
        sha256 = sample["sha256"]
        source = locate(root, sha256)
        if source is None:
            print(f"[skip] {sample['family']} {sha256[:12]} not found", flush=True)
            continue
        filename = sha256 + EXTENSIONS.get(sample["language"], ".txt")
        started = time.time()
        print(f"[run ] {sample['family']} {sha256[:12]}", flush=True)
        try:
            with source.open("rb") as handle:
                saved = service.analyze_sample(handle, filename, sample["family"])
            extraction = (saved.get("features") or {}).get("llm_script_extraction") or {}
            print(f"[done] {sha256[:12]} status=ok llm={extraction.get('status')} "
                  f"label={saved.get('classification', {}).get('label')} elapsed={time.time()-started:.1f}s", flush=True)
            summary.append({"sha256": sha256, "status": "ok"})
        except Exception as exc:
            print(f"[fail] {sha256[:12]} {type(exc).__name__}: {exc}", flush=True)
            summary.append({"sha256": sha256, "status": "failed", "error": str(exc)})
    print(json.dumps({"total": len(summary),
                      "ok": sum(item["status"] == "ok" for item in summary),
                      "failed": sum(item["status"] == "failed" for item in summary)}, indent=2), flush=True)


if __name__ == "__main__":
    main()

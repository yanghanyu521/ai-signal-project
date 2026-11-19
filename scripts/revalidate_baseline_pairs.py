"""Re-run cross-validation for baseline samples against their case reports."""
from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from dotenv import load_dotenv

load_dotenv(PROJECT / ".env")

from ai_signal_hub.config import Settings
from ai_signal_hub.database import Database
from ai_signal_hub.legacy import LegacyAdapters
from ai_signal_hub.repository import Repository
from ai_signal_hub.services import HubService


def baseline_shas() -> set[str]:
    shas = set()
    for path in (PROJECT / "evaluation" / "script_baseline").glob("*.json"):
        if path.name == "report_side.json":
            continue
        for sample in json.loads(path.read_text(encoding="utf-8"))["samples"]:
            shas.add(sample["sha256"])
    return shas


def main() -> None:
    settings = Settings()
    database = Database(settings.database_path)
    database.initialize()
    service = HubService(settings, Repository(database), LegacyAdapters(settings))
    targets = baseline_shas()
    results = []
    for case in service.repository.list_cases(limit=500):
        detail = service.repository.get_case(case["id"])
        if not detail:
            continue
        samples = [item for item in detail["samples"] if item["sha256"] in targets]
        reports = detail["reports"]
        for sample in samples:
            for report in reports:
                label = f"{case['title']} | {sample['sha256'][:12]} × {report['report_id'][:12]}"
                try:
                    result = service.cross_validate_case(
                        case_id=case["id"], sample_sha256=sample["sha256"], report_id=report["report_id"])
                    summary = result.get("joint_summary") or {}
                    counts = {key: len(summary.get(key) or []) for key in ("confirmed", "conflicts", "report_complements")}
                    print(f"[ok] {label} {counts}", flush=True)
                    results.append({"case": case["id"], "sample": sample["sha256"], "report": report["report_id"], "status": "ok", **counts})
                except Exception as exc:
                    print(f"[skip/fail] {label} {type(exc).__name__}: {exc}", flush=True)
                    results.append({"case": case["id"], "sample": sample["sha256"], "report": report["report_id"],
                                    "status": "failed", "error": str(exc)})
    print(json.dumps({"pairs": len(results), "ok": sum(r["status"] == "ok" for r in results),
                      "failed": sum(r["status"] == "failed" for r in results)}, indent=2), flush=True)


if __name__ == "__main__":
    main()

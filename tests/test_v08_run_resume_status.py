from __future__ import annotations

import json

from scripts.run_v08_remediation_45 import _completed


def test_failed_analysis_must_not_be_skipped_on_resume(tmp_path) -> None:
    path = tmp_path / "status.json"
    for analysis_status in ("failed", "partial", None):
        path.write_text(json.dumps({"status": "completed", "analysis_status": analysis_status}),
                        encoding="utf-8")
        assert not _completed(path)
    for analysis_status in ("completed", "unsupported"):
        path.write_text(json.dumps({"status": "completed", "analysis_status": analysis_status}),
                        encoding="utf-8")
        assert _completed(path)

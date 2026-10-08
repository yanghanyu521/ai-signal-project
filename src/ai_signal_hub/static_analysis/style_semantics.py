"""Source-bound semantic style observations, independent of AI-use evidence."""
from __future__ import annotations

import hashlib
from typing import Any

from .materials import MaterialIndex


LABELS = {"explanatory_comment", "documentation_pattern", "dialogue_residue",
          "comment_code_mismatch", "style_shift", "generation_claim", "hallucination_candidate"}


def analyze_style(index: MaterialIndex, client: Any | None, *, max_units: int = 12) -> dict[str, Any]:
    source = [unit for unit in index.units if unit.representation == "original_source"
              and unit.language in {"python", "javascript", "powershell"}]
    if client is None or not source:
        return {"status": "unavailable", "reason": "llm_disabled_or_no_original_source",
                "observations": [], "rejected_count": 0}
    selected = source[:max_units]
    try:
        response = client.analyze([unit.as_dict(include_content=True) for unit in selected],
                                  task="stylometry")
    except Exception as exc:
        return {"status": "failed", "reason": type(exc).__name__,
                "observations": [], "rejected_count": 0}
    units = {unit.unit_id: unit for unit in selected}
    accepted: list[dict[str, Any]] = []
    rejected = 0
    for item in response.get("observations") or []:
        if not isinstance(item, dict) or item.get("label") not in LABELS:
            rejected += 1
            continue
        raw = item.get("raw_value")
        ids = item.get("source_unit_ids")
        if not isinstance(raw, str) or not raw or not isinstance(ids, list) or not ids:
            rejected += 1
            continue
        found = next((units.get(uid) for uid in ids if uid in units and raw in units[uid].content), None)
        if found is None:
            rejected += 1
            continue
        offset = found.content.index(raw)
        base_line = found.location.get("source_lines", [None])[0]
        line = base_line + found.content[:offset].count("\n") if isinstance(base_line, int) else None
        status = "semantic_hypothesis" if item["label"] in {
            "comment_code_mismatch", "style_shift", "hallucination_candidate"} else "observed_indicator"
        accepted.append({"label": item["label"], "raw_value": raw,
                         "source_unit_ids": [found.unit_id],
                         "source_location": {"unit_id": found.unit_id, "line": line,
                                             "unit_char_offset": offset},
                         "evidence_text_hash": "sha256:" + hashlib.sha256(raw.encode()).hexdigest(),
                         "evidence_status": status, "verification": "exact_source_match",
                         "explanation": str(item.get("explanation") or "")[:500],
                         "proves_generator_model": False})
    return {"status": "partial" if len(source) > max_units else "completed",
            "observations": accepted, "rejected_count": rejected,
            "source_units_considered": len(selected), "source_units_total": len(source)}

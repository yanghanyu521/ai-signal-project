"""Source-bound semantic style observations, independent of AI-use evidence."""
from __future__ import annotations

import hashlib
import io
import re
import time
import tokenize
from typing import Any

from .materials import MaterialIndex


LABELS = {"explanatory_comment", "documentation_pattern", "dialogue_residue",
          "comment_code_mismatch", "style_shift", "generation_claim", "hallucination_candidate"}


def _segment(unit: Any, raw: str, offset: int) -> str:
    if unit.language == "python":
        lines = unit.content.splitlines(keepends=True)
        starts = [0]
        for line in lines:
            starts.append(starts[-1] + len(line))
        try:
            for token in tokenize.generate_tokens(io.StringIO(unit.content).readline):
                start = starts[token.start[0] - 1] + token.start[1]
                end = starts[token.end[0] - 1] + token.end[1]
                if start <= offset < end:
                    if token.type == tokenize.COMMENT:
                        return "comment"
                    if token.type == tokenize.STRING:
                        return "embedded_prompt" if re.search(
                            r"(?i)\b(?:summarize|classify|generate|ignore|assistant|system|write)\b|总结|分类|生成|忽略",
                            raw) else "data_text"
        except (tokenize.TokenError, IndentationError, IndexError):
            pass
    line = unit.content[:offset].count("\n")
    source_line = unit.content.splitlines()[line].lstrip() if unit.content.splitlines() else ""
    if source_line.startswith(("#", "//", "/*", "*", "'")):
        return "comment"
    return "code"


def analyze_style(index: MaterialIndex, client: Any | None, *, max_units: int = 12,
                  max_requests: int = 128) -> dict[str, Any]:
    source = [unit for unit in index.units if unit.representation == "original_source"
              and unit.language in {"python", "javascript", "powershell"}]
    if client is None or not source:
        return {"status": "unavailable", "reason": "llm_disabled_or_no_original_source",
                "observations": [], "rejected_count": 0}
    selected = source[:max_units * max_requests]
    units = {unit.unit_id: unit for unit in selected}
    accepted: list[dict[str, Any]] = []
    rejected = 0
    rejection_reasons: dict[str, int] = {}
    usage: dict[str, int | float] = {}
    requests = 0
    failed_units = 0
    started = time.monotonic()
    for start in range(0, len(selected), max_units):
        batch = selected[start:start + max_units]
        try:
            response = client.analyze([unit.as_dict(include_content=True) for unit in batch],
                                      task="stylometry")
            requests += 1
            for key, value in (response.get("usage") or {}).items():
                if isinstance(value, (int, float)):
                    usage[key] = usage.get(key, 0) + value
        except Exception:
            failed_units += len(batch)
            continue
        batch_units = {unit.unit_id: unit for unit in batch}
        for item in response.get("observations") or []:
            observation = _validate_observation(item, batch_units)
            if isinstance(observation, str):
                rejected += 1
                rejection_reasons[observation] = rejection_reasons.get(observation, 0) + 1
            else:
                accepted.append(observation)
    status = "failed" if failed_units == len(selected) else "partial" if failed_units or len(source) > len(selected) else "completed"
    return {"status": status, "observations": accepted, "rejected_count": rejected,
            "rejection_reasons": rejection_reasons, "source_units_considered": len(selected),
            "source_units_total": len(source), "source_units_failed": failed_units,
            "requests": requests, "provider_usage": usage,
            "elapsed_seconds": round(time.monotonic() - started, 4)}


def _validate_observation(item: Any, units: dict[str, Any]) -> dict[str, Any] | str:
        if not isinstance(item, dict) or item.get("label") not in LABELS:
            return "invalid_label"
        raw = item.get("raw_value")
        ids = item.get("source_unit_ids")
        if not isinstance(raw, str) or not raw or not isinstance(ids, list) or not ids:
            return "invalid_shape"
        found = next((units.get(uid) for uid in ids if uid in units and raw in units[uid].content), None)
        if found is None:
            return "unanchored"
        offset = found.content.index(raw)
        segment = _segment(found, raw, offset)
        if item["label"] in {"dialogue_residue", "generation_claim"} and segment in {
            "embedded_prompt", "data_text"}:
            return "text_asset_not_code_style"
        base_line = found.location.get("source_lines", [None])[0]
        line = base_line + found.content[:offset].count("\n") if isinstance(base_line, int) else None
        status = "semantic_hypothesis" if item["label"] in {
            "comment_code_mismatch", "style_shift", "hallucination_candidate"} else "observed_indicator"
        return {"label": item["label"], "raw_value": raw, "source_segment": segment,
                         "source_unit_ids": [found.unit_id],
                         "source_location": {"unit_id": found.unit_id, "line": line,
                                             "unit_char_offset": offset},
                         "evidence_text_hash": "sha256:" + hashlib.sha256(raw.encode()).hexdigest(),
                         "evidence_status": status, "verification": "exact_source_match",
                         "explanation": str(item.get("explanation") or "")[:500],
                         "proves_generator_model": False}

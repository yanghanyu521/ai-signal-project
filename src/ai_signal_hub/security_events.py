"""Global AI security event library: xlsx import, filtered listing and CRUD.

The catalog comes from AI安全事件库.xlsx (sheet 事件库). Events are identified
by their AISEC-* event_id; imports are idempotent upserts. The 可分析样本哈希
column is free text, so hashes are extracted mechanically and the original text
is preserved for the detail view.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .database import Database

EVENT_TYPES = ("AI辅助恶意样本开发", "恶意行为调用AI", "Agent编排攻击行动")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _date_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "nat", "none"}:
        return None
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d")
    match = re.match(r"(\d{4})[-/年.](\d{1,2})[-/月.](\d{1,2})", text)
    if match:
        return f"{match.group(1)}-{int(match.group(2)):02d}-{int(match.group(3)):02d}"
    return text


def parse_sample_text(text: str | None) -> dict[str, Any]:
    """Split the free-text sample column into per-line entries with hashes."""
    raw = (text or "").strip()
    if not raw or raw.lower() in {"nan", "none"}:
        raw = ""
    entries = []
    for segment in re.split(r"[\n;；]+", raw):
        segment = segment.strip()
        if not segment:
            continue
        hashes = list(dict.fromkeys(match.group(0).lower() for match in SHA256_RE.finditer(segment)))
        entries.append({"text": segment, "hashes": hashes})
    all_hashes = list(dict.fromkeys(hash_ for entry in entries for hash_ in entry["hashes"]))
    return {
        "raw": raw,
        "entries": entries,
        "hashes": all_hashes,
        "has_samples": bool(all_hashes),
        "sample_count": len(all_hashes),
    }


def _split_values(value: Any) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in re.split(r"[;；\n]+", str(value)) if item.strip()]


def samples_from_entries(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Structured per-row input: one hash plus one note per row."""
    clean = []
    for entry in entries:
        hash_ = str(entry.get("hash") or "").strip().lower()
        note = str(entry.get("note") or "").strip()
        if hash_ and not SHA256_RE.fullmatch(hash_):
            raise ValueError(f"哈希必须是 64 位十六进制字符串：{hash_[:32]}…")
        if not hash_ and not note:
            continue
        text = (f"SHA256: {hash_}" if hash_ else "") + (f"（{note}）" if note else "")
        clean.append({"text": text, "hashes": [hash_] if hash_ else [], "note": note})
    hashes = list(dict.fromkeys(entry["hashes"][0] for entry in clean if entry["hashes"]))
    return {
        "raw": "\n".join(entry["text"] for entry in clean) or "无",
        "entries": clean,
        "hashes": hashes,
        "has_samples": bool(hashes),
        "sample_count": len(hashes),
    }


class SecurityEventLibrary:
    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def _row_to_list_item(row) -> dict[str, Any]:
        return {
            "event_id": row["event_id"],
            "event_date": row["event_date"],
            "name": row["name"],
            "event_types": json.loads(row["event_types"]),
            "has_samples": bool(row["has_samples"]),
            "sample_count": row["sample_count"],
            "status": row["status"],
            "first_seen_at": row["first_seen_at"],
            "updated_at": row["updated_at"],
        }

    def list(self, *, report_date_from=None, report_date_to=None, event_type=None,
             has_samples=None, first_seen_from=None, first_seen_to=None,
             q=None, limit=100, offset=0) -> dict[str, Any]:
        clauses, params = [], []
        if report_date_from:
            clauses.append("event_date >= ?")
            params.append(report_date_from)
        if report_date_to:
            clauses.append("event_date <= ?")
            params.append(report_date_to)
        if event_type:
            clauses.append("event_types LIKE ?")
            params.append(f"%{event_type}%")
        if has_samples is not None:
            clauses.append("has_samples = ?")
            params.append(1 if has_samples else 0)
        if first_seen_from:
            clauses.append("substr(first_seen_at, 1, 10) >= ?")
            params.append(first_seen_from)
        if first_seen_to:
            clauses.append("substr(first_seen_at, 1, 10) <= ?")
            params.append(first_seen_to)
        if q:
            clauses.append("(name LIKE ? OR event_id LIKE ? OR summary LIKE ?)")
            params.extend([f"%{q}%"] * 3)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.database.connect() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM security_event_library {where}", params).fetchone()[0]
            rows = connection.execute(
                f"SELECT * FROM security_event_library {where} "
                "ORDER BY event_date DESC, event_id LIMIT ? OFFSET ?",
                [*params, limit, offset]).fetchall()
        return {"total": total, "items": [self._row_to_list_item(row) for row in rows]}

    def get(self, event_id: str) -> dict[str, Any] | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM security_event_library WHERE event_id = ?", (event_id,)).fetchone()
        if row is None:
            return None
        item = self._row_to_list_item(row)
        item.update({
            "summary": row["summary"],
            "source": row["source"],
            "sources": _split_values(row["source"]),
            "samples": json.loads(row["sample_detail"]),
        })
        return item

    def _upsert(self, connection, event_id: str, payload: dict[str, Any], *, preserve_dates: bool) -> None:
        if payload.get("sample_entries") is not None:
            samples = samples_from_entries(payload["sample_entries"])
        else:
            samples = parse_sample_text(payload.get("sample_text"))
        event_types = payload.get("event_types") or []
        if isinstance(event_types, str):
            event_types = _split_values(event_types)
        invalid = [item for item in event_types if item not in EVENT_TYPES]
        if invalid:
            raise ValueError(f"事件类型仅限 {'、'.join(EVENT_TYPES)}；非法值：{'、'.join(invalid)}")
        name = (payload.get("name") or "").strip()
        if not name:
            raise ValueError("事件名称不能为空")
        now = _now()
        existing = connection.execute(
            "SELECT first_seen_at FROM security_event_library WHERE event_id = ?", (event_id,)).fetchone()
        first_seen = payload.get("first_seen_at") or (existing["first_seen_at"] if existing else None) or now
        updated_at = payload.get("updated_at") or now
        if preserve_dates and existing:
            updated_at = payload.get("updated_at") or now
        connection.execute(
            """INSERT INTO security_event_library (
                   event_id, event_date, name, event_types, summary, source,
                   sample_raw, sample_detail, has_samples, sample_count,
                   first_seen_at, updated_at, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(event_id) DO UPDATE SET
                   event_date=excluded.event_date, name=excluded.name,
                   event_types=excluded.event_types, summary=excluded.summary,
                   source=excluded.source, sample_raw=excluded.sample_raw,
                   sample_detail=excluded.sample_detail, has_samples=excluded.has_samples,
                   sample_count=excluded.sample_count, updated_at=excluded.updated_at,
                   status=excluded.status""",
            (event_id, _date_text(payload.get("event_date")), name, json.dumps(event_types, ensure_ascii=False),
             payload.get("summary") or "", payload.get("source") or "",
             samples["raw"], json.dumps(samples, ensure_ascii=False),
             1 if samples["has_samples"] else 0, samples["sample_count"],
             first_seen, updated_at, payload.get("status") or "新增"),
        )

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        event_id = (payload.get("event_id") or "").strip()
        if not event_id:
            date_part = (_date_text(payload.get("event_date")) or _now()[:10]).replace("-", "")
            event_id = f"AISEC-{date_part}-CUSTOM-{datetime.now(UTC).strftime('%H%M%S%f')}"
        with self.database.connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM security_event_library WHERE event_id = ?", (event_id,)).fetchone()
            if exists:
                raise ValueError(f"事件ID已存在：{event_id}")
            self._upsert(connection, event_id, payload, preserve_dates=False)
        return self.get(event_id)

    def update(self, event_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self.database.connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM security_event_library WHERE event_id = ?", (event_id,)).fetchone()
            if not exists:
                raise KeyError(event_id)
            self._upsert(connection, event_id, payload, preserve_dates=True)
        return self.get(event_id)

    def delete(self, event_id: str) -> None:
        with self.database.connect() as connection:
            cursor = connection.execute(
                "DELETE FROM security_event_library WHERE event_id = ?", (event_id,))
            if cursor.rowcount == 0:
                raise KeyError(event_id)

    def import_excel(self, source: Any) -> dict[str, int]:
        import pandas as pd

        frame = pd.read_excel(source, sheet_name="事件库", dtype=str)
        imported = 0
        with self.database.connect() as connection:
            for _, row in frame.iterrows():
                event_id = str(row.get("事件ID") or "").strip()
                if not event_id or event_id.lower() == "nan":
                    continue
                self._upsert(connection, event_id, {
                    "event_date": row.get("时间"),
                    "name": row.get("事件名称"),
                    "event_types": _split_values(row.get("事件类型")),
                    "summary": row.get("事件概要") if str(row.get("事件概要")) != "nan" else "",
                    "source": row.get("来源") if str(row.get("来源")) != "nan" else "",
                    "sample_text": row.get("可分析样本哈希"),
                    "first_seen_at": _date_text(row.get("首次入库时间")),
                    "updated_at": _date_text(row.get("最近更新时间")),
                    "status": row.get("状态") if str(row.get("状态")) != "nan" else "新增",
                }, preserve_dates=True)
                imported += 1
        return {"imported": imported}

    def import_xlsx(self, path: Path) -> dict[str, int]:
        return self.import_excel(path)

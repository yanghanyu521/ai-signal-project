from __future__ import annotations

import copy
import json
import re
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from .database import Database, json_text, utc_now


def _first(*values: Any) -> Any:
    return next((value for value in values if value not in (None, "", [], {})), None)


def _date_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        candidate = _first(
            value.get("value"), value.get("date"), value.get("start"),
            value.get("first_seen"), value.get("published"),
        )
        return _date_text(candidate)
    return str(value) if value is not None else None


def _event_date(event: dict[str, Any], fallback: str | None = None) -> str | None:
    time = event.get("time") or {}
    if "precision" in time:
        # Structured report time must not fall back to publication date or a
        # fabricated January/day placeholder. Legacy undated formats stay compatible.
        value = _date_text(time.get("start"))
        precision = time["precision"]
        if not value or precision in {"unknown", "quarter", "range"}:
            return None
        if precision == "year":
            return value[:4] if re.fullmatch(r"\d{4}(?:-\d{2})?(?:-\d{2})?", value) else None
        if precision == "month":
            return value[:7] if re.fullmatch(r"\d{4}-\d{2}(?:-\d{2})?", value) else None
        return value if precision == "day" and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) else None
    return _date_text(_first(time.get("start"), time.get("date"), time.get("first_seen"), fallback))


def _event_name(event: dict[str, Any]) -> str:
    identity = event.get("identity") or {}
    return _first(identity.get("event_name"), identity.get("name"), event.get("name"), "未命名事件")


def _logical_report_key(title: str | None, content_sha256: str | None) -> str:
    normalized_title = "".join(character.lower() for character in str(title or "") if character.isalnum())
    return f"title:{normalized_title}" if normalized_title else f"sha256:{content_sha256 or ''}"


def _unique_text(values: list[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        key = text.casefold()
        if text and key not in seen:
            seen.add(key)
            result.append(text)
    return result


def _event_extracted_context(event: dict[str, Any]) -> dict[str, list[str]]:
    attribution = event.get("attribution") or {}
    actors = attribution.get("actors") or []
    targets = event.get("targets") or []
    return {
        "organizations": _unique_text([
            *(item.get("name") for item in actors if isinstance(item, dict)),
            *(item.get("name") for item in targets if isinstance(item, dict)),
        ]),
        "countries_or_regions": _unique_text([
            *(item.get("country_or_region") for item in actors if isinstance(item, dict)),
            *(item.get("country_or_region") for item in targets if isinstance(item, dict)),
        ]),
    }


def _sample_key_features(result: dict[str, Any]) -> dict[str, Any]:
    features = result.get("features") or {}
    prompts = (features.get("prompt") or {}).get("embedded_prompts") or []
    attribution = (result.get("classification") or {}).get("model_attribution") or {}
    tool_evidence = (features.get("toolchain") or {}).get("evidence") or []
    normalized_evidence = [item.get("normalized") or {} for item in tool_evidence]

    def attributed(name: str) -> Any:
        return _first(attribution.get(name), *(item.get(name) for item in normalized_evidence))

    return {
        "toolchain": {
            "vendor": attributed("vendor"),
            "family": attributed("family"),
            "model": attributed("model"),
            "evidence": tool_evidence,
        },
        "prompts": [
            {
                "text": item.get("text") or item.get("text_preview"),
                "source": item.get("source"),
                "evidence_level": item.get("evidence_level"),
                "features": [
                    key for key, enabled in (item.get("features") or {}).items() if enabled is True
                ] if isinstance(item.get("features"), dict) else item.get("features") or [],
                "target": item.get("target"),
            }
            for item in prompts
        ],
        "code_style": {
            "language": (features.get("code_style") or {}).get("language"),
            "recoverability": (features.get("code_style") or {}).get("recoverability"),
            "metrics": (features.get("code_style") or {}).get("metrics") or {},
        },
    }


class Repository:
    def __init__(self, database: Database):
        self.db = database

    def upsert_sample(
        self,
        result: dict[str, Any],
        *,
        original_name: str | None = None,
        source_case: str | None = None,
        artifact_path: str | None = None,
    ) -> dict[str, Any]:
        sample = result.get("sample") or {}
        attribution = result.get("classification", {}).get("model_attribution", {})
        involvement = result.get("classification", {}).get("llm_involvement", {})
        sha256 = str(sample.get("sha256") or "").lower()
        if len(sha256) != 64:
            raise ValueError("样本结果缺少有效 SHA-256")
        now = utc_now()
        status = "completed_with_errors" if result.get("errors") else "analyzed"
        values = (
            sha256,
            sha256,
            original_name,
            sample.get("size"),
            sample.get("file_type"),
            sample.get("language"),
            sample.get("recoverability"),
            involvement.get("label"),
            attribution.get("vendor"),
            attribution.get("family"),
            attribution.get("model"),
            attribution.get("confidence"),
            source_case,
            status,
            artifact_path,
            json_text(result),
            now,
            now,
        )
        with self.db.connect() as connection:
            connection.execute(
                """
                INSERT INTO samples(
                    id, sha256, original_name, size_bytes, file_type, language, recoverability,
                    llm_label, model_vendor, model_family, model_name, confidence, source_case,
                    status, artifact_path, result_json, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(sha256) DO UPDATE SET
                    original_name=COALESCE(excluded.original_name, samples.original_name),
                    size_bytes=excluded.size_bytes, file_type=excluded.file_type,
                    language=excluded.language, recoverability=excluded.recoverability,
                    llm_label=excluded.llm_label, model_vendor=excluded.model_vendor,
                    model_family=excluded.model_family, model_name=excluded.model_name,
                    confidence=excluded.confidence,
                    source_case=COALESCE(excluded.source_case, samples.source_case),
                    status=excluded.status, artifact_path=COALESCE(excluded.artifact_path, samples.artifact_path),
                    result_json=excluded.result_json, updated_at=excluded.updated_at
                """,
                values,
            )
            connection.execute(
                "UPDATE event_sample_links SET sample_id=? WHERE sample_sha256=? AND sample_id IS NULL",
                (sha256, sha256),
            )
        return self.get_sample(sha256)

    def get_sample(self, sha256: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM samples WHERE sha256=?", (sha256.lower(),)).fetchone()
            sample = self.db.row(row, ("result_json",))
            if not sample:
                return None
            links = connection.execute(
                """
                SELECT l.method, l.confidence, l.propagation_allowed,
                       e.id AS event_id, e.name, e.event_date, e.source_url
                FROM event_sample_links l JOIN events e ON e.id=l.event_id
                WHERE l.sample_sha256=? ORDER BY e.event_date DESC, e.name
                """,
                (sha256.lower(),),
            ).fetchall()
            validations = connection.execute(
                """
                SELECT id, report_id, event_id, supports, contradicts, complements,
                       inconclusive, created_at FROM cross_validations
                WHERE sample_id=? ORDER BY created_at DESC
                """,
                (sha256.lower(),),
            ).fetchall()
            sample["linked_events"] = self.db.rows(links)
            sample["cross_validations"] = self.db.rows(validations)
            return sample

    def list_samples(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.db.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, sha256, original_name, size_bytes, file_type, language, llm_label,
                       model_vendor, model_family, model_name, confidence, source_case,
                       status, created_at, updated_at
                FROM samples ORDER BY updated_at DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return self.db.rows(rows)

    def upsert_report(
        self,
        result: dict[str, Any],
        *,
        original_name: str | None,
        artifact_path: str | None,
        source_kind: str = "extracted_report",
    ) -> dict[str, Any]:
        stored_result = copy.deepcopy(result)
        report = stored_result.get("report") or {}
        incoming_report_id = str(report.get("report_id") or "")
        if not incoming_report_id:
            raise ValueError("报告结果缺少 report_id")
        logical_key = _logical_report_key(report.get("title"), report.get("content_sha256"))
        with self.db.connect() as connection:
            existing_rows = connection.execute(
                "SELECT report_id,title,content_sha256 FROM reports ORDER BY created_at"
            ).fetchall()
        exact = next(
            (
                row for row in existing_rows
                if report.get("content_sha256") and row["content_sha256"] == report.get("content_sha256")
            ),
            None,
        )
        logical = next(
            (
                row for row in existing_rows
                if _logical_report_key(row["title"], row["content_sha256"]) == logical_key
            ),
            None,
        )
        selected_existing = exact or logical
        report_id = str(selected_existing["report_id"] if selected_existing else incoming_report_id)
        report["report_id"] = report_id
        now = utc_now()
        status = stored_result.get("extraction", {}).get("validation_status") or "unknown"
        values = (
            report_id, report_id, original_name, report.get("url"), report.get("title"),
            report.get("publisher"), _date_text(report.get("publication_date")), report.get("content_type"),
            report.get("content_sha256"), status, artifact_path, json_text(stored_result), now, now,
        )
        with self.db.connect() as connection:
            connection.execute(
                """
                INSERT INTO reports(id, report_id, original_name, canonical_url, title, publisher,
                    publication_date, content_type, content_sha256, status, artifact_path,
                    result_json, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(report_id) DO UPDATE SET
                    original_name=COALESCE(excluded.original_name, reports.original_name),
                    canonical_url=COALESCE(excluded.canonical_url, reports.canonical_url),
                    title=excluded.title, publisher=excluded.publisher,
                    publication_date=excluded.publication_date, content_type=excluded.content_type,
                    content_sha256=excluded.content_sha256, status=excluded.status,
                    artifact_path=COALESCE(excluded.artifact_path, reports.artifact_path),
                    result_json=excluded.result_json, updated_at=excluded.updated_at
                """,
                values,
            )
        for event in stored_result.get("events") or []:
            self.upsert_report_event(report_id, event, report, source_kind=source_kind)
        return self.get_report(report_id)

    def upsert_report_event(
        self,
        report_id: str,
        event: dict[str, Any],
        report_meta: dict[str, Any],
        *,
        source_kind: str,
    ) -> str:
        external_id = str(event.get("event_id") or uuid.uuid4().hex)
        event_id = external_id
        identity = event.get("identity") or {}
        attribution = event.get("attribution") or {}
        actors = [item.get("name") for item in attribution.get("actors", []) if item.get("name")]
        ai = event.get("ai_involvement") or {}
        status = event.get("status") or {}
        now = utc_now()
        with self.db.connect() as connection:
            connection.execute(
                """
                INSERT INTO events(id, report_db_id, external_event_id, name, event_type,
                    event_date, status, summary, actor_region, ai_summary, model_service,
                    source_name, source_url, source_kind, raw_json, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    report_db_id=excluded.report_db_id, name=excluded.name,
                    event_type=excluded.event_type, event_date=excluded.event_date,
                    status=excluded.status, summary=excluded.summary,
                    actor_region=excluded.actor_region, ai_summary=excluded.ai_summary,
                    model_service=excluded.model_service, source_name=excluded.source_name,
                    source_url=excluded.source_url, raw_json=excluded.raw_json,
                    updated_at=excluded.updated_at
                """,
                (
                    event_id, report_id, external_id, _event_name(event), identity.get("event_type"),
                    _event_date(event, report_meta.get("publication_date")),
                    _first(status.get("operational_status"), status.get("value")),
                    identity.get("summary"), "; ".join(actors) or None,
                    _first(ai.get("summary"), ai.get("role"), ai.get("mode")), None,
                    report_meta.get("publisher"), report_meta.get("url"), source_kind,
                    json_text(event), now, now,
                ),
            )
        for artifact in event.get("artifacts") or []:
            for sha256 in artifact.get("sha256") or []:
                self.upsert_event_sample_link(event_id, sha256, "sha256_exact", 1.0, True)
        return event_id

    def upsert_research_event(self, record: dict[str, str]) -> str:
        external_id = record["event_id"]
        event_id = f"research:{external_id}"
        now = utc_now()
        with self.db.connect() as connection:
            connection.execute(
                """
                INSERT INTO events(id, report_db_id, external_event_id, name, event_type,
                    event_date, status, summary, actor_region, ai_summary, model_service,
                    source_name, source_url, source_kind, raw_json, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, event_type=excluded.event_type,
                    event_date=excluded.event_date, actor_region=excluded.actor_region,
                    ai_summary=excluded.ai_summary, model_service=excluded.model_service,
                    source_name=excluded.source_name, source_url=excluded.source_url,
                    raw_json=excluded.raw_json, updated_at=excluded.updated_at
                """,
                (
                    event_id, None, external_id, record.get("event_name") or external_id,
                    record.get("event_type"), record.get("report_date"), record.get("sample_status"),
                    record.get("evidence_note"), record.get("actor_or_region"),
                    record.get("ai_use_summary"), record.get("reported_model_or_service"),
                    record.get("source_name"), record.get("source_url"), "research_csv",
                    json_text(record), now, now,
                ),
            )
        for sha256 in (record.get("sample_sha256_list") or "").split(";"):
            sha256 = sha256.strip().lower()
            if len(sha256) == 64:
                self.upsert_event_sample_link(event_id, sha256, "research_report_hash", 0.95, True)
        return event_id

    def upsert_event_sample_link(
        self, event_id: str, sha256: str, method: str, confidence: float, propagation_allowed: bool
    ) -> None:
        sha256 = sha256.lower()
        with self.db.connect() as connection:
            sample = connection.execute("SELECT id FROM samples WHERE sha256=?", (sha256,)).fetchone()
            connection.execute(
                """
                INSERT INTO event_sample_links(id, event_id, sample_id, sample_sha256, method,
                    confidence, propagation_allowed, created_at)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(event_id, sample_sha256, method) DO UPDATE SET
                    sample_id=COALESCE(excluded.sample_id, event_sample_links.sample_id),
                    confidence=excluded.confidence,
                    propagation_allowed=excluded.propagation_allowed
                """,
                (
                    uuid.uuid4().hex, event_id, sample["id"] if sample else None, sha256,
                    method, confidence, int(propagation_allowed), utc_now(),
                ),
            )

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM reports WHERE report_id=?", (report_id,)).fetchone()
            report = self.db.row(row, ("result_json",))
            if not report:
                return None
            events = connection.execute(
                "SELECT id, external_event_id, name, event_type, event_date, status, summary, actor_region, ai_summary, model_service, source_url FROM events WHERE report_db_id=? ORDER BY event_date DESC, name",
                (report_id,),
            ).fetchall()
            report["events"] = self.db.rows(events)
            return report

    def list_reports(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.db.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, report_id, original_name, canonical_url, title, publisher,
                       publication_date, content_type, content_sha256, status, created_at, updated_at
                FROM reports ORDER BY updated_at DESC
                """
            ).fetchall()
        logical: dict[str, dict[str, Any]] = {}
        for item in self.db.rows(rows):
            key = _logical_report_key(item.get("title"), item.get("content_sha256"))
            if key in logical:
                logical[key]["duplicate_record_count"] += 1
                continue
            item["duplicate_record_count"] = 1
            logical[key] = item
        return list(logical.values())[offset:offset + limit]

    def report_result_for_comparison(self, report_id: str) -> dict[str, Any]:
        report = self.get_report(report_id)
        if not report:
            raise KeyError("报告不存在")
        result = copy.deepcopy(report["result_json"])
        with self.db.connect() as connection:
            report_rows = connection.execute(
                "SELECT report_id,title,content_sha256 FROM reports"
            ).fetchall()
            selected_key = _logical_report_key(report.get("title"), report.get("content_sha256"))
            logical_ids = [
                row["report_id"]
                for row in report_rows
                if _logical_report_key(row["title"], row["content_sha256"]) == selected_key
            ]
            placeholders = ",".join("?" for _ in logical_ids)
            rows = connection.execute(
                f"SELECT raw_json FROM events WHERE report_db_id IN ({placeholders}) ORDER BY event_date DESC,name",
                logical_ids,
            ).fetchall()
        stored_events_by_name: dict[str, dict[str, Any]] = {}
        for row in rows:
            event = json.loads(row["raw_json"])
            event_name = _event_name(event)
            key = "".join(character.lower() for character in event_name if character.isalnum())
            stored_events_by_name.setdefault(key or str(event.get("event_id")), event)
        stored_events = list(stored_events_by_name.values())
        if stored_events:
            result["events"] = stored_events
        result.setdefault("report", {})["report_id"] = report_id
        return result

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM events WHERE id=? OR external_event_id=?", (event_id, event_id)).fetchone()
        return self.db.row(row, ("raw_json",))

    def get_event_context(
        self, event_id: str | None, fallback_event: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        event_row = self.get_event(event_id) if event_id else None
        event = (event_row or {}).get("raw_json") or fallback_event or {}
        extracted = _event_extracted_context(event)
        override = None
        resolved_id = (event_row or {}).get("id")
        if resolved_id:
            with self.db.connect() as connection:
                row = connection.execute(
                    "SELECT * FROM event_context_overrides WHERE event_id=?", (resolved_id,)
                ).fetchone()
            override = self.db.row(
                row, ("organizations_json", "countries_or_regions_json")
            )
        manual = None
        if override:
            manual = {
                "organizations": override.pop("organizations_json"),
                "countries_or_regions": override.pop("countries_or_regions_json"),
                **override,
            }
        effective = {
            key: (manual[key] if manual is not None else extracted[key])
            for key in ("organizations", "countries_or_regions")
        }
        return {
            "event_id": resolved_id or event_id,
            "extracted": extracted,
            "manual_override": manual,
            "effective": effective,
            "source": "manual_override" if manual is not None else "report_extraction",
            "updated_at": manual.get("updated_at") if manual else None,
            "editable": bool(resolved_id),
        }

    @staticmethod
    def _clean_context_values(values: list[str]) -> list[str]:
        if len(values) > 50:
            raise ValueError("单个字段最多保存 50 项")
        cleaned: list[str] = []
        for value in values:
            text = str(value).strip()
            if len(text) > 200:
                raise ValueError("组织或国家/地区名称不能超过 200 个字符")
            if any(ord(character) < 32 and character not in "\t\n\r" for character in text):
                raise ValueError("组织或国家/地区名称包含非法控制字符")
            if text:
                cleaned.append(text)
        return _unique_text(cleaned)

    def save_event_context_override(
        self,
        event_id: str,
        *,
        organizations: list[str],
        countries_or_regions: list[str],
    ) -> dict[str, Any]:
        event = self.get_event(event_id)
        if not event:
            raise KeyError("事件不存在")
        organizations = self._clean_context_values(organizations)
        countries_or_regions = self._clean_context_values(countries_or_regions)
        now = utc_now()
        with self.db.connect() as connection:
            connection.execute(
                """
                INSERT INTO event_context_overrides(
                    event_id,organizations_json,countries_or_regions_json,source,created_at,updated_at
                ) VALUES(?,?,?,?,?,?)
                ON CONFLICT(event_id) DO UPDATE SET
                    organizations_json=excluded.organizations_json,
                    countries_or_regions_json=excluded.countries_or_regions_json,
                    source=excluded.source,
                    updated_at=excluded.updated_at
                """,
                (
                    event["id"], json_text(organizations), json_text(countries_or_regions),
                    "manual_ui", now, now,
                ),
            )
        return self.get_event_context(event["id"])

    def save_cross_validation(
        self, sample_id: str, report_id: str, event_id: str | None, result: dict[str, Any]
    ) -> dict[str, Any]:
        summary = result.get("summary") or {}
        now = utc_now()
        with self.db.connect() as connection:
            existing = connection.execute(
                """
                SELECT id FROM cross_validations
                WHERE sample_id=? AND report_id=? AND COALESCE(event_id,'')=COALESCE(?,'')
                ORDER BY COALESCE(updated_at,created_at) DESC LIMIT 1
                """,
                (sample_id, report_id, event_id),
            ).fetchone()
            validation_id = existing["id"] if existing else uuid.uuid4().hex
            values = (
                int(summary.get("supports", 0)), int(summary.get("contradicts", 0)),
                int(summary.get("complements", 0)), int(summary.get("inconclusive", 0)),
                json_text(result), now,
            )
            if existing:
                connection.execute(
                    """
                    UPDATE cross_validations SET supports=?,contradicts=?,complements=?,
                        inconclusive=?,result_json=?,updated_at=? WHERE id=?
                    """,
                    (*values, validation_id),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO cross_validations(id,sample_id,report_id,event_id,supports,
                        contradicts,complements,inconclusive,result_json,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (validation_id, sample_id, report_id, event_id, *values[:-1], now, now),
                )
        return {"id": validation_id, **result}

    def create_or_update_case(
        self,
        *,
        case_id: str | None,
        title: str | None,
        notes: str | None,
        status: str,
    ) -> dict[str, Any]:
        now = utc_now()
        if case_id:
            with self.db.connect() as connection:
                exists = connection.execute("SELECT id FROM analysis_cases WHERE id=?", (case_id,)).fetchone()
                if not exists:
                    raise KeyError("分析案例不存在")
                connection.execute(
                    "UPDATE analysis_cases SET title=COALESCE(?,title), notes=COALESCE(?,notes), status=?, updated_at=? WHERE id=?",
                    (title, notes, status, now, case_id),
                )
        else:
            case_id = uuid.uuid4().hex
            with self.db.connect() as connection:
                connection.execute(
                    "INSERT INTO analysis_cases(id,title,status,notes,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                    (case_id, title or f"分析案例 {case_id[:8]}", status, notes, now, now),
                )
        return self.get_case(case_id)

    def attach_case_sample(self, case_id: str, sample_id: str, method: str) -> None:
        with self.db.connect() as connection:
            connection.execute(
                "INSERT INTO case_samples(case_id,sample_id,relation_method,created_at) VALUES(?,?,?,?) ON CONFLICT(case_id,sample_id) DO UPDATE SET relation_method=excluded.relation_method",
                (case_id, sample_id.lower(), method, utc_now()),
            )

    def attach_case_report(self, case_id: str, report_id: str, method: str) -> None:
        with self.db.connect() as connection:
            connection.execute(
                "INSERT INTO case_reports(case_id,report_id,relation_method,created_at) VALUES(?,?,?,?) ON CONFLICT(case_id,report_id) DO UPDATE SET relation_method=excluded.relation_method",
                (case_id, report_id, method, utc_now()),
            )

    def update_case_status(self, case_id: str, status: str) -> None:
        with self.db.connect() as connection:
            connection.execute(
                "UPDATE analysis_cases SET status=?, updated_at=? WHERE id=?",
                (status, utc_now(), case_id),
            )

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM analysis_cases WHERE id=?", (case_id,)).fetchone()
            case = self.db.row(row)
            if not case:
                return None
            samples = connection.execute(
                """
                SELECT s.sha256, s.original_name, s.source_case, s.llm_label, s.model_name,
                       cs.relation_method, cs.created_at
                FROM case_samples cs JOIN samples s ON s.id=cs.sample_id
                WHERE cs.case_id=? ORDER BY cs.created_at
                """,
                (case_id,),
            ).fetchall()
            reports = connection.execute(
                """
                SELECT r.report_id, r.title, r.publisher, r.publication_date,
                       cr.relation_method, cr.created_at
                FROM case_reports cr JOIN reports r ON r.id=cr.report_id
                WHERE cr.case_id=? ORDER BY cr.created_at
                """,
                (case_id,),
            ).fetchall()
        case["samples"] = self.db.rows(samples)
        case["reports"] = self.db.rows(reports)
        return case

    def list_cases(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.db.connect() as connection:
            rows = connection.execute(
                """
                SELECT c.*,
                       (SELECT COUNT(*) FROM case_samples cs WHERE cs.case_id=c.id) AS sample_count,
                       (SELECT COUNT(*) FROM case_reports cr WHERE cr.case_id=c.id) AS report_count
                FROM analysis_cases c ORDER BY c.updated_at DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return self.db.rows(rows)

    def all_sample_results(self) -> list[dict[str, Any]]:
        with self.db.connect() as connection:
            rows = connection.execute(
                "SELECT sha256, result_json FROM samples ORDER BY sha256"
            ).fetchall()
        return self.db.rows(rows, ("result_json",))

    def replace_sample_similarity(
        self,
        *,
        algorithm_version: str,
        distance_threshold: float,
        clusters: list[dict[str, Any]],
        relations: list[dict[str, Any]],
        details: dict[str, Any] | None = None,
        expected_samples: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        run_id = uuid.uuid4().hex
        created_at = utc_now()
        cluster_count = len({item["cluster_label"] for item in clusters})
        with self.db.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if expected_samples is not None:
                current = self.db.rows(connection.execute("SELECT sha256,result_json FROM samples ORDER BY sha256").fetchall(), ("result_json",))
                if current != expected_samples:
                    raise RuntimeError("样本结果在计算期间发生变化，请重试重建")
            connection.execute("DELETE FROM sample_cluster_runs")
            connection.execute(
                "INSERT INTO sample_cluster_runs(id,algorithm_version,sample_count,cluster_count,distance_threshold,created_at,details_json) VALUES(?,?,?,?,?,?,?)",
                (run_id, algorithm_version, len(clusters), cluster_count, distance_threshold, created_at, json_text(details or {})),
            )
            connection.executemany(
                "INSERT INTO sample_clusters(sample_id,run_id,cluster_label,cluster_size,updated_at,details_json) VALUES(?,?,?,?,?,?)",
                [
                    (item["sample_id"], run_id, item["cluster_label"], item["cluster_size"], created_at, json_text(item.get("details") or {}))
                    for item in clusters
                ],
            )
            connection.executemany(
                """
                INSERT INTO sample_relations(id,run_id,source_sample_id,target_sample_id,
                    overall_similarity,toolchain_similarity,prompt_similarity,code_style_similarity,
                    same_cluster,common_features_json,created_at,details_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        uuid.uuid4().hex, run_id, item["source_sample_id"], item["target_sample_id"],
                        item["overall_similarity"] or 0.0, item["toolchain_similarity"] or 0.0, item["prompt_similarity"] or 0.0,
                        item["code_style_similarity"] or 0.0, int(item["same_cluster"]),
                        json_text(item["common_features"]), created_at, json_text(item.get("details") or {}),
                    )
                    for item in relations
                ],
            )
        return {
            "run_id": run_id,
            "algorithm_version": algorithm_version,
            "sample_count": len(clusters),
            "cluster_count": cluster_count,
            "distance_threshold": distance_threshold,
            "created_at": created_at,
            "details": details or {},
        }

    def sample_associations(self, sha256: str, limit: int = 10, *, include_unmatched: bool = False) -> dict[str, Any]:
        sha256 = sha256.lower()
        with self.db.connect() as connection:
            sample = connection.execute(
                "SELECT id,result_json FROM samples WHERE sha256=?", (sha256,)
            ).fetchone()
            if not sample:
                raise KeyError("样本不存在")
            cluster = connection.execute(
                "SELECT cluster_label,cluster_size,run_id,updated_at,details_json FROM sample_clusters WHERE sample_id=?",
                (sha256,),
            ).fetchone()
            run = connection.execute("SELECT * FROM sample_cluster_runs WHERE id=?", (cluster["run_id"],)).fetchone() if cluster else None
            rows = connection.execute(
                """
                SELECT CASE WHEN sr.source_sample_id=? THEN sr.target_sample_id ELSE sr.source_sample_id END AS related_sha256,
                       s.source_case, s.llm_label, s.model_name, s.result_json,
                       sr.overall_similarity, sr.toolchain_similarity, sr.prompt_similarity,
                       sr.code_style_similarity, sr.same_cluster, sr.common_features_json, sr.details_json,
                       sr.source_sample_id, sr.target_sample_id
                FROM sample_relations sr
                JOIN samples s ON s.id=CASE WHEN sr.source_sample_id=? THEN sr.target_sample_id ELSE sr.source_sample_id END
                WHERE (sr.source_sample_id=? OR sr.target_sample_id=?)
                ORDER BY sr.overall_similarity DESC, related_sha256
                """,
                (sha256, sha256, sha256, sha256),
            ).fetchall()
        relations = self.db.rows(rows, ("common_features_json", "details_json", "result_json"))
        for item in relations:
            item["key_features"] = _sample_key_features(item.pop("result_json") or {})
            item["common_features"] = item.pop("common_features_json")
            item["same_cluster"] = bool(item["same_cluster"])
            item["comparison"] = comparison = item.pop("details_json") or {}
            if comparison:
                for group, detail in comparison["groups"].items():
                    item[group + "_similarity"] = detail["score"]
                if comparison["status"] == "not_comparable":
                    item["overall_similarity"] = None
                item["comparable_weight"] = comparison["comparable_weight"]
            else:
                item["comparable_weight"] = None
        cluster_result = self.db.row(cluster, ("details_json",))
        diagnostic = cluster_result.pop("details_json") if cluster_result else {}
        run_result = self.db.row(run, ("details_json",))
        if run_result:
            run_result["details"] = run_result.pop("details_json")
        positives = [r for r in relations if (r["overall_similarity"] or 0.0) > 0.000001]
        comparable_count = sum(r["comparison"].get("status") == "comparable" for r in relations)
        if not cluster_result:
            status, message = "not_clustered", "该样本尚未生成关联结果，请重建聚类。"
        elif not diagnostic:
            status, message = "legacy_results", "当前是旧算法结果，缺少可比性诊断，请重建聚类。"
        elif diagnostic.get("status") == "no_features":
            status, message = "no_features", "该样本没有可用于当前比较的工具链、Prompt或合格源码统计证据；不是聚类距离阈值造成的。"
        elif not relations:
            status, message = "no_other_samples", "知识库中没有其他样本可比较。"
        elif positives:
            status, message = "available", "已返回正分候选；候选列表不按聚类距离阈值筛选，同簇与否单独显示。"
        elif not comparable_count:
            status, message = "no_comparable_evidence", "与其他样本没有可比较的证据组，不能解释为已证实不相似。"
        else:
            status, message = "no_positive_matches", "已比较可用证据，但没有正分匹配；不是聚类距离阈值筛选的结果。"
        return {
            "sample_sha256": sha256,
            "source_key_features": _sample_key_features(json.loads(sample["result_json"])),
            "cluster": cluster_result,
            "run": run_result,
            "feature_availability": diagnostic,
            "association_status": status,
            "message": message,
            "association_summary": {"evaluated_pairs": len(relations), "comparable_pairs": comparable_count,
                                    "positive_pairs": len(positives), "include_unmatched": include_unmatched},
            "related_samples": (relations if include_unmatched else positives)[:limit],
            "interpretation": "总分按固定权重合成，缺失组不重分配权重；null表示不可比较，0表示可比但无匹配；非同源、同模型或AI生成概率。",
        }

    def search(self, query: str, limit: int = 50) -> dict[str, Any]:
        """Search knowledge as connected sample/report subjects, not independent tables."""
        query = query.strip()
        pattern = f"%{query}%"
        with self.db.connect() as connection:
            direct_samples = self.db.rows(connection.execute(
                """
                SELECT sha256,original_name,source_case,llm_label,model_vendor,
                       model_family,model_name,status,updated_at
                FROM samples WHERE sha256 LIKE ? OR original_name LIKE ? OR source_case LIKE ?
                    OR model_vendor LIKE ? OR model_family LIKE ? OR model_name LIKE ?
                ORDER BY updated_at DESC LIMIT ?
                """,
                (*([pattern] * 6), limit),
            ).fetchall())
            direct_reports = self.db.rows(connection.execute(
                """
                SELECT report_id,title,publisher,publication_date,canonical_url,status
                FROM reports WHERE title LIKE ? OR publisher LIKE ? OR canonical_url LIKE ?
                ORDER BY publication_date DESC LIMIT ?
                """,
                (pattern, pattern, pattern, limit),
            ).fetchall())
            direct_events = self.db.rows(connection.execute(
                """
                SELECT id,report_db_id,external_event_id,name,event_type,event_date,
                       actor_region,ai_summary,model_service,source_name,source_url
                FROM events WHERE name LIKE ? OR actor_region LIKE ? OR ai_summary LIKE ?
                    OR model_service LIKE ? OR source_name LIKE ?
                ORDER BY event_date DESC,name LIMIT ?
                """,
                (*([pattern] * 5), limit),
            ).fetchall())

            seed_sample_ids = {item["sha256"] for item in direct_samples}
            direct_report_ids = {item["report_id"] for item in direct_reports}
            direct_event_ids = {item["id"] for item in direct_events}
            direct_event_names = {
                str(item.get("name") or "").casefold() for item in direct_events if item.get("name")
            }

            if direct_report_ids:
                report_ids = direct_report_ids
                placeholders = ",".join("?" for _ in report_ids)
                rows = connection.execute(
                    f"""
                    SELECT DISTINCT cs.sample_id FROM case_samples cs
                    JOIN case_reports cr ON cr.case_id=cs.case_id
                    WHERE cr.report_id IN ({placeholders})
                    """,
                    tuple(report_ids),
                ).fetchall()
                seed_sample_ids.update(row["sample_id"] for row in rows)
            if direct_event_ids:
                placeholders = ",".join("?" for _ in direct_event_ids)
                rows = connection.execute(
                    f"SELECT DISTINCT sample_id FROM event_sample_links WHERE event_id IN ({placeholders}) AND sample_id IS NOT NULL",
                    tuple(direct_event_ids),
                ).fetchall()
                seed_sample_ids.update(row["sample_id"] for row in rows)
            if direct_event_names:
                rows = connection.execute(
                    "SELECT sha256,source_case FROM samples WHERE source_case IS NOT NULL"
                ).fetchall()
                seed_sample_ids.update(
                    row["sha256"] for row in rows
                    if str(row["source_case"]).casefold() in direct_event_names
                )

            seed_rows: list[Any] = []
            if seed_sample_ids:
                placeholders = ",".join("?" for _ in seed_sample_ids)
                seed_rows = connection.execute(
                    f"SELECT sha256,source_case FROM samples WHERE sha256 IN ({placeholders})",
                    tuple(seed_sample_ids),
                ).fetchall()
            family_names = sorted({
                str(row["source_case"]).strip() for row in seed_rows if str(row["source_case"] or "").strip()
            }, key=str.casefold)
            ungrouped_sample_ids = [
                row["sha256"] for row in seed_rows if not str(row["source_case"] or "").strip()
            ]
            group_specs = [*( (family, None) for family in family_names), *(
                (None, sample_id) for sample_id in ungrouped_sample_ids
            )]

            groups: list[dict[str, Any]] = []
            included_report_keys: set[str] = set()
            included_event_ids: set[str] = set()
            included_sample_ids: set[str] = set()
            for family, ungrouped_sample_id in group_specs[:limit]:
                if family:
                    sample_query = "source_case=? COLLATE NOCASE"
                    sample_query_params = (family,)
                else:
                    sample_query = "sha256=?"
                    sample_query_params = (ungrouped_sample_id,)
                sample_rows = self.db.rows(connection.execute(
                    f"""
                    SELECT sha256,original_name,source_case,llm_label,model_vendor,
                           model_family,model_name,status,updated_at
                    FROM samples WHERE {sample_query} ORDER BY updated_at DESC
                    """,
                    sample_query_params,
                ).fetchall())
                sample_ids = [item["sha256"] for item in sample_rows]
                subject_label = family or sample_rows[0].get("original_name") or sample_ids[0][:12]
                included_sample_ids.update(sample_ids)
                placeholders = ",".join("?" for _ in sample_ids)
                case_links = self.db.rows(connection.execute(
                    f"""
                    SELECT DISTINCT r.report_id,r.title,r.publisher,r.publication_date,
                           r.canonical_url,r.status,ac.id AS case_id,ac.title AS case_title,
                           cr.relation_method
                    FROM case_samples cs
                    JOIN analysis_cases ac ON ac.id=cs.case_id
                    JOIN case_reports cr ON cr.case_id=ac.id
                    JOIN reports r ON r.id=cr.report_id
                    WHERE cs.sample_id IN ({placeholders})
                    ORDER BY r.publication_date DESC,r.title
                    """,
                    tuple(sample_ids),
                ).fetchall()) if sample_ids else []

                report_map: dict[str, dict[str, Any]] = {}
                for item in case_links:
                    logical_key = _logical_report_key(item.get("title"), None)
                    report = report_map.setdefault(logical_key, {
                        key: item.get(key) for key in (
                            "report_id", "title", "publisher", "publication_date",
                            "canonical_url", "status",
                        )
                    })
                    report.setdefault("_report_ids", set()).add(item["report_id"])
                    report.setdefault("relations", []).append({
                        "type": "analysis_case", "case_id": item["case_id"],
                        "case_title": item["case_title"], "method": item["relation_method"],
                    })

                event_report_rows = self.db.rows(connection.execute(
                    """
                    SELECT DISTINCT r.report_id,r.title,r.publisher,r.publication_date,
                           r.canonical_url,r.status
                    FROM events e JOIN reports r ON r.id=e.report_db_id
                    WHERE e.name=? COLLATE NOCASE
                    """,
                    (family,),
                ).fetchall()) if family else []
                for item in event_report_rows:
                    logical_key = _logical_report_key(item.get("title"), None)
                    report = report_map.setdefault(logical_key, dict(item))
                    report.setdefault("_report_ids", set()).add(item["report_id"])
                    report.setdefault("relations", []).append({"type": "target_event_name"})

                for logical_key, report in report_map.items():
                    all_report_ids = report.pop("_report_ids")
                    source_report_ids = [report["report_id"], *sorted(all_report_ids - {report["report_id"]})]
                    event_map: dict[str, dict[str, Any]] = {}
                    for report_id in source_report_ids:
                        event_rows = self.db.rows(connection.execute(
                            """
                            SELECT DISTINCT e.id AS event_id,e.name,e.event_type,e.event_date,
                                   e.actor_region,e.ai_summary,e.model_service,e.source_name,e.source_url,
                                   e.source_kind
                            FROM events e
                            LEFT JOIN event_sample_links l ON l.event_id=e.id
                            LEFT JOIN cross_validations v ON v.event_id=e.id
                            WHERE e.report_db_id=? AND (
                                e.name=? COLLATE NOCASE OR l.sample_id IN ({sample_placeholders})
                                OR (v.sample_id IN ({sample_placeholders}) AND v.report_id=?)
                            )
                            ORDER BY CASE WHEN e.source_kind='extracted_report' THEN 0 ELSE 1 END,
                                     e.updated_at DESC,e.event_date DESC,e.name
                            """.format(sample_placeholders=placeholders),
                            (report_id, family or "", *sample_ids, *sample_ids, report_id),
                        ).fetchall())
                        for item in event_rows:
                            event_key = "".join(
                                character.casefold() for character in str(item.get("name") or "")
                                if character.isalnum()
                            ) or item["event_id"]
                            event_map.setdefault(event_key, item)
                    report["target_events"] = list(event_map.values())
                    report["source_report_ids"] = source_report_ids
                    unique_relations: list[dict[str, Any]] = []
                    relation_keys: set[tuple[Any, ...]] = set()
                    for relation in report.get("relations") or []:
                        relation_key = (
                            relation.get("type"), relation.get("case_id"), relation.get("method")
                        )
                        if relation_key not in relation_keys:
                            relation_keys.add(relation_key)
                            unique_relations.append(relation)
                    report["relations"] = unique_relations
                    included_event_ids.update(event_map)
                    included_report_keys.add(logical_key)

                reasons: list[str] = []
                if any(item["sha256"] in {row["sha256"] for row in direct_samples} for item in sample_rows):
                    reasons.append("sample_match")
                if family and family.casefold() in direct_event_names:
                    reasons.append("event_name_match")
                if any(
                    report_id in direct_report_ids
                    for report in report_map.values()
                    for report_id in report.get("source_report_ids", [])
                ):
                    reasons.append("report_match")
                groups.append({
                    "subject": {
                        "family": family, "label": subject_label, "match_reasons": reasons,
                    },
                    "samples": sample_rows,
                    "reports": list(report_map.values()),
                })

        unlinked_reports = [
            item for item in direct_reports
            if _logical_report_key(item.get("title"), None) not in included_report_keys
        ]
        included_family_names = {
            str(item.get("subject", {}).get("family") or "").casefold() for item in groups
        }
        unlinked_events = [
            item for item in direct_events
            if item["id"] not in included_event_ids
            and str(item.get("name") or "").casefold() not in included_family_names
        ]
        return {
            "query": query,
            "summary": {
                "families": len(groups),
                "samples": len(included_sample_ids),
                "reports": len(included_report_keys),
                "events": len(included_event_ids),
            },
            "results": groups,
            "unlinked_direct_matches": {
                "reports": unlinked_reports,
                "events": unlinked_events,
            },
            "interpretation": "结果以样本/家族为中心，通过分析案例、报告目标事件和已验证关系展开对应报告；不是三张表的独立关键词命中。",
        }

    def statistics(self, date_from: str | None = None, date_to: str | None = None) -> dict[str, Any]:
        now = datetime.now(UTC)
        current_month = now.strftime("%Y-%m")
        previous_month = f"{now.year - (1 if now.month == 1 else 0):04d}-{12 if now.month == 1 else now.month - 1:02d}"

        def conditions(column: str, base: list[str] | None = None) -> tuple[str, list[str]]:
            items = list(base or [])
            params: list[str] = []
            if date_from:
                items.append(f"date({column})>=date(?)")
                params.append(date_from)
            if date_to:
                items.append(f"date({column})<=date(?)")
                params.append(date_to)
            return (" WHERE " + " AND ".join(items) if items else "", params)

        with self.db.connect() as connection:
            all_curated = connection.execute("SELECT COUNT(*) FROM events WHERE source_kind='research_csv'").fetchone()[0]
            curated_base = ["source_kind='research_csv'"] if all_curated else []
            event_where, event_params = conditions("event_date", curated_base)
            record_where, record_params = conditions("event_date")
            sample_where, sample_params = conditions("created_at")
            report_where, report_params = conditions("created_at")
            validation_where, validation_params = conditions("created_at")
            case_where, case_params = conditions("created_at")
            curated_events = connection.execute(f"SELECT COUNT(*) FROM events{event_where}", event_params).fetchone()[0]
            event_records = connection.execute(f"SELECT COUNT(*) FROM events{record_where}", record_params).fetchone()[0]
            report_event_base = ["source_kind!='research_csv'"]
            report_event_where, report_event_params = conditions("event_date", report_event_base)
            report_rows = connection.execute(
                f"SELECT title,content_sha256 FROM reports{report_where}", report_params
            ).fetchall()
            metric_rows = connection.execute(
                "SELECT metric_key,metric_value FROM knowledge_metrics"
            ).fetchall()
            business_metrics = {row["metric_key"]: int(row["metric_value"]) for row in metric_rows}
            global_events = business_metrics.get("global_ai_security_events", 25)
            analyzable_events = business_metrics.get("analyzable_events", 9)
            if analyzable_events > global_events:
                raise ValueError("知识范围指标异常：可分析事件数不能超过全球事件总数")
            validation_rows = connection.execute(
                f"""
                SELECT sample_id,report_id,COALESCE(event_id,'') AS event_key,
                       supports,contradicts,complements,inconclusive,created_at,
                       COALESCE(updated_at,created_at) AS effective_at
                FROM cross_validations{validation_where}
                ORDER BY effective_at,created_at
                """,
                validation_params,
            ).fetchall()
            latest_validations: dict[tuple[str, str, str], Any] = {}
            for row in validation_rows:
                latest_validations[(row["sample_id"], row["report_id"], row["event_key"])] = row
            logical_report_count = len({
                _logical_report_key(row["title"], row["content_sha256"])
                for row in report_rows
            })
            totals = {
                "events": curated_events,
                "global_ai_security_events": global_events,
                "analyzable_events": analyzable_events,
                "events_without_samples": global_events - analyzable_events,
                "curated_research_events": curated_events,
                "event_records": event_records,
                "report_event_records": connection.execute(
                    f"SELECT COUNT(*) FROM events{report_event_where}", report_event_params
                ).fetchone()[0],
                "samples": connection.execute(f"SELECT COUNT(*) FROM samples{sample_where}", sample_params).fetchone()[0],
                "reports": logical_report_count,
                "logical_reports": logical_report_count,
                "report_records": len(report_rows),
                "sample_families": connection.execute(
                    f"SELECT COUNT(DISTINCT source_case) FROM samples{sample_where}{' AND ' if sample_where else ' WHERE '}source_case IS NOT NULL AND trim(source_case)!=''",
                    sample_params,
                ).fetchone()[0],
                "family_report_mappings": connection.execute(
                    f"SELECT COUNT(*) FROM analysis_cases{case_where}{' AND ' if case_where else ' WHERE '}notes='legacy_family_report_mapping'",
                    case_params,
                ).fetchone()[0],
                "cross_validation_records": len(validation_rows),
                "analysis_cases": connection.execute(f"SELECT COUNT(*) FROM analysis_cases{case_where}", case_params).fetchone()[0],
            }
            event_monthly_rows = connection.execute(
                f"""
                SELECT substr(event_date,1,7) AS month, COUNT(*) AS count
                FROM events{event_where}{" AND " if event_where else " WHERE "}event_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]*'
                GROUP BY substr(event_date,1,7) ORDER BY month
                """, event_params
            ).fetchall()
            knowledge_where, knowledge_params = conditions("created_at", curated_base)
            knowledge_monthly_rows = connection.execute(
                f"""
                SELECT substr(created_at,1,7) AS month, COUNT(*) AS count
                FROM events{knowledge_where}
                GROUP BY substr(created_at,1,7) ORDER BY month
                """, knowledge_params
            ).fetchall()
            classification_rows = connection.execute(
                f"SELECT COALESCE(llm_label,'unknown') AS label, COUNT(*) AS count FROM samples{sample_where} GROUP BY COALESCE(llm_label,'unknown') ORDER BY count DESC",
                sample_params,
            ).fetchall()
            model_rows = connection.execute(
                f"SELECT model_name AS model, COUNT(*) AS count FROM samples{sample_where}{' AND ' if sample_where else ' WHERE '}model_name IS NOT NULL AND model_name!='' GROUP BY model_name ORDER BY count DESC, model_name",
                sample_params,
            ).fetchall()
            family_rows = connection.execute(
                f"SELECT source_case AS family,COUNT(*) AS count FROM samples{sample_where}{' AND ' if sample_where else ' WHERE '}source_case IS NOT NULL AND trim(source_case)!='' GROUP BY source_case ORDER BY count DESC,source_case",
                sample_params,
            ).fetchall()
            relation_totals = [
                sum(int(row[field]) for row in latest_validations.values())
                for field in ("supports", "contradicts", "complements", "inconclusive")
            ]
        monthly = {row["month"]: row["count"] for row in knowledge_monthly_rows}
        current_count = monthly.get(current_month, 0)
        previous_count = monthly.get(previous_month, 0)
        growth_rate = None if previous_count == 0 else (current_count - previous_count) / previous_count * 100
        return {
            "scope": "全球事件与可分析事件采用知识范围业务口径且为全量值；样本家族按样本来源标注统计；报告按规范化标题逻辑去重；数据库事件物理记录分来源审计；日期筛选只作用于知识库记录型指标",
            "as_of": now.isoformat(),
            "range": {"date_from": date_from, "date_to": date_to},
            "totals": totals,
            "monthly": {
                "current_month": current_month, "current_count": current_count,
                "previous_month": previous_month, "previous_count": previous_count,
                "growth_rate": growth_rate,
                "growth_absolute": current_count - previous_count,
                "basis": "knowledge_created_at",
            },
            "event_monthly": self.db.rows(event_monthly_rows),
            "knowledge_monthly": self.db.rows(knowledge_monthly_rows),
            "sample_classification": self.db.rows(classification_rows),
            "model_distribution": self.db.rows(model_rows),
            "sample_family_distribution": self.db.rows(family_rows),
            "cross_validation_relations": [
                {"relation": name, "count": int(value)}
                for name, value in zip(("supports", "contradicts", "complements", "inconclusive"), relation_totals)
            ],
        }

    def save_generated_report(
        self,
        *,
        report_id: str,
        title: str,
        date_from: str | None,
        date_to: str | None,
        scope: str,
        snapshot: dict[str, Any],
        file_path: str,
    ) -> dict[str, Any]:
        created_at = utc_now()
        with self.db.connect() as connection:
            connection.execute(
                "INSERT INTO generated_reports(id,title,date_from,date_to,scope,snapshot_json,file_path,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (report_id, title, date_from, date_to, scope, json_text(snapshot), file_path, created_at),
            )
        return {"id": report_id, "title": title, "file_path": file_path, "created_at": created_at}

    def list_generated_reports(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.connect() as connection:
            rows = connection.execute(
                "SELECT id,title,date_from,date_to,scope,file_path,created_at FROM generated_reports ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return self.db.rows(rows)

    def get_generated_report(self, report_id: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM generated_reports WHERE id=?", (report_id,)).fetchone()
        return self.db.row(row, ("snapshot_json",))

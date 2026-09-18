from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS samples (
            id TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL UNIQUE,
            original_name TEXT,
            size_bytes INTEGER,
            file_type TEXT,
            language TEXT,
            recoverability TEXT,
            llm_label TEXT,
            model_vendor TEXT,
            model_family TEXT,
            model_name TEXT,
            confidence REAL,
            source_case TEXT,
            status TEXT NOT NULL,
            artifact_path TEXT,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_samples_model ON samples(model_name, model_family);
        CREATE INDEX IF NOT EXISTS idx_samples_case ON samples(source_case);

        CREATE TABLE IF NOT EXISTS sample_analysis_runs (
            id TEXT PRIMARY KEY,
            sample_sha256 TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
            result_schema_version TEXT,
            analyzer_version TEXT NOT NULL,
            trigger_kind TEXT NOT NULL,
            artifact_path TEXT,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sample_runs_sha
            ON sample_analysis_runs(sample_sha256, created_at DESC);

        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL UNIQUE,
            original_name TEXT,
            canonical_url TEXT,
            title TEXT,
            publisher TEXT,
            publication_date TEXT,
            content_type TEXT,
            content_sha256 TEXT,
            status TEXT NOT NULL,
            artifact_path TEXT,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reports_date ON reports(publication_date);

        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            report_db_id TEXT REFERENCES reports(id) ON DELETE SET NULL,
            external_event_id TEXT,
            name TEXT NOT NULL,
            event_type TEXT,
            event_date TEXT,
            status TEXT,
            summary TEXT,
            actor_region TEXT,
            ai_summary TEXT,
            model_service TEXT,
            source_name TEXT,
            source_url TEXT,
            source_kind TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_event_external_source
            ON events(external_event_id, source_kind);
        CREATE INDEX IF NOT EXISTS idx_events_date ON events(event_date);
        CREATE INDEX IF NOT EXISTS idx_events_name ON events(name);

        CREATE TABLE IF NOT EXISTS event_context_overrides (
            event_id TEXT PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
            organizations_json TEXT NOT NULL DEFAULT '[]',
            countries_or_regions_json TEXT NOT NULL DEFAULT '[]',
            source TEXT NOT NULL DEFAULT 'manual_ui',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS knowledge_metrics (
            metric_key TEXT PRIMARY KEY,
            metric_value INTEGER NOT NULL CHECK(metric_value >= 0),
            label TEXT NOT NULL,
            source TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS event_sample_links (
            id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            sample_id TEXT REFERENCES samples(id) ON DELETE SET NULL,
            sample_sha256 TEXT NOT NULL,
            method TEXT NOT NULL,
            confidence REAL NOT NULL,
            propagation_allowed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            UNIQUE(event_id, sample_sha256, method)
        );
        CREATE INDEX IF NOT EXISTS idx_links_sha ON event_sample_links(sample_sha256);

        CREATE TABLE IF NOT EXISTS cross_validations (
            id TEXT PRIMARY KEY,
            sample_id TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
            report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
            event_id TEXT,
            supports INTEGER NOT NULL,
            contradicts INTEGER NOT NULL,
            complements INTEGER NOT NULL,
            inconclusive INTEGER NOT NULL,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS generated_reports (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            date_from TEXT,
            date_to TEXT,
            scope TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            file_path TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS analysis_cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS case_samples (
            case_id TEXT NOT NULL REFERENCES analysis_cases(id) ON DELETE CASCADE,
            sample_id TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
            relation_method TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(case_id, sample_id)
        );

        CREATE TABLE IF NOT EXISTS case_reports (
            case_id TEXT NOT NULL REFERENCES analysis_cases(id) ON DELETE CASCADE,
            report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
            relation_method TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(case_id, report_id)
        );

        CREATE TABLE IF NOT EXISTS sample_cluster_runs (
            id TEXT PRIMARY KEY,
            algorithm_version TEXT NOT NULL,
            sample_count INTEGER NOT NULL,
            cluster_count INTEGER NOT NULL,
            distance_threshold REAL NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sample_clusters (
            sample_id TEXT PRIMARY KEY REFERENCES samples(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES sample_cluster_runs(id) ON DELETE CASCADE,
            cluster_label TEXT NOT NULL,
            cluster_size INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sample_relations (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES sample_cluster_runs(id) ON DELETE CASCADE,
            source_sample_id TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
            target_sample_id TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
            overall_similarity REAL NOT NULL,
            toolchain_similarity REAL NOT NULL,
            prompt_similarity REAL NOT NULL,
            code_style_similarity REAL NOT NULL,
            same_cluster INTEGER NOT NULL,
            common_features_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(run_id, source_sample_id, target_sample_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sample_rel_source ON sample_relations(source_sample_id, overall_similarity DESC);
        CREATE INDEX IF NOT EXISTS idx_sample_rel_target ON sample_relations(target_sample_id, overall_similarity DESC);
        """
        with self.connect() as connection:
            connection.executescript(schema)
            now = utc_now()
            connection.executemany(
                """
                INSERT OR IGNORE INTO knowledge_metrics(metric_key,metric_value,label,source,updated_at)
                VALUES(?,?,?,?,?)
                """,
                (
                    ("global_ai_security_events", 25, "全球AI安全事件", "business_scope_2026-09-05", now),
                    ("analyzable_events", 9, "有样本、可分析事件", "business_scope_2026-09-05", now),
                ),
            )
            # Additive migration: keep historical numeric columns and raw results.
            # Missing/not-comparable scores are represented in details_json and
            # projected as null by the API; old NOT NULL columns retain zero.
            for table in ("sample_cluster_runs", "sample_clusters", "sample_relations"):
                columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
                if "details_json" not in columns:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN details_json TEXT NOT NULL DEFAULT '{{}}'")
            validation_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(cross_validations)")
            }
            if "updated_at" not in validation_columns:
                connection.execute("ALTER TABLE cross_validations ADD COLUMN updated_at TEXT")
                connection.execute("UPDATE cross_validations SET updated_at=created_at WHERE updated_at IS NULL")
            # Preserve the current snapshot of databases created before the
            # append-only run table existed. Re-running initialization is safe.
            connection.execute(
                """
                INSERT OR IGNORE INTO sample_analysis_runs(
                    id,sample_sha256,result_schema_version,analyzer_version,
                    trigger_kind,artifact_path,result_json,created_at)
                SELECT 'migration:' || sha256,sha256,
                       json_extract(result_json,'$.schema_version'),
                       'pre-run-history','migration_snapshot',artifact_path,result_json,updated_at
                FROM samples
                """
            )

    @staticmethod
    def row(row: sqlite3.Row | None, json_fields: tuple[str, ...] = ()) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        for field in json_fields:
            if result.get(field):
                result[field] = json.loads(result[field])
        return result

    @staticmethod
    def rows(rows: list[sqlite3.Row], json_fields: tuple[str, ...] = ()) -> list[dict[str, Any]]:
        return [Database.row(row, json_fields) for row in rows]


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

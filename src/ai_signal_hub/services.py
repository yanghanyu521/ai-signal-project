from __future__ import annotations

import csv
import json
import re
import uuid
from pathlib import Path
from typing import Any, BinaryIO

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .config import Settings
from .database import utc_now
from .legacy import LegacyAdapters
from .repository import Repository
from .similarity import SampleSimilarityService
from .storage import (
    UploadTooLarge,
    move_without_overwrite,
    safe_report_suffix,
    sanitize_display_name,
    stream_to_temporary,
)


class HubService:
    def __init__(self, settings: Settings, repository: Repository, legacy: LegacyAdapters):
        self.settings = settings
        self.repository = repository
        self.legacy = legacy
        self.similarity = SampleSimilarityService(repository)

    def analyze_sample(self, source: BinaryIO, filename: str | None, source_case: str | None) -> dict[str, Any]:
        display_name = sanitize_display_name(filename, "uploaded.sample")
        temp_path, sha256, _ = stream_to_temporary(
            source, self.settings.quarantine_dir / ".incoming", self.settings.max_upload_bytes
        )
        stored_path = move_without_overwrite(temp_path, self.settings.quarantine_dir / f"{sha256}.sample")
        artifact_dir = self.settings.sample_artifact_dir / sha256
        result = self.legacy.analyze_sample(stored_path, artifact_dir)
        actual_sha = str(result.get("sample", {}).get("sha256") or "").lower()
        if actual_sha != sha256:
            raise RuntimeError("上传阶段与分析阶段计算的 SHA-256 不一致，结果未入库")
        saved = self.repository.upsert_sample(
            result,
            original_name=display_name,
            source_case=source_case,
            artifact_path=str(artifact_dir.resolve()),
        )
        self.similarity.rebuild()
        saved["sample_associations"] = self.similarity.associations(sha256)
        return saved

    def analyze_report(
        self,
        source: BinaryIO,
        filename: str | None,
        canonical_url: str | None,
        use_llm: bool = True,
        target_name: str | None = None,
        target_aliases: list[str] | None = None,
    ) -> dict[str, Any]:
        target_name, target_aliases = self._target_descriptor(target_name, target_aliases)
        if not target_name:
            raise ValueError("上传报告前必须指定要抽取的样本或家族名称")
        if not use_llm:
            raise ValueError("报告规则提取已移除；请省略 use_llm 或传 true，报告正文将发送到已配置的大模型接口")
        suffix = safe_report_suffix(filename)
        display_name = sanitize_display_name(filename, f"report{suffix}")
        run_id = uuid.uuid4().hex
        run_dir = self.settings.report_dir / run_id
        temp_path, _, _ = stream_to_temporary(
            source, run_dir / ".incoming", self.settings.max_upload_bytes
        )
        source_path = move_without_overwrite(temp_path, run_dir / f"source{suffix}")
        artifact_dir = run_dir / "artifacts"
        result = self.legacy.analyze_report(
            source_path,
            artifact_dir,
            canonical_url=canonical_url or None,
            use_llm=use_llm,
            target_name=target_name,
            target_aliases=target_aliases,
        )
        return self.repository.upsert_report(
            result, original_name=display_name, artifact_path=str(artifact_dir.resolve())
        )

    @staticmethod
    def _target_descriptor(
        target_name: str | None, target_aliases: list[str] | None = None
    ) -> tuple[str | None, list[str]]:
        value = str(target_name or "").strip()
        aliases = [str(item).strip() for item in target_aliases or [] if str(item).strip()]
        if not value:
            return None, list(dict.fromkeys(aliases))
        match = re.fullmatch(r"\s*(.+?)\s*[（(]\s*([^）)]+)\s*[）)]\s*", value)
        if match:
            value = match.group(1).strip()
            aliases.insert(0, match.group(2).strip())
        return value, list(dict.fromkeys(alias for alias in aliases if alias.lower() != value.lower()))

    @staticmethod
    def _canonical_name(value: Any) -> str:
        return "".join(character.lower() for character in str(value or "") if character.isalnum())

    @classmethod
    def _event_for_sample(
        cls,
        report_result: dict[str, Any],
        sample_sha256: str,
        sample_family: str | None = None,
    ) -> tuple[str | None, str]:
        events = report_result.get("events") or []
        for event in events:
            for artifact in event.get("artifacts") or []:
                hashes = {str(value).lower() for value in artifact.get("sha256") or []}
                if sample_sha256.lower() in hashes:
                    return event.get("event_id"), "sha256_exact"
        family, aliases = cls._target_descriptor(sample_family)
        wanted = {cls._canonical_name(value) for value in [family, *aliases] if value}
        family_matches = []
        if wanted:
            for event in events:
                identity = event.get("identity") or {}
                names = [identity.get("event_name"), *(identity.get("aliases") or [])]
                for artifact in event.get("artifacts") or []:
                    names.extend([artifact.get("family"), *(artifact.get("aliases") or [])])
                if wanted & {cls._canonical_name(value) for value in names if value}:
                    family_matches.append(event)
            if len(family_matches) == 1:
                return family_matches[0].get("event_id"), "family_unique_match"
        if len(events) == 1:
            return events[0].get("event_id"), "single_event_user_pairing"
        return None, "multiple_events_require_selection"

    def analyze_case(
        self,
        *,
        case_id: str | None,
        title: str | None,
        notes: str | None,
        sample_source: BinaryIO | None,
        sample_filename: str | None,
        existing_sample_sha256: str | None,
        report_source: BinaryIO | None,
        report_filename: str | None,
        existing_report_id: str | None,
        source_case: str | None,
        canonical_url: str | None,
        use_llm: bool = True,
        target_name: str | None = None,
        target_aliases: list[str] | None = None,
    ) -> dict[str, Any]:
        if sample_source and existing_sample_sha256:
            raise ValueError("不能同时上传新样本并选择已有样本")
        if report_source and existing_report_id:
            raise ValueError("不能同时上传新报告并选择已有报告")
        if report_source and not use_llm:
            raise ValueError("报告规则提取已移除；请省略 use_llm 或传 true")
        if not any((sample_source, existing_sample_sha256, report_source, existing_report_id, case_id)):
            raise ValueError("至少上传或选择一个样本/报告，或指定已有案例")

        case = self.repository.create_or_update_case(
            case_id=case_id, title=title, notes=notes, status="processing"
        )
        sample = None
        report = None
        if sample_source:
            sample = self.analyze_sample(sample_source, sample_filename, source_case)
            self.repository.attach_case_sample(case["id"], sample["sha256"], "uploaded")
        elif existing_sample_sha256:
            sample = self.repository.get_sample(existing_sample_sha256)
            if not sample:
                raise KeyError("选择的已有样本不存在")
            self.repository.attach_case_sample(case["id"], sample["sha256"], "user_selected_existing")

        current = self.repository.get_case(case["id"])
        if sample is None and len(current["samples"]) == 1:
            sample = self.repository.get_sample(current["samples"][0]["sha256"])

        if report_source:
            effective_target = target_name or source_case or (sample or {}).get("source_case")
            try:
                report = self.analyze_report(
                    report_source,
                    report_filename,
                    canonical_url,
                    use_llm,
                    effective_target,
                    target_aliases,
                )
            except Exception:
                self.repository.update_case_status(case["id"], "report_analysis_failed")
                raise
            self.repository.attach_case_report(case["id"], report["report_id"], "uploaded")
        elif existing_report_id:
            report = self.repository.get_report(existing_report_id)
            if not report:
                raise KeyError("选择的已有报告不存在")
            self.repository.attach_case_report(case["id"], report["report_id"], "user_selected_existing")

        current = self.repository.get_case(case["id"])
        if report is None and len(current["reports"]) == 1:
            report = self.repository.get_report(current["reports"][0]["report_id"])

        validation = None
        validation_status = None
        if sample and report:
            comparison_report = self.repository.report_result_for_comparison(report["report_id"])
            sample_family = target_name or source_case or sample.get("source_case")
            event_id, selection_method = self._event_for_sample(
                comparison_report, sample["sha256"], sample_family
            )
            if event_id:
                try:
                    validation = self.cross_validate(
                        sample_sha256=sample["sha256"],
                        report_id=report["report_id"],
                        event_id=event_id,
                        sample_family=sample_family,
                    )
                    validation_status = selection_method
                    status = "ready_for_review"
                except ValueError as exc:
                    validation_status = f"validation_pending: {exc}"
                    status = "validation_pending"
            else:
                validation_status = selection_method
                status = "event_selection_required"
        elif current["samples"]:
            status = "waiting_for_report"
        elif current["reports"]:
            status = "waiting_for_sample"
        else:
            status = "empty"
        self.repository.update_case_status(case["id"], status)
        final_case = self.repository.get_case(case["id"])
        associations = self.similarity.associations(sample["sha256"]) if sample else None
        joint_summary = None
        if sample and report:
            joint_summary = self.build_joint_summary(
                sample,
                self.repository.report_result_for_comparison(report["report_id"]),
                validation,
                validation.get("event_id") if validation else event_id,
            )
        return {
            "case": final_case,
            "sample": sample,
            "report": report,
            "cross_validation": validation,
            "validation_status": validation_status,
            "sample_associations": associations,
            "joint_summary": joint_summary,
        }

    def cross_validate(
        self,
        *,
        sample_sha256: str,
        report_id: str,
        event_id: str | None,
        sample_family: str | None,
    ) -> dict[str, Any]:
        sample = self.repository.get_sample(sample_sha256.lower())
        if not sample:
            raise KeyError("样本不存在")
        report = self.repository.get_report(report_id)
        if not report:
            raise KeyError("报告不存在")
        result = self.legacy.compare(
            self.repository.report_result_for_comparison(report_id),
            sample["result_json"],
            event_id=event_id,
            sample_family=sample_family,
        )
        matched_event_id = result.get("event_id")
        link = result.get("link") or {}
        if matched_event_id:
            self.repository.upsert_event_sample_link(
                matched_event_id,
                sample_sha256,
                link.get("method") or "comparison",
                float(link.get("confidence") or 0.0),
                bool(link.get("propagation_allowed")),
            )
        return self.repository.save_cross_validation(
            sample_sha256.lower(), report_id, matched_event_id, result
        )

    def cross_validate_case(
        self,
        *,
        case_id: str,
        sample_sha256: str | None = None,
        report_id: str | None = None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        case = self.repository.get_case(case_id)
        if not case:
            raise KeyError("分析案例不存在")
        sample_ids = [item["sha256"] for item in case["samples"]]
        report_ids = [item["report_id"] for item in case["reports"]]
        if not sample_ids or not report_ids:
            raise ValueError("该案例尚未同时关联样本和报告")
        if sample_sha256 is None:
            if len(sample_ids) != 1:
                raise ValueError("案例包含多个样本，请明确选择样本")
            sample_sha256 = sample_ids[0]
        if report_id is None:
            if len(report_ids) != 1:
                raise ValueError("案例包含多份报告，请明确选择报告")
            report_id = report_ids[0]
        if sample_sha256 not in sample_ids or report_id not in report_ids:
            raise ValueError("所选样本或报告不属于该分析案例")
        sample = self.repository.get_sample(sample_sha256)
        report = self.repository.get_report(report_id)
        if not sample or not report:
            raise KeyError("案例关联对象不存在")
        family = next(
            (item.get("source_case") for item in case["samples"] if item["sha256"] == sample_sha256),
            None,
        )
        report_result = self.repository.report_result_for_comparison(report_id)
        selection_method = "explicit_event_id"
        if not event_id:
            event_id, selection_method = self._event_for_sample(report_result, sample_sha256, family)
        if not event_id:
            raise ValueError("案例报告中存在多个候选事件，无法唯一匹配目标样本/家族")
        validation = self.cross_validate(
            sample_sha256=sample_sha256,
            report_id=report_id,
            event_id=event_id,
            sample_family=family,
        )
        self.repository.update_case_status(case_id, "ready_for_review")
        return {
            "case": self.repository.get_case(case_id),
            "selection_method": selection_method,
            "cross_validation": validation,
            "joint_summary": self.build_joint_summary(sample, report_result, validation, event_id),
        }

    def build_joint_summary(
        self,
        sample: dict[str, Any],
        report_result: dict[str, Any],
        validation: dict[str, Any] | None,
        event_id: str | None,
    ) -> dict[str, Any]:
        sample_result = sample.get("result_json") or {}
        events = report_result.get("events") or []
        event = next((item for item in events if item.get("event_id") == event_id), None)
        if event is None and len(events) == 1:
            event = events[0]
        event = event or {}
        sample_features = sample_result.get("features") or {}
        sample_prompt = sample_features.get("prompt") or {}
        report_signals = event.get("ai_signals") or {}
        comparisons = (validation or {}).get("comparisons") or []
        evidence_by_id = {
            item.get("evidence_id"): item.get("excerpt")
            for item in event.get("evidence") or []
            if item.get("evidence_id") and item.get("excerpt")
        }

        def true_flags(value: dict[str, Any] | None) -> list[str]:
            return [str(key) for key, enabled in (value or {}).items() if enabled is True]

        def relation_items(relation: str) -> list[dict[str, Any]]:
            return [
                {
                    "signal_group": item.get("signal_group"),
                    "sample_value": (item.get("sample") or {}).get("value"),
                    "report_value": (item.get("report") or {}).get("value"),
                    "notes": item.get("notes"),
                    "evidence_ids": (item.get("report") or {}).get("evidence_ids") or [],
                }
                for item in comparisons
                if item.get("relation") == relation
            ]

        identity = event.get("identity") or {}
        sample_toolchain = sample_features.get("toolchain") or {}
        resolved_event_id = event.get("event_id") or event_id
        return {
            "case_subject": {
                "sample_sha256": sample.get("sha256"),
                "sample_family": sample.get("source_case"),
                "report_id": report_result.get("report", {}).get("report_id"),
                "event_id": resolved_event_id,
                "event_name": identity.get("event_name"),
            },
            "sample_ai_toolchain": {
                "source_language": sample_toolchain.get("source_language"),
                "file_type": sample_toolchain.get("file_type"),
                "packaging_candidates": sample_toolchain.get("packaging_candidates") or [],
                "evidence": sample_toolchain.get("evidence") or [],
                "model_attribution": sample_result.get("classification", {}).get("model_attribution") or {},
            },
            "report_ai_toolchain": report_signals.get("toolchain") or [],
            "sample_prompt_features": {
                "embedded_prompt_count": len(sample_prompt.get("embedded_prompts") or []),
                "structural_features": true_flags(sample_prompt.get("structural_features")),
                "special_tokens": sample_prompt.get("special_tokens") or [],
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
                    for item in sample_prompt.get("embedded_prompts") or []
                ],
            },
            "report_prompt_features": [
                {
                    "availability": item.get("availability"),
                    "text": item.get("text"),
                    "purpose": item.get("purpose"),
                    "target_model": item.get("target_model"),
                    "structural_features": true_flags(item.get("structural_features")),
                    "constraints": item.get("constraints") or [],
                    "evidence_ids": item.get("evidence_ids") or [],
                    "evidence_excerpts": [
                        evidence_by_id[evidence_id]
                        for evidence_id in item.get("evidence_ids") or []
                        if evidence_id in evidence_by_id
                    ],
                }
                for item in report_signals.get("prompts") or []
            ],
            "event_context": self.repository.get_event_context(resolved_event_id, event),
            "comparison_summary": (validation or {}).get("summary") or {},
            "confirmed": relation_items("supports"),
            "conflicts": relation_items("contradicts"),
            "report_complements": relation_items("complements"),
            "inconclusive": relation_items("inconclusive"),
            "supplementary_report_features": {
                "time": event.get("time") or {},
                "status": event.get("status") or {},
                "attribution": event.get("attribution") or {},
                "targets": event.get("targets") or [],
                "ai_involvement": event.get("ai_involvement") or {},
                "code_style": report_signals.get("code_style") or [],
                "key_behaviors": event.get("key_behaviors") or [],
                "outcomes": event.get("outcomes") or [],
                "limitations": event.get("limitations") or [],
            },
            "interpretation": "样本侧为静态证据；报告侧为原文证据。确认、冲突和补充关系不改变两侧原始证据。",
        }

    def import_legacy(
        self,
        *,
        include_samples: bool = True,
        include_events: bool = True,
        include_reports: bool = False,
    ) -> dict[str, Any]:
        summary = {
            "samples_imported": 0,
            "samples_missing": 0,
            "events_imported": 0,
            "reports_imported": 0,
            "family_cases_linked": 0,
            "errors": [],
        }
        if include_samples:
            manifest_path = self.settings.seed_data_dir / "样本清单" / "已完成特征提取样本清单.csv"
            seed_root = self.settings.seed_data_dir.resolve()
            with manifest_path.open("r", encoding="utf-8-sig", newline="") as handle:
                for row in csv.DictReader(handle):
                    try:
                        result_path = (seed_root / row["结果位置"]).resolve()
                        if seed_root not in result_path.parents:
                            raise ValueError("种子样本结果路径越界")
                        if not result_path.is_file():
                            summary["samples_missing"] += 1
                            continue
                        result = json.loads(result_path.read_text(encoding="utf-8"))
                        self.repository.upsert_sample(
                            result,
                            original_name=None,
                            source_case=row.get("来源/案例"),
                            artifact_path=str(result_path.parent),
                        )
                        summary["samples_imported"] += 1
                    except Exception as exc:
                        summary["errors"].append({"stage": "sample_import", "sha256": row.get("SHA-256"), "message": str(exc)})
        if include_events:
            event_path = self.settings.seed_data_dir / "ai_attack_events.csv"
            with event_path.open("r", encoding="utf-8-sig", newline="") as handle:
                for row in csv.DictReader(handle):
                    try:
                        self.repository.upsert_research_event(row)
                        summary["events_imported"] += 1
                    except Exception as exc:
                        summary["errors"].append({"stage": "event_import", "event_id": row.get("event_id"), "message": str(exc)})
        if include_reports:
            report_root = self.settings.seed_data_dir / "reports"
            for path in report_root.glob("*/report_events.json"):
                try:
                    family = path.parent.name
                    result = json.loads(path.read_text(encoding="utf-8"))
                    saved_report = self.repository.upsert_report(
                        result,
                        original_name=result.get("report", {}).get("file_name"),
                        artifact_path=str(path.parent),
                        source_kind="legacy_extracted_report",
                    )
                    summary["reports_imported"] += 1
                    case_title = f"{family} 家族知识案例"
                    existing_case = next(
                        (item for item in self.repository.list_cases(500, 0) if item["title"] == case_title),
                        None,
                    )
                    family_samples = [
                        item
                        for item in self.repository.list_samples(500, 0)
                        if self._canonical_name(self._target_descriptor(item.get("source_case"))[0])
                        == self._canonical_name(family)
                    ]
                    family_case = self.repository.create_or_update_case(
                        case_id=existing_case["id"] if existing_case else None,
                        title=case_title,
                        notes="legacy_family_report_mapping",
                        status="ready_for_review" if family_samples else "waiting_for_sample",
                    )
                    self.repository.attach_case_report(
                        family_case["id"], saved_report["report_id"], "legacy_family_mapping"
                    )
                    for family_sample in family_samples:
                        self.repository.attach_case_sample(
                            family_case["id"], family_sample["sha256"], "legacy_family_mapping"
                        )
                    summary["family_cases_linked"] += 1
                except Exception as exc:
                    summary["errors"].append({"stage": "report_import", "path": str(path), "message": str(exc)})
        if include_samples and summary["samples_imported"]:
            try:
                summary["clustering"] = self.similarity.rebuild()
            except Exception as exc:
                summary["errors"].append({"stage": "sample_clustering", "message": str(exc)})
        return summary

    def generate_report(
        self,
        *,
        title: str,
        date_from: str | None,
        date_to: str | None,
    ) -> dict[str, Any]:
        snapshot = self.repository.statistics(date_from=date_from, date_to=date_to)
        report_id = uuid.uuid4().hex
        environment = Environment(
            loader=FileSystemLoader(self.settings.report_template_path.parent),
            undefined=StrictUndefined,
            autoescape=False,
            keep_trailing_newline=True,
        )
        template = environment.get_template(self.settings.report_template_path.name)
        content = template.render(
            title=title,
            generated_at=utc_now(),
            snapshot_id=report_id,
            **snapshot,
        )
        destination = self.settings.generated_report_dir / f"{report_id}.md"
        destination.write_text(content, encoding="utf-8")
        record = self.repository.save_generated_report(
            report_id=report_id,
            title=title,
            date_from=date_from,
            date_to=date_to,
            scope=snapshot["scope"],
            snapshot=snapshot,
            file_path=str(destination.resolve()),
        )
        record["content"] = content
        record["snapshot"] = snapshot
        return record

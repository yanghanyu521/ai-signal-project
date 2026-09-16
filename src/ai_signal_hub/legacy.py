from __future__ import annotations

import json
import copy
import re
import sys
from pathlib import Path
from typing import Any

from .config import Settings


class LegacyUnavailable(RuntimeError):
    pass


def _add_src(project: Path) -> None:
    source = project / "src"
    if not source.is_dir():
        raise LegacyUnavailable(f"旧项目源码目录不存在: {source}")
    value = str(source)
    if value not in sys.path:
        sys.path.insert(0, value)


class LegacyAdapters:
    def __init__(self, settings: Settings):
        self.settings = settings

    def availability(self) -> dict[str, Any]:
        return {
            "sample_project": {
                "path": str(self.settings.legacy_sample_project),
                "available": (self.settings.legacy_sample_project / "src" / "aisig").is_dir(),
            },
            "report_project": {
                "path": str(self.settings.legacy_report_project),
                "available": (self.settings.legacy_report_project / "src" / "report_extractor").is_dir(),
            },
        }

    def analyze_sample(self, sample_path: Path, artifact_dir: Path) -> dict[str, Any]:
        _add_src(self.settings.legacy_sample_project)
        from aisig.cli import analyze

        analyze(
            sample_path,
            artifact_dir,
            self.settings.legacy_sample_project / "configs" / "limits.yaml",
            self.settings.legacy_sample_project / "rules" / "llm_rules.yaml",
        )
        result_path = artifact_dir / "result.json"
        if not result_path.is_file():
            raise RuntimeError("旧样本分析器未生成 result.json")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        from .sample_rules import apply_sample_rules
        from .prompt_recovery import MAX_FILE, recover_prompt_features

        if not result.get("errors"):
            from aisig.report import write_artifacts

            # The adapter only reads payload bytes; the rule module never runs
            # PowerShell, imports samples, or sends their contents to a model.
            with sample_path.open("rb") as handle:
                data = handle.read(min(self.settings.max_upload_bytes, MAX_FILE) + 1)
            if len(data) > min(self.settings.max_upload_bytes, MAX_FILE):
                raise ValueError("样本超过统一平台静态规则输入上限")
            enhanced = apply_sample_rules(result, data)
            enhanced = recover_prompt_features(enhanced, data)
            # A missing decompiler must not prevent reading model markers from
            # the very same CArchive script bytes used for prompt recovery.
            # Do not infer a toolchain from the natural-language prompt itself.
            if not enhanced["features"]["toolchain"].get("evidence"):
                self._recover_packaged_toolchain(enhanced, data)
            if enhanced != result:
                strings = [json.loads(line) for line in (artifact_dir / "strings.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
                write_artifacts(artifact_dir, enhanced, strings,
                                self.settings.legacy_sample_project / "schemas" / "result.schema.json")
            result = enhanced
        return result

    def _recover_packaged_toolchain(self, result: dict[str, Any], data: bytes) -> None:
        from .prompt_recovery import _pyinstaller_members, _digest
        from aisig.cli import _config
        from aisig.toolchain import extract_toolchain
        from aisig.string_extract import extract_strings
        from aisig.classify import classify
        import struct
        import zlib

        if b'MEI\x0c\x0b\x0a\x0b\x0e' not in data:
            return
        rules = _config(self.settings.legacy_sample_project / "rules" / "llm_rules.yaml")
        evidence = []
        try:
            for name, offset, member in _pyinstaller_members(data):
                found = extract_toolchain(extract_strings(member, 5000, 4096), rules, result["sample"], member)
                for item in found.get("evidence", []):
                    item["source"] = f"carchive_static:{name}:{item.get('source', 'bytes')}"
                    item["recovery_origin"] = {"layer": "pyinstaller_script", "member": name,
                        "member_sha256": _digest(member), "container_offset": offset}
                    evidence.append(item)
        except (ValueError, struct.error, zlib.error):
            return
        if evidence:
            features = result["features"]
            features["toolchain"]["evidence"] = evidence
            features["recovery"]["static_toolchain"] = {"status": "recovered", "method": "carchive_script_bytes",
                "decompiler_required": False, "source_recovered": False}
            result["classification"] = classify(features["toolchain"], features["prompt"])

    def analyze_report(
        self,
        report_path: Path,
        artifact_dir: Path,
        canonical_url: str | None = None,
        use_llm: bool = True,
        target_name: str | None = None,
        target_aliases: list[str] | None = None,
    ) -> dict[str, Any]:
        _add_src(self.settings.legacy_report_project)
        from .report_llm import extract_report_with_llm

        if not use_llm:
            raise ValueError("报告规则提取已移除；请省略 use_llm 或传 true，报告正文将发送到已配置的大模型接口")
        if not target_name or not target_name.strip():
            raise ValueError("报告抽取必须指定目标样本或家族名称")
        return extract_report_with_llm(
            report_path,
            canonical_url=canonical_url,
            output_dir=artifact_dir,
            schema_path=self.settings.legacy_report_project / "schemas" / "report_events_v03.schema.json",
            target_name=target_name,
            target_aliases=target_aliases,
        )

    def compare(
        self,
        report_result: dict[str, Any],
        sample_result: dict[str, Any],
        *,
        event_id: str | None = None,
        sample_family: str | None = None,
    ) -> dict[str, Any]:
        _add_src(self.settings.legacy_report_project)
        from report_extractor.event_compare_v3 import compare_event_to_sample

        # Support both historic bare digests and current sha256:<digest> without
        # mutating stored evidence or changing the legacy projects.
        report_copy, sample_copy = copy.deepcopy(report_result), copy.deepcopy(sample_result)
        prompts = list(sample_copy.get("features", {}).get("prompt", {}).get("embedded_prompts", []))
        for event in report_copy.get("events", []):
            prompts.extend(event.get("ai_signals", {}).get("prompts", []))
        for prompt in prompts:
            digest = str(prompt.get("text_hash") or "").lower().removeprefix("sha256:")
            if re.fullmatch(r"[a-f0-9]{64}", digest):
                prompt["text_hash"] = "sha256:" + digest
        return compare_event_to_sample(
            report_copy,
            sample_copy,
            event_id=event_id,
            sample_family=sample_family,
        )

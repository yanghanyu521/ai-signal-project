from __future__ import annotations

import json
import copy
import re
from importlib.util import find_spec
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import Settings


class LegacyUnavailable(RuntimeError):
    """Compatibility exception retained for existing API error handling."""
    pass


class LegacyAdapters:
    def __init__(self, settings: Settings):
        self.settings = settings

    def availability(self) -> dict[str, Any]:
        sample_llm_credentials_configured = bool(
            self.settings.sample_llm_enabled and self.settings.sample_llm_model.strip()
            and self.settings.sample_llm_api_key
        )
        endpoint = urlparse(self.settings.sample_llm_base_url)
        remote = endpoint.hostname not in {"127.0.0.1", "localhost", "::1"}
        transfer_allowed = not remote or (
            self.settings.sample_llm_allow_remote
            and self.settings.sample_llm_transfer_policy in {"remote_redacted", "remote_full"}
        )
        return {
            "sample_project": {
                "path": str(self.settings.legacy_sample_project),
                "available": find_spec("aisig") is not None
                and (self.settings.legacy_sample_project / "rules" / "llm_rules.yaml").is_file(),
            },
            "report_project": {
                "path": str(self.settings.legacy_report_project),
                "available": find_spec("report_extractor") is not None
                and (self.settings.legacy_report_project / "schemas" / "report_events_v03.schema.json").is_file(),
            },
            "sample_semantic_analysis": {
                "enabled": self.settings.sample_llm_enabled,
                "configured": sample_llm_credentials_configured and transfer_allowed,
                "credentials_configured": sample_llm_credentials_configured,
                "mode": self.settings.sample_llm_mode,
                "remote_transfer_allowed": self.settings.sample_llm_allow_remote,
                "transfer_policy": self.settings.sample_llm_transfer_policy,
                "configuration_boundary": "shared_deepseek_defaults_with_sample_specific_overrides",
            },
            "docker_static_tools": {
                "enabled": self.settings.static_tools_docker_enabled,
                "jadx_image": self.settings.jadx_docker_image,
                "ghidra_image": self.settings.ghidra_docker_image,
            },
        }

    def analyze_sample(self, sample_path: Path, artifact_dir: Path) -> dict[str, Any]:
        from aisig.cli import analyze

        analyze(
            sample_path,
            artifact_dir,
            self.settings.legacy_sample_project / "configs" / "limits.yaml",
            self.settings.legacy_sample_project / "rules" / "llm_rules.yaml",
        )
        result_path = artifact_dir / "result.json"
        if not result_path.is_file():
            raise RuntimeError("内置样本分析器未生成 result.json")
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
            self._recover_packaged_toolchain(enhanced, data)
            self._run_semantic_static_analysis(enhanced, data, artifact_dir)
            # Classification is a derived view and must be computed exactly
            # once from the final merged evidence set.
            from aisig.classify import classify
            enhanced["classification"] = classify(
                enhanced["features"]["toolchain"], enhanced["features"]["prompt"]
            )
            enhanced["classification"]["derivation_stage"] = "final"
            enhanced["schema_version"] = "0.3"
            if enhanced != result:
                strings = [json.loads(line) for line in (artifact_dir / "strings.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
                write_artifacts(artifact_dir, enhanced, strings,
                                self.settings.legacy_sample_project / "schemas" / "result.schema.json")
            result = enhanced
        return result

    def _run_semantic_static_analysis(
        self, result: dict[str, Any], data: bytes, artifact_dir: Path
    ) -> None:
        from .static_analysis import run_static_analysis
        from .static_analysis.materials import build_material_index

        features = result.setdefault("features", {})
        try:
            client = None
            policy_blocked = False
            if self.settings.sample_llm_enabled:
                from .static_analysis.llm import SampleLLMClient
                endpoint = urlparse(self.settings.sample_llm_base_url)
                valid_endpoint = endpoint.scheme in {"http", "https"} and bool(endpoint.hostname)
                is_remote = valid_endpoint and endpoint.hostname not in {"127.0.0.1", "localhost", "::1"}
                policy_blocked = bool(valid_endpoint and is_remote and (
                    not self.settings.sample_llm_allow_remote
                    or self.settings.sample_llm_transfer_policy == "local_only"
                ))
                if not policy_blocked:
                    client = SampleLLMClient(
                        base_url=self.settings.sample_llm_base_url,
                        model=self.settings.sample_llm_model,
                        api_key=self.settings.sample_llm_api_key,
                        allow_remote=self.settings.sample_llm_allow_remote,
                        transfer_policy=self.settings.sample_llm_transfer_policy,
                        timeout_seconds=self.settings.sample_llm_timeout_seconds,
                        max_output_tokens=self.settings.sample_llm_max_output_tokens,
                    )
            material_index = build_material_index(data, result.get("sample") or {})
            if self.settings.static_tools_docker_enabled:
                from .static_analysis.docker_tools import DockerStaticTools
                material_index = DockerStaticTools(
                    enabled=True,
                    jadx_image=self.settings.jadx_docker_image,
                    ghidra_image=self.settings.ghidra_docker_image,
                    timeout_seconds=self.settings.static_tool_timeout_seconds,
                ).augment(material_index, data, result.get("sample") or {}, artifact_dir)
            self._sync_prompt_compositions(features, material_index)
            analysis = run_static_analysis(
                data, result.get("sample") or {}, artifact_dir,
                llm_client=client, mode=self.settings.sample_llm_mode,
                max_input_tokens=self.settings.sample_llm_max_input_tokens,
                max_requests=self.settings.sample_llm_max_requests,
                max_reasoning_rounds=self.settings.sample_llm_max_reasoning_rounds,
                max_queries_per_round=self.settings.sample_llm_max_queries_per_round,
                max_context_units=self.settings.sample_llm_max_context_units,
                recovered_index=material_index,
                relation_anchors=self._relation_anchors(features),
            )
            if policy_blocked:
                run = analysis["run"]
                run["limitations"] = [
                    "sample_llm_remote_policy_blocked" if item == "sample_llm_disabled" else item
                    for item in run.get("limitations", [])
                ]
                run["llm_transfer"] = {
                    "provider": endpoint.hostname,
                    "remote": True,
                    "destination": "blocked",
                    "policy": self.settings.sample_llm_transfer_policy,
                    "redaction_count": 0,
                    "redaction_mapping_persisted": False,
                }
        except Exception as exc:
            # Semantic analysis is an optional enhancement. Configuration,
            # model and parser failures must never discard deterministic facts.
            features["static_analysis"] = {
                "materials": {"status": "failed", "unit_count": 0},
                "run": {"status": "failed", "errors": [f"{type(exc).__name__}: {exc}"],
                        "limitations": ["deterministic_results_retained"]},
            }
            self._sync_fact_index(features)
            return
        features["static_analysis"] = {
            "materials": analysis["materials"],
            "run": {key: value for key, value in analysis["run"].items() if key != "facts"},
        }
        facts = features.setdefault("facts", [])
        facts.extend(item for item in analysis["run"]["facts"]
                     if item.get("fact_id") not in {fact.get("fact_id") for fact in facts})
        self._merge_semantic_facts(features, analysis["run"]["facts"])
        self._sync_prompt_compositions(features, material_index)
        self._sync_fact_index(features)

    @staticmethod
    def _sync_prompt_compositions(features: dict[str, Any], material_index: Any) -> None:
        """Group verified static prompt components by the call-containing unit.

        A composition is deliberately not labelled as the complete runtime prompt:
        opaque calls, branches, user input and SDK serialization are not executed.
        """
        import hashlib

        prompt = features.setdefault("prompt", {})
        records = prompt.get("embedded_prompts", []) or []
        units = list(getattr(material_index, "units", []) or [])

        def containing(line: Any) -> Any | None:
            if not isinstance(line, int):
                return None
            candidates = []
            for unit in units:
                source_lines = unit.location.get("source_lines") or []
                if len(source_lines) == 2 and all(isinstance(value, int) for value in source_lines):
                    if source_lines[0] <= line <= source_lines[1]:
                        candidates.append(unit)
            return min(candidates, key=lambda unit: (
                (unit.location["source_lines"][1] - unit.location["source_lines"][0]),
                unit.kind == "module_init", unit.unit_id,
            )) if candidates else None

        grouped: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
        record_links: dict[int, list[str]] = {}
        for index, item in enumerate(records):
            if item.get("call_binding") != "relation_verified" or item.get("role") != "application":
                continue
            origin = item.get("recovery_origin") or item.get("origin") or {}
            component_unit = containing(origin.get("line"))
            for site in item.get("call_sites") or []:
                target = containing(site.get("line"))
                if target is None:
                    continue
                key = (target.unit_id, int(site["line"]), str(site.get("callee") or "unknown"))
                grouped.setdefault(key, []).append({
                    "text": item.get("text"), "text_hash": item.get("text_hash"),
                    "source_unit_id": component_unit.unit_id if component_unit else target.unit_id,
                    "source_location": {"line": origin.get("line"), "end_line": origin.get("end_line")},
                    "completeness": item.get("completeness") or "static_component",
                    "record_index": index,
                })

        compositions = []
        for (target_id, line, callee), components in sorted(grouped.items()):
            components.sort(key=lambda item: (
                item["source_location"].get("line") or 0,
                item["source_location"].get("end_line") or 0,
                item.get("text_hash") or "",
            ))
            seed = json.dumps([target_id, line, callee], ensure_ascii=False)
            composition_id = "prompt-composition:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]
            public_components = []
            for order, component in enumerate(components, 1):
                record_links.setdefault(component.pop("record_index"), []).append(composition_id)
                public_components.append({"order": order, **component})
            compositions.append({
                "composition_id": composition_id,
                "target_call_unit_id": target_id,
                "target_call": {"line": line, "callee": callee},
                "components": public_components,
                "component_count": len(public_components),
                "unknown_component_count": None,
                "unknown_component_count_status": "not_quantifiable_without_execution",
                "static_reconstruction": "".join(str(item.get("text") or "") for item in public_components),
                "composition_semantics": "ordered_static_components_not_runtime_serialization",
                "call_binding": "relation_verified",
                "runtime_complete": False,
                "completeness": "static_components_only",
                "limitations": ["runtime_values_and_sdk_serialization_not_executed"],
            })
        for index, item in enumerate(records):
            item["runtime_complete"] = False
            if record_links.get(index):
                item["composition_ids"] = record_links[index]
        prompt["compositions"] = compositions

    @staticmethod
    def _relation_anchors(features: dict[str, Any]) -> list[dict[str, Any]]:
        anchors: list[dict[str, Any]] = []
        for item in (features.get("toolchain") or {}).get("evidence", []) or []:
            anchors.append({
                "signal_group": "toolchain",
                "raw_value": item.get("raw_value") or item.get("value"),
                "verification_status": item.get("verification_status"),
                "verification": item.get("verification") or {},
                "source_location": item.get("source_location") or {},
                "role": item.get("role") or "unknown",
            })
        for item in (features.get("prompt") or {}).get("embedded_prompts", []) or []:
            origin = item.get("origin") or {}
            anchors.append({
                "signal_group": "prompt",
                "raw_value": item.get("text"),
                "verification_status": (
                    "relation_verified" if item.get("call_binding") == "relation_verified"
                    else item.get("verification_status")
                ),
                "verification": item.get("verification") or {},
                "source_location": item.get("source_location") or {
                    "line": origin.get("line"), "end_line": origin.get("end_line")
                },
                "role": item.get("role") or "unknown",
            })
        return [anchor for anchor in anchors if isinstance(anchor.get("raw_value"), str)]

    @staticmethod
    def _sync_fact_index(features: dict[str, Any]) -> None:
        """Expose legacy evidence through the versioned fact contract."""
        import hashlib

        facts = features.setdefault("facts", [])
        seen = {item.get("fact_id") for item in facts}
        records = []
        for item in (features.get("toolchain") or {}).get("evidence", []) or []:
            records.append(("toolchain", item.get("raw_value") or item.get("value"), item))
        for item in (features.get("prompt") or {}).get("embedded_prompts", []) or []:
            records.append(("prompt", item.get("text") or item.get("text_preview"), item))
        for group, raw, item in records:
            if not isinstance(raw, str) or not raw:
                continue
            unit_ids = item.get("source_unit_ids") or []
            seed = json.dumps(
                [group, raw, sorted(unit_ids)] if item.get("discovery_method") == "llm"
                else [group, raw, unit_ids, item.get("source"), item.get("offset")],
                ensure_ascii=False,
            )
            fact_id = "fact:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]
            if fact_id in seen:
                continue
            facts.append({
                "fact_id": fact_id, "signal_group": group, "raw_value": raw,
                "normalized_value": item.get("normalized") or {},
                "source_unit_ids": unit_ids,
                "source_location": item.get("source_location") or {"file_offset": item.get("offset")},
                "evidence_text_hash": "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "discovery_method": item.get("discovery_method") or "rule",
                "verification_status": item.get("verification_status") or "unverified",
                "verification": item.get("verification") or {
                    "location": "verified" if item.get("verification_status") in {
                        "location_verified", "relation_verified"
                    } else "unknown",
                    "relation": "verified" if item.get("verification_status") == "relation_verified" else "unknown",
                    "role": "verified" if item.get("role") in {
                        "application", "dependency", "example", "analysis_helper", "analyzer_directive"
                    } else "unknown",
                },
                "attribution_eligible": bool(item.get("attribution_eligible")),
                "semantic_review_status": item.get("semantic_review_status") or "not_reviewed",
                "limitations": item.get("limitations") or [], "role": item.get("role") or "unknown",
            })
            seen.add(fact_id)

    @staticmethod
    def _merge_semantic_facts(features: dict[str, Any], facts: list[dict[str, Any]]) -> None:
        import hashlib

        tool_evidence = features.setdefault("toolchain", {}).setdefault("evidence", [])
        prompts = features.setdefault("prompt", {}).setdefault("embedded_prompts", [])
        tool_seen = {(item.get("type"), item.get("value"), tuple(item.get("source_unit_ids") or []))
                     for item in tool_evidence}
        prompt_seen = {item.get("text_hash") for item in prompts}
        for fact in facts:
            raw = fact.get("raw_value")
            if fact.get("signal_group") == "toolchain":
                normalized = fact.get("normalized_value") or {}
                if normalized.get("model_identifier_raw"):
                    kind = "model_argument"
                    normalized = {**normalized, "model": normalized["model_identifier_raw"]}
                elif normalized.get("service_endpoint"):
                    kind = "service_endpoint"
                elif normalized.get("sdk_name"):
                    kind = "sdk_call"
                else:
                    kind = "semantic_toolchain_candidate"
                key = (kind, raw, tuple(fact.get("source_unit_ids") or []))
                if key not in tool_seen:
                    tool_evidence.append({
                        "type": kind, "value": raw, "raw_value": raw,
                        "normalized": normalized, "source": "sample_llm_static_analysis",
                        "source_unit_ids": fact.get("source_unit_ids") or [],
                        "source_location": fact.get("source_location") or {},
                        "discovery_method": "llm", "verification_status": fact.get("verification_status"),
                        "verification": fact.get("verification") or {},
                        "attribution_eligible": bool(fact.get("attribution_eligible")),
                        "semantic_review_status": fact.get("semantic_review_status"),
                        "role": fact.get("role"), "proposed_role": fact.get("proposed_role"),
                        "limitations": fact.get("limitations") or [],
                        "confidence": 0.7,
                    })
                    tool_seen.add(key)
            elif fact.get("signal_group") == "prompt" and isinstance(raw, str):
                digest = "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
                if digest not in prompt_seen:
                    prompts.append({
                        "text": raw, "text_hash": digest, "source": "sample_llm_static_analysis",
                        "source_unit_ids": fact.get("source_unit_ids") or [],
                        "source_location": fact.get("source_location") or {},
                        "discovery_method": "llm", "verification_status": fact.get("verification_status"),
                        "verification": fact.get("verification") or {},
                        "attribution_eligible": bool(fact.get("attribution_eligible")),
                        "semantic_review_status": fact.get("semantic_review_status"),
                        "role": fact.get("role"), "proposed_role": fact.get("proposed_role"),
                        "completeness": "string_constant",
                        "call_binding": (
                            "relation_verified" if fact.get("attribution_eligible") else "unverified"
                        ), "comparison_eligible": False,
                        "limitations": fact.get("limitations") or [],
                    })
                    prompt_seen.add(digest)
            elif fact.get("signal_group") == "code_observation" and isinstance(raw, str):
                observations = features.setdefault("code_generation_signals", {}).setdefault("observations", [])
                if fact.get("fact_id") not in {item.get("fact_id") for item in observations}:
                    observations.append({
                        "fact_id": fact.get("fact_id"), "raw_value": raw,
                        "source_unit_ids": fact.get("source_unit_ids") or [],
                        "source_location": fact.get("source_location") or {},
                        "discovery_method": "llm", "verification": fact.get("verification") or {},
                        "verification_status": fact.get("verification_status"),
                        "attribution_eligible": False,
                        "semantic_review_status": fact.get("semantic_review_status"),
                        "role": fact.get("role"), "proposed_role": fact.get("proposed_role"),
                        "limitations": fact.get("limitations") or [],
                    })

    def _recover_packaged_toolchain(self, result: dict[str, Any], data: bytes) -> None:
        from .prompt_recovery import _pyinstaller_members, _digest
        from aisig.cli import _config
        from aisig.toolchain import extract_toolchain
        from aisig.string_extract import extract_strings
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
            existing = features["toolchain"].setdefault("evidence", [])
            keys = {
                (item.get("type"), item.get("value"), item.get("source"), item.get("offset"),
                 (item.get("recovery_origin") or {}).get("member"))
                for item in existing
            }
            added = 0
            for item in evidence:
                key = (item.get("type"), item.get("value"), item.get("source"), item.get("offset"),
                       (item.get("recovery_origin") or {}).get("member"))
                if key not in keys:
                    existing.append(item)
                    keys.add(key)
                    added += 1
            features["recovery"]["static_toolchain"] = {"status": "recovered", "method": "carchive_script_bytes",
                "decompiler_required": False, "source_recovered": False, "evidence_added": added}

    def analyze_report(
        self,
        report_path: Path,
        artifact_dir: Path,
        canonical_url: str | None = None,
        use_llm: bool = True,
        target_name: str | None = None,
        target_aliases: list[str] | None = None,
    ) -> dict[str, Any]:
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

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest

from ai_signal_hub.repository import Repository
from ai_signal_hub.services import HubService
from ai_signal_hub.similarity import extract_feature_groups
from ai_signal_hub.storage import UploadTooLarge, safe_report_suffix, stream_to_temporary


PROJECT = Path(__file__).resolve().parents[1]


def test_storage_limits_and_report_whitelist(tmp_path: Path) -> None:
    with pytest.raises(UploadTooLarge):
        stream_to_temporary(BytesIO(b"x" * 11), tmp_path, 10)
    assert safe_report_suffix("report.PDF") == ".pdf"
    with pytest.raises(ValueError):
        safe_report_suffix("payload.exe")


def test_similarity_ignores_unknown_placeholders() -> None:
    groups = extract_feature_groups(
        {
            "features": {"toolchain": {"evidence": []}, "prompt": {}, "code_style": {}},
            "classification": {
                "model_attribution": {"vendor": None, "family": "unknown", "model": "—"}
            },
        }
    )
    assert groups["toolchain"] == {}


def test_legacy_import_is_idempotent(platform: tuple[HubService, Repository]) -> None:
    service, repository = platform
    first = service.import_legacy(include_reports=True)
    second = service.import_legacy(include_reports=True)
    assert first["samples_imported"] == 45
    assert first["events_imported"] == 11
    assert first["reports_imported"] == 9
    assert first["family_cases_linked"] == 9
    assert not first["errors"]
    assert not second["errors"]
    stats = repository.statistics()
    assert stats["totals"]["samples"] == 45
    assert stats["totals"]["events"] == 11
    assert stats["totals"]["global_ai_security_events"] == 25
    assert stats["totals"]["analyzable_events"] == 9
    assert stats["totals"]["events_without_samples"] == 16
    assert stats["totals"]["sample_families"] == 9
    assert stats["totals"]["logical_reports"] == 7
    assert stats["totals"]["family_report_mappings"] == 9
    search = repository.search("fruitshell", limit=100)
    assert search["summary"] == {"families": 1, "samples": 1, "reports": 1, "events": 1}
    assert search["results"][0]["subject"]["family"] == "FRUITSHELL"
    assert search["results"][0]["samples"][0]["source_case"] == "FRUITSHELL"
    assert "GTIG AI Threat Tracker" in search["results"][0]["reports"][0]["title"]
    assert [item["name"] for item in search["results"][0]["reports"][0]["target_events"]] == ["FRUITSHELL"]
    assert search["unlinked_direct_matches"] == {"reports": [], "events": []}


def test_sample_report_cross_validation_and_report_generation(
    platform: tuple[HubService, Repository],
    report_model,
) -> None:
    service, repository = platform
    sample_path = PROJECT / "tests" / "fixtures" / "sanitized" / "promptflux.txt"
    report_path = PROJECT / "tests" / "fixtures" / "reports" / "promptflux_report.html"

    with sample_path.open("rb") as handle:
        sample = service.analyze_sample(handle, sample_path.name, "PROMPTFLUX")
    with report_path.open("rb") as handle, pytest.raises(ValueError, match="必须指定"):
        service.analyze_report(handle, report_path.name, None, False, None)
    with report_path.open("rb") as handle:
        report = service.analyze_report(
            handle, report_path.name, None, target_name="PROMPTFLUX"
        )

    event_id = report["result_json"]["events"][0]["event_id"]
    assert len(report["result_json"]["events"]) == 1
    assert report["result_json"]["events"][0]["identity"]["event_name"] == "PROMPTFLUX"
    assert report["result_json"]["extraction"]["target_event_only"] is True
    validation = service.cross_validate(
        sample_sha256=sample["sha256"],
        report_id=report["report_id"],
        event_id=event_id,
        sample_family="PROMPTFLUX",
    )
    assert validation["summary"]["supports"] >= 1
    assert validation["summary"]["complements"] >= 1

    generated = service.generate_report(
        title="自动化测试报告", date_from=None, date_to=None
    )
    assert "本地知识库" in generated["content"]
    assert generated["snapshot"]["totals"]["samples"] == 1
    assert generated["snapshot"]["totals"]["reports"] == 1
    assert generated["snapshot"]["totals"]["sample_families"] == 1
    assert Path(generated["file_path"]).is_file()


def test_joint_case_can_be_completed_later_and_sample_relations_are_automatic(
    platform: tuple[HubService, Repository],
    report_model,
) -> None:
    service, repository = platform
    sample_path = PROJECT / "tests" / "fixtures" / "sanitized" / "promptflux.txt"
    second_sample_path = PROJECT / "tests" / "fixtures" / "sanitized" / "fruitshell.txt"
    report_path = PROJECT / "tests" / "fixtures" / "reports" / "promptflux_report.html"

    with sample_path.open("rb") as handle:
        first = service.analyze_case(
            case_id=None,
            title="PROMPTFLUX 联合分析",
            notes="先上传样本",
            sample_source=handle,
            sample_filename=sample_path.name,
            existing_sample_sha256=None,
            report_source=None,
            report_filename=None,
            existing_report_id=None,
            source_case="PROMPTFLUX",
            canonical_url=None,
            use_llm=False,
        )
    assert first["case"]["status"] == "waiting_for_report"
    assert len(first["case"]["samples"]) == 1
    assert len(first["case"]["reports"]) == 0

    with report_path.open("rb") as handle:
        completed = service.analyze_case(
            case_id=first["case"]["id"],
            title=None,
            notes="后补对应报告",
            sample_source=None,
            sample_filename=None,
            existing_sample_sha256=None,
            report_source=handle,
            report_filename=report_path.name,
            existing_report_id=None,
            source_case="PROMPTFLUX",
            canonical_url=None,
            use_llm=True,
        )
    assert completed["case"]["status"] == "ready_for_review"
    assert len(completed["case"]["samples"]) == 1
    assert len(completed["case"]["reports"]) == 1
    assert completed["cross_validation"]["summary"]["supports"] >= 1
    assert completed["joint_summary"]["case_subject"]["event_name"] == "PROMPTFLUX"
    repeated = service.cross_validate_case(case_id=first["case"]["id"])
    assert repeated["cross_validation"]["summary"]["supports"] >= 1
    assert repeated["joint_summary"]["report_complements"]

    with second_sample_path.open("rb") as handle:
        second = service.analyze_sample(handle, second_sample_path.name, "FRUITSHELL")
    associations = repository.sample_associations(second["sha256"], limit=10)
    assert associations["cluster"] is not None
    assert len(associations["related_samples"]) == 1
    related = associations["related_samples"][0]
    assert 0.0 <= related["overall_similarity"] <= 1.0
    assert {"toolchain_similarity", "prompt_similarity", "code_style_similarity"} <= set(related)
    assert all("unknown" not in feature for feature in related["common_features"])

    filtered = service.generate_report(
        title="空时间范围测试",
        date_from="2000-01-01",
        date_to="2000-01-02",
    )
    assert filtered["snapshot"]["range"] == {
        "date_from": "2000-01-01",
        "date_to": "2000-01-02",
    }
    assert filtered["snapshot"]["totals"]["samples"] == 0
    assert filtered["snapshot"]["totals"]["reports"] == 0
    assert "筛选区间：2000-01-01 至 2000-01-02" in filtered["content"]


def test_joint_summary_exposes_prompt_evidence_and_persists_manual_context(platform) -> None:
    service, repository = platform
    sha256 = "d" * 64
    sample = repository.upsert_sample({
        "sample": {"sha256": sha256},
        "classification": {"model_attribution": {"vendor": "OpenAI", "family": "GPT", "model": "gpt-test"}},
        "features": {
            "toolchain": {"evidence": []},
            "prompt": {"embedded_prompts": [{"text": "Return only the requested code.", "source": "strings:ascii", "features": ["code_only"]}]},
            "code_style": {},
        },
    }, source_case="TEST-FAMILY")
    event_id = "event:context-test"
    report_result = {
        "report": {"report_id": "report:context-test", "title": "Context report"},
        "extraction": {"validation_status": "valid"},
        "events": [{
            "event_id": event_id,
            "identity": {"event_name": "TEST-FAMILY"},
            "attribution": {"actors": [{"name": "APT-Test", "country_or_region": "Country-A"}]},
            "targets": [{"name": "Victim-Org", "country_or_region": "Region-B"}],
            "ai_signals": {"toolchain": [], "prompts": [{
                "availability": "described_only", "text": None, "purpose": "生成代码",
                "target_model": None, "structural_features": {}, "constraints": [],
                "evidence_ids": ["evidence:prompt"],
            }], "code_style": []},
            "evidence": [{"evidence_id": "evidence:prompt", "excerpt": "The malware sends a detailed instruction to the model."}],
        }],
    }
    report = repository.upsert_report(report_result, original_name="context.md", artifact_path=None)
    summary = service.build_joint_summary(sample, report["result_json"], None, event_id)
    assert summary["sample_prompt_features"]["prompts"][0]["text"] == "Return only the requested code."
    assert summary["report_prompt_features"][0]["text"] is None
    assert summary["report_prompt_features"][0]["evidence_excerpts"]
    assert summary["event_context"]["effective"] == {
        "organizations": ["APT-Test", "Victim-Org"],
        "countries_or_regions": ["Country-A", "Region-B"],
    }

    updated = repository.save_event_context_override(
        event_id, organizations=["人工组织"], countries_or_regions=["人工地区"]
    )
    assert updated["source"] == "manual_override"
    assert updated["effective"] == {
        "organizations": ["人工组织"], "countries_or_regions": ["人工地区"]
    }
    assert updated["extracted"]["organizations"] == ["APT-Test", "Victim-Org"]


def test_cross_validation_save_is_idempotent_for_same_object(platform) -> None:
    _, repository = platform
    sha256 = "e" * 64
    repository.upsert_sample({"sample": {"sha256": sha256}}, source_case="TEST")
    report = repository.upsert_report(
        {"report": {"report_id": "report:idempotent", "title": "Idempotent"}, "events": []},
        original_name="idempotent.md", artifact_path=None,
    )
    result = {"summary": {"supports": 1, "contradicts": 0, "complements": 0, "inconclusive": 0}}
    first = repository.save_cross_validation(sha256, report["report_id"], "event:x", result)
    second = repository.save_cross_validation(sha256, report["report_id"], "event:x", result)
    assert first["id"] == second["id"]
    stats = repository.statistics()
    assert "cross_validations" not in stats["totals"]
    assert stats["totals"]["cross_validation_records"] == 1

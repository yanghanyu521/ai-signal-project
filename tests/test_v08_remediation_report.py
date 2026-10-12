from __future__ import annotations

from scripts.report_v08_remediation import _group, markdown


def test_zip_containing_executable_is_in_binary_package_group() -> None:
    assert _group({"format": "zip"}) == "binary_or_package"


def test_report_never_presents_candidate_volume_as_accuracy() -> None:
    count = {key: 0 for key in (
        "toolchain_candidates", "prompt_candidates", "relation_verified_tools",
        "llm_toolchain_location_candidates", "llm_toolchain_semantic_confirmed",
        "llm_toolchain_static_call_verified",
        "relation_verified_prompts", "fingerprint", "main_requests", "style_requests",
        "main_tokens", "style_tokens", "strings_discovered", "strings_retained",
        "string_units_screened", "strings_rejected_by_limit", "bytes_scanned",
        "byte_scan_denominator", "archive_members_discovered", "archive_members_considered",
        "archive_members_recovered", "member_rejected_by_limit", "member_bytes_scanned")}
    result = {"post_result_files": 0, "post_fully_analyzed": 0,
              "same_sha_across_available_versions": True,
              "groups": {name: {"samples": 0, "versions": {v: {**count, "llm_statuses": {}} for v in (
                  "v07_rule", "v07_llm", "v08_pre", "v08_post")}}
                  for name in ("script_source", "binary_or_package", "other_or_unresolved")}}
    report = markdown(result)
    assert "候选记录数，不是正确数" in report
    assert "尚待" not in report or "人工" in report
    assert "0/45" in report
    result["post_fully_analyzed"] = 45
    assert "45 份主 LLM 运行状态均为 completed" in markdown(result)

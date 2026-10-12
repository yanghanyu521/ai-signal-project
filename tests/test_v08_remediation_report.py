from __future__ import annotations

from scripts.report_v08_remediation import markdown


def test_report_never_presents_candidate_volume_as_accuracy() -> None:
    count = {key: 0 for key in (
        "toolchain_candidates", "prompt_candidates", "relation_verified_tools",
        "relation_verified_prompts", "fingerprint", "main_requests", "style_requests",
        "main_tokens", "style_tokens", "strings_discovered", "strings_retained",
        "string_units_screened", "strings_rejected_by_limit")}
    result = {"post_result_files": 0, "same_sha_across_available_versions": True,
              "groups": {name: {"samples": 0, "versions": {v: dict(count) for v in (
                  "v07_rule", "v07_llm", "v08_pre", "v08_post")}}
                  for name in ("script_source", "binary_or_package", "other_or_unresolved")}}
    report = markdown(result)
    assert "候选记录数，不是正确数" in report
    assert "尚待" not in report or "人工" in report
    assert "0/45" in report

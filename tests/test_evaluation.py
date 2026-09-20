from __future__ import annotations

from evaluation.run_eval import run


def test_harmless_evaluation_suite_runs_and_reports_required_metrics() -> None:
    result = run()
    assert result["case_count"] == 11
    required = {
        "model_identifier_precision", "model_identifier_recall",
        "model_vendor_false_attribution_rate", "prompt_component_precision",
        "prompt_component_recall", "prompt_call_binding_precision",
        "decoy_false_positive_rate", "role_error_rate", "citation_validity_rate",
        "relation_verified_precision", "analysis_failure_rate", "average_requests",
        "average_tokens", "average_latency",
    }
    assert required <= result["metrics"].keys()
    assert all(item["id"] in set("ABCDEFGHIJK") for item in result["details"])

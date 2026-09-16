from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest


@pytest.mark.parametrize("page", ["intake.py", "report_analysis.py"])
def test_report_pages_explain_default_llm_and_have_no_opt_in_switch(monkeypatch, page):
    ui = Path(__file__).resolve().parents[1] / "ui"
    monkeypatch.syspath_prepend(str(ui))
    from ui_utils import api
    monkeypatch.setattr(api, "get_json", lambda *args, **kwargs: [])
    # Isolated page test: these pages have no relative navigation of their own.
    app = AppTest.from_file(ui / "app_pages" / page)
    app.session_state["api_base_url"] = "http://test.invalid"
    app.run()
    assert not app.exception
    assert not app.checkbox
    assert any("大模型" in item.value and "全文" in item.value for item in app.info)


def test_joint_summary_displays_prompt_text_and_chinese_context(monkeypatch):
    ui = Path(__file__).resolve().parents[1] / "ui"
    monkeypatch.syspath_prepend(str(ui))

    def page():
        from ui_utils.presenters import render_joint_summary
        render_joint_summary({
            "case_subject": {"sample_family": "TEST", "event_name": "TEST"},
            "sample_ai_toolchain": {"model_attribution": {"vendor": "OpenAI", "family": "GPT", "model": "gpt-test"}},
            "report_ai_toolchain": [],
            "sample_prompt_features": {
                "embedded_prompt_count": 1, "structural_features": ["code_only"], "special_tokens": [],
                "prompts": [{"text": "Return only code.", "source": "静态字符串", "features": ["code_only"]}],
            },
            "report_prompt_features": [{
                "availability": "described_only", "text": None, "purpose": "生成代码",
                "target_model": None, "structural_features": [], "constraints": [],
                "evidence_excerpts": ["The report describes an instruction sent to a model."],
            }],
            "event_context": {
                "effective": {"organizations": ["APT-Test"], "countries_or_regions": ["Region-Test"]},
                "source": "report_extraction", "editable": False,
            },
            "confirmed": [], "report_complements": [], "conflicts": [],
            "supplementary_report_features": {},
        })

    app = AppTest.from_function(page).run()
    assert not app.exception
    assert any(item.value == "Return only code." for item in app.code)
    assert any("未披露" in item.label for item in app.expander)
    markdown = "\n".join(item.value for item in app.markdown)
    assert "相关组织" in markdown and "APT-Test" in markdown
    assert "国家/地区" in markdown and "Region-Test" in markdown


def test_dashboard_uses_business_event_scope(monkeypatch):
    ui = Path(__file__).resolve().parents[1] / "ui"
    monkeypatch.syspath_prepend(str(ui))
    from ui_utils import api

    stats = {
        "totals": {
            "global_ai_security_events": 25, "analyzable_events": 9, "events_without_samples": 16,
            "sample_families": 9, "samples": 45, "logical_reports": 7,
            "family_report_mappings": 9, "cross_validation_records": 22,
            "curated_research_events": 11, "report_event_records": 18, "report_records": 9,
            "analysis_cases": 13, "event_records": 29,
        },
        "event_monthly": [], "knowledge_monthly": [], "sample_classification": [],
        "sample_family_distribution": [], "model_distribution": [], "scope": "测试口径", "as_of": "now",
    }
    monkeypatch.setattr(api, "get_json", lambda *args, **kwargs: stats)
    app = AppTest.from_file(ui / "app_pages" / "dashboard.py")
    app.session_state["api_base_url"] = "http://test.invalid"
    app.run()
    assert not app.exception
    labels = {item.label: item.value for item in app.metric}
    assert labels["全球 AI 安全事件"] == "25"
    assert labels["有样本、可分析事件"] == "9"
    assert labels["暂无样本事件"] == "16"
    assert "已交叉验证对象" not in labels


def test_knowledge_search_groups_sample_with_its_report(monkeypatch):
    ui = Path(__file__).resolve().parents[1] / "ui"
    monkeypatch.syspath_prepend(str(ui))
    from ui_utils import api

    response = {
        "summary": {"families": 1, "samples": 1, "reports": 1, "events": 1},
        "results": [{
            "subject": {"family": "FRUITSHELL", "match_reasons": ["sample_match", "event_name_match"]},
            "samples": [{
                "sha256": "f" * 64, "original_name": "fruitshell.exe", "source_case": "FRUITSHELL",
                "llm_label": "confirmed", "model_vendor": None, "model_family": None,
                "model_name": None, "status": "analyzed",
            }],
            "reports": [{
                "report_id": "report:test", "title": "GTIG AI Threat Tracker", "publisher": "Google",
                "publication_date": "2025-01-01", "relations": [{
                    "type": "analysis_case", "case_title": "FRUITSHELL 家族知识案例",
                }],
                "target_events": [{"name": "FRUITSHELL", "event_type": "malware"}],
            }],
        }],
        "unlinked_direct_matches": {"reports": [], "events": []},
        "interpretation": "关联检索",
    }
    monkeypatch.setattr(api, "get_json", lambda *args, **kwargs: response)
    app = AppTest.from_file(ui / "app_pages" / "knowledge.py")
    app.session_state["api_base_url"] = "http://test.invalid"
    app.run()
    app.text_input[0].input("fruitshell")
    app.button[0].click().run()
    assert not app.exception
    assert not app.tabs
    labels = {item.label: item.value for item in app.metric}
    assert labels["关联样本"] == "1" and labels["对应报告"] == "1"
    markdown = "\n".join(item.value for item in app.markdown)
    assert "GTIG AI Threat Tracker" in markdown
    assert "分析案例中的家族—报告关系" in "\n".join(item.value for item in app.caption)

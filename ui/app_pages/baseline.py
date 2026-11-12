from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

BASELINE_DIR = Path(__file__).resolve().parents[2] / "evaluation" / "script_baseline"
METRICS_PATH = BASELINE_DIR.parent / "script_baseline_metrics.json"

SCOPE_LABELS = {
    "script_with_ai_calls": "含 AI 调用",
    "script_llm_assisted_no_ai_calls": "LLM 辅助开发·无 AI 调用",
}
CATEGORY_BADGES = {
    "program_prompt": ":blue-badge[程序提示词]",
    "jailbreak_prompt": ":red-badge[越狱提示词]",
    "analyzer_injection": ":violet-badge[分析器注入]",
    "prompt_template_prefix": ":gray-badge[模板前缀]",
    "image_generation_prompt": ":orange-badge[图像提示词]",
    "image_generation_negative_prompt": ":orange-badge[图像负面提示词]",
    "other": ":gray-badge[其他]",
}
RELATION_BADGES = {
    "supports": ":green-badge[supports]",
    "complements": ":blue-badge[complements]",
    "contradicts": ":red-badge[contradicts]",
}


@st.cache_data
def load_baseline() -> tuple[list[dict], dict]:
    samples = []
    report_side = {}
    for path in sorted(BASELINE_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if path.name == "report_side.json":
            report_side = data
            continue
        for sample in data["samples"]:
            sample["family"] = data["family"]
            sample["language"] = data["language"]
            samples.append(sample)
    return samples, report_side


def calling_badge(value) -> str:
    if value is True:
        return ":blue-badge[AI 调用确认]"
    if value is False:
        return ":green-badge[无 AI 调用]"
    return ":orange-badge[静态不可确认]"


def render_toolchain(toolchain: list[dict]) -> None:
    rows = []
    for tool in toolchain:
        rows.append({
            "模型": tool.get("model") or "—",
            "SDK / 调用": tool.get("sdk") or tool.get("type") or "—",
            "端点 / CLI": tool.get("endpoint") or json.dumps(tool.get("clis", ""), ensure_ascii=False)[:120],
            "认证": tool.get("auth") or "—",
        })
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def render_sample(sample: dict) -> None:
    with st.container(border=True):
        st.markdown(f"**{sample['family']}** · `{sample['sha256'][:24]}…`")
        badges = [calling_badge(sample["ai_calling"]), f":gray-badge[{sample['language']}]"]
        if sample.get("obfuscation"):
            badges.append(":orange-badge[混淆]")
        st.markdown(" ".join(badges))
        if sample.get("same_as"):
            st.caption(f"近重复变体，基准继承自 {sample['same_as'][:16]}…；差异：{sample.get('differences_from_reference')}")
        if sample.get("behavior_summary"):
            st.write(sample["behavior_summary"])
        if sample.get("network_indicators"):
            st.caption("网络指标：" + "；".join(sample["network_indicators"]))
        toolchain = sample.get("toolchain") or []
        if toolchain:
            st.markdown(":material/build: **工具链**")
            render_toolchain(toolchain)
        prompts = sample.get("prompts") or []
        if prompts:
            st.markdown(f":material/chat: **提示词（{len(prompts)} 条）**")
            for prompt in prompts:
                badge = CATEGORY_BADGES.get(prompt.get("category"), ":gray-badge[提示词]")
                st.markdown(f"{badge} `{prompt.get('id')}`")
                text = prompt.get("text") or prompt.get("decoded_text") or prompt.get("text_prefix")
                if text:
                    st.code(text, language=None, wrap_lines=True)
                for element in prompt.get("key_elements") or []:
                    st.caption(f"· {element}")
                for item in prompt.get("items") or []:
                    st.caption(f"· {item}")
                if prompt.get("purpose"):
                    st.caption(f"用途：{prompt['purpose']}")
        expectations = sample.get("extraction_expectations") or {}
        if expectations:
            must_find = expectations.get("must_find") or []
            must_not = expectations.get("must_not_claim") or []
            left, right = st.columns(2)
            with left:
                st.markdown(":material/check_circle: **必须提取**")
                for item in must_find:
                    st.caption(f"· {item}")
            with right:
                st.markdown(":material/block: **禁止输出（幻觉检查）**")
                for item in must_not:
                    st.caption(f"· {item}")


st.title(":material/fact_check: 真实脚本基准与提取评估")
st.caption(
    "19 个真实恶意脚本的人工分析基准：13 个可确认 AI 调用、2 个混淆不可静态确认、1 个分析器注入、"
    "3 个 LLM 辅助开发。基准只含特征与证据行号，不含恶意代码本体。"
)

samples, report_side = load_baseline()
tab_samples, tab_reports, tab_metrics = st.tabs([
    ":material/list: 样本基准", ":material/article: 报告侧基准", ":material/analytics: 评分结果",
])

with tab_samples:
    families = sorted({sample["family"] for sample in samples})
    selected_family = st.pills("家族筛选", ["全部"] + families, default="全部")
    scope_filter = st.segmented_control(
        "分析范围", ["全部", "含 AI 调用", "LLM 辅助开发·无 AI 调用"], default="全部"
    )
    visible = [
        sample for sample in samples
        if (selected_family in (None, "全部") or sample["family"] == selected_family)
        and (scope_filter in (None, "全部") or sample["analysis_scope"].startswith(
            "script_with_ai_calls" if scope_filter == "含 AI 调用" else "script_llm_assisted"
        ))
    ]
    left, right, middle = st.columns(3)
    left.metric("基准样本", len(samples), border=True)
    right.metric("可确认 AI 调用", sum(sample["ai_calling"] is True for sample in samples), border=True)
    middle.metric("当前筛选", len(visible), border=True)
    st.dataframe(
        pd.DataFrame([
            {
                "家族": sample["family"],
                "SHA-256 前12位": sample["sha256"][:12],
                "语言": sample["language"],
                "范围": SCOPE_LABELS.get(sample["analysis_scope"], sample["analysis_scope"]),
                "混淆": sample.get("obfuscation") or "无",
                "提示词数": len(sample.get("prompts") or []),
            }
            for sample in visible
        ]),
        hide_index=True,
        width="stretch",
    )
    for sample in visible:
        render_sample(sample)

with tab_reports:
    st.caption("报告侧特征与样本侧的预期交叉验证关系；组织/国家/时间字段只允许 complements。")
    for family in report_side.get("families", []):
        with st.container(border=True):
            st.markdown(f"**{family['family']}**")
            for report in family.get("reports", []):
                st.markdown(f":material/article: {report.get('source')}")
                st.caption(json.dumps(
                    {key: value for key, value in report.items() if key != "source"}, ensure_ascii=False))
            for relation in family.get("cross_validation_expectations", []):
                badge = RELATION_BADGES.get(relation["relation"], ":gray-badge[?]")
                st.markdown(f"{badge} {relation['field']}")
                if relation.get("note"):
                    st.caption(relation["note"])
            if family.get("note"):
                st.info(family["note"], icon=":material/info:")

with tab_metrics:
    if not METRICS_PATH.is_file():
        st.info(
            "尚无评分结果。对样本运行分析后执行：\n\n"
            "```powershell\n"
            ".\\.venv\\Scripts\\python.exe .\\evaluation\\run_script_baseline.py "
            "--results-dir .\\data\\artifacts\\samples\n```",
            icon=":material/info:",
        )
    else:
        metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
        scored = metrics.get("scored", 0)
        clean = metrics.get("clean_samples", 0)
        if scored and clean == scored:
            st.success(f"全部 {scored} 个已评分样本通过基准检查，未发现幻觉或漏提。", icon=":material/check_circle:")
        left, right, middle = st.columns(3)
        left.metric("已评分样本", scored, border=True)
        right.metric("无问题样本", clean, border=True)
        middle.metric("未评分", metrics.get("missing_or_not_completed", 0), border=True)
        finding_counts = metrics.get("finding_counts") or {}
        if finding_counts:
            st.markdown("**问题分类统计**")
            st.dataframe(pd.DataFrame(
                [{"问题类型": key, "次数": value} for key, value in finding_counts.items()]
            ), hide_index=True, width="stretch")
        st.dataframe(
            pd.DataFrame([
                {
                    "家族": item.get("family"),
                    "SHA-256 前12位": item["sha256"][:12],
                    "状态": item["status"],
                    "问题数": len(item.get("findings") or []),
                    "问题": "; ".join(f["check"] for f in item.get("findings") or []),
                }
                for item in metrics.get("details", [])
            ]),
            hide_index=True,
            width="stretch",
            column_config={
                "状态": st.column_config.TextColumn("状态", help="scored=已评分；其他为未评分原因"),
            },
        )

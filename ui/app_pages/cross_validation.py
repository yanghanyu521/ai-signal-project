from __future__ import annotations

import streamlit as st

from ui_utils.api import ApiError, api_base_url, get_json, post_json
from ui_utils.presenters import render_event_context_editor, render_joint_summary


st.title("按分析案例执行交叉验证")
st.caption("先选择联合分析案例，系统只允许比较该案例中已经对应的样本和报告，避免任意对象误配。")

try:
    cases = get_json(api_base_url(), "/api/v1/analysis-cases", (("limit", 500),))
except ApiError as exc:
    st.error(str(exc))
    st.stop()

ready_cases = [item for item in cases if item.get("sample_count", 0) and item.get("report_count", 0)]
if not ready_cases:
    st.info("暂无同时包含样本和报告的案例。请先在“联合分析”页面补齐案例。")
    st.stop()

case_options = {
    f"{item['title']} · {item['status']} · {item['id'][:8]}": item["id"]
    for item in ready_cases
}
case_label = st.selectbox("分析案例", list(case_options))
case_id = case_options[case_label]

try:
    case = get_json(api_base_url(), f"/api/v1/analysis-cases/{case_id}")
except ApiError as exc:
    st.error(str(exc))
    st.stop()

sample_options = {
    f"{item.get('source_case') or '未标注'} · {item['sha256'][:12]}…": item["sha256"]
    for item in case["samples"]
}
report_options = {
    f"{item.get('title') or item['report_id']} · {item['report_id'][:12]}…": item["report_id"]
    for item in case["reports"]
}

with st.container(border=True):
    st.write(f"**案例状态：** {case['status']}")
    st.write(f"**案例样本：** {len(sample_options)} 个")
    st.write(f"**案例报告：** {len(report_options)} 份")

with st.form("case_cross_validation", border=True):
    sample_label = st.selectbox("案例内样本", list(sample_options), disabled=len(sample_options) == 1)
    report_label = st.selectbox("案例内报告", list(report_options), disabled=len(report_options) == 1)
    st.caption("单样本、单报告案例会自动选择；复杂案例只允许从当前案例内部选择。")
    submitted = st.form_submit_button("执行交叉验证", type="primary", icon=":material/compare_arrows:")

if submitted:
    try:
        with st.status("正在核对样本静态证据与报告原文证据…") as status:
            result = post_json(
                api_base_url(),
                f"/api/v1/analysis-cases/{case_id}/cross-validate",
                {
                    "sample_sha256": sample_options[sample_label],
                    "report_id": report_options[report_label],
                    "event_id": None,
                },
            )
            status.update(label="交叉验证完成", state="complete")
        st.session_state["latest_cross_validation"] = result
    except ApiError as exc:
        st.error(str(exc))

latest = st.session_state.get("latest_cross_validation")
if latest and (latest.get("case") or {}).get("id") == case_id:
    render_joint_summary(latest["joint_summary"])
    render_event_context_editor(latest["joint_summary"], key_prefix="cross_validation")
    with st.expander("原始验证结果（审计用）", icon=":material/data_object:"):
        st.json(latest)

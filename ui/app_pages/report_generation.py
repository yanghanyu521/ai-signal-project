from __future__ import annotations

from datetime import date

import streamlit as st

from ui_utils.api import ApiError, api_base_url, post_json


st.title("自动生成统计报告")
st.caption("报告保存生成时的统计快照；选择时间范围后，事件按发生日期过滤，样本、报告、案例和交叉验证按知识库创建日期过滤。")

with st.form("generate_report", border=True):
    title = st.text_input("报告标题", value="AI 安全事件与样本分析统计报告")
    date_range = st.date_input("统计时间范围（可选）", value=())
    submitted = st.form_submit_button("生成 Markdown 报告", type="primary", icon=":material/description:")

if submitted:
    date_from = date_range[0].isoformat() if len(date_range) == 2 else None
    date_to = date_range[1].isoformat() if len(date_range) == 2 else None
    try:
        result = post_json(
            api_base_url(),
            "/api/v1/generated-reports",
            {"title": title, "date_from": date_from, "date_to": date_to},
        )
        st.success("报告已生成并保存。")
        st.download_button(
            "下载 Markdown",
            result["content"],
            file_name=f"{result['id']}.md",
            mime="text/markdown",
            icon=":material/download:",
        )
        st.markdown(result["content"])
    except ApiError as exc:
        st.error(str(exc))

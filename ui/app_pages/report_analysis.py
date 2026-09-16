from __future__ import annotations

import streamlit as st

from ui_utils.api import ApiError, api_base_url, post_file


st.title("安全报告事件抽取")
st.caption("支持 PDF、HTML、DOCX、Markdown 和 TXT。必须先指定样本/家族，只抽取报告中与该目标对应的事件。")

with st.form("report_upload", border=True):
    uploaded = st.file_uploader("选择报告", type=["pdf", "html", "htm", "docx", "md", "txt"])
    target_name = st.text_input("目标样本/家族", placeholder="例如 PROMPTFLUX")
    target_aliases = st.text_input("目标别名（可选，逗号分隔）")
    canonical_url = st.text_input("报告原始 URL（可选）")
    st.info(
        "默认直接使用大模型：提交后，解析出的报告全文将发送到已配置的 DeepSeek 兼容接口。"
        "不进行规则预筛选；仅容量超限时全覆盖分块。结果保留原文证据并需人工复核，失败不会回退规则。"
    )
    submitted = st.form_submit_button("抽取报告事件", type="primary", icon=":material/article:")

if submitted:
    if not uploaded or not target_name.strip():
        st.error("请先选择报告并填写目标样本/家族。")
    else:
        try:
            with st.status("正在解析报告并构建事件证据…", expanded=True) as status:
                result = post_file(
                    api_base_url(),
                    "/api/v1/reports/analyze",
                    filename=uploaded.name,
                    content=uploaded.getvalue(),
                    data={
                        "canonical_url": canonical_url,
                        "target_name": target_name,
                        "target_aliases": target_aliases,
                    },
                )
                status.update(label="报告抽取完成并已写入知识库", state="complete")
            with st.container(horizontal=True):
                st.metric("报告 ID", result["report_id"][:16] + "…", border=True)
                st.metric("事件数", len(result["events"]), border=True)
                st.metric("校验状态", result["status"], border=True)
            st.dataframe(result["events"], hide_index=True)
            with st.expander("完整安全结构化结果"):
                st.json(result["result_json"])
        except ApiError as exc:
            st.error(str(exc))

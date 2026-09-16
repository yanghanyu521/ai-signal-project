from __future__ import annotations

import streamlit as st

from ui_utils.api import ApiError, api_base_url, post_file


st.title("恶意样本静态分析")
st.warning("只上传已获授权的样本。平台仅做静态读取，禁止运行、导入、调试、仿真或外传样本。")

with st.form("sample_upload", border=True):
    uploaded = st.file_uploader("选择单个样本", accept_multiple_files=False)
    source_case = st.text_input("来源或案例（可选）", placeholder="例如 PromptLock")
    submitted = st.form_submit_button("开始静态分析", type="primary", icon=":material/bug_report:")

if submitted:
    if not uploaded:
        st.error("请先选择样本。")
    else:
        try:
            with st.status("正在上传并进行纯静态分析…", expanded=True) as status:
                result = post_file(
                    api_base_url(),
                    "/api/v1/samples/analyze",
                    filename=uploaded.name,
                    content=uploaded.getvalue(),
                    data={"source_case": source_case},
                )
                status.update(label="分析完成并已写入知识库", state="complete")
            classification = result["result_json"]["classification"]
            with st.container(horizontal=True):
                st.metric("SHA-256", result["sha256"][:16] + "…", border=True)
                st.metric("LLM 参与", classification["llm_involvement"]["label"], border=True)
                st.metric("具体模型", classification["model_attribution"].get("model") or "unknown", border=True)
            with st.expander("完整安全结构化结果"):
                st.json(result["result_json"])
        except ApiError as exc:
            st.error(str(exc))

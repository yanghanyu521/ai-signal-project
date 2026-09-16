from __future__ import annotations

import os

import streamlit as st


st.set_page_config(
    page_title="AI 信号提取统一平台",
    page_icon=":material/security:",
    layout="wide",
)

st.session_state.setdefault(
    "api_base_url", os.getenv("AI_SIGNAL_HUB_API_BASE_URL", "http://127.0.0.1:8000")
)

with st.sidebar:
    st.text_input("API 地址", key="api_base_url")
    st.caption("测试界面只调用 FastAPI，不直接读取知识库或恶意样本。")
    st.caption("v0.3 · 样本本地静态分析 · 报告大模型提取")

pages = [
    st.Page("app_pages/dashboard.py", title="全局看板", icon=":material/monitoring:"),
    st.Page("app_pages/intake.py", title="联合分析", icon=":material/add_link:"),
    st.Page("app_pages/sample_associations.py", title="样本关联", icon=":material/hub:"),
    st.Page("app_pages/cross_validation.py", title="交叉验证", icon=":material/compare_arrows:"),
    st.Page("app_pages/knowledge.py", title="知识库", icon=":material/database:"),
    st.Page("app_pages/report_generation.py", title="生成报告", icon=":material/description:"),
]

navigation = st.navigation(pages)
navigation.run()

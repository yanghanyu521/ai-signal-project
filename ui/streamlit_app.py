from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from ui_utils.style import inject_css


st.set_page_config(
    page_title="AI 信号提取统一平台",
    page_icon=":material/security:",
    layout="wide",
)
inject_css()

st.session_state.setdefault(
    "api_base_url", os.getenv("AI_SIGNAL_HUB_API_BASE_URL", "http://127.0.0.1:8000")
)

st.logo(str(Path(__file__).parent / "assets" / "logo.png"), size="large")

with st.sidebar:
    st.markdown("## :material/security: AI 信号提取平台")
    st.write("恶意脚本静态分析 · 报告大模型提取")
    st.markdown(":violet-badge[v0.9] :blue-badge[仅脚本样本] :green-badge[纯静态·不外传]")
    st.space("small")

pages = {
    "总览": [
        st.Page("app_pages/dashboard.py", title="全局看板", icon=":material/monitoring:"),
    ],
    "分析工作台": [
        st.Page("app_pages/intake.py", title="联合分析", icon=":material/add_link:"),
        st.Page("app_pages/sample_associations.py", title="样本关联", icon=":material/hub:"),
        st.Page("app_pages/cross_validation.py", title="交叉验证", icon=":material/compare_arrows:"),
    ],
    "知识与报告": [
        st.Page("app_pages/knowledge.py", title="知识库", icon=":material/database:"),
        st.Page("app_pages/report_generation.py", title="生成报告", icon=":material/description:"),
    ],
    "质量评估": [
        st.Page("app_pages/baseline.py", title="基准评估", icon=":material/fact_check:"),
    ],
}

navigation = st.navigation(pages)
navigation.run()

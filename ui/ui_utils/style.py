"""App-wide layout polish that native theming cannot express (sidebar font
sizes, nav spacing, card/metric geometry). Colors stay in config.toml."""
from __future__ import annotations

import streamlit as st

APP_CSS = """
<style>
/* ---------- Sidebar ---------- */
section[data-testid="stSidebar"] {
    font-size: 16px;
}
section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"],
section[data-testid="stSidebar"] [data-testid="stPageLink-NavLink"] {
    font-size: 17px;
    font-weight: 500;
    padding: 0.5rem 0.8rem;
    margin-bottom: 2px;
    border-radius: 9px;
}
section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"]:hover,
section[data-testid="stSidebar"] [data-testid="stPageLink-NavLink"]:hover {
    background: rgba(99, 102, 241, 0.09);
}
section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"] {
    font-weight: 650;
}
section[data-testid="stSidebar"] [data-testid="stSidebarNavItems"] {
    gap: 0.15rem;
}
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h2 {
    font-size: 24px;
    margin-bottom: 0.1rem;
}
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
    font-size: 15px;
}

/* ---------- Metric cards ---------- */
[data-testid="stMetric"] {
    border-radius: 14px !important;
    padding: 14px 18px !important;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.06);
}
[data-testid="stMetricLabel"] {
    font-size: 14px;
    font-weight: 500;
}
[data-testid="stMetricValue"] {
    font-size: 30px;
    font-weight: 650;
    line-height: 1.25;
}

/* ---------- Bordered cards / expanders ---------- */
[data-testid="stVerticalBlockBorderWrapper"] {
    border-radius: 14px !important;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
}
[data-testid="stVerticalBlockBorderWrapper"] [data-testid="stMarkdownContainer"] h3 {
    font-size: 19px;
}

/* ---------- Tabs ---------- */
button[data-baseweb="tab"] {
    font-size: 16px;
    font-weight: 500;
}

/* ---------- Buttons ---------- */
.stButton > button, .stFormSubmitButton > button {
    border-radius: 9px;
    font-weight: 500;
}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
    box-shadow: 0 2px 8px rgba(79, 70, 229, 0.28);
}

/* ---------- Data display ---------- */
[data-testid="stDataFrame"] {
    border-radius: 12px;
    overflow: hidden;
}
[data-testid="stCodeBlock"], pre {
    border-radius: 10px;
}
.stMainBlockContainer {
    padding-top: 1.6rem;
}
</style>
"""


def inject_css() -> None:
    st.markdown(APP_CSS, unsafe_allow_html=True)

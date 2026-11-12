from __future__ import annotations

import pandas as pd
import streamlit as st

from ui_utils.api import ApiError, api_base_url, get_json, post_json


st.title(":material/monitoring: 全局态势看板")
st.caption("事件库范围截至 2026-10-17；新增两家族的样本及报告尚未分析入库。主指标与实际处理进度分口径展示。")

with st.container(horizontal=True):
    if st.button("刷新数据", icon=":material/refresh:"):
        get_json.clear()
        st.rerun()
    if st.button("开始联合分析", icon=":material/add_link:", type="primary"):
        st.switch_page("app_pages/intake.py")
    if st.button("查看基准评估", icon=":material/fact_check:"):
        st.switch_page("app_pages/baseline.py")
    with st.popover("导入旧项目数据", icon=":material/database_upload:"):
        st.caption("将旧项目的安全结构化结果幂等导入知识库，不会重复新增。")
        if st.button("确认导入", icon=":material/database_upload:"):
            try:
                with st.status("正在幂等导入安全结构化结果…", expanded=True) as status:
                    result = post_json(
                        api_base_url(),
                        "/api/v1/knowledge/import-legacy",
                        {"include_samples": True, "include_events": True, "include_reports": True},
                    )
                    st.json(result)
                    status.update(label="导入完成", state="complete")
            except ApiError as exc:
                st.error(str(exc))

try:
    stats = get_json(api_base_url(), "/api/v1/statistics/overview")
except ApiError as exc:
    st.error(str(exc))
    st.stop()

totals = dict(stats["totals"])
catalog_keys = (
    "catalog_sample_families",
    "catalog_logical_reports",
    "catalog_family_report_mappings",
)
if any(key not in totals for key in catalog_keys):
    # An API process started before the scope update can read the migrated
    # database totals while still returning the old response shape.
    if (totals.get("global_ai_security_events"), totals.get("analyzable_events")) == (46, 11):
        totals.update(
            catalog_sample_families=11,
            catalog_logical_reports=9,
            catalog_family_report_mappings=11,
        )
        st.warning("运行中的 API 尚未加载新版统计字段；主指标暂按 2026-10-17 事件库口径显示。重启 API 后此提示将自动消失。")
    else:
        st.error("看板与运行中的 API 统计字段不兼容。请重启 API，刷新页面后重试。")
        st.stop()
st.subheader(":material/public: 事件库规模")
with st.container(horizontal=True):
    st.metric("全球 AI 安全事件", totals["global_ai_security_events"], border=True)
    st.metric("有样本、可分析事件", totals["analyzable_events"], border=True)
    st.metric("暂无样本事件", totals["events_without_samples"], border=True)
    st.metric("样本家族", totals["catalog_sample_families"], border=True)
    st.metric("已分析样本", totals["samples"], border=True)

st.subheader(":material/inventory_2: 入库与映射")
with st.container(horizontal=True):
    st.metric("去重报告", totals["catalog_logical_reports"], border=True)
    st.metric("家族—报告映射", totals["catalog_family_report_mappings"], border=True)

st.info(
    f"其中已分析入库 **{totals['sample_families']}** 个家族、**{totals['samples']}** 个样本；"
    f"已入库去重报告 **{totals['logical_reports']}** 份、家族—报告映射 **{totals['family_report_mappings']}** 组。"
    "CLOSEDQUORUM 与 CL-UNK-1211 的样本、报告仍待处理。"
)

with st.container(border=True):
    st.subheader(":material/folder_open: 研究与证据记录口径")
    st.write(
        f"历史研究 CSV 收录 **{totals['curated_research_events']}** 条事件；"
        f"报告抽取产生 **{totals['report_event_records']}** 条目标事件证据；"
        f"报告表保留 **{totals['report_records']}** 条原始记录，按标题逻辑去重后已入库 **{totals['logical_reports']}** 份；"
        f"当前共 **{totals['analysis_cases']}** 个分析案例；"
        f"交叉验证表保留 **{totals['cross_validation_records']}** 条执行记录。"
    )
    st.caption("历史研究事件和已入库记录都不等于事件库中的 46 个全球 AI 安全事件；图表仍仅覆盖已入库数据。")

left, right = st.columns(2)
with left.container(border=True, height="stretch"):
    st.subheader(":material/calendar_month: 历史研究事件发生月")
    monthly = pd.DataFrame(stats["event_monthly"])
    if monthly.empty:
        st.info("暂无日期完整的事件。")
    else:
        st.bar_chart(monthly, x="month", y="count", x_label="月份", y_label="研究事件")

with right.container(border=True, height="stretch"):
    st.subheader(":material/donut_large: 样本静态结论")
    distribution = pd.DataFrame(stats["sample_classification"])
    if distribution.empty:
        st.info("暂无样本。")
    else:
        st.bar_chart(distribution, x="label", y="count", x_label="结论", y_label="样本数")

with st.container(border=True):
    st.subheader(":material/trending_up: 历史研究事件收录月趋势")
    knowledge_monthly = pd.DataFrame(stats["knowledge_monthly"])
    if knowledge_monthly.empty:
        st.info("暂无知识库收录记录。")
    else:
        st.bar_chart(knowledge_monthly, x="month", y="count", x_label="月份", y_label="新收录研究事件")

left, right = st.columns(2)
with left.container(border=True, height="stretch"):
    st.subheader(":material/family_restroom: 样本家族覆盖")
    families = pd.DataFrame(stats["sample_family_distribution"])
    if families.empty:
        st.info("暂无样本家族标注。")
    else:
        st.dataframe(families, hide_index=True)
with right.container(border=True, height="stretch"):
    st.subheader(":material/modeling: 具体模型分布")
    models = pd.DataFrame(stats["model_distribution"])
    if models.empty:
        st.info("暂无具体模型归因。")
    else:
        st.dataframe(models, hide_index=True)

st.caption(f"统计口径：{stats['scope']} · 截止 {stats['as_of']}")
st.caption(f"数据库事件记录共 {totals['event_records']} 条；这是证据/调研物理记录，不是全球事件数。")

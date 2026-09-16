from __future__ import annotations

import pandas as pd
import streamlit as st

from ui_utils.api import ApiError, api_base_url, get_json


st.title("本地知识库关联检索")
st.caption("输入样本名、家族、哈希、模型或报告关键词；结果会沿知识库关系找到匹配样本及其对应报告和目标事件。")

with st.form("knowledge_search", border=False):
    query = st.text_input(
        "关键词", placeholder="例如 FRUITSHELL、PROMPTFLUX、SHA-256、模型或报告标题"
    )
    submitted = st.form_submit_button("检索", type="primary", icon=":material/search:")

if submitted:
    if not query.strip():
        st.error("请输入关键词。")
    else:
        try:
            st.session_state["knowledge_search_result"] = get_json(
                api_base_url(), "/api/v1/knowledge/search",
                (("q", query.strip()), ("limit", 100)),
            )
        except ApiError as exc:
            st.error(str(exc))

result = st.session_state.get("knowledge_search_result")
if result:
    summary = result.get("summary") or {}
    with st.container(horizontal=True):
        st.metric("匹配家族", summary.get("families", 0), border=True)
        st.metric("关联样本", summary.get("samples", 0), border=True)
        st.metric("对应报告", summary.get("reports", 0), border=True)
        st.metric("目标事件记录", summary.get("events", 0), border=True)

    results = result.get("results") or []
    if not results:
        st.info("没有找到能够关联到样本的知识条目。")
    reason_labels = {
        "sample_match": "样本或家族关键词命中",
        "event_name_match": "报告目标事件名称命中",
        "report_match": "报告关键词命中后反查样本",
    }
    relation_labels = {
        "analysis_case": "分析案例中的家族—报告关系",
        "target_event_name": "报告内目标事件名称一致",
    }
    for group in results:
        subject = group.get("subject") or {}
        family = subject.get("label") or subject.get("family") or "未标注样本"
        with st.container(border=True):
            st.subheader(family)
            reasons = [reason_labels.get(item, item) for item in subject.get("match_reasons") or []]
            if reasons:
                st.caption("检索命中依据：" + "、".join(reasons))

            samples = group.get("samples") or []
            st.write(f"**关联样本（{len(samples)}）**")
            if samples:
                st.dataframe(pd.DataFrame([{
                    "SHA-256": item.get("sha256"),
                    "文件名": item.get("original_name"),
                    "静态分析结论": item.get("llm_label"),
                    "模型厂商": item.get("model_vendor"),
                    "模型家族": item.get("model_family"),
                    "具体模型": item.get("model_name"),
                    "分析状态": item.get("status"),
                } for item in samples]), hide_index=True)

            reports = group.get("reports") or []
            st.write(f"**对应报告（{len(reports)}）**")
            if not reports:
                st.warning("该样本/家族尚未建立对应报告关系。")
            for report in reports:
                with st.container(border=True):
                    st.write(f"**{report.get('title') or '未命名报告'}**")
                    st.caption(
                        f"发布方：{report.get('publisher') or '未记录'}　"
                        f"发布日期：{report.get('publication_date') or '未记录'}"
                    )
                    relations = report.get("relations") or []
                    relation_text = []
                    for relation in relations:
                        label = relation_labels.get(relation.get("type"), "知识库关系")
                        if relation.get("case_title"):
                            label += f"（{relation['case_title']}）"
                        relation_text.append(label)
                    st.caption("关联依据：" + "、".join(dict.fromkeys(relation_text)))

                    events = report.get("target_events") or []
                    if events:
                        st.dataframe(pd.DataFrame([{
                            "目标事件": item.get("name"),
                            "事件类型": item.get("event_type"),
                            "发生时间": item.get("event_date"),
                            "相关组织/地区": item.get("actor_region"),
                            "AI参与摘要": item.get("ai_summary"),
                            "模型或服务": item.get("model_service"),
                        } for item in events]), hide_index=True)
                    else:
                        st.caption("该报告已与样本建立关系，但还没有匹配到同名目标事件记录。")

    unlinked = result.get("unlinked_direct_matches") or {}
    if unlinked.get("reports") or unlinked.get("events"):
        with st.expander("未关联到样本的直接关键词命中", icon=":material/link_off:"):
            st.caption("这些记录命中了关键词，但知识库中尚无可靠的样本关系，因此不并入上方结果。")
            if unlinked.get("reports"):
                st.write("**报告**")
                st.dataframe(pd.DataFrame([{
                    "报告标题": item.get("title"), "发布方": item.get("publisher"),
                    "发布日期": item.get("publication_date"), "状态": item.get("status"),
                } for item in unlinked["reports"]]), hide_index=True)
            if unlinked.get("events"):
                st.write("**事件**")
                st.dataframe(pd.DataFrame([{
                    "事件名称": item.get("name"), "事件类型": item.get("event_type"),
                    "发生时间": item.get("event_date"), "相关组织/地区": item.get("actor_region"),
                    "AI参与摘要": item.get("ai_summary"), "模型或服务": item.get("model_service"),
                } for item in unlinked["events"]]), hide_index=True)
    st.caption(result.get("interpretation") or "")

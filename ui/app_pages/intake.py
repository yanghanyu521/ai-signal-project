from __future__ import annotations

import pandas as pd
import streamlit as st

from ui_utils.api import ApiError, api_base_url, get_json, post_files
from ui_utils.presenters import render_event_context_editor, render_joint_summary


st.title("样本与报告联合分析")
st.caption("一个案例代表一组明确对应的样本与技术报告。可以同时上传，也可以先建案例、后续补齐另一侧。")
st.warning("恶意样本仅做纯静态分析，禁止执行、导入、调试、仿真或上传外部服务。")

with st.container(border=True):
    st.subheader("怎么操作")
    st.markdown(
        "1. 首次分析选择“新建分析案例”，上传样本和/或报告。\n"
        "2. 如果先只上传样本，之后回到本页选择原案例，只上传对应报告即可。\n"
        "3. 样本按 SHA-256 去重，报告按规范化标题逻辑去重；重复上传会更新既有知识条目并保留案例关系。\n"
        "4. 上传报告时必须指定要抽取的样本或家族，系统不会把报告中的其他事件自动算到该样本名下。"
    )

try:
    samples = get_json(api_base_url(), "/api/v1/samples", (("limit", 500),))
    reports = get_json(api_base_url(), "/api/v1/reports", (("limit", 500),))
    cases = get_json(api_base_url(), "/api/v1/analysis-cases", (("limit", 500),))
except ApiError as exc:
    st.error(str(exc))
    st.stop()

sample_options = {"不选择已有样本": None}
sample_options.update(
    {f"{item.get('source_case') or '未标注'} · {item['sha256'][:12]}…": item["sha256"] for item in samples}
)
report_options = {"不选择已有报告": None}
report_options.update(
    {
        f"{item.get('title') or item['report_id']} · {item['report_id'][:12]}…"
        + (f" · 合并{item['duplicate_record_count']}条" if item.get("duplicate_record_count", 1) > 1 else ""): item["report_id"]
        for item in reports
    }
)
case_options = {"新建分析案例": None}
case_options.update(
    {f"{item['title']} · {item['status']} · {item['id'][:8]}": item["id"] for item in cases}
)

selected_case = st.selectbox(
    "要新建还是继续已有案例？",
    list(case_options),
    help="后补报告时请选择之前只上传了样本的案例。",
)
selected_case_id = case_options[selected_case]
selected_case_detail = None
case_target = ""
if selected_case_id:
    try:
        selected_case_detail = get_json(api_base_url(), f"/api/v1/analysis-cases/{selected_case_id}")
    except ApiError as exc:
        st.error(str(exc))
        st.stop()
    case_samples = selected_case_detail.get("samples") or []
    case_reports = selected_case_detail.get("reports") or []
    case_target = next((item.get("source_case") for item in case_samples if item.get("source_case")), "")
    with st.container(border=True):
        st.write(f"**当前案例：** {selected_case_detail['title']}")
        st.write(f"**已有样本：** {', '.join(item.get('source_case') or item['sha256'][:12] for item in case_samples) or '无'}")
        st.write(f"**已有报告：** {', '.join(item.get('title') or item['report_id'] for item in case_reports) or '无'}")
        if case_samples and not case_reports:
            st.info("该案例正在等待报告：本次只需上传对应报告，并确认目标样本/家族名称。", icon=":material/info:")

with st.form("joint_analysis", border=True):
    title = st.text_input(
        "案例标题",
        value="" if not selected_case_detail else selected_case_detail["title"],
        placeholder="例如 PromptLock 样本与报告复核",
        disabled=selected_case_detail is not None,
    )
    notes = st.text_area("备注（可选）", height=80)
    left, right = st.columns(2)
    with left:
        st.subheader("样本侧")
        sample_file = st.file_uploader("上传新样本", key="joint_sample")
        selected_sample = st.selectbox("或者选择已有样本", list(sample_options))
        source_case = st.text_input("样本来源/家族", value=case_target, placeholder="例如 PROMPTFLUX")
        st.caption("未知样本会新增入库；SHA-256 已存在时更新原记录，不会重复新增样本。")
    with right:
        st.subheader("报告侧")
        report_file = st.file_uploader(
            "上传新报告", type=["pdf", "html", "htm", "docx", "md", "txt"], key="joint_report"
        )
        selected_report = st.selectbox("或者选择已有报告", list(report_options))
        target_name = st.text_input(
            "报告抽取目标样本/家族",
            value=case_target,
            placeholder="例如 PROMPTFLUX",
            help="只抽取报告中与这个名称对应的事件信息。案例已有样本时会自动带出其来源/家族。",
        )
        target_aliases = st.text_input("目标别名（可选，逗号分隔）", placeholder="例如 APT28, UAC-0001")
        canonical_url = st.text_input("报告原始 URL（可选）")
        st.info(
            "报告默认由大模型直接提取，不再进行规则匹配或关键词筛选。提交新报告会将解析后的全文"
            "发送到已配置的 DeepSeek 兼容接口；仅容量超限时全覆盖分块。模型结果须通过原文证据"
            "校验并等待人工复核；模型失败会报错，不会回退规则。恶意样本文件不会发送。"
        )
        st.caption("选择已有报告只复用历史结果，不自动重新调用模型。")
    submitted = st.form_submit_button("提交联合分析", type="primary", icon=":material/add_link:")

if submitted:
    if sample_file and sample_options[selected_sample]:
        st.error("样本侧只能选择“上传新样本”或“已有样本”之一。")
    elif report_file and report_options[selected_report]:
        st.error("报告侧只能选择“上传新报告”或“已有报告”之一。")
    elif report_file and not (target_name.strip() or source_case.strip() or case_target):
        st.error("上传报告前请填写“报告抽取目标样本/家族”。")
    elif not any((sample_file, report_file, sample_options[selected_sample], report_options[selected_report], selected_case_id)):
        st.error("请至少上传或选择一个样本/报告。")
    else:
        files = {}
        if sample_file:
            files["sample_file"] = (sample_file.name, sample_file.getvalue(), "application/octet-stream")
        if report_file:
            files["report_file"] = (report_file.name, report_file.getvalue(), "application/octet-stream")
        try:
            with st.status("正在分析并建立对应关系…", expanded=True) as status:
                result = post_files(
                    api_base_url(),
                    "/api/v1/analysis-cases",
                    files=files,
                    data={
                        "case_id": selected_case_id,
                        "title": title,
                        "notes": notes,
                        "existing_sample_sha256": sample_options[selected_sample],
                        "existing_report_id": report_options[selected_report],
                        "source_case": source_case,
                        "canonical_url": canonical_url,
                        "target_name": target_name,
                        "target_aliases": target_aliases,
                    },
                )
                status.update(label="联合分析完成", state="complete")
            get_json.clear()
            case = result["case"]
            with st.container(horizontal=True):
                st.metric("案例状态", case["status"], border=True)
                st.metric("关联样本", len(case["samples"]), border=True)
                st.metric("关联报告", len(case["reports"]), border=True)
                st.metric("自动验证", result.get("validation_status") or "未触发", border=True)
            if result.get("joint_summary"):
                render_joint_summary(result["joint_summary"])
                render_event_context_editor(result["joint_summary"], key_prefix="intake")
            if result.get("sample_associations"):
                association = result["sample_associations"]
                cluster = association.get("cluster") or {}
                with st.expander("新样本知识库关联", icon=":material/hub:"):
                    st.caption(f"簇：{cluster.get('cluster_label', '未聚类')} · 簇大小：{cluster.get('cluster_size', 0)}")
                    st.dataframe(pd.DataFrame(association["related_samples"]), hide_index=True)
                    st.caption(association["interpretation"])
            with st.expander("原始联合分析结果（审计用）", icon=":material/data_object:"):
                st.json(result)
        except ApiError as exc:
            st.error(str(exc))

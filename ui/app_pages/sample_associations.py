from __future__ import annotations

import pandas as pd
import streamlit as st

from ui_utils.api import ApiError, api_base_url, get_json, post_json
from ui_utils.presenters import (
    GROUP_LABELS, VALUE_LABELS, common_feature_label, render_sample_key_features,
)


st.title("样本聚类与关联分析")
st.caption("工具链事实、Prompt哈希/结构、合格源码统计分别评分后加权合成，再做层次聚类；分数不是同源或AI生成概率。")

try:
    samples = get_json(api_base_url(), "/api/v1/samples", (("limit", 500),))
except ApiError as exc:
    st.error(str(exc))
    st.stop()

if not samples:
    st.info("知识库暂无样本。")
    st.stop()

options = {f"{item.get('source_case') or '未标注'} · {item.get('model_name') or 'unknown'} · {item['sha256'][:12]}…": item["sha256"] for item in samples}
selected = st.selectbox("选择样本", list(options))
include_unmatched = st.checkbox("显示零匹配及不可比较的样本对", value=False,
                                help="默认只显示正分候选。开启后可查看缺失证据、跨语言等原因；聚类距离阈值不控制此列表。")

try:
    result = get_json(
        api_base_url(),
        f"/api/v1/samples/{options[selected]}/associations",
        (("limit", 100), ("include_unmatched", str(include_unmatched).lower())),
    )
except ApiError as exc:
    st.error(str(exc))
    st.stop()

supports_diagnostics = "association_status" in result
if not supports_diagnostics:
    st.warning("当前API进程尚未加载新版关联接口，请先重启本项目API；已禁用旧进程上的重建操作，避免覆盖新版结果。")
with st.container(horizontal=True):
    if st.button("重建全部聚类", icon=":material/refresh:", disabled=not supports_diagnostics):
        try:
            rebuilt = post_json(api_base_url(), "/api/v1/samples/recluster", {})
            st.success(f"已完成 {rebuilt['sample_count']} 个样本、{rebuilt['cluster_count']} 个簇的重建。")
            result = get_json(
                api_base_url(), f"/api/v1/samples/{options[selected]}/associations",
                (("limit", 100), ("include_unmatched", str(include_unmatched).lower())),
            )
        except ApiError as exc:
            st.error(str(exc))

cluster = result.get("cluster") or {}
with st.container(horizontal=True):
    st.metric("聚类编号", cluster.get("cluster_label") or "未聚类", border=True)
    st.metric("簇内样本", cluster.get("cluster_size") or 0, border=True)
    st.metric("返回近邻", len(result["related_samples"]), border=True)

st.info(result.get("message") or "旧结果缺少可比性说明，请重建聚类。")
reason_labels = {
    "missing_toolchain_evidence": "缺少工具链证据", "missing_prompt_evidence": "缺少Prompt证据",
    "missing_comparable_prompt_evidence": "没有共同可比较的Prompt证据类型",
    "different_languages": "语言不同", "invalid_source_quality": "源码质量不满足比较条件",
    "not_original_source": "非原始源码（仅字符串/恢复代码）", "parse_error": "源码解析失败",
    "unknown_language": "语言未知", "missing_metrics": "缺少统计指标",
    "python_ast_unavailable": "缺少Python AST指标", "insufficient_metrics": "有效统计指标不足",
    "insufficient_shared_metrics": "共同有效统计指标不足",
}
group_labels = {"toolchain": "工具链事实", "prompt": "Prompt内容/结构", "code_style": "代码统计"}
availability = result.get("feature_availability", {}).get("groups") or {}
if availability:
    st.dataframe(pd.DataFrame([
        {"特征组": group_labels[key], "可用于比较": item.get("available"), "有效项目数": item.get("count", 0),
         "说明": reason_labels.get(item.get("reason"), item.get("reason")) or "可用，样本对仍需检查可比性"}
        for key, item in availability.items()
    ]), hide_index=True)
run = result.get("run") or {}
if run:
    st.caption(f"算法：{run.get('algorithm_version')}；聚类距离阈值：{run.get('distance_threshold')}。"
               "阈值只决定同簇关系，不屏蔽有正分的跨簇候选。")

rows = []
for item in result["related_samples"]:
    code = item.get("comparison", {}).get("groups", {}).get("code_style", {})
    reason = reason_labels.get(code.get("reason"), code.get("reason"))
    rows.append({key: item.get(key) for key in (
        "related_sha256", "source_case", "overall_similarity", "toolchain_similarity", "prompt_similarity",
        "code_style_similarity", "comparable_weight", "same_cluster")})
    rows[-1]["code_status"] = reason or ("可比较" if code.get("status") == "comparable" else "旧结果待重建")
frame = pd.DataFrame(rows)
if frame.empty:
    st.caption("当前筛选下没有结果；可开启上方选项查看零分及不可比较原因。")
else:
    st.dataframe(
        frame,
        hide_index=True,
        column_config={
            "related_sha256": "样本SHA-256", "source_case": "家族", "same_cluster": "同一聚类",
            "overall_similarity": st.column_config.NumberColumn("总关联分", format="percent"),
            "toolchain_similarity": st.column_config.NumberColumn("工具链事实", format="percent"),
            "prompt_similarity": st.column_config.NumberColumn("Prompt内容/结构", format="percent"),
            "code_style_similarity": st.column_config.NumberColumn("代码统计", format="percent"),
            "comparable_weight": st.column_config.NumberColumn("可比权重覆盖率", format="percent"),
            "code_status": "代码统计可比性",
        },
    )
    st.caption("分数空白表示不可比较，不等于0%；0%表示有可比证据但无匹配。总分不把缺失组权重分摊到其他组。")
    pair_options = {f"{item.get('source_case') or '未标注'} · {item['related_sha256'][:12]}…": item
                    for item in result["related_samples"]}
    pair_label = st.selectbox("查看样本对评分依据", list(pair_options))
    pair = pair_options[pair_label]
    left, right = st.columns(2)
    with left:
        render_sample_key_features(result.get("source_key_features") or {}, "当前样本关键特征")
    with right:
        render_sample_key_features(pair.get("key_features") or {}, "关联样本关键特征")
    comparison_rows = []
    for group, detail in (pair.get("comparison") or {}).get("groups", {}).items():
        comparison_rows.append({
            "特征类别": GROUP_LABELS.get(group, "其他特征"),
            "相似度": detail.get("score"),
            "可比状态": VALUE_LABELS.get(detail.get("status"), detail.get("status") or "未知"),
            "说明": reason_labels.get(detail.get("reason"), detail.get("reason")) or "—",
        })
    if comparison_rows:
        st.dataframe(
            pd.DataFrame(comparison_rows), hide_index=True,
            column_config={"相似度": st.column_config.NumberColumn("相似度", format="percent")},
        )
    common = pair.get("common_features") or []
    if common:
        st.caption("共同关键特征：" + "、".join(common_feature_label(item) for item in common))
st.caption(result["interpretation"])

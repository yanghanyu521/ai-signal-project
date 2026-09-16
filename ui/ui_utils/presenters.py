from __future__ import annotations

import json
import re
from typing import Any

import pandas as pd
import streamlit as st

from ui_utils.api import ApiError, api_base_url, patch_json


GROUP_LABELS = {
    "toolchain": "AI 工具链",
    "prompt": "提示词",
    "code_style": "代码生成/文体",
    "event_context": "事件背景",
}
FIELD_LABELS = {
    "vendor": "模型厂商", "provider": "模型厂商", "family": "模型家族",
    "model": "具体模型", "service": "服务/API", "endpoint": "接口地址",
    "sdk_or_library": "SDK/依赖库", "purpose": "用途", "stage": "攻击阶段",
    "availability": "原文可用性", "text_hash": "提示词哈希", "value": "内容",
    "actors": "相关组织", "name": "名称", "aliases": "别名", "actor_type": "组织类型",
    "country_or_region": "国家/地区", "confidence": "置信度", "basis": "判断依据",
    "limitations": "限制说明", "status": "状态", "summary": "摘要",
    "role_definition": "角色设定", "output_only": "仅输出结果", "code_only": "仅输出代码",
    "single_line_command": "单行命令", "self_modification": "自修改要求", "evasion": "规避检测",
    "jailbreak": "越狱指令", "safety_framing": "安全话术包装",
}
VALUE_LABELS = {
    "full_text": "完整原文", "partial_text": "部分原文", "described_only": "仅描述、未披露原文",
    "manual_override": "人工修订", "report_extraction": "报告抽取",
    "comparable": "可比较", "not_comparable": "不可比较",
    "supports": "相互确认", "contradicts": "存在冲突", "complements": "报告补充",
    "inconclusive": "证据不足", "unknown": "未知", "not_stated": "报告未说明",
}


def common_feature_label(value: str) -> str:
    parts = value.split(":")
    if len(parts) >= 3 and parts[0] == "toolchain":
        kind = {"vendor": "模型厂商", "family": "模型家族", "model": "具体模型", "sdk": "SDK/依赖库"}.get(parts[1], "工具链")
        return f"{kind}：{':'.join(parts[2:])}"
    if len(parts) >= 3 and parts[:2] == ["prompt", "flag"]:
        return f"提示词结构：{FIELD_LABELS.get(':'.join(parts[2:]), ':'.join(parts[2:]))}"
    if value == "prompt:exact_sha256":
        return "提示词正文完全一致"
    if value.startswith("prompt:fuzzy"):
        return "提示词正文近似"
    if value.startswith("code_style:"):
        return "代码统计特征：" + value.split(":", 1)[1]
    return "其他共同特征"


def _translated(value: Any) -> Any:
    if isinstance(value, dict):
        return {FIELD_LABELS.get(str(key), str(key)): _translated(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_translated(item) for item in value]
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, str):
        return VALUE_LABELS.get(value, value)
    return value


def _text(value: Any) -> str:
    if value in (None, "", [], {}):
        return "—"
    if isinstance(value, (dict, list)):
        return json.dumps(_translated(value), ensure_ascii=False)
    return str(VALUE_LABELS.get(value, value))


def _labels(values: list[str]) -> str:
    return "、".join(FIELD_LABELS.get(item, VALUE_LABELS.get(item, item)) for item in values) or "未检出"


def _relation_frame(items: list[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame([
        {
            "特征类别": GROUP_LABELS.get(item.get("signal_group"), "其他特征"),
            "样本证据": _text(item.get("sample_value")),
            "报告证据": _text(item.get("report_value")),
            "判断说明": item.get("notes") or "—",
            "证据引用": "、".join(item.get("evidence_ids") or []) or "—",
        }
        for item in items
    ])


def _show_relation(title: str, items: list[dict[str, Any]], empty_text: str) -> None:
    with st.container(border=True):
        st.subheader(title)
        if items:
            st.dataframe(_relation_frame(items), hide_index=True)
        else:
            st.caption(empty_text)


def _show_prompt_text(text: str | None, *, label: str = "提示词正文") -> None:
    st.write(f"**{label}：**")
    if text:
        st.code(text, language=None, wrap_lines=True, height=min(360, max(100, len(text) // 3)))
    else:
        st.caption("没有可展示的提示词原文。")


def render_sample_key_features(features: dict[str, Any], title: str) -> None:
    with st.container(border=True):
        st.subheader(title)
        toolchain = features.get("toolchain") or {}
        st.write(
            f"**模型厂商：** {_text(toolchain.get('vendor'))}　"
            f"**模型家族：** {_text(toolchain.get('family'))}　"
            f"**具体模型：** {_text(toolchain.get('model'))}"
        )
        prompts = features.get("prompts") or []
        if prompts:
            st.write(f"**提示词数量：** {len(prompts)}")
            for index, prompt in enumerate(prompts, 1):
                with st.expander(f"提示词 {index} · {_text(prompt.get('source'))}", expanded=index == 1):
                    _show_prompt_text(prompt.get("text"))
                    st.caption(
                        f"证据等级：{_text(prompt.get('evidence_level'))}；"
                        f"结构特征：{_labels(prompt.get('features') or [])}"
                    )
        else:
            st.caption("未提取到可展示的提示词正文。")
        code = features.get("code_style") or {}
        st.caption(
            f"代码语言：{_text(code.get('language'))}；可恢复性：{_text(code.get('recoverability'))}"
        )


def render_event_context_editor(summary: dict[str, Any], *, key_prefix: str = "joint") -> None:
    context = summary.get("event_context") or {}
    event_id = context.get("event_id")
    if not context.get("editable") or not event_id:
        st.info("当前事件没有可写回的知识库记录，组织和国家/地区暂不可修改。")
        return
    effective = context.get("effective") or {}
    with st.form(f"{key_prefix}_event_context_{event_id}", border=True):
        st.subheader("人工修订组织与国家/地区")
        st.caption("一行一项；保存后写入本地知识库并永久覆盖展示值，报告模型抽取原值仍保留用于审计。")
        organizations = st.text_area(
            "相关组织",
            value="\n".join(effective.get("organizations") or []),
            placeholder="例如 APT28",
            key=f"{key_prefix}_organizations_{event_id}",
        )
        locations = st.text_area(
            "国家/地区",
            value="\n".join(effective.get("countries_or_regions") or []),
            placeholder="例如 Russia\nUkraine",
            key=f"{key_prefix}_locations_{event_id}",
        )
        submitted = st.form_submit_button("保存到知识库", type="primary", icon=":material/save:")
    if submitted:
        split = lambda value: [item.strip() for item in re.split(r"[\n,，;；]+", value) if item.strip()]
        try:
            updated = patch_json(
                api_base_url(), f"/api/v1/events/{event_id}/context",
                {"organizations": split(organizations), "countries_or_regions": split(locations)},
            )
            summary["event_context"] = updated
            st.success("已永久保存到本地知识库。")
        except ApiError as exc:
            st.error(str(exc))


def render_joint_summary(summary: dict[str, Any]) -> None:
    subject = summary.get("case_subject") or {}
    st.subheader("联合分析摘要")
    with st.container(horizontal=True):
        st.metric("目标样本/家族", subject.get("sample_family") or subject.get("event_name") or "未标注", border=True)
        st.metric("报告目标事件", subject.get("event_name") or "未匹配", border=True)
        st.metric("确认项", len(summary.get("confirmed") or []), border=True)
        st.metric("补充项", len(summary.get("report_complements") or []), border=True)
        st.metric("冲突项", len(summary.get("conflicts") or []), border=True)

    left, right = st.columns(2)
    with left.container(border=True, height="stretch"):
        st.subheader("样本侧 AI 工具链")
        toolchain = summary.get("sample_ai_toolchain") or {}
        attribution = toolchain.get("model_attribution") or {}
        for label, value in (
            ("语言", toolchain.get("source_language")), ("文件类型", toolchain.get("file_type")),
            ("模型厂商", attribution.get("vendor")), ("模型家族", attribution.get("family")),
            ("具体模型", attribution.get("model")),
        ):
            st.write(f"**{label}：** {_text(value)}")
        evidence_rows = []
        for item in toolchain.get("evidence") or []:
            normalized = item.get("normalized") or {}
            evidence_rows.append({
                "线索类型": _text(item.get("type")), "具体内容": _text(item.get("raw") or item.get("value")),
                "模型厂商": _text(normalized.get("vendor")), "模型家族": _text(normalized.get("family")),
                "具体模型": _text(normalized.get("model")), "来源位置": _text(item.get("source") or item.get("location")),
            })
        if evidence_rows:
            st.dataframe(pd.DataFrame(evidence_rows), hide_index=True)
        else:
            st.caption("样本中没有更多可直接展示的工具链证据。")
    with right.container(border=True, height="stretch"):
        st.subheader("报告侧 AI 工具链")
        report_tools = summary.get("report_ai_toolchain") or []
        if report_tools:
            st.dataframe(pd.DataFrame([{
                "模型厂商": _text(item.get("provider")), "模型家族": _text(item.get("family")),
                "具体模型": _text(item.get("model")),
                "服务/API": _text(item.get("service") or item.get("endpoint") or item.get("sdk_or_library")),
                "用途": _text(item.get("purpose")), "攻击阶段": _text(item.get("stage")),
                "证据引用": "、".join(item.get("evidence_ids") or []) or "—",
            } for item in report_tools]), hide_index=True)
        else:
            st.caption("报告中没有抽取到目标对象的 AI 工具链描述。")

    left, right = st.columns(2)
    with left.container(border=True, height="stretch"):
        st.subheader("样本侧提示词特征")
        prompt = summary.get("sample_prompt_features") or {}
        st.write(f"**嵌入式提示词数量：** {prompt.get('embedded_prompt_count', 0)}")
        st.write(f"**结构特征：** {_labels(prompt.get('structural_features') or [])}")
        st.write(f"**特殊标记：** {_labels(list(map(str, prompt.get('special_tokens') or [])))}")
        for index, item in enumerate(prompt.get("prompts") or [], 1):
            with st.expander(f"样本提示词 {index} · {_text(item.get('source'))}", expanded=index == 1):
                _show_prompt_text(item.get("text"))
                st.caption(f"证据等级：{_text(item.get('evidence_level'))}；结构特征：{_labels(item.get('features') or [])}")
    with right.container(border=True, height="stretch"):
        st.subheader("报告侧提示词特征")
        report_prompts = summary.get("report_prompt_features") or []
        if not report_prompts:
            st.caption("报告中没有抽取到目标对象的提示词特征。")
        for index, item in enumerate(report_prompts, 1):
            with st.expander(f"报告提示词 {index} · {_text(item.get('availability'))}", expanded=index == 1):
                st.write(f"**用途：** {_text(item.get('purpose'))}")
                st.write(f"**目标模型：** {_text(item.get('target_model'))}")
                st.write(f"**结构特征：** {_labels(item.get('structural_features') or [])}")
                st.write(f"**约束：** {_labels(item.get('constraints') or [])}")
                if item.get("text"):
                    _show_prompt_text(item["text"])
                else:
                    st.warning("报告只描述了提示词用途或行为，没有披露提示词原文；以下是对应报告证据片段。")
                    for excerpt in item.get("evidence_excerpts") or []:
                        st.code(excerpt, language=None, wrap_lines=True, height=min(300, max(100, len(excerpt) // 3)))

    context = summary.get("event_context") or {}
    effective = context.get("effective") or {}
    with st.container(border=True):
        st.subheader("重点事件背景")
        st.write(f"**相关组织：** {_labels(effective.get('organizations') or [])}")
        st.write(f"**国家/地区：** {_labels(effective.get('countries_or_regions') or [])}")
        st.caption(f"当前显示来源：{VALUE_LABELS.get(context.get('source'), context.get('source') or '未知')}")

    _show_relation("交叉确认", summary.get("confirmed") or [], "当前没有可直接交叉确认的字段。")
    _show_relation("报告补充的信息", summary.get("report_complements") or [], "当前没有新增补充字段。")
    _show_relation("冲突与待复核", summary.get("conflicts") or [], "当前没有发现直接冲突。")

    supplements = summary.get("supplementary_report_features") or {}
    with st.container(border=True):
        st.subheader("其他报告事件背景")
        st.caption("这些字段通常无法只靠样本静态分析获得，仍属于报告原文证据。")
        rows = [
            {"中文特征名": label, "报告内容": _text(supplements.get(key))}
            for key, label in (
                ("time", "发生时间"), ("status", "事件状态"), ("ai_involvement", "AI 参与方式"),
                ("code_style", "代码文体/生成机制"), ("key_behaviors", "关键行为"),
                ("outcomes", "事件结果"), ("limitations", "限制与反证"),
            ) if supplements.get(key) not in (None, "", [], {})
        ]
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True)
        else:
            st.caption("暂无其他可展示的事件背景。")
    st.caption(summary.get("interpretation") or "")

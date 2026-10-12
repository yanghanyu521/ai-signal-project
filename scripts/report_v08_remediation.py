"""Evidence-bounded four-way comparison; candidate counts are not accuracy."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _group(sample: dict) -> str:
    fmt = sample.get("format")
    if fmt in {"pe", "elf", "mach_o", "apk", "dex", "python_bytecode"}:
        return "binary_or_package"
    if fmt == "text" and sample.get("recoverability") == "original_source":
        return "script_source"
    return "other_or_unresolved"


def _stats(result: dict) -> dict:
    features = result.get("features") or {}
    tools = (features.get("toolchain") or {}).get("evidence") or []
    prompts = (features.get("prompt") or {}).get("embedded_prompts") or []
    generation = features.get("code_generation_signals") or {}
    static = features.get("static_analysis") or {}
    run = static.get("run") or {}
    coverage = run.get("coverage") or {}
    recovery = coverage.get("recovery_coverage") or {}
    main_usage = (run.get("budget") or {}).get("provider_usage") or {}
    style = generation.get("semantic_analysis") or {}
    style_usage = style.get("provider_usage") or {}
    return {
        "sample_size_bytes": result.get("sample", {}).get("size"),
        "toolchain_candidates": len(tools), "prompt_candidates": len(prompts),
        "llm_toolchain_location_candidates": sum(
            item.get("discovery_method") == "llm" and
            item.get("semantic_confirmation_status") == "candidate" for item in tools),
        "llm_toolchain_semantic_confirmed": sum(
            item.get("discovery_method") == "llm" and
            item.get("semantic_confirmation_status") == "semantic_confirmed" for item in tools),
        "llm_toolchain_static_call_verified": sum(
            item.get("discovery_method") == "llm" and
            item.get("semantic_confirmation_status") == "static_call_verified" for item in tools),
        "relation_verified_tools": sum(item.get("verification_status") == "relation_verified" for item in tools),
        "relation_verified_prompts": sum(item.get("call_binding") == "relation_verified" for item in prompts),
        "fingerprint": generation.get("fingerprint") is not None,
        "style_observations": len(generation.get("style_indicators") or []),
        "style_rejected_text_asset": (style.get("rejection_reasons") or {}).get("text_asset_not_code_style", 0),
        "style_status": style.get("status"), "style_source_units": style.get("source_units_total"),
        "style_considered_units": style.get("source_units_considered"),
        "llm_status": run.get("status"), "main_requests": (run.get("budget") or {}).get("requests", 0),
        "style_requests": style.get("requests", 0),
        "main_tokens": main_usage.get("total_tokens"), "style_tokens": style_usage.get("total_tokens"),
        "main_elapsed_seconds": run.get("elapsed_seconds"), "style_elapsed_seconds": style.get("elapsed_seconds"),
        "strings_discovered": recovery.get("strings_discovered"),
        "strings_retained": recovery.get("strings_retained"),
        "strings_rejected_by_limit": recovery.get("strings_rejected_by_limit"),
        "bytes_scanned": recovery.get("bytes_scanned"),
        "byte_scan_denominator": result.get("sample", {}).get("size") if recovery.get("bytes_scanned") is not None else None,
        "member_bytes_scanned": recovery.get("member_bytes_scanned"),
        "archive_members_discovered": recovery.get("members_discovered"),
        "archive_members_considered": recovery.get("members_considered"),
        "archive_members_recovered": recovery.get("members_recovered"),
        "string_units_indexed": coverage.get("string_units_indexed"),
        "string_units_screened": coverage.get("string_units_screened"),
        "string_analysis_rate": coverage.get("string_analysis_rate"),
        "member_rejected_by_limit": recovery.get("members_rejected_by_limit"),
    }


def compare(v07: Path, v08_old: Path, post: Path) -> dict:
    manifest = _read(post / "manifest.json")
    if len(manifest) != 45:
        raise ValueError("Post-run manifest must contain 45 samples")
    rows = []
    for item in manifest:
        sha = item["sha256"]
        paths = {
            "v07_rule": v07 / "samples" / sha / "old_rule_result.json",
            "v07_llm": v07 / "samples" / sha / "v07_llm" / "result.json",
            "v08_pre": v08_old / "samples" / sha / "v08" / "result.json",
            "v08_post": post / "samples" / sha / "v08" / "result.json",
        }
        results = {key: _read(path) for key, path in paths.items()}
        current = results["v08_post"]
        sample = current.get("sample") or results["v08_pre"].get("sample") or {}
        row = {"sha256": sha, "family": item.get("family"), "group": _group(sample),
               "same_sha_across_versions": all(
                   result.get("sample", {}).get("sha256") == sha for result in results.values() if result),
               "versions_present": {key: bool(result) for key, result in results.items()},
               "versions": {key: _stats(result) if result else None for key, result in results.items()},
               "accuracy_status": "pending_human_adjudication"}
        rows.append(row)
    grouped = {}
    for group in ("script_source", "binary_or_package", "other_or_unresolved"):
        subset = [row for row in rows if row["group"] == group]
        totals = {}
        for version in ("v07_rule", "v07_llm", "v08_pre", "v08_post"):
            stats = [row["versions"][version] for row in subset if row["versions"][version]]
            totals[version] = {key: sum((entry.get(key) or 0) for entry in stats)
                               for key in ("toolchain_candidates", "prompt_candidates",
                                           "llm_toolchain_location_candidates",
                                           "llm_toolchain_semantic_confirmed",
                                           "llm_toolchain_static_call_verified",
                                           "relation_verified_tools", "relation_verified_prompts",
                                           "fingerprint", "style_observations", "style_rejected_text_asset",
                                           "main_requests", "style_requests", "main_tokens", "style_tokens",
                                           "main_elapsed_seconds", "style_elapsed_seconds",
                                           "strings_discovered", "strings_retained", "strings_rejected_by_limit",
                                           "bytes_scanned", "byte_scan_denominator", "member_bytes_scanned",
                                           "archive_members_discovered", "archive_members_considered",
                                           "archive_members_recovered", "member_rejected_by_limit",
                                           "string_units_indexed", "string_units_screened")}
            totals[version]["result_files"] = len(stats)
            totals[version]["llm_statuses"] = dict(Counter(entry.get("llm_status") for entry in stats))
        grouped[group] = {"samples": len(subset), "versions": totals}
    post_statuses = dict(Counter(
        (row["versions"]["v08_post"] or {}).get("llm_status") for row in rows
    ))
    return {"schema_version": "v08-remediation-comparison/1.0", "expected_samples": 45,
            "post_result_files": sum(row["versions_present"]["v08_post"] for row in rows),
            "post_analysis_statuses": post_statuses,
            "post_fully_analyzed": post_statuses.get("completed", 0),
            "same_sha_across_available_versions": all(row["same_sha_across_versions"] for row in rows),
            "groups": grouped, "rows": rows,
            "correct_candidates": None, "missed_candidates": None,
            "wrong_relation_upgrades": None, "style_label_accuracy": None,
            "limitation": "Accuracy and complete recall require adjudicated gold standard and independent miss audit."}


def markdown(result: dict, style: dict | None = None, gold: dict | None = None) -> str:
    lines = ["# v0.8 整改与 45 样本复测评估", "",
             "## 复测范围与可信边界", "",
             f"同 SHA-256 清单 45 个；整改后结果文件 {result['post_result_files']}/45，"
             f"主 LLM 完整分析 {result['post_fully_analyzed']}/45。"
             f"可用结果的 SHA 一致性：{'通过' if result['same_sha_across_available_versions'] else '失败'}。",
             "比较四组：v0.7 规则、v0.7 完整 LLM、整改前 v0.8、整改后 v0.8。"
             "样本未执行，报告侧未重构；原始样本及未脱敏证据只在私有 `data/evaluations/`。"
             "失败/部分完成的候选仍列在表内，但不能视为完整复测或准确率结论。", "",
             "## 已验证的量化结果", "",
             "下表均为候选记录数，不是正确数、检出率或模型来源判定。", "",
             "| 材料组 | 样本 | 工具链候选（规则 / v0.7 LLM / v0.8 前 / 整改后） | "
             "Prompt 候选（同序） | 整改后静态调用候选（工具链 / Prompt） | 整改后源码文体指纹 |",
             "|---|---:|---:|---:|---:|---:|"]
    for group, label in (("script_source", "脚本源码"),
                         ("binary_or_package", "PE/APK 等二进制与封装"),
                         ("other_or_unresolved", "其他/未确认")):
        item = result["groups"][group]
        versions = [item["versions"][key] for key in ("v07_rule", "v07_llm", "v08_pre", "v08_post")]
        last = versions[-1]
        lines.append(f"| {label} | {item['samples']} | "
                     f"{' / '.join(str(v['toolchain_candidates']) for v in versions)} | "
                     f"{' / '.join(str(v['prompt_candidates']) for v in versions)} | "
                     f"{last['relation_verified_tools']} / {last['relation_verified_prompts']} | "
                     f"{last['fingerprint']} |")
    statuses = Counter()
    for item in result["groups"].values():
        statuses.update(item["versions"]["v08_post"]["llm_statuses"])
    lines += ["", f"整改后主 LLM 状态：`{json.dumps(dict(statuses), ensure_ascii=False)}`。", ""]
    tier_totals = {key: sum(item["versions"]["v08_post"][key] for item in result["groups"].values())
                   for key in ("llm_toolchain_location_candidates",
                               "llm_toolchain_semantic_confirmed",
                               "llm_toolchain_static_call_verified")}
    lines += [f"LLM 新发现工具链的证据层级：仅位置候选 {tier_totals['llm_toolchain_location_candidates']}，"
              f"语义确认 {tier_totals['llm_toolchain_semantic_confirmed']}，"
              f"静态调用验证 {tier_totals['llm_toolchain_static_call_verified']}。"
              "这些是自动证据层级，仍须人工判断真伪。", ""]
    lines += ["", "整改后 LLM 与扫描覆盖（只统计实际保存的结果）：", "",
              "| 材料组 | 主提取请求 | 文体请求 | 主提取 Token* | 文体 Token* | "
              "字符串发现 / 保留 / 进入 LLM | 字符串材料丢弃 |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for group, label in (("script_source", "脚本源码"),
                         ("binary_or_package", "PE/APK 等"),
                         ("other_or_unresolved", "其他")):
        v = result["groups"][group]["versions"]["v08_post"]
        lines.append(f"| {label} | {v['main_requests']} | {v['style_requests']} | "
                     f"{v['main_tokens']} | {v['style_tokens']} | "
                     f"{v['strings_discovered']} / {v['strings_retained']} / {v['string_units_screened']} | "
                     f"{v['strings_rejected_by_limit']} |")
    lines += ["", "*仅汇总提供方实际返回的 `total_tokens`；如缺失则此列是已知下界。"
              "主提取与文体分析请求分别统计，耗时和逐样本覆盖见私有 `comparison_summary.json`。",
              "", "二进制材料扫描口径："]
    binary = result["groups"]["binary_or_package"]["versions"]["v08_post"]
    bytes_total = binary["byte_scan_denominator"]
    lines += [f"- 非归档二进制实际扫描 {binary['bytes_scanned']}/{bytes_total} 字节"
              + (f"（{binary['bytes_scanned']/bytes_total:.1%}）" if bytes_total else "（无可比样本）") + "。",
              f"- 归档成员发现/考虑/恢复 {binary['archive_members_discovered']}/"
              f"{binary['archive_members_considered']}/{binary['archive_members_recovered']}；"
              f"因限制拒绝 {binary['member_rejected_by_limit']}，成员字节扫描 "
              f"{binary['member_bytes_scanned']}。归档压缩文件大小不能充当未压缩成员分母。",
              "", "## 待人工复核的结果", "",
              "工具链与 Prompt 的正确候选数、漏检数、Precision、Recall、F1、静态调用关系正确升级/错误升级"
              "均需双人标注和冲突裁决。当前不得把候选数量变化解释为准确率变化。"
              "独立漏检检查只抽样未命中区域；在未穷尽、未裁决前，Recall 最多是候选池指标。", ""]
    if style:
        local = style.get("source_only_local_audit") or {}
        neighbor = style.get("nearest_neighbor") or {}
        rejected_text = sum(item["versions"]["v08_post"]["style_rejected_text_asset"]
                            for item in result["groups"].values())
        lines += ["## 代码文体专项", "",
                  f"源码指纹 {style.get('source_fingerprints')}/{style.get('base_samples')}；"
                  f"同进程重复指标一致 {local.get('same_process_repeated_metrics', '未测')}/"
                  f"{local.get('repeat_compared', '未测')}；Python AST 重排后规范化结构一致 "
                  f"{local.get('ast_unparse_same_structure', '未测')}/{local.get('format_compared', '未测')}。",
                  f"同家族 Top-1 近邻代理：{neighbor.get('top1_same_family_proxy')}"
                  f"（有标签可比较 {neighbor.get('family_labeled_pairs')} 对）；"
                  f"嵌入文本被自动排除的错误文体候选 {rejected_text} 条（仍须人工复核）。"
                  "这只是样本检索代理，不是生成模型归因。LLM 文体标签准确率尚待人工裁决；"
                  "45 个样本没有生成模型来源真值，不计算模型来源识别准确率。", ""]
    lines += ["## 无法验证与下一步", "",
              "未覆盖/未处理的二进制字符串、APK 成员上限、静态调用不可观测的运行时路径，"
              "以及尚未进行跨平台格式化验证的文体鲁棒性，均不能由本批次确证。"
              "下一步先完成人工金标准与独立漏检裁决，再计算分脚本/二进制、家族、已知/未知模型的指标。", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v07", type=Path, required=True)
    parser.add_argument("--v08-pre", type=Path, required=True)
    parser.add_argument("--post", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.v07, args.v08_pre, args.post)
    output = args.post / "comparison_summary.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    style = _read(args.post / "style_evaluation.json")
    (args.post / "analysis_report.md").write_text(markdown(result, style), encoding="utf-8")
    print(json.dumps({"post_result_files": result["post_result_files"],
                      "same_sha": result["same_sha_across_available_versions"],
                      "groups": {key: value["samples"] for key, value in result["groups"].items()}},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()

"""Create an evidence-bounded Markdown summary from isolated v0.8 outputs."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


GROUP_NAMES = {
    "script_source": "脚本原始源码",
    "executable_or_package": "可执行文件、字节码与应用封装",
    "other_or_unresolved": "其他或格式未确认",
}


def _count(value: dict, key: str) -> int:
    return int(value.get(key, 0))


def render(output: Path) -> str:
    summary = json.loads((output / "aggregate_summary.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    records = []
    for spec in manifest:
        path = output / "samples" / spec["sha256"] / "comparison.json"
        if path.is_file():
            records.append(json.loads(path.read_text(encoding="utf-8")))
    groups = summary.get("groups") or {}
    lines = [
        "# v0.8 对 45 个恶意样本的重新静态分析与历史规则对比",
        "",
        f"生成时间：{summary['generated_at']}。完成 {summary['completed_samples']}/{summary['expected_samples']}；"
        f"状态分布：`{json.dumps(summary['states'], ensure_ascii=False)}`。",
        "",
        "## 口径与边界",
        "",
        "同一 SHA-256 原始文件以 v0.8 静态管线重新分析，历史基线取 2026-09-20 "
        "独立批次保存的 `old_rule_result.json`（非 v0.7 LLM 结果）。本批次启用 DeepSeek v4，"
        "采用远端脱敏传输；不执行恶意样本，不使用 Ghidra/JADX，不写正式知识库。"
        "工具链和 Prompt 数量均为候选记录数，不是准确率或已验证调用数。",
        "",
        "脚本组要求原始源码且可识别语言；可执行/封装组按文件头归类 PE、ELF、Mach-O、APK、DEX、Python 字节码。"
        "其余格式单列，不能硬并进脚本或可执行文件。v0.8 的二进制代码文体不可比较，不以零分代替。",
        "",
        "## 分组汇总",
        "",
        "| 分组 | 样本 | 规则工具链 → v0.8 | 规则Prompt → v0.8 | LLM事实/可归因 | 文件/局部/成员源码指纹 | 主提取请求* | Docker运行 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key in GROUP_NAMES:
        item = groups.get(key) or {}
        lines.append(
            f"| {GROUP_NAMES[key]} | {_count(item, 'samples')} | "
            f"{_count(item, 'old_toolchain')} → {_count(item, 'v08_toolchain')} | "
            f"{_count(item, 'old_prompt')} → {_count(item, 'v08_prompt')} | "
            f"{_count(item, 'llm_facts')}/{_count(item, 'eligible_llm_facts')} | "
            f"{_count(item, 'fingerprints')}/{_count(item, 'local_profiles')}/{_count(item, 'member_source_profiles')} | "
            f"{_count(item, 'requests')} | {_count(item, 'docker_tool_runs')} |"
        )
    lines += ["", "候选记录数增加不等于覆盖更多样本。按‘至少一条候选’计：", "",
              "| 分组 | 有工具链候选的样本 规则→v0.8 | 有Prompt候选的样本 规则→v0.8 |",
              "|---|---:|---:|"]
    for key in GROUP_NAMES:
        item = groups.get(key) or {}
        lines.append(f"| {GROUP_NAMES[key]} | "
                     f"{_count(item, 'old_toolchain_positive_samples')}→{_count(item, 'v08_toolchain_positive_samples')} | "
                     f"{_count(item, 'old_prompt_positive_samples')}→{_count(item, 'v08_prompt_positive_samples')} |")
    fact_groups = Counter()
    for item in records:
        fact_groups.update(item["v08_extra"].get("llm_fact_groups") or {})
    llm_tools = sum(tool.get("discovery_method") == "llm" for item in records
                    for tool in item["v08"]["toolchain"])
    llm_prompts = sum(prompt.get("discovery_method") == "llm" for item in records
                      for prompt in item["v08"]["prompts"])
    binary_formats = Counter(item["sample_format"] for item in records
                             if item["group"] == "executable_or_package")
    lines += ["", "*请求数只统计主 AI 信号提取，不含另行调用的源码文体语义复核；不能据此推算总 Token/成本。", "",
              f"可执行/封装组格式构成：`{json.dumps(dict(binary_formats), ensure_ascii=False)}`。",
              "",
              f"主 LLM 事实按类型为工具链 {fact_groups['toolchain']}、Prompt {fact_groups['prompt']}、"
              f"旧式代码观察 {fact_groups['code_observation']}；最终合并结果中标记 LLM 来源的工具链记录 "
              f"{llm_tools}、Prompt 记录 {llm_prompts}。旧式代码观察不自动进入 v0.8 文体指纹。",
              "",
              "## 代码特征口径变化", "",
              "历史规则版的 `code_style` 是描述性统计，v0.8 的 `code_generation_signals.fingerprint` "
              "则要求可信原始源码并记录可重复的词法/结构指标，两者不是相同特征量，不能简单按有无计算准确率。", "",
              "| 分组 | 历史有代码统计的样本 | v0.8 文件指纹 | v0.8 局部指纹 |",
              "|---|---:|---:|---:|"]
    for key in GROUP_NAMES:
        subset = [item for item in records if item["group"] == key]
        old_with_metrics = 0
        for item in subset:
            old_path = output / "samples" / item["sha256"] / "historical_rule_result.json"
            old_full = json.loads(old_path.read_text(encoding="utf-8"))
            old_with_metrics += bool((((old_full.get("features") or {}).get("code_style") or {}).get("metrics") or {}))
        item = groups.get(key) or {}
        lines.append(f"| {GROUP_NAMES[key]} | {old_with_metrics} | "
                     f"{_count(item, 'fingerprints')} | {_count(item, 'local_profiles')} |")
    lines += ["", "## 分样本结果", ""]
    for key in GROUP_NAMES:
        subset = [item for item in records if item["group"] == key]
        lines += [f"### {GROUP_NAMES[key]}（{len(subset)}）", "",
                  "| 家族 | SHA-256前12位 | 格式/语言 | 工具链 规则→v0.8 | Prompt 规则→v0.8 | "
                  "LLM状态 | 文体指纹 | 局部数 | 成员源码数 |",
                  "|---|---|---|---:|---:|---|---|---:|---:|"]
        for item in subset:
            old, new, extra = item["old_rule"], item["v08"], item["v08_extra"]
            lines.append(
                f"| {item['family']} | `{item['sha256'][:12]}` | "
                f"{item['sample_format']}/{item['language'] or '—'} | "
                f"{len(old['toolchain'])}→{len(new['toolchain'])} | "
                f"{len(old['prompts'])}→{len(new['prompts'])} | "
                f"{extra['llm_run_status'] or '—'} | "
                f"{'有' if extra['fingerprint_available'] else '无'} | {extra['local_profile_count']} | "
                f"{extra['member_source_profile_count']} |"
            )
        lines.append("")
    changed = sorted(records, key=lambda item: (
        len(item["old_rule_to_v08"]["toolchain_added"]) +
        len(item["old_rule_to_v08"]["prompt_added"])), reverse=True)
    lines += ["## 差异解读与复核入口", "",
              "以下列出新增候选最多的样本，供逐条核对原文证据；新增不等于正确，缺失也不必然是退化。", "",
              "| 家族 | SHA-256前12位 | 新增工具链 | 缺失工具链 | 新增Prompt | 缺失Prompt |",
              "|---|---|---:|---:|---:|---:|"]
    for item in changed[:12]:
        delta = item["old_rule_to_v08"]
        lines.append(f"| {item['family']} | `{item['sha256'][:12]}` | "
                     f"{len(delta['toolchain_added'])} | {len(delta['toolchain_missing'])} | "
                     f"{len(delta['prompt_added'])} | {len(delta['prompt_missing'])} |")
    quality_path = output / "quality_audit.json"
    quality = json.loads(quality_path.read_text(encoding="utf-8")) if quality_path.is_file() else {}
    flags = quality.get("semantic_review_flag_reasons") or {}
    losses = [item for item in records if item["group"] == "executable_or_package"
              and item["old_rule"]["prompts"] and not item["v08"]["prompts"]]
    promptspy = [item for item in records if item["family"] == "PromptSpy"]
    promptspy_empty = sum(not item["v08"]["toolchain"] and not item["v08"]["prompts"]
                          for item in promptspy)
    lines += ["", "## 主要发现与问题", "",
              f"- 完整性：{quality.get('totals', {}).get('completed_samples', '待审计')}/45 份结果通过单独的结果审计；"
              f"主 LLM 事实 {quality.get('totals', {}).get('llm_facts_valid', '待审计')}/"
              f"{quality.get('totals', {}).get('llm_facts', '待审计')}、LLM 文体观察 "
              f"{quality.get('totals', {}).get('llm_style_observations_valid', '待审计')}/"
              f"{quality.get('totals', {}).get('llm_style_observations', '待审计')} 有逐字来源锚点；"
              "这只能证明位置可复核，不代表语义正确。",
              f"- 文体语义误分：至少 {flags.get('overlaps_application_prompt', 0)} 条 `dialogue_residue` "
              "与已提取的应用 Prompt 重叠，应优先回归指令资产而非视为代码生成文体；"
              f"另有 {flags.get('no_explicit_ai_code_generation_claim', 0)} 条 `generation_claim` "
              "没有显式 AI 生成代码声明。这些是自动复核标记，原始输出未被静默改写。",
              f"- 二进制 Prompt 退化：{len(losses)} 个有旧 Prompt 的样本在本次变为 0 条："
              + ("、".join(f"`{item['sha256'][:12]}`" for item in losses) if losses else "无")
              + "。应逐项核查旧证据来源与本次受限材料范围。",
              f"- PromptSpy：{len(promptspy)} 个 APK 中 {promptspy_empty} 个在本次没有工具链或 Prompt 候选；"
              "这是受限静态材料的覆盖现象，不是没有 AI 行为的证明。",
              "- PROMPTFLUX `eb0687daed29` 的原始文件是 VBScript 文本而非 PE；v0.8 暂不支持 VBScript 代码文体指纹。",
              ""]
    for item in losses:
        source_types = sorted({str(prompt.get("source") or "unknown")
                               for prompt in item["old_rule"]["prompts"]})
        current = json.loads((output / "samples" / item["sha256"] / "v08/result.json").read_text(encoding="utf-8"))
        recovery = (((current.get("features") or {}).get("recovery") or {}).get("pyinstaller") or {})
        lines.append(f"  - `{item['sha256'][:12]}`：旧 Prompt 来源 `{', '.join(source_types)}`；"
                     f"本次 PyInstaller 恢复状态 `{recovery.get('status', 'unknown')}`。")
    recheck = output.parent / "20261008_v08_pyinstaller_policy_recheck"
    if recheck.is_dir():
        lines.append("  - 已关闭旧 PyInstaller 解包/pycdc 路径并对这两份 PE 独立复测；"
                     "两份工具链与 Prompt 候选数均与全量批次相同，恢复状态改为 "
                     "`disabled_v08_binary_strings_only`。复测原始产物保存在相邻独立目录。")
    lines.append("")
    all_statuses = Counter(item["v08_extra"]["llm_run_status"] for item in records)
    lines += ["", f"模型分析状态：`{json.dumps(dict(all_statuses), ensure_ascii=False)}`。",
              "逐样本差异见 `samples/<sha256>/comparison.json`；v0.8 完整结果和静态材料见 "
              "`samples/<sha256>/v08/`；规则基线副本见 `historical_rule_result.json`；"
              "表格见 `tables/sample_matrix.csv`。", "",
              "## 不能由本批次推出的结论", "",
              "45 个真实恶意样本没有可靠的代码生成模型来源标签，不能把文体近邻当作模型归因准确率。"
              "LLM事实通过原文引用校验仅说明可定位，不等于语义正确；需要对新增与缺失候选人工复核。"
              "脚本 AST、PE/APK 字符串、封装内原始脚本属于不同证据质量，不应合并计算单一检出率。"
              "现有 A–K 合成评估中的二进制案例使用历史保存的反编译导出，不代表 v0.8 运行时反编译能力。", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    report = output / "analysis_report.md"
    report.write_text(render(output), encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()

# 19 个真实脚本样本人工基准（script_baseline v1.0）

本目录是**真实恶意脚本的人工分析基准**，用于检验"纯大模型 + 规则"提取方案的准确率。与 `evaluation/gold_standard/`（无害合成样本评测集）不同，这里每条结论都由人工逐行阅读真实样本得出，并标注了文件内证据位置（行号）。

- 不包含任何恶意代码本体，只包含特征、提示词内容摘录和证据位置；原始样本保存在仓库外（`D:\长安通讯\AI驱动的攻击手段检测\恶意样本文件`）。
- 样本范围：19 个脚本（16 个含 AI 调用 / 3 个 LLM 辅助开发无 AI 调用）。6 个无 AI 信号的纯脚本不再进入分析范围，仅作为负例登记在 `malterminal.json` 的 `excluded_negative_controls`。
- 报告侧基准在 `report_side.json`，含与样本侧的预期交叉验证关系（supports / complements）。

## 文件与覆盖范围

| 文件 | 家族 | 样本数 | 语言 | 关键考点 |
|---|---|---|---|---|
| `lamehug.json` | LAMEHUG | 5 | Python | HF router 端点、Qwen 模型、hf_ token 轮换、b64 编码提示词（ae6ed1721d37）、近重复变体 |
| `malterminal.json` | MalTerminal | 8 | Python | openai SDK、gpt-3.5-turbo/-1106/gpt-4 区分、EvilBOT 越狱提示词、逐函数代码生成提示词、pyobfuscate/PyArmor 不可恢复边界 |
| `quietvault.json` | QUIETVAULT | 1 | JavaScript | AI CLI（claude/gemini/q）调用与权限绕过旗标、agent 提示词、无模型名不可编造 |
| `slopoly.json` | SLOPOLY | 1 | PowerShell | 无 AI 调用，LLM 辅助开发只有文体弱信号 |
| `fruitshell.json` | FRUITSHELL | 1 | PowerShell | 分析器定向提示注入（analyzer_injection），不得当作程序提示词 |
| `promptflux.json` | PROMPTFLUX | 1 | VBScript | Gemini 自我再生提示词、内嵌 PE 与 AI 特征的区分 |
| `phantomraven.json` | PhantomRaven | 2 | JavaScript | 无 AI 调用，仅 C2 域名不同的变体对 |

## 基准条目结构

每个样本条目包含：

- `sha256` / `size_bytes` / `family` / `language`
- `analysis_scope`：`script_with_ai_calls` 或 `script_llm_assisted_no_ai_calls`
- `ai_calling`：true / false / `not_statically_confirmable`（混淆不可静态确认）
- `toolchain`：SDK/服务/端点/模型/认证/参数 + `evidence.lines`
- `prompts`：分类（program_prompt / jailbreak_prompt / analyzer_injection / prompt_template_prefix）、文本或解码后文本、用途、证据行号
- `behavior_summary` / `network_indicators`
- `extraction_expectations`：`must_find`（漏提即召回缺失）、`must_not_claim`（出现即幻觉/误报）——这是打分的核心
- 近重复变体用 `same_as` + `differences_from_reference` 表示，避免重复劳动

## 评分口径建议

1. **工具链**：模型名精确匹配（`gpt-3.5-turbo` 与 `gpt-3.5-turbo-1106` 是不同答案）；厂商与 SDK 分开计分。
2. **提示词**：按条目数计召回；base64 编码条目必须解码后比较；`analyzer_injection` 与 `program_prompt` 分类错误单独计为误报。
3. **幻觉率**：`must_not_claim` 命中即计一次；对 3afbb9fe6bab / 4ddbc14d8b6a 两个混淆样本，任何具体模型/提示词输出都计幻觉。
4. **负例**：6 个排除样本和 SLOPOLY / PhantomRaven 若报出 AI 调用即误报。
5. **交叉验证**：按 `report_side.json` 的预期关系判定，组织/国家/时间字段只允许 `complements`。

## 已确认的分析师表格勘误

- "提示词 b64 加密"实际属于 `ae6ed1721d37`（`prompt_b64_p1/p2`）；`cf4d430d0760` 的两条侦察提示词是明文。
- `c1a80983779d` 导入了 Fernet 并生成密钥，但提示词未被加密，混淆手段是标识符改换与排版。
- `4c73717d933f` 除两条 EvilBOT 提示词外，还有一条 `exec test.py` 提示词和 `create_prompt` 前缀模板，提示词总数应按 4 计。
- `854b559bae2c` 的模型是 `gpt-3.5-turbo`，与多数变体的 `gpt-3.5-turbo-1106` 不同。
- `c86a5fcefbf0`（表格中写作 c86a5fcebf0）与 `4c73717d933f` 仅菜单文案与缩进不同。

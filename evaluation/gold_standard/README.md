# 45 样本金标准：人工标注指南

这里只存公开的数据契约与工具；带样本路径、原始值、报告文字、未脱敏证据的 CSV/JSON 必须输出到 `data/evaluations/` 等受控目录，不能提交仓库。

## 顺序

1. 核验 v0.7 规则、v0.7 完整 LLM、v0.8 原始以及整改后四组运行结果的 SHA-256 一致。缺组时不补造值。
2. 运行 `python -m evaluation.gold_standard.build_queue --v07 <目录> --v08 <目录> --post <目录> --output data/evaluations/<批次>/gold/candidates.csv`。输出同时有 JSON。按 SHA、类别、原始值和来源位置去重；同值不同位置保留多个证据。
3. 两名标注员分别复制队列到私有目录，**独立**填写 `true_ai_feature` (`yes/no/uncertain`)、`static_call_verified` (`yes/no/uncertain`)、`prompt_role` (`program_prompt/jailbreak_prompt/analyzer_injection/ordinary_text/uncertain/not_applicable`)、`model_familiarity` (`known/unknown/uncertain/not_applicable`) 和 `annotator`。不得以工具输出标签代替原始证据检查。工具链的 `prompt_role` 填 `not_applicable`；Prompt 的 `model_familiarity` 填 `not_applicable`。`static_call_verified=yes` 要有源码 AST/调用链或可信反编译调用链佐证，只有字符串位置不能标 yes。
4. `python -m evaluation.gold_standard.adjudicate --first <A.csv> --second <B.csv> --output <adjudicated.csv>`。一致的记录为 `agreed`，冲突和缺项为 `pending`、字段变为 `uncertain`。第三方查看原始证据后填写 `resolved`、`adjudicator` 和最终字段；保留冲突 JSON。不能把 `uncertain` 算作负例。
5. 独立漏检检查：`python -m evaluation.gold_standard.miss_scan --manifest <manifest.json> --candidate-queue <candidates.csv> --output <miss_queue.csv>`。该流程对未命中字符串及源码区域按位置独立抽样，**不是穷尽搜索**；审查员需进一步检查未入池区域和超限材料，将确认的新特征追加到候选表、两人标注并裁决。只有全部原始区域已覆盖、没有截断或未裁决记录，才能签发 `complete=true` 的私有漏检审计。
6. `python -m evaluation.gold_standard.evaluate --adjudicated <adjudicated.csv> --output <metrics.json>`。未通过完整漏检审计时，Recall/F1 只能叫“候选池 Recall/F1”；未标注时指标为 `null`，不能当作零。所有数据值均按实际标注产生。

## 特征边界

- 工具链：SDK、服务、模型或私有部署别名须有原始静态证据。未知名不自动判错；普通业务 `model` 字段不自动判真。区分“字符串存在”“AI 语义确认”“静态调用验证”。不推断未出现的厂商。
- Prompt：程序送往模型的指令、试图绕过模型限制的越狱指令、针对本分析器的注入和普通文本分开。无调用关系但语义明确的 Prompt 保留为候选，不升级为调用验证。
- 文体：独立检查代码/注释/嵌入 Prompt/数据四种材料；标注 `generation_claim` 和 `dialogue_residue` 是否确实属于源码作者残留。验证重复运行指标、格式化前后变化、已知近邻是否检索到。45 个恶意样本无生成模型真值，不能报告模型来源识别准确率。

文体评估脚本：`python -m evaluation.gold_standard.style_eval --base <整改后批次> --manifest <私有manifest.json> --repeat <重复批次> --formatted <格式化批次> --labels <已裁决文体标签.csv> --output <私有评估.json>`。缺少某组可以省略相应参数，输出为 `null` 而非虚构数值。提供 manifest 时，可另行做同进程确定性重复和 Python `ast.unparse` 格式化实验；两者不等于跨平台/外部格式化验证。文体标签按 `style_label_template.csv` 私有填写；近邻的“同家族 Top-1”仅作检索代理，不是生成模型来源准确率。

## 指标口径

工具链和 Prompt 分别给 Precision、候选池 Recall、候选池 F1，分脚本/二进制、家族、已知/未知模型及静态调用升级正确/错误。需同时报告待标注、`uncertain` 和漏检审查覆盖比例。`candidate_versions` 表示出现在哪一版，不能据“提取条数增加”推断准确率。

# API 接口清单（v0.3）

所有接口以 `/api/v1` 为前缀，具体请求与响应 Schema 以服务启动后的 OpenAPI `/docs` 为准。

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/health` | 健康检查、数据库与旧项目可用性 |
| POST | `/analysis-cases` | 联合上传或选择已有样本/报告，建立或补齐分析案例 |
| GET | `/analysis-cases` | 列出分析案例及两侧对象数量 |
| GET | `/analysis-cases/{case_id}` | 查看案例、关联样本和关联报告 |
| POST | `/analysis-cases/{case_id}/cross-validate` | 只对案例内部已关联的样本和报告执行交叉验证 |
| POST | `/samples/analyze` | 上传并静态分析单个样本 |
| GET | `/samples` | 分页列出样本 |
| GET | `/samples/{sha256}` | 样本详情、证据快照和关联事件 |
| GET | `/samples/{sha256}/associations` | 样本聚类、分项相似度、近邻和共同特征 |
| POST | `/samples/recluster` | 重建当前知识库全部样本聚类 |
| POST | `/reports/analyze` | 上传报告，按必填 `target_name` 和可选 `target_aliases` 定向抽取目标事件 |
| GET | `/reports` | 列出报告 |
| GET | `/reports/{report_id}` | 报告详情和事件 |
| POST | `/cross-validations` | 对指定样本与报告事件做交叉验证 |
| GET | `/knowledge/search?q=` | 跨样本、报告和事件检索 |
| POST | `/knowledge/import-legacy` | 幂等导入旧项目结构化结果 |
| PATCH | `/events/{event_id}/context` | 永久修订事件的相关组织与国家/地区；保留报告抽取原值 |
| GET | `/statistics/overview?date_from=&date_to=` | 全局或指定日期范围的统计快照 |
| POST | `/generated-reports` | 按模板生成 Markdown 报告 |
| GET | `/generated-reports` | 列出已生成报告 |
| GET | `/generated-reports/{id}/download` | 下载报告文件 |

`POST /analysis-cases` 在上传报告时也接受 `target_name` 和逗号分隔的 `target_aliases`。响应中的 `joint_summary` 是面向界面的确定性摘要；原始样本、报告和验证 JSON 仍保留用于审计。

`joint_summary` 会返回样本提示词正文、报告提示词原文或对应证据片段，以及 `event_context`。报告未披露提示词原文时，`text` 为 `null`，调用方不得把描述性证据片段冒充提示词正文。`PATCH /events/{event_id}/context` 请求体为 `organizations` 和 `countries_or_regions` 字符串数组；人工值保存在独立覆盖表中，报告抽取值仍可审计。

统计响应的 `global_ai_security_events=25`、`analyzable_events=9` 和 `events_without_samples=16` 是当前知识范围业务口径；`event_records` 是数据库物理证据记录数，`cross_validation_records` 保留交叉验证历史执行行数。统计接口不再返回容易与已分析样本数混淆的 `cross_validations` 对象数。

`GET /knowledge/search` 是关联检索，不再返回三张表各自独立的模糊匹配结果。响应以 `results[]` 中的样本/家族为主体，包含 `samples`、通过分析案例或目标事件关联得到的 `reports`，以及每份报告内与主体对应的 `target_events`。无法可靠关联到样本的直接命中放在 `unlinked_direct_matches`，不得与主体结果混合。

新报告默认直接调用大模型，`use_llm` 默认 `true`，推荐省略此参数；显式 `false` 返回 `400`（仅样本分析或复用已有报告不受影响）。不再有报告规则模式或规则降级。全文策略、配置和 `extraction` 元数据见 [v0.3 说明](07_报告纯大模型抽取说明.md)。

静态样本规则补丁：`POST /samples/analyze`及联合上传中的新样本分析已接入PowerShell/分析器注释规则。`result_json`可新增`static_rules`、`sample.language_detection`、`features.code_style.metrics_method/syntax_validation`与`classification.analysis_targeting`；Prompt候选增加原文、字节定位、规则ID及目标类型。此类候选不代表已确认调用模型。详见[FruitShell规则验收](11_FruitShell静态规则修补与验收_20260903.md)。关联算法v2.1中统计口径不同的代码分为null，原因`different_metric_methods`；接口路径不变。

## Prompt 上下文恢复扩展

样本分析入口另已接入 `prompt-context-recovery-v1`。`result_json.features.prompt.recovery_diagnostics` 记录恢复阶段与限制；新增候选包含 `text / boundary / completeness / call_binding / comparison_eligible / recovery_origin / extraction_version`。静态组成部分不等于完整运行时请求，`comparison_eligible=false` 的不确定窗口仅有 `evidence_text_hash`，无 `text_hash / fuzzy_hash`，不作为全文计算精确或模糊匹配。源码不执行、样本不发往模型。支持范围、13个样本复核和生效条件见[Prompt修复说明](13_工具链阳性样本Prompt漏提复核与修复_20260903.md)。

## 错误约定

样本关联接口新增`include_unmatched`查询参数（默认false）、`association_status/message/feature_availability/run`及样本对`comparison`明细。分数null表示不可比较，0表示有可比证据但无匹配；不再将缺失证据冒充0分结论。详细字段与新版评分见[样本相似度说明](10_样本相似度与FruitShell关联修正_20260903.md)。调用方应兼容nullable分数；路径仍为`/api/v1`。

- `400`：文件类型、哈希、关联参数或抽取结果不符合契约。
- `404`：样本、报告、事件或生成报告不存在。
- `413`：上传超过配置上限。
- `422`：请求体字段校验失败。
- `502`：大模型接口失败、无效响应、证据校验失败或请求次数超限；报告不入库。
- `503`：模型密钥/接口配置/鉴权不可用，或依赖项目不可用。
- `500`：内部处理失败；响应不回显密钥、完整样本内容或危险中间材料。

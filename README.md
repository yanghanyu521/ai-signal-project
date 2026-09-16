# AI 信号提取统一平台

本项目从设计之初即面向 AI 参与网络攻击的统一分析需求，同时提供恶意样本静态特征提取和样本对应安全报告分析，并以 API 作为统一业务入口。平台保留两条相互独立的证据链：

- 样本侧只从恶意样本字节和静态恢复材料中提取 AI 工具链、Prompt、代码文体候选和模型归因证据。
- 报告侧只从报告原文中提取事件、攻击者/目标、AI 参与方式、样本/IOC、工具链、Prompt 和局限，并保留原文证据引用。
- 交叉验证结果作为第三类数据单独保存，使用 `supports / contradicts / complements / inconclusive`，不会覆盖任一原始结果。

当前版本提供 FastAPI、SQLite 本地知识库、联合分析案例、历史结果导入、样本自动聚类关联、统计与 Markdown 报告生成，以及 Streamlit 测试界面。

v0.3.0：新上传报告默认直接由大模型提取，已移除报告规则匹配和关键词预筛选。首次提交解析全文，仅模型容量/输出超限时全覆盖分块；保留原文证据校验，不回退规则。样本静态分析和历史结果不变。

2026-09-02 准确性修订：增加全文独立语义复核、高风险字段断言、完整性检查、身份原文锚点、日期精度保护和Prompt哈希格式兼容。DeepSeek v4默认启用思考模式；提取与复核会增加等待时间和模型用量，真实复测仍有语义误判及交付失败，需人工复核。问题分级与实测记录见 [主要问题修复说明](docs/09_报告抽取问题分级与主要修复_20260902.md)。

启动 API 前请配置 `DEEPSEEK_API_KEY`（兼容 `cc-api`），可通过 `DEEPSEEK_BASE_URL`、`DEEPSEEK_MODEL` 指定接口/型号。密钥只能通过本机环境变量注入，不得写入仓库。详细配置、全文策略与失败语义见 [报告纯大模型抽取说明](docs/07_报告纯大模型抽取说明.md)。

## 运行依赖

- Python 3.11 或更高版本。
- 样本静态分析器 `ai_signal_demo`。
- 报告解析与交叉验证组件 `报告信息抽取`。

默认情况下，两个依赖项目与本仓库位于同一父目录：

```text
workspace/
├── ai-signal-project/
├── ai_signal_demo/
└── 报告信息抽取/
```

如果目录位置不同，请设置 `AI_SIGNAL_HUB_LEGACY_SAMPLE_PROJECT` 和 `AI_SIGNAL_HUB_LEGACY_REPORT_PROJECT`。本仓库不包含原始恶意样本、运行数据库或两个依赖项目的源码。

## 快速启动

```powershell
git clone git@github.com:yanghanyu521/ai-signal-project.git
Set-Location '.\ai-signal-project'
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'

.\.venv\Scripts\python.exe -m ai_signal_hub.main
```

另开一个终端启动测试界面：

```powershell
Set-Location '.\ai-signal-project'
.\.venv\Scripts\streamlit.exe run .\ui\streamlit_app.py
```

也可以分别运行 `scripts/start_api.ps1` 和 `scripts/start_ui.ps1`。API 与前端需要两个终端进程。

API 文档默认位于 [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)。

## 首次导入已有知识

服务启动后调用：

```powershell
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/v1/knowledge/import-legacy' `
  -ContentType 'application/json' -Body '{"include_samples":true,"include_events":true,"include_reports":true}'
```

也可以用命令行：

```powershell
.\.venv\Scripts\python.exe -m ai_signal_hub.importer
```

默认导入 45 条既有样本结果、研究事件表和 final_v8 历史报告结果，并建立 9 个家族知识案例。当前主口径为 45 个样本、9 个家族、9 组家族—报告映射和 7 份逻辑去重报告；11 条早期研究事件与报告事件证据单独展示。

## 主要 API

2026-09-03 Prompt漏提复核：已补齐Python模型参数依赖追踪、Base64常量、Go字符串边界、DEX与PyInstaller成员静态恢复。13个重点缺口中12个恢复提示词或组成部分，已备份更新知识库并重建关联；不确定边界片段不当全文参与匹配。详见[复核与修复记录](docs/13_工具链阳性样本Prompt漏提复核与修复_20260903.md)。后续新上传使用此逻辑仍需重启运行中的API。

FruitShell静态规则已补齐：PowerShell多线索识别、代码词法统计及AI分析器定向注释候选；具体范围、真实隔离复测和生效方式见[FruitShell规则验收](docs/11_FruitShell静态规则修补与验收_20260903.md)。历史结果不会仅因代码更新自动重提取。

2026-09-03 样本关联已改为证据分组评分和真实固定权重融合，支持不可比较原因；不再把跨语言代码统计显示为高相似度。算法、FruitShell空关联原因及复算结果见[样本相似度修正](docs/10_样本相似度与FruitShell关联修正_20260903.md)。

- `POST /api/v1/analysis-cases`：样本/报告联合上传，按目标家族定向抽取，或选择已有案例补齐对应关系。
- `POST /api/v1/analysis-cases/{case_id}/cross-validate`：只在指定案例内执行样本—报告交叉验证。
- `POST /api/v1/samples/analyze`：上传一个样本，受控落盘并进行纯静态分析。
- `GET /api/v1/samples/{sha256}/associations`：查看工具链、Prompt、代码统计候选关系和聚类；`include_unmatched=true`同时查看零分/不可比较原因，分数可为null。
- `POST /api/v1/samples/recluster`：重建全部样本聚类。
- `POST /api/v1/reports/analyze`：上传报告并按 `target_name` 指定样本/家族定向抽取事件。
- `POST /api/v1/cross-validations`：对一个样本结果和报告事件进行证据对照。
- `PATCH /api/v1/events/{event_id}/context`：人工修订相关组织和国家/地区并永久写入知识库，同时保留报告抽取原值。
- `GET /api/v1/knowledge/search`：以样本/家族为中心检索，并沿分析案例和目标事件关系返回对应报告。
- `GET /api/v1/statistics/overview`：获取 25 个全球事件、9 个可分析事件、45 个样本以及报告、模型归因和月增长等分口径指标。
- `POST /api/v1/generated-reports`：按当前知识库快照填充统计报告模板。
- `POST /api/v1/knowledge/import-legacy`：导入两个旧项目的安全结构化结果。

## 安全提示

- 平台绝不执行、导入、调试、仿真或上传恶意样本。
- `data/quarantine` 中的文件使用哈希名和 `.sample` 后缀保存；不要双击、预览或交给解释器。
- 原始样本和运行数据已在 `.gitignore` 中排除。
- 当前是本地单用户测试版，API 默认只监听 `127.0.0.1`。对外部署前必须补充认证、权限、反向代理、TLS、审计日志和独立分析沙箱。

详细需求、架构、v1/v2 意见处理、v0.3 报告大模型改造和验收范围见 `docs/`；报告抽取当前行为以 `07_报告纯大模型抽取说明.md` 为准。

# AI 信号提取统一平台

本项目从设计之初即面向 AI 参与网络攻击的统一分析需求，同时提供恶意样本静态特征提取和样本对应安全报告分析，并以 API 作为统一业务入口。平台保留两条相互独立的证据链：

- 样本侧只从恶意样本字节和静态恢复材料中提取 AI 工具链、Prompt、代码文体候选和模型归因证据。
- 报告侧只从报告原文中提取事件、攻击者/目标、AI 参与方式、样本/IOC、工具链、Prompt 和局限，并保留原文证据引用。
- 交叉验证结果作为第三类数据单独保存，使用 `supports / contradicts / complements / inconclusive`，不会覆盖任一原始结果。

当前版本提供 FastAPI、SQLite 本地知识库、联合分析案例、历史结果导入、样本自动聚类关联、统计与 Markdown 报告生成，以及 Streamlit 测试界面。

v0.7.0：样本侧证据链改为“候选发现—静态关系验证—主体角色验证—归因门禁”。仅位置命中的 LLM 候选、依赖/示例代码和分析器定向指令都不能直接改变模型归因；Python 工具链与 Prompt 共用作用域感知静态图，语义分析支持多轮受控查询，JADX/Ghidra 关系落到可查询的分析单元 ID。新增 PromptComposition、三层覆盖率、外发策略、A—K 无害评测集与 Python 3.11/3.12 CI。详见 [v0.7 证据验证架构](docs/19_静态AI信号证据验证架构_v0.7.md) 和 [评测说明](docs/20_AI信号静态提取评测说明.md)。

v0.6.0：样本侧接入 DeepSeek V4 与 Docker 静态恢复；v0.7 起远端外发不再默认开启，历史配置说明以 v0.7 文档为准。APK/DEX 与 PE/ELF 分别通过网络隔离的 JADX、Ghidra Docker 容器恢复 Java 方法、函数伪代码、字符串及导入表。

v0.5.0：按静态分析审查意见修复型号截断、SDK/模型厂商混淆、最终分类不同步、归档内层漏扫、Prompt比较资格及证据偏移等问题；新增统一静态材料索引、受限上下文查询、独立样本侧LLM链路、分析运行历史和显式重新分析API。整改范围和未验收项见 [静态分析整改落实说明](docs/17_静态分析审查意见整改落实_20260917.md)。

v0.4.0：样本静态分析与报告解析组件已完成单仓库整合，源码、规则、Schema、测试夹具及结构化知识种子均随项目提供，不再需要另外部署旧项目。

v0.3.0：新上传报告默认直接由大模型提取，已移除报告规则匹配和关键词预筛选。首次提交解析全文，仅模型容量/输出超限时全覆盖分块；保留原文证据校验，不回退规则。样本静态分析和历史结果不变。

2026-09-02 准确性修订：增加全文独立语义复核、高风险字段断言、完整性检查、身份原文锚点、日期精度保护和Prompt哈希格式兼容。DeepSeek v4默认启用思考模式；提取与复核会增加等待时间和模型用量，真实复测仍有语义误判及交付失败，需人工复核。问题分级与实测记录见 [主要问题修复说明](docs/09_报告抽取问题分级与主要修复_20260902.md)。

启动 API 前请配置 `DEEPSEEK_API_KEY`（兼容 `cc-api`），可通过 `DEEPSEEK_BASE_URL`、`DEEPSEEK_MODEL` 指定接口/型号。密钥只能通过本机环境变量注入，不得写入仓库。详细配置、全文策略与失败语义见 [报告纯大模型抽取说明](docs/07_报告纯大模型抽取说明.md)。

## 项目组成与运行依赖

项目现已自包含，样本静态分析器和报告解析组件的源码均已整合进同一仓库，不再依赖本机同级目录。基础运行需要 Python 3.11 或更高版本及 `pyproject.toml` 中声明的 Python 依赖；APK/DEX、PE/ELF 深度静态恢复另需 Docker Desktop 或兼容 Docker Engine。

```text
ai-signal-project/
├── src/
│   ├── ai_signal_hub/      # 统一 API、知识库、关联分析与统计报告
│   ├── aisig/              # 恶意样本纯静态 AI 信号分析器
│   └── report_extractor/   # 报告解析、事件抽取与证据对照
├── components/
│   ├── ai_signal_demo/     # 样本分析规则、限制配置与 Schema
│   ├── report_extractor/   # 报告结构 Schema
│   └── seed_data/          # 可公开的结构化知识种子，不含原始样本
├── docker/                 # 固定版本的 JADX/Ghidra 隔离镜像定义与导出脚本
├── ui/                     # Streamlit 测试界面
├── tests/                  # 平台与两个内置组件的回归测试
└── docs/                   # 需求、设计、验收与阶段报告
```

`components/seed_data` 包含 45 个样本的结构化分析结果、9 个家族报告抽取结果和事件统计种子，用于初始化本地知识库；不包含原始恶意样本或报告原文。运行数据库和用户上传内容仍只保存在已忽略的 `data/` 目录。

## 快速启动

```powershell
git clone git@github.com:yanghanyu521/ai-signal-project.git
Set-Location '.\ai-signal-project'
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'

# 首次使用 APK/DEX 或 PE/ELF 深度静态恢复时构建镜像
.\scripts\build_static_tool_images.ps1

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

默认从仓库内置的结构化种子数据导入 45 条既有样本结果、研究事件表和 9 个家族报告结果，并建立 9 个家族知识案例。当前主口径为 45 个样本、9 个家族、9 组家族—报告映射和 7 份逻辑去重报告；11 条早期研究事件与报告事件证据单独展示。

## 主要 API

2026-09-03 Prompt漏提复核：已补齐Python模型参数依赖追踪、Base64常量、Go字符串边界、DEX与PyInstaller成员静态恢复。13个重点缺口中12个恢复提示词或组成部分，已备份更新知识库并重建关联；不确定边界片段不当全文参与匹配。详见[复核与修复记录](docs/13_工具链阳性样本Prompt漏提复核与修复_20260903.md)。后续新上传使用此逻辑仍需重启运行中的API。

FruitShell静态规则已补齐：PowerShell多线索识别、代码词法统计及AI分析器定向注释候选；具体范围、真实隔离复测和生效方式见[FruitShell规则验收](docs/11_FruitShell静态规则修补与验收_20260903.md)。历史结果不会仅因代码更新自动重提取。

2026-09-03 样本关联已改为证据分组评分和真实固定权重融合，支持不可比较原因；不再把跨语言代码统计显示为高相似度。算法、FruitShell空关联原因及复算结果见[样本相似度修正](docs/10_样本相似度与FruitShell关联修正_20260903.md)。

- `POST /api/v1/analysis-cases`：样本/报告联合上传，按目标家族定向抽取，或选择已有案例补齐对应关系。
- `POST /api/v1/analysis-cases/{case_id}/cross-validate`：只在指定案例内执行样本—报告交叉验证。
- `POST /api/v1/samples/analyze`：上传一个样本，受控落盘并进行纯静态分析。
- `POST /api/v1/samples/{sha256}/reanalyze`：使用本地隔离保存的原始样本显式重新分析；没有原始样本时返回409，不伪装为已重提取。
- `GET /api/v1/samples/{sha256}/analysis-runs`：查看追加保存的历次结构化分析快照。
- `GET /api/v1/samples/{sha256}/associations`：查看工具链、Prompt、代码统计候选关系和聚类；`include_unmatched=true`同时查看零分/不可比较原因，分数可为null。
- `POST /api/v1/samples/recluster`：重建全部样本聚类。
- `POST /api/v1/reports/analyze`：上传报告并按 `target_name` 指定样本/家族定向抽取事件。
- `POST /api/v1/cross-validations`：对一个样本结果和报告事件进行证据对照。
- `PATCH /api/v1/events/{event_id}/context`：人工修订相关组织和国家/地区并永久写入知识库，同时保留报告抽取原值。
- `GET /api/v1/knowledge/search`：以样本/家族为中心检索，并沿分析案例和目标事件关系返回对应报告。
- `GET /api/v1/statistics/overview`：获取 25 个全球事件、9 个可分析事件、45 个样本以及报告、模型归因和月增长等分口径指标。
- `POST /api/v1/generated-reports`：按当前知识库快照填充统计报告模板。
- `POST /api/v1/knowledge/import-legacy`：从仓库内置种子数据初始化既有结构化知识（保留接口名以兼容原调用方）。

## 安全提示

- 平台绝不执行、导入、调试或仿真恶意样本；JADX/Ghidra 仅做静态恢复。启用样本侧 DeepSeek 后会向模型服务发送源码、反编译代码和提取出的静态材料，但不会把完整可执行文件编码后作为模型输入。
- `data/quarantine` 中的文件使用哈希名和 `.sample` 后缀保存；不要双击、预览或交给解释器。
- 原始样本和运行数据已在 `.gitignore` 中排除。
- 当前是本地单用户测试版，API 默认只监听 `127.0.0.1`。对外部署前必须补充认证、权限、反向代理、TLS、审计日志和独立分析沙箱。
- 样本侧大模型功能默认启用并复用报告侧 DeepSeek V4 配置，但远端外发默认禁止。密钥优先级为 `SAMPLE_LLM_API_KEY` → `DEEPSEEK_API_KEY` → `cc-api`；只有同时设置 `SAMPLE_LLM_ALLOW_REMOTE=true` 与 `SAMPLE_LLM_TRANSFER_POLICY=remote_redacted|remote_full` 才会发送样本静态材料。策略阻止时仍完成本地确定性分析并记录 `llm_transfer.destination=blocked`。
- 不设置单次分析总 token 预算；`SAMPLE_LLM_MAX_INPUT_TOKENS` 只控制每次请求的上下文大小，材料会自动分批。`SAMPLE_LLM_MAX_REQUESTS`（默认128）和超时仍作为故障/失控保护，触发后明确返回 `partial` 与未处理单元清单。
- JADX/Ghidra 容器运行时固定关闭网络、只读挂载样本、删除 Linux capabilities、限制 CPU/内存/PID，并在超时后强制回收；这降低风险但不能替代专用隔离分析主机。

详细需求、架构、v1/v2 意见处理、v0.3 报告大模型改造和验收范围见 `docs/`；报告抽取当前行为以 `07_报告纯大模型抽取说明.md` 为准。

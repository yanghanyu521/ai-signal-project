# 样本 DeepSeek V4 与 Docker 静态工具接入说明

## 1. 当前行为

样本分析继续保留原有确定性规则结果，同时增加大模型语义分析。大模型直接读取统一静态材料，包括源码函数、配置与常量、归档成员、静态字符串、JADX Java 反编译结果及 Ghidra 函数伪代码；不要求先命中已知型号或关键词规则。

样本侧默认使用与报告抽取相同的 DeepSeek V4 服务：

- 默认模型：`deepseek-v4-flash`；
- 默认地址：`https://api.deepseek.com`；
- 密钥读取顺序：`SAMPLE_LLM_API_KEY` → `DEEPSEEK_API_KEY` → 系统变量 `cc-api`；
- `SAMPLE_LLM_*` 只作为样本侧覆盖项，不配置时继承 `DEEPSEEK_*`；
- 默认启用思考模式，推理强度为 low，与报告侧配置兼容。

平台不设置“整个样本分析最多可使用多少 token”的总预算。`SAMPLE_LLM_MAX_INPUT_TOKENS=64000` 表示单次请求的上下文上限，恢复出的材料会在该上限内自动批量装箱并顺序覆盖，不再按固定字符数挑选片段。`SAMPLE_LLM_MAX_REQUESTS=128`、单请求输出上限和 HTTP 超时仍保留为异常保护；如果触发，结果明确标记为 `partial`，并列出未处理材料，不能显示为全覆盖。

模型返回的 `raw_value` 必须逐字存在于引用材料中，否则进入 `rejected_facts`。工具链事实还必须落入模型标识、SDK、服务端点或厂商等明确类型，只有 `invoke` 之类泛化方法名的候选会被拒绝。模型不能把自己的判断标记为人工已复核；接受的语义事实统一为 `semantic_review_status=needs_review`。SDK 厂商、服务商和模型厂商分字段保存，材料没有相应原文时不会由后端补写。

## 2. JADX 与 Ghidra Docker 工具

首次部署执行：

```powershell
.\scripts\build_static_tool_images.ps1
```

构建产物：

- `ai-signal/jadx:1.5.6`：处理 APK、DEX；输出 Java 反编译源，平台进一步形成方法级与类结构材料；
- `ai-signal/ghidra:12.1.3`：处理 PE、ELF、Mach-O；输出函数伪代码、虚拟地址、调用名、字符串引用和导入表。

镜像构建文件固定工具版本并校验官方发布包 SHA-256。运行容器不执行样本，且固定采用以下边界：

- `--network none`；
- 输入目录只读挂载，输出进入独立分析工件目录；
- 根文件系统只读，临时目录使用受限 tmpfs；
- 删除全部 Linux capabilities，启用 `no-new-privileges`；
- 限制 2 CPU、6 GiB 内存、256 PID；
- 设定分析超时，超时后强制删除容器。

容器隔离是本地测试和静态恢复边界，不等同于专用恶意代码分析沙箱。生产环境仍建议在独立主机或专用隔离节点运行 Docker Engine。

## 3. 配置项

```dotenv
SAMPLE_LLM_ENABLED=true
# SAMPLE_LLM_BASE_URL=https://api.deepseek.com
# SAMPLE_LLM_MODEL=deepseek-v4-flash
# SAMPLE_LLM_API_KEY=...  # 通常无需重复配置，默认读取 cc-api
SAMPLE_LLM_ALLOW_REMOTE=true
SAMPLE_LLM_MODE=coverage
SAMPLE_LLM_MAX_REQUESTS=128
SAMPLE_LLM_TIMEOUT_SECONDS=240
SAMPLE_LLM_MAX_INPUT_TOKENS=64000
SAMPLE_LLM_MAX_OUTPUT_TOKENS=16384

STATIC_TOOLS_DOCKER_ENABLED=true
JADX_DOCKER_IMAGE=ai-signal/jadx:1.5.6
GHIDRA_DOCKER_IMAGE=ai-signal/ghidra:12.1.3
STATIC_TOOL_TIMEOUT_SECONDS=600
```

`SAMPLE_LLM_ENABLED=false` 可关闭样本材料外发，但不会关闭本地规则与 Docker 静态恢复。`STATIC_TOOLS_DOCKER_ENABLED=false` 可关闭 Docker 恢复，APK/PE 等输入会保留明确限制状态。

## 4. 真实无害夹具验证

本轮完成三类真实验证，均未使用恶意样本：

1. DeepSeek V4：通过系统变量 `cc-api` 成功调用，输入无害 Python 夹具；正确抽取未知部署名 `harmless-nebula-v9` 和完整提示词 `Summarize this harmless test record.`，两条事实均通过本地原文定位，未产生拒绝事实。该次调用用量为输入777、输出2964、合计3741 token。
2. JADX：使用官方 JADX 仓库无害 `hello.dex` 夹具，容器成功完成，得到14个统一材料单元，含 `decompiled_method` 和 `decompiled_class_structure`。
3. Ghidra：使用无害 ELF 夹具，容器成功完成，得到111个函数伪代码、字符串及导入表材料单元。

这些结果证明真实模型、真实容器和统一材料索引已连通，不等于对所有文件格式、混淆、壳或编译器变体均可完整恢复，也不构成总体语义准确率评估。

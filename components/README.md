# 内置组件资源

本目录保存两个已整合分析组件的非 Python 运行资源：

- `ai_signal_demo/`：样本静态分析限制、AI 信号规则和结果 Schema；对应源码位于 `src/aisig/`。
- `report_extractor/`：报告与事件结构 Schema；对应源码位于 `src/report_extractor/`。
- `seed_data/`：用于初始化知识库的结构化样本结果、报告事件结果和事件统计 CSV。

`seed_data/` 不包含原始恶意样本或报告原文。请勿把用户上传文件、完整字符串转储、恢复载荷、API 密钥或运行数据库放入本目录；这些内容应留在已被 Git 忽略的 `data/` 目录或仓库外的受控位置。

# AI 信号静态提取评测集

本目录只包含无害合成样本和保存的无害反编译导出，不包含真实恶意代码，不执行样本，也不调用远程模型。A—K 分别覆盖已知正例、词典外模型、私有端点、诱饵、依赖、示例、分析器定向指令、动态 Prompt、封装调用、多模型及二进制/反编译关系。

运行：

```powershell
.\.venv\Scripts\python.exe .\evaluation\run_eval.py --output .\evaluation\latest_metrics.json
```

`latest_metrics.json` 是运行产物，不作为固定“成绩”写死在测试中。评测脚本默认关闭样本侧 LLM 和 Docker，只评价确定性基线；模型请求数、token 和耗时因此会如实显示为 0/本地耗时。真实模型或真实 Docker 评测应在隔离环境单独执行，并保存环境、模型版本和策略。

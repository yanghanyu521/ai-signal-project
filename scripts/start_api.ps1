$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "项目虚拟环境不存在，请先按 README 安装依赖：$python"
}

Set-Location -LiteralPath $projectRoot
& $python -m ai_signal_hub.main

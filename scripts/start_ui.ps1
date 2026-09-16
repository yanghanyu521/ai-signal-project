$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$streamlit = Join-Path $projectRoot '.venv\Scripts\streamlit.exe'

if (-not (Test-Path -LiteralPath $streamlit -PathType Leaf)) {
    throw "项目虚拟环境不存在，请先按 README 安装依赖：$streamlit"
}

Set-Location -LiteralPath $projectRoot
& $streamlit run '.\ui\streamlit_app.py'

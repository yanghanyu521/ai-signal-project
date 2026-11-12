$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$webRoot = Join-Path $projectRoot 'web'

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "未找到 Node.js，请先安装 Node.js 20+。"
}
if (-not (Test-Path -LiteralPath (Join-Path $webRoot 'node_modules') -PathType Container)) {
    Write-Host "首次运行，正在安装前端依赖…"
    & npm --prefix $webRoot install --no-audit --no-fund
}

Set-Location -LiteralPath $webRoot
& npm run dev

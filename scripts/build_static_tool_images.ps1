$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot

docker build --tag 'ai-signal/jadx:1.5.6' (Join-Path $ProjectRoot 'docker/jadx')
if ($LASTEXITCODE -ne 0) { throw 'JADX image build failed' }

docker build --tag 'ai-signal/ghidra:12.1.3' (Join-Path $ProjectRoot 'docker/ghidra')
if ($LASTEXITCODE -ne 0) { throw 'Ghidra image build failed' }

docker image inspect 'ai-signal/jadx:1.5.6' 'ai-signal/ghidra:12.1.3' `
    --format '{{.RepoTags}} {{.Id}}'

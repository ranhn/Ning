# 同时启动「Go 后端(:8787)」+「ARTEX 原生前端(:5174)」
#
#   powershell -ExecutionPolicy Bypass -File scripts\run-console.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\run-console.ps1 -UiPort 5175 -ApiPort 8788
#
# 说明：
#   - 后端负责真实能力（三层闸门/预算/指纹/证据/报告）
#   - 前端是 ARTEX 原生 Next.js 应用，侧边栏新增 "ARGUS Gate" 页，通过 /argus/* 反向代理读真实后端
#   - ARTEX 其余页面仍是 mock 数据（其 API 契约与 ARGUS 领域模型不同，需逐页写适配层）
param(
  [int]$ApiPort = 8787,
  [int]$UiPort = 5174,
  [string]$Dns = "lab.internal=10.20.0.5,api.lab.internal=10.20.0.6,evil.example.com=203.0.113.9"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path "bin/argus.exe")) {
  Write-Host "==> 构建后端" -ForegroundColor Cyan
  go build -trimpath -o bin/argus.exe ./cmd/argus
}

Write-Host "==> 启动后端 :$ApiPort" -ForegroundColor Cyan
$api = Start-Process -FilePath "$root\bin\argus.exe" `
  -ArgumentList "serve", "-addr", "127.0.0.1:$ApiPort", "-data", "data", "-web", "", "-dns", $Dns `
  -WorkingDirectory $root -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 1

if (-not (Test-Path "webui\node_modules")) {
  Write-Host "==> 首次运行，安装前端依赖（约 650MB，几分钟）" -ForegroundColor Yellow
  Push-Location webui
  & "C:\Program Files\nodejs\npm.cmd" ci --no-audit --no-fund
  Pop-Location
}

Write-Host "==> 启动 ARTEX 前端 :$UiPort" -ForegroundColor Cyan
$env:NEXT_PUBLIC_MOCK = "1"
# 清空 ARTEX 自带的演示数据（acme.com 那套），未接真实后端的页面显示空状态
$env:NEXT_PUBLIC_MOCK_CLEAN = "1"
$env:NEXT_TELEMETRY_DISABLED = "1"
$env:AUTOPENTEST_API = "http://127.0.0.1:$ApiPort"
$ui = Start-Process -FilePath "C:\Program Files\nodejs\npx.cmd" `
  -ArgumentList "next", "dev", "-p", $UiPort `
  -WorkingDirectory "$root\webui" -PassThru -WindowStyle Hidden

Write-Host ""
Write-Host "  ARTEX 界面      : http://127.0.0.1:$UiPort/" -ForegroundColor Green
Write-Host "  ARGUS Gate 页   : http://127.0.0.1:$UiPort/function/argus" -ForegroundColor Green
Write-Host "  后端 API        : http://127.0.0.1:$ApiPort/api/health"
Write-Host ""
Write-Host "  停止: Stop-Process -Id $($api.Id),$($ui.Id) -Force"

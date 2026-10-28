# 本地一键启动 ARGUS（前端 + API 同一个端口）
#
#   powershell -ExecutionPolicy Bypass -File scripts\run-local.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\run-local.ps1 -Lan -Token mytoken
#
# 默认：只监听 127.0.0.1:8787，无鉴权（本机可用），并带演示用静态解析表，
# 这样 lab.internal 之类不存在的域名不会被"解析失败即拒绝"全部拦下。
param(
  [int]$Port = 8787,
  [switch]$Lan,
  [string]$Token = "",
  [string]$Dns = "lab.internal=10.20.0.5,api.lab.internal=10.20.0.6,evil.example.com=203.0.113.9"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# 构建（若本机没有 go，请先构建好 bin/argus.exe 并放到 PATH）
if (Get-Command go -ErrorAction SilentlyContinue) {
  Write-Host "==> go build" -ForegroundColor Cyan
  go build -trimpath -o bin/argus.exe ./cmd/argus
} elseif (-not (Test-Path "bin/argus.exe")) {
  throw "找不到 go 工具链，也没有 bin/argus.exe"
}

$addr = if ($Lan) { ":$Port" } else { "127.0.0.1:$Port" }
if ($Lan -and [string]::IsNullOrWhiteSpace($Token)) {
  $Token = [Convert]::ToBase64String((1..18 | ForEach-Object { Get-Random -Maximum 256 }))
  Write-Host "==> 已生成访问 token（局域网访问必须带）: $Token" -ForegroundColor Yellow
}
if ([string]::IsNullOrWhiteSpace($Token)) {
  Write-Host "==> 未设置 token：仅允许本机访问" -ForegroundColor DarkYellow
}

$args = @("serve", "-addr", $addr, "-data", "data", "-web", "web")
if (-not [string]::IsNullOrWhiteSpace($Token)) { $args += @("-token", $Token) }
if (-not [string]::IsNullOrWhiteSpace($Dns)) { $args += @("-dns", $Dns) }

$url = "http://127.0.0.1:$Port/"
if (-not [string]::IsNullOrWhiteSpace($Token)) { $url += "?token=$Token" }
Write-Host ""
Write-Host "  控制台: $url" -ForegroundColor Green
Write-Host "  API   : http://$(if($Lan){'<本机IP>'}else{'127.0.0.1'}):$Port/api/health"
Write-Host ""

& ./bin/argus.exe @args

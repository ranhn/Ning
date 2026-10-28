<#
.SYNOPSIS
    创建并启动一个 ARGUS 任务（自动生成授权范围与种子意图）。

.DESCRIPTION
    只用一条命令就能从"什么都没有"到"任务跑起来、界面有数据"。
    会根据本机已安装的工具自动生成种子意图（装了 nmap 就扫端口，只有 curl 就抓响应头）。

.PARAMETER Target
    授权目标。域名（example.com）、IP（10.0.0.5）或 CIDR（10.0.0.0/24）。

.PARAMETER Kind
    范围类型：domain_suffix（默认，匹配子域）/ exact_domain / exact_ip / cidr / exact_url

.PARAMETER Goal
    任务目标描述，会写进报告。留空则自动生成。

.EXAMPLE
    .\scripts\new-task.ps1 -Target 10.20.0.5
    .\scripts\new-task.ps1 -Target lab.internal -Kind domain_suffix -Workers 3
    .\scripts\new-task.ps1 -Target 10.0.0.0/24 -Kind cidr -Minutes 60
#>
param(
  [Parameter(Mandatory = $true)][string]$Target,
  [ValidateSet('domain_suffix', 'exact_domain', 'exact_ip', 'cidr', 'exact_url')]
  [string]$Kind = 'domain_suffix',
  [string]$Goal = '',
  [int]$Workers = 2,
  [int]$Minutes = 30,
  [string]$Api = 'http://127.0.0.1:8787',
  [string]$Token = $env:ARGUS_TOKEN
)

$ErrorActionPreference = 'Stop'

# ---- 1. 探测本机可用工具，生成对应意图 ----
$seed = New-Object System.Collections.ArrayList
$hasNmap = [bool](Get-Command nmap -ErrorAction SilentlyContinue)
$hasCurl = [bool](Get-Command curl.exe -ErrorAction SilentlyContinue) -or [bool](Get-Command curl -ErrorAction SilentlyContinue)

$isCidr = $Kind -eq 'cidr'
$isUrl = $Kind -eq 'exact_url'
$hostTarget = ($Target -replace '^https?://', '') -replace '/.*$', ''

if ($hasNmap) {
  $nmapArgs = if ($isCidr) { "nmap -sV -Pn --top-ports 100 $Target" } else { "nmap -sV -Pn --top-ports 100 $hostTarget" }
  [void]$seed.Add(@{ action = 'Bash'; summary = (@{ command = $nmapArgs } | ConvertTo-Json -Compress); param_key = 'nmap-top100' })
}

if ($hasCurl) {
  $urls = if ($isUrl) { @($Target) } else { @("http://$hostTarget/", "https://$hostTarget/") }
  foreach ($u in $urls) {
    $cmd = "curl -sS -D - -o NUL --max-time 8 $u"
    $pk = 'curl-' + ($u -replace '[^a-zA-Z0-9]', '')
    [void]$seed.Add(@{ action = 'Bash'; summary = (@{ command = $cmd } | ConvertTo-Json -Compress); param_key = $pk })
  }
  if (-not $isCidr -and -not $isUrl) {
    [void]$seed.Add(@{ action = 'Bash'; summary = (@{ command = "curl -sS --max-time 8 http://$hostTarget/robots.txt" } | ConvertTo-Json -Compress); param_key = 'curl-robots' })
  }
}

if ($seed.Count -eq 0) {
  Write-Warning '本机没有 nmap 也没有 curl，只能创建空任务（需要手动加意图）。'
}

# ---- 2. 组装请求 ----
if ([string]::IsNullOrWhiteSpace($Goal)) {
  $Goal = "对 $Target 进行授权范围内的信息收集与风险验证（$Kind）"
}

$body = [ordered]@{
  name    = ($Target -replace '[^\w\.\-/]', '_') + '-' + (Get-Date -Format 'MMdd-HHmm')
  goal    = $Goal
  scope   = @(@{ kind = $Kind; value = $Target })
  workers = $Workers
  minutes = $Minutes
  seed    = @($seed)
} | ConvertTo-Json -Depth 6

$tmp = Join-Path $env:TEMP ('argus-task-' + [guid]::NewGuid().ToString('N') + '.json')
[IO.File]::WriteAllText($tmp, $body, (New-Object System.Text.UTF8Encoding($false)))

$headers = @{}
if ($Token) { $headers['Authorization'] = "Bearer $Token" }

try {
  $created = Invoke-RestMethod -Uri "$Api/api/tasks" -Method Post -ContentType 'application/json; charset=utf-8' `
    -Headers $headers -InFile $tmp -TimeoutSec 30
} finally {
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

$id = $created.task.id
Write-Host ''
Write-Host "任务已创建  #$id  $($created.task.name)" -ForegroundColor Green
Write-Host "  范围      $Kind : $Target"
Write-Host "  种子意图  $($created.seed_intents) 条（去重后丢弃 $($created.seed_deduped) 条）"
Write-Host "  工具      nmap=$(if($hasNmap){'有'}else{'无'})  curl=$(if($hasCurl){'有'}else{'无'})"

# ---- 3. 启动 ----
Invoke-RestMethod -Uri "$Api/api/tasks/$id/start" -Method Post -Headers $headers -TimeoutSec 30 | Out-Null

Write-Host ''
Write-Host "已启动，等待执行..." -ForegroundColor Cyan
$state = ''
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Seconds 2
  $d = Invoke-RestMethod -Uri "$Api/api/tasks/$id" -Headers $headers -TimeoutSec 10
  $state = $d.task.state
  if ($state -in @('done', 'stopped', 'timeout')) { break }
}

Write-Host ''
Write-Host "终态：$state"
Write-Host "  意图 $($d.intents)  漏洞 $($d.findings)  越界 $($d.violations)  证据 $($d.evidence)"
Write-Host ''
Write-Host '在浏览器里看结果：'
Write-Host '  http://127.0.0.1:5174/function/argus     三层闸门 / 越界 / 证据 / 报告'
Write-Host '  http://127.0.0.1:5174/function/findings  漏洞列表'
Write-Host "  $Api/api/tasks/$id/report                 Markdown 报告"

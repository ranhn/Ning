---
name: recon-web
description: Web 目标只读侦察：端口/标题/技术栈指纹，不做任何破坏性动作
license: MIT
---

# Web 只读侦察

## 适用场景
拿到一个已授权的域名/IP，需要在不触发告警、不修改目标的前提下摸清面。

## 步骤
1. **端口与服务**：`nmap -sV -Pn --top-ports 100 <target>`（不要用 `-sS` 扫全端口，容易被封）
2. **HTTP 指纹**：抓取首页与响应头
   ```bash
   curl -sS -D - -o /dev/null --max-time 10 http://<target>/
   ```
3. **常见路径**：`/robots.txt`、`/sitemap.xml`、`/.well-known/security.txt`
4. **技术栈**：从响应头 `Server` / `X-Powered-By` / `Set-Cookie` 推断；不要靠 Wappalyzer 之类的被动猜测下结论

## 产出（写成 fact）
- `reachable`：`<host>:<port> 返回 200，Server: nginx/1.24`
- `tech`：`<host> 使用 PHP 8.2 + nginx`

## 禁止
- 任何写操作（POST/PUT/DELETE）
- 目录爆破超过 200 个请求（属于扫描行为，会触发 WAF）
- 对非授权范围的目标发起请求（闸门会拦，但不要主动尝试）

# ARGUS

**授权渗透测试的编排与管控平台** —— 把「授权范围」从文档里的条款，变成执行期与网络期不可绕过的代码约束。

```
三层范围闸门 · 三维预算硬闸 · 意图指纹去重 · 哈希链证据 · 沙箱/容器隔离 · 出口白名单
```

---

## 1. 概述

AI 驱动的自动化渗透测试已经能自己规划、自己调工具。真正拦住它进生产的从来不是"能力不够"，而是**没人能证明它不会越界**。

ARGUS 的取舍很明确：**不追求更聪明的 Agent，先把"它绝不会打到范围外"做成可验证的事实**。在此基础上再谈自主性、效率与覆盖度。

系统的核心是一条贯穿三层的判定链：

| 层 | 拦截点 | 拦什么 |
|---|---|---|
| L1 意图层 | 任务入队前 | 目标不在授权范围、参数含越界主机 |
| L2 执行层 | 工具调用前 | 实际要执行的目标（含 DNS 解析后的 IP）越界 |
| L3 网络层 | socket 建立时 | 最终要连的 IP 越界（DNS 重绑定在此失效） |

任一层命中即拒绝，并写入 `scope_violation` 台账。**三层独立生效**：前两层被绕过，第三层仍然挡住。

---

## 2. 设计原则

1. **失败关闭（fail-closed）**：范围为空、解析失败、判定不确定，一律拒绝，不做"善意推测"。
2. **边界在代码里，不在提示词里**："请只在授权范围内操作"是建议，`CheckDial` 是约束。
3. **结论必须可复现**：每条漏洞绑定证据（原始命令 + 输出 + 哈希链），复核人不需要信任执行者。
4. **资源必须封顶**：单意图 / 单任务 / 单日三维预算，超限即熔断，不允许"跑飞"。

---

## 3. 架构

```
┌─────────────────────────────────────────────────────────────┐
│  呈现层   Web 控制台（Next.js）· REST API · Markdown 报告      │
├─────────────────────────────────────────────────────────────┤
│  控制面   任务编排 · CAS 领取 · 防抖规划 · deadline 有序收尾     │
│           三维预算 · 意图指纹去重 · LLM 规划器                   │
├─────────────────────────────────────────────────────────────┤
│  执行面   执行器（三级隔离）                                    │
│           sim（自检） → real（同机沙箱） → container（一次性）    │
├─────────────────────────────────────────────────────────────┤
│  安全面   L1 意图闸门 → L2 执行闸门 → L3 网络闸门               │
│           出口网关白名单（与闸门同源生成）                       │
├─────────────────────────────────────────────────────────────┤
│  证据面   只追加 JSONL · SHA-256 哈希链 · 可校验 · 可回放        │
├─────────────────────────────────────────────────────────────┤
│  知识面   事实层（fact）· ATT&CK 映射 · Sigma 检测草稿           │
└─────────────────────────────────────────────────────────────┘
```

| 包 | 职责 |
|---|---|
| `internal/scope` | 范围规则、目标抽取（URL / IP / 主机名） |
| `internal/gate` | 三层闸门、解析钉 IP、元数据红线 |
| `internal/netguard` | 拨号期闸门（`Dial.Control`），出站 HTTP 复用闸门解析结果 |
| `internal/budget` | 三维预算账本，原子扣减 |
| `internal/dedupe` | `sha256(asset|action|param)` 指纹去重 |
| `internal/evidence` | 哈希链证据库 |
| `internal/engine` | 调度器：领取、防抖、心跳、收敛、截止收尾 |
| `internal/toolbox` | 命令白名单沙箱 + 容器后端 + 工具指纹校验 |
| `internal/planner` | OpenAI 兼容 LLM 规划器（token 计入预算） |
| `internal/egress` | 授权范围 → 出口网关白名单 |
| `internal/attack` | ATT&CK 映射、Sigma 草稿 |
| `internal/selftest` | 23 项安全不变量自检 |

---

## 4. 安全模型

### 4.1 威胁模型

| 编号 | 威胁 | 控制措施 |
|---|---|---|
| T1 | 模型提出范围外目标 | L1/L2 闸门 + 空范围默认拒绝 |
| T2 | DNS 重绑定绕过域名校验 | 域名授权即钉住解析 IP；L3 只校验 IP |
| T3 | 提示词注入诱导越权 | 闸门不读提示词，只读工具输入与真实 IP |
| T4 | 工具自身 0day / 读到宿主文件 | 容器隔离：只读根、`cap-drop ALL`、非 root、仅挂任务目录 |
| T5 | 证据被篡改 | 哈希链，`Verify()` 可定位断点 |
| T6 | 预算失控（token / 步数） | 三维硬闸，超限整体不扣并熔断 |

### 4.2 三层闸门

```go
// L1：任务入队（intent 粒度）
dec := gate.CheckIntent(ctx, taskID, intentID, tool, targets)

// L2：工具调用前（解析后校验 IP）
dec := gate.CheckTool(ctx, taskID, intentID, tool, inputJSON)

// L3：socket 建立时（只认 IP，不认域名）
dialer.Control = func(network, address string, c syscall.RawConn) error {
    return gate.CheckDial(ipOf(address))
}
```

### 4.3 不变量（由 `argus selftest` 逐条验证）

| # | 不变量 |
|---|---|
| 1–4 | 空范围拒绝；范围外域名 / IP / CIDR 越界必拦 |
| 5–6 | 云元数据地址（`169.254.169.254` 等）永久红线，写入 CIDR 也不放行 |
| 7–8 | 域名授权钉住解析 IP；未钉住的公网 IP 仍被 L3 拦截 |
| 9–11 | 指纹去重（含并发）；预算超限不扣款；截止时间有序收尾 |
| 12–14 | 证据链可校验、可续写、篡改可定位 |
| 15–17 | 创建任务必须带非空 scope；报告含越界台账；ATT&CK 映射覆盖中英文写法 |
| 18–19 | 资产只来自"放行过的目标"；越界目标不进资产图 |
| 20–21 | 沙箱拒绝 shell 注入 / 非白名单工具 / 危险参数；工具指纹不匹配即禁用 |
| 22 | 容器隔离参数完整（只读根 / cap-drop / 非 root / pids / memory / add-host），缺运行时**拒绝启动** |
| 23 | 出口白名单与闸门同源（同一份 scope 生成） |

### 4.4 已知边界

- **不做 MITM 流量录制**：只记录执行器实际发出的 HTTP 请求（URL、状态、响应体、错误）。
- **单实例**：状态为 JSON 快照（`state.json`），不支持多副本共享；HA 需切换 PostgreSQL 实现（`schema.sql` 已就绪）。
- **容器模式需 Docker / Podman**：缺失时启动即失败，不退化到同机执行。
- **不含后渗透能力**：工具白名单只含探测与验证类工具。

---

## 5. 核心能力

### 5.1 范围闸门（`internal/gate`）

支持五类规则：`exact_domain` / `domain_suffix` / `cidr` / `exact_ip` / `exact_url`。
匹配前先做目标抽取（从工具输入里取 URL、IP、主机名），再做判定；**抽取不到目标时按"无目标"处理而非放行**。

### 5.2 三维预算（`internal/budget`）

| 维度 | 上限来源 | 行为 |
|---|---|---|
| 单意图 | 步数 / token / 成本 | 超限该意图终止 |
| 单任务 | 同上 | 超限任务熔断 |
| 单日 | 同上 | 超限拒绝新任务 |

`ChargeAll` 原子扣减：任一项超限则**整体不扣**，避免"扣了一半"的中间态。

### 5.3 意图指纹去重（`internal/dedupe`）

`sha256(assetID | action | normalized(paramKey))`，参数顺序、大小写、空白归一化。同一指纹只入图一次，抑制模型复读导致的步数浪费。

### 5.4 哈希链证据（`internal/evidence`）

```
{"seq":42,"id":"ev-000042","kind":"command","payload":{...},"hash":"<sha256(prev|payload)>"}
```

- 只追加，`Verify()` 返回首个断点
- 重启续写原链（不重置 `last hash`）
- 文件不可读时备份为 `*.corrupt-<ts>` 并重建，**服务不因证据文件损坏而起不来**

### 5.5 执行隔离（三级）

| 模式 | 隔离强度 | 适用 |
|---|---|---|
| `-exec sim` | 仅跑 `echo`，用于自检与演示 | 开发 |
| `-exec real` | 无 shell 分词、二进制白名单、危险参数禁用、受限环境变量 | 单机生产 |
| `-exec container` | 每意图一次性容器：只读根 + `cap-drop ALL` + 非 root + pids/内存/CPU 上限 + 仅挂任务目录 | 生产推荐 |

真实执行器与模拟执行器**共用同一份前置校验**（`preflight`：规则层 → L2 闸门 → 资产记账），换执行器不削弱任何一道闸门。

外部二进制无法挂 `Dial.Control`，因此启动前做 **L3 预校验**：目标解析出的每个 IP 都必须通过 `CheckDial`，任一越界即拒绝启动。

### 5.6 出口管控（`internal/egress`）

授权范围直接生成网关配置，不需要手写白名单：

```bash
argus egress -scope "domain_suffix:lab.internal,cidr:10.20.0.0/16" -o deploy/egress/argus-allow.conf
```

```squid
acl argus_domains dstdomain .lab.internal
acl argus_nets dst 10.20.0.0/16
http_access allow CONNECT argus_domains
http_access deny all
never_direct allow all
```

容器侧配套：`--network <internal-net>` + `--add-host <闸门批准的 host:ip>`，
容器内 DNS 与闸门判定是同一份答案。

### 5.7 规划与知识层

- **规划器**：OpenAI 兼容接口，上下文含任务目标、已有意图（含状态）、已确认资产与漏洞、**被闸门拦过的目标**；输出强约束为 JSON，做防御性解析。
- **token 计量**：模型消耗计入同一本预算账，超限同样熔断；未配置模型时自然收敛，不空转。
- **事实层**：每次执行沉淀 `fact`（可访问性、技术栈、失败原因），下一轮规划可复用，避免重复探索。
- **紫队**：每条 finding 自动映射 ATT&CK 技术，并生成 Sigma 检测草稿（`GET /api/findings/{id}/sigma`）。

### 5.8 报告

Markdown 输出，含授权范围、漏洞（严重级别 / ATT&CK / 证据哈希）、**命令回放**（原始命令 + 输出摘录 + 退出码）、越界台账、探索路径、预算快照。

---

## 6. 快速开始

```bash
# 1. 自检（23 项安全不变量，无外部依赖）
go run ./cmd/argus selftest

# 2. 端到端演示（3 worker，含越界拦截 / 去重 / 带证据的 finding）
go run ./cmd/argus demo

# 3. 启动服务
go build -o bin/argus ./cmd/argus
./bin/argus serve -addr 127.0.0.1:8787 -data data -token $ARGUS_TOKEN
```

Windows 一键启动（后端 + Web 控制台）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run-console.ps1
```

创建一个任务：

```bash
curl -X POST localhost:8787/api/tasks -H "Authorization: Bearer $ARGUS_TOKEN" \
  -H 'Content-Type: application/json' --data @examples/demo-task.json
```

---

## 7. 部署

| 形态 | 适用 | 文件 |
|---|---|---|
| systemd | 单机 | `deploy/`（非 root、`ProtectSystem=strict`、只读根） |
| Docker Compose | 常规 | `Dockerfile`、`docker-compose.yml` |
| Kubernetes | 多租户 / 规模化 | `deploy/k8s/deployment.yaml`、`networkpolicy.yaml` |
| 出口网关 | 需要网络层白名单 | `deploy/egress/`（squid + internal network） |
| 工具镜像 | 容器执行 | `deploy/toolbox/Dockerfile` |

最低配置：2 vCPU / 2 GB / 20 GB。推荐：4 vCPU / 4 GB / 100 GB SSD。

生产必做：

1. 设置 `-token`（否则 API 无鉴权）
2. 仅监听 `127.0.0.1`，由反向代理暴露 443
3. `data/` 作为唯一可写目录
4. 容器模式不要挂 docker socket（用 rootless）

---

## 8. HTTP API

| 分组 | 端点 |
|---|---|
| 任务 | `GET/POST /api/tasks`、`GET /api/tasks/{id}`、`POST /api/tasks/{id}/start|stop`、`GET /api/tasks/{id}/report` |
| 范围 | `GET /api/tasks/{id}/scope`、`GET /api/tasks/{id}/egress` |
| 执行 | `GET /api/exploration/intents`、`GET /api/tasks/{id}/evidence`、`GET /api/evidence/{id}` |
| 结果 | `GET /api/findings`、`GET /api/findings/{id}/sigma`、`PATCH /api/findings/{id}`（status / severity） |
| 越界 | `GET /api/tasks/{id}/violations` |
| 资产 | `GET /api/assets`、`GET /api/assets/counts` |
| 管控 | `GET/POST /api/intercept/rules`、`GET /api/intercept/pending`、`POST /api/intercept/pending/{id}/decide` |
| 配置 | `GET/PUT /api/llm`、`POST /api/llm/test`、`GET /api/settings` |
| 运维 | `GET /api/health`、`GET /api/budget`、`GET /api/stats`、`GET /api/skills` |

兼容层（`internal/api/compat*.go`）按 Web 控制台的原生形状返回数据，前端无需二次映射。

---

## 9. 质量保证

```
go vet ./...            0
go build ./...          0
argus selftest          23/23 通过
前端 tsc --noEmit       0
```

- CI（`.github/workflows/ci.yml`）：`go vet` → `go build` → `selftest` → 前端构建
- 安全回归：自检覆盖全部不变量，任何一条失败即阻断合并
- 实测基线（本机）：`demo` 任务 6 意图 / 3 完成 / 3 拦截 / 1 去重 / 1 条带证据 finding，耗时约 4 秒

---

## 10. 路线图

| 版本 | 内容 | 状态 |
|---|---|---|
| v0.1 | 安全内核（三层闸门 / 预算 / 去重 / 证据 / 调度 / 报告） | 完成 |
| v0.2 | 真实工具执行（白名单沙箱 + 工具指纹校验） | 完成 |
| v0.3 | 容器隔离 + 出口网关白名单 + 事实层 | 完成 |
| v0.4 | 发现生命周期（复测 / 导出 / Sigma）、规则审批 | 完成 |
| v1.0 | PostgreSQL 后端、多副本、多租户 | 规划中 |

---

## 11. 第三方组件

Web 控制台的界面基于开源项目 **ARTEX**（MIT License）的中文版本构建，其原始许可声明保留在 `webui/LICENSE`。
Go 后端为独立实现，**零外部依赖**（仅标准库）。

---

## 12. 使用边界

本系统仅用于**已获得书面授权**的渗透测试、自有资产安全评估与安全教学环境。

使用者须自行确保：

- 对每个测试目标持有明确的书面授权
- 遵守所在司法辖区法律及目标所属方的安全策略
- 不将本系统用于未授权访问、数据窃取或任何破坏性用途

作者不对任何滥用行为承担责任。

---

## License

MIT（见 `LICENSE`），附带使用限制声明。

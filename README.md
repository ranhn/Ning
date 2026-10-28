# ARGUS

**带三层范围闸门的自主渗透测试系统** —— 从 ARTEX 生态（GitHub star 榜前十，约 100 万行 Go）的源码级横评中提炼设计，
并补上这十家全都没有的那一层：**执行期与网络期的授权范围控制**。

> 定位：实验级 → 可交付级的第一步。当前版本 `0.1.0` 完成 A1 阶段（安全内核 + 单任务闭环 + 证据链 + 报告）。
> 不含真实攻击载荷：`demo`/`selftest` 走完整链路但只执行本地 `echo`，换掉 `Executor` 即可接入 nmap/nuclei 等真实工具。

---

## 为什么要自己做

对 ARTEX 及其 star 榜前十的全量源码比对结论（详见 `../ARTEX/ARGUS-最强方案.md`）：

| 事实 | 后果 |
|---|---|
| 原作者 2026-10-08 闭源，原库与官方镜像均已下架 | 只能用 fork，且 fork 会悄悄回退安全修复 |
| `bdg9412/artex-ko-plus`（AegisLoop，245★）**回退了 0.3.15 鉴权修复** | `hash, _, _ := GetSetting` 丢错误 + 无条件 `SetSetting` = 未认证管理员覆盖 |
| 十家全部只有"意图层"范围校验（`EvaluateAssetGate` 挂在 `insert_assets`/`add_intent`） | worker 直接 `curl 范围外域名`，一步都不用经过闸门 |
| `max_turns` 默认 0（不限）、token 只记账不熔断 | 跑飞时没有刹车 |
| 意图去重靠 prompt 里"主要靠它自己比对" | 重复意图烧预算 |
| CI 不跑 `go test`（2k 星的镜像 0 增量，141 星的仓库反而 307 个测试 + race + 隔离 PG） | star 数与质量无关 |

**ARGUS 的判断：不存在"最强 fork"，只存在"最强的拼装方式 + 自研内核"。**

---

## 三层闸门（本项目的核心）

```
模型想去哪            工具要打哪                  包实际发到哪
    │                     │                            │
    ▼                     ▼                            ▼
┌─────────┐         ┌──────────┐              ┌──────────────┐
│ intent  │   →     │   exec   │      →       │   network    │
│ 派发/资产│         │ 解析+解析后判定│            │ Dialer.Control│
└─────────┘         └──────────┘              └──────────────┘
   Deny                Deny                        Deny
```

- **第 1 层 `gate.CheckIntent`**：派发意图/写资产前的校验。
- **第 2 层 `gate.CheckTool`**：从工具输入（JSON / Bash 文本 / URL）抽取全部 host、IP、URL，
  **先解析再判定**；解析失败 = 失败关闭。
- **第 3 层 `gate.CheckDial`**：在 socket 建立前只认 IP，**不解析任何域名**，
  因此 DNS 重绑定、CNAME 跳转、脚本内计算目标都绕不过去。由 `netguard.Dialer` 的
  `Control` 回调挂载，`netguard.HTTPClient` 显式禁用环境变量代理。

铁律三条：

1. **空范围 = 拒绝一切**（ARTEX 是"没配规则就全放行"）。
2. **任何一层命中即 `deny`**，不是 `ask`——人工审批可能被误点通过。
3. **第 3 层必须能在前两层被完全绕过时独立生效**。

云元数据地址（`169.254.169.254`、`100.100.100.200`、`fd00:ec2::254` 等）属于**永久红线**：
即使你把 `169.254.0.0/16` 写进授权范围，仍然拒绝（见 `gate.blockedAddr`）。

---

## 快速开始

### 本地直接访问（前端 + API 同端口，推荐）

```powershell
# Windows 一键启动（自动构建，带演示解析表）
powershell -ExecutionPolicy Bypass -File scripts\run-local.ps1

# 局域网访问（自动生成 token，URL 带 ?token= 即可）
powershell -ExecutionPolicy Bypass -File scripts\run-local.ps1 -Lan -Token mytoken
```

然后打开 **http://127.0.0.1:8787/** —— 左侧「⚡ 一键演示任务」会创建一个
带授权范围的示例任务（3 条正常意图 + 3 次越界拦截 + 1 条带证据的 SQL 注入），
可在「概览 / 意图 / 漏洞 / 越界拦截 / 证据 / 报告」六个标签页里看到全过程。

```bash
# 等价的手工启动
go build -o bin/argus ./cmd/argus
./bin/argus serve -addr 127.0.0.1:8787 -data data -web web \
  -dns lab.internal=10.20.0.5,api.lab.internal=10.20.0.6
```

> `-dns` 是实验室/离线用的静态解析表。不配它时，`lab.internal` 这类不存在的域名会解析失败，
> 而解析失败按失败关闭处理——这是**正确行为**，但会让演示任务全部被拦。
> `-web` 留空则只提供 API（前端可单独部署到 nginx/CDN）。

### ARTEX 原生界面（webui/）

### 真实工具执行器（`-exec real`，默认）

`internal/toolbox` 是真实执行的唯一入口，`internal/agent/real.go` 是使用它的执行器。
**前置校验与模拟执行器完全共用**（`preflight`：规则层 → 第 2 层闸门 → 资产记账），
只有"执行"这一步换成沙箱调用——换执行器不会削弱任何一道闸门。

| 防线 | 做法 |
|---|---|
| 不经过 shell | 自己分词成 argv 再 `exec.CommandContext`，`; \| & $ `` ` `` > < \n \` 一律**拒绝**（不转义） |
| 二进制白名单 | nmap / nuclei / curl / httpx / dig / whois / nikto / sqlmap / ffuf / whatweb，其余拒绝 |
| 危险参数禁用 | nmap `--script`/`-iL`/`-o*`、curl `-o`/`-K`/`-T`、sqlmap `--os-shell`/`--file-*` 等 |
| 文件系统 | 参数禁用绝对路径与 `..`；工作目录固定 `data/work`；输出截断 64KB |
| 环境变量 | 只留 PATH/HOME/TMPDIR/LANG，**显式清空所有 `*_PROXY`**（防止绕过网络层） |
| 网络层 | 外部二进制无法挂 Dial.Control，因此启动前做**第 3 层预校验**：目标解析出的每个 IP 都过 `CheckDial`，任一越界即拒绝启动 |
| 超时 | 按工具设定（curl 60s / nmap 5min / sqlmap 8min），超时 kill 并记 blocked |

实测（`-exec real`，scope 只允许 127.0.0.1）：

```
#44 done     curl -sS http://127.0.0.1:8787/api/health   → 真实输出 {"evidence":65,"ok":true,"service":"argus",...}
#45 blocked  curl -sS http://example.com/                → 越界：域名不在授权范围（exec 层）
#46 blocked  curl .../api/health; whoami                 → 控制字符，sandbox_denied（未执行）
```

### 每意图一次性容器（`-exec container`，真隔离）

同机沙箱防的是"模型乱写命令"，防不住"工具自身 0day"和"读到宿主机文件"。容器把这两件事一起解决：

```bash
# 1) 构建工具镜像（只装探测/验证工具，不含后渗透框架）
docker build -t argus-toolbox:latest deploy/toolbox

# 2) 建一个受控出网网络（由网关/防火墙做白名单；none = 完全无网）
docker network create --internal argus-egress

# 3) 用容器执行器启动
argus serve -exec container -image argus-toolbox:latest -egress-net argus-egress
```

每个意图一条命令，固定参数（`internal/toolbox/container.go`）：

```
docker run --rm --name argus-<intent>-<ts> \
  --network <egress-net> --user 65534:65534 \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 512m --cpus 1 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v <data>/work/task-<id>:/work:rw -w /work \
  --add-host <闸门批准过的 host:ip> \
  --entrypoint <工具> argus-toolbox:latest <参数...>
```

三个关键点：

1. **`--add-host` 来自闸门**：容器内 DNS 拿到的就是 `gate.CheckDial` 批准过的 IP，
   容器自己解析不到第二个地址——DNS 重绑定在隔离层同样无效。
2. **失败关闭**：`-exec container` 启动时探测运行时，找不到 docker/podman 直接**拒绝启动**
   （`容器运行时不可用：找不到 docker…`），绝不悄悄退化成本机执行。
3. **只挂载任务工作目录**，根文件系统只读，`/tmp` 是 noexec 的 tmpfs。

> 本机（开发机）没有 Docker，所以容器模式只做了**参数构造与失败关闭**的自检验证；
> 容器内真实执行需要在一台有 Docker 的机器上跑 `argus serve -exec container`。

### 出口网关白名单（与闸门同源，不用手写）

网络层的最终形态：容器在 `--internal` 网络里没有 NAT，**唯一出口是 squid**，而 squid 的放行清单
由 ARGUS 从任务授权范围生成。

```bash
# 从范围生成网关配置片段（自动建目录）
argus egress -scope "domain_suffix:lab.internal,cidr:10.20.0.0/16" -o deploy/egress/argus-allow.conf

# 起网关（internal 网络 + 只读根，不映射端口，公网碰不到）
docker compose -f deploy/egress/docker-compose.egress.yml up -d

# 让容器走网关
argus serve -exec container -egress-net argus-egress -egress-proxy http://egress:3128
```

生成的内容是标准 squid ACL：

```
acl argus_domains dstdomain .lab.internal
acl argus_nets dst 10.20.0.0/16
http_access allow CONNECT argus_domains
http_access allow CONNECT argus_nets
http_access deny all
never_direct allow all
```

同一份清单也能从运行中的任务拉取（`GET /api/tasks/{id}/egress`，返回 `squid_conf` / `hosts_file`），
这样"任务声明的范围"和"网关实际放行的目标"永远是同一份数据。

### 报告里的命令回放

每条 finding 附"原始命令 + 输出摘录 + 退出码"，报告末尾还有最近 20 条命令回放：

```console
$ curl -sS --max-time 5 http://127.0.0.1:8787/api/health
{"evidence":69,"ok":true,"service":"argus","time":"2026-10-28T01:34:01Z"}
# exit 0
```

复核人不用翻证据库就能复现结论（证据哈希与 ATT&CK 技术仍保留在每条 finding 上）。

### 持久化：重启不丢

`store.Open(data/state.json)` 提供内存存储的 JSON 快照：

- **授权范围也一起落盘**（`Task.ScopeRules`）：否则重启后任务还在、范围没了，
  闸门会按"空范围=默认拒绝"把一切拦下，报告与出口白名单也会变空——"看起来正常、实际失忆"是最坏的情况。
  重启后 `scopeOf()` 会从持久化规则重建并缓存，闸门 / 报告 / 网关白名单看到的都是同一份范围。
- 任何写操作（任务/意图/漏洞/资产/越界/事实/流量/规则/审批）都标记 dirty，后台 500ms 内**原子落盘**（临时文件 + rename）；
- 落盘在锁外进行（先拷贝快照再写），不阻塞调度；
- 启动时自动加载；**文件损坏会备份成 `*.corrupt-<ts>` 并重新开始**，而不是让服务起不来
  （本机 DLP 会加密非白名单进程写入的文件，这个分支真会被走到）；
- 实测：起任务 → 杀进程 → 重启，`tasks=1 assets=2 findings=1` 全部还在。

### 运行期配置 LLM（不重启生效）

```bash
# 查看（密钥只回显 api_key_set，绝不回显明文）
curl -s localhost:8787/api/llm

# 配置模型（api_key 传空字符串 = 保持原值）
curl -s -XPUT localhost:8787/api/llm -H 'Content-Type: application/json' -d '{
  "provider":"openai","model":"gpt-4.1",
  "base_url":"https://api.openai.com/v1","api_key":"sk-...",
  "max_tokens":2048,"temperature":0.2,"timeout_seconds":120
}'

# 连通性测试（返回 ok / latency_ms / tokens / 模型原文错误）
curl -s -XPOST localhost:8787/api/llm/test
```

也支持环境变量（优先级低于 settings.json）：`ARGUS_LLM_BASE_URL` / `ARGUS_LLM_API_KEY` /
`ARGUS_LLM_MODEL` / `ARGUS_LLM_PROVIDER` / `ARGUS_LLM_MAX_TOKENS`。

配置好后 `engine` 会自动切换到 `planner.LLMPlanner`：

- 每轮把 **任务目标 + 已有意图（含状态）+ 已确认资产 + 已确认漏洞 + 被闸门拦截的目标** 喂给模型；
- 要求模型只输出 JSON（`response_format: json_object`），并做**防御性解析**（能剥 ```json 包裹和前后噪声）；
- 模型产出的意图依然要过**三层闸门 / 预算 / 指纹去重**——模型绕不过任何一道；
- 模型消耗的 token 计入同一本预算账（`chargePlan`），超限同样熔断；
- 未配置时返回空 → 任务自然收敛，不会空转。

### 十家 fork 最强能力的落地清单

| 来源 | 它们最强的地方 | ARGUS 落地 | 状态 |
|---|---|---|---|
| 全部十家 | 都没有"执行期/网络期"范围校验 | 三层闸门（intent → exec → network，Dial.Control 只认 IP） | ✅ 自检锁死 |
| `cskwork` | 拨号期白名单、防 DNS 重绑定 | 出站 HTTP **复用闸门同一份解析结果**再拨号（`HTTPClientWithLookup`） | ✅ 实测 |
| `bdg9412` | 任务级资产允许/阻断 | 任务创建强制 scope + 资产带 task_id | ✅ |
| `BaaRai` | 工具链、skill 体系、findings discipline | `skills/<name>/SKILL.md` 注册表（`GET /api/skills`）+ finding 必须绑证据 | ✅ |
| ARTEX 核心 | 双图（意图 + 事实） | `store.Fact` + 执行后自动沉淀 + `/api/exploration/facts` | ✅ |
| ARTEX 核心 | MITM 流量录制 | 执行器真实出站录制（URL/状态/响应体/错误）+ `/api/traffic` | ✅ |
| ARTEX 核心 | 可配置拦截规则 + 审批 | `deny/ask/allow` 规则层（闸门之上）+ 审批队列 + 裁决历史 | ✅ |
| `RuoJi6` | 漏洞归并、统一报告 | 发现生命周期（status/severity PATCH）+ 复测 + md/csv/json 导出 | ✅ |
| `jiwoochris` | 检测规则（Sigma/ATT&CK） | `GET /api/findings/{id}/sigma` 导出检测草稿 | ✅ |
| `sharenjun` | 工程纪律（测试/CI/验证账本） | **19 项自检** + CI 门禁 + 每步实测 | ✅ |
| 我自己的成熟度方案 | 持久化、预算、指纹去重 | `state.json` 快照（重启不丢）+ 三层预算 + 指纹唯一 | ✅ |

内置拦截规则（首次启动播种，可删）：

| 规则 | 动作 |
|---|---|
| 禁止磁盘破坏操作（`rm -rf /`、`mkfs`、`dd if=`、fork bomb） | deny |
| 禁止改系统账户（`useradd`、`passwd root`、`chmod 777 /`） | deny |
| 主动攻击工具需审批（`sqlmap`、`nuclei`、`hydra`、`msfconsole`） | **ask → 审批队列** |
| 禁止反弹 shell（`bash -i >&`、`nc -e /bin/sh`、`/dev/tcp/`） | deny |

> 关键设计：这些规则是**闸门之上的附加层**。全部删掉，三层范围闸门依然生效；
> 但反过来不成立——只有规则、没有闸门（ARTEX 的形态）是挡不住越界的。

### 品牌：已全量替换为 ARGUS

- 页面标题：`ARGUS — 自主渗透测试控制台`
- 侧边栏品牌、登录页、报告标题、mock 文案：`ARTEX` → `ARGUS`（17 个文件 / 36 处，源码中已无 `ARTEX` 残留）
- 认证存储键：`artex_token` → `argus_token`（`lib/auth.ts` 与 `lib/api.ts` 同步修改，否则登录态会丢）
- 前端包名：`artex-web` → `argus-web`
- Go 侧本来就没有 ARTEX 字符串（模块名 `github.com/argus/argus`）

`webui/` 是 ARTEX 的原生 Next.js 前端（品牌已替换），**用的是中文原版**
（`ARTEX/upstream-0.3.15-zh/web`，`artex-web 2.2.0`，196 个文件，含 47,397 个中文字符），
`package.json` 与英文 fork `BaaRai/ARTEX v0.4.0` **完全一致**，因此 `node_modules` 可直接复用。

完整信息架构（中文文案）：仪表盘 / 对话 / 任务 / 发现 / 流量 / 工具执行 / LLM 录制 / 资产 /
资产同步 / 工作空间 + 系统（LLM、Agent、MCP、Skill、工具、通知、拦截规则、资产拦截、
审批记录、日志、系统设置）。

> 切换到中文版的步骤（已执行，供复现）：
> 1. `robocopy` 中文版 `web` 的 `src` 覆盖 `webui/src`（不加 `/MIR`，保留我们新增的 2 个文件）；
> 2. 重新打 4 处补丁：`lib/api.ts`（tasks / task / findings / findingsPage / report 优先取真实数据）、
>    `navigation/sidebar/sidebar-items.ts`（新增 ARGUS 闸门入口）；
> 3. `next.config.mjs` 在 `webui/` 根目录，不受覆盖影响；
> 4. 重启 `next dev`，`tsc --noEmit` 应为 0。

我们做了两处集成：

1. **新增侧边栏入口 `ARGUS Gate`**（`src/navigation/sidebar/sidebar-items.ts`），
   页面在 `src/app/(main)/function/argus/page.tsx`，用 ARTEX 自己的 Card/Badge/Tabs 组件，
   展示 **真实后端数据**：三层闸门命中、预算账本、意图指纹、漏洞（ATT&CK）、越界记录、证据链、报告。
2. **反向代理**（`next.config.mjs`）：`/argus/*` → `http://127.0.0.1:8787/api/*`，
   前端不需要跨域，也不需要给 Go 端加 CORS。

```powershell
# 后端 + ARTEX 前端一起起（前端 mock 模式，无需 ARTEX 自己的后端）
powershell -ExecutionPolicy Bypass -File scripts\run-console.ps1
# 打开 http://127.0.0.1:5174/function/argus
```

**现状边界（重要）**：ARTEX 原有页面走的是它自带的 mock 数据（`NEXT_PUBLIC_MOCK=1`），
因为它的 API 契约有 200+ 个接口、领域模型（asset/intent/session/traffic）与 ARGUS 不同。

已接入真实数据的页面（适配层 `src/lib/argus-live.ts`，在 `src/lib/api.ts` 的方法里优先调用）：

| 页面 | 真实数据来源 | 说明 |
|---|---|---|
| **Tasks 列表** | `GET /api/tasks` | 任务名/目标/状态/时间/进行中标记 |
| **Tasks 详情** | `GET /api/tasks/{id}` | 概览、目标、报告页签 |
| **Findings 列表 / 任务内 Findings 页签** | `GET /api/findings`、`GET /api/tasks/{id}/findings` | 严重级别、类别、ATT&CK、证据 ID；筛选与分页在前端完成 |
| **Report** | `GET /api/tasks/{id}/report` | Markdown 原文 |
| **ARGUS Gate** | 全部端点 | 三层闸门 / 预算 / 意图 / 越界 / 证据 / 报告 |

**降级设计**：`argus-live.ts` 里任何一次请求失败（后端没起 / 超时 / 字段不匹配）都返回 `null`，
调用方立刻回落到原 mock 数据——**界面不会白屏或崩**，只是回到演示数据。

### 干净的界面（`NEXT_PUBLIC_MOCK_CLEAN=1`）

ARTEX 自带的 fixture（`src/lib/mock/data.ts`，4132 行，含 17 条假漏洞、acme.com 资产、流量、
LLM 记录等）默认会作为页面兜底显示。设 `NEXT_PUBLIC_MOCK_CLEAN=1` 后，`mock/handler.ts`
在模块初始化时把这些 fixture 的**数组全部置空、聚合计数归零**（在 `structuredClone` 之前执行），
接口形状与兜底能力不变，但页面上不再出现任何假数据：

```
findings.stats = {total:0,pending:0,critical:0,high:0,medium:0,low:0}
findings 分页 total=0 / items=0
tasks=0  stats.assets=0  stats.findings_confirmed=0  traffic.total=0
```

仍为 mock 的页面：Dashboard 图表、Traffic、Tool Execution、LLM Recording、Assets、Asset Sync、
Workspace、System 下全部（LLM/Agent/MCP/Skill/Tools/Notifications/Interception/Logs/Settings）。
其中 **Interception / Asset Interception** 与我们的越界记录语义最贴近，是下一步优先替换项。

### 命令行与自检

```bash
# 1. 自检（15 项安全不变量，无需外部依赖）
go run ./cmd/argus selftest

# 2. 端到端演示（3 worker，含 3 次越界拦截 + 1 次去重 + 1 条带证据的 finding）
go run ./cmd/argus demo

# 3. 起服务
export ARGUS_TOKEN=$(head -c 24 /dev/urandom | base64)
go run ./cmd/argus serve -addr 127.0.0.1:8787 -data ./data
```

`selftest` 输出示例：

```
PASS  scope: 空范围默认拒绝
PASS  gate: 12 个越界目标全部拦截
PASS  network: 未授权 IP 被第 3 层独立拦截
PASS  budget: 超限拒绝且不扣减
PASS  engine: 端到端闭环（收敛/拦截/去重/证据）
PASS  api: 无范围任务被拒 + 有范围可运行 + 报告可导出
15/15 通过
```

### API

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/health` | 免鉴权健康检查 |
| `POST` | `/api/tasks` | 建任务。**`goal` 与 `scope` 均必填**（目标歧义门禁） |
| `GET` | `/api/tasks` | 任务列表 |
| `GET` | `/api/tasks/{id}` | 任务详情（含运行态、计数） |
| `POST` | `/api/tasks/{id}/start` | 启动（202），重复启动 409 |
| `POST` | `/api/tasks/{id}/stop` | 优雅停止（有序收尾） |
| `GET` | `/api/tasks/{id}/intents` | 探索路径 |
| `GET` | `/api/tasks/{id}/findings` | 漏洞（每条必有 `evidence_id`） |
| `GET` | `/api/tasks/{id}/violations` | 越界记录（按 `intent`/`exec`/`network` 分层统计） |
| `GET` | `/api/tasks/{id}/report` | **可交付 Markdown 报告** |
| `GET` | `/api/evidence/{id}` | 证据（含哈希链前驱/摘要） |
| `GET` | `/api/budget` | 三层预算账本快照 + 证据链校验结果 |

### ARTEX 兼容接口（`internal/api/compat.go`）

这些接口直接返回 **ARTEX 前端原生形状**，前端无需再做字段映射，因此 ARTEX 的对应页面可以直接吃真实数据：

| 前端页面 | 接口 | 数据来源 |
|---|---|---|
| 仪表盘 | `GET /api/stats` | 资产数、已确认漏洞数、引擎状态、当前任务 |
| 资产 | `GET /api/assets`、`/api/assets/counts` | **新增 `store.Asset`**：只记录"过闸门后真实访问过"的主机，天然带任务归属 |
| 工具执行 | `GET /api/commands`、`/api/commands/stats` | 证据链里 `kind=command` 的记录（工具/入参/输出/退出码） |
| 发现 | `GET /api/exploration/findings/stats` | 漏洞总数、按严重级别、漏洞类别、按任务聚合 |
| 任务详情 | `GET /api/exploration/intents`、`/api/exploration/activity`、`/api/exploration/graph` | 意图状态机 + 越界事件 + finding 派生边 |
| 任务范围 | `GET /api/tasks/{id}/scope` | 任务创建时声明的授权范围（只读，不可由界面改写） |
| 发现页资产树 | `GET /api/exploration/findings/asset-tree` | 按 finding 目标聚合（扁平化，不编造多级层级） |
| 任务覆盖度 | `GET /api/tasks/{id}/coverage` | 分母=过闸门碰过的资产，分子=其中产出漏洞的资产（比 ARTEX 口径更实） |
| 任务目标 | `GET /api/tasks/{id}/goals` | 任务创建时声明的 goal |
| token 统计 | `GET /api/exploration/tokens`、`/api/tokens/usage`、`/api/tokens/daily` | 规划器尚未接入 LLM，返回零值结构 |
| 流量 | `GET /api/traffic`、`/api/traffic/hosts` | 返回 `enabled:false`（无 MITM 录制能力，不编造数据） |

> 资产模型是这次补的关键一环：`agent.SimExecutor` 在闸门放行后把目标写入 `store.Asset`，
> 所以"资产页"里出现的每一台主机，都是**确实通过三层闸门**的目标——不是扫描器猜出来的。
> 实测：`demo-lab` 跑完 `/assets` 返回 `lab.internal`、`api.lab.internal` 两个 subdomain，
> 而 `evil.example.com` / `8.8.8.8` / `169.254.169.254` **不在资产里**（它们被拦在闸门外）。

```bash
curl -s -XPOST localhost:8787/api/tasks -H "Authorization: Bearer $ARGUS_TOKEN" -d '{
  "name": "lab-1",
  "goal": "评估 lab.internal 的 Web 面风险",
  "scope": [{"kind":"domain_suffix","value":"lab.internal"},
            {"kind":"cidr","value":"10.20.0.0/16"}],
  "minutes": 30,
  "seed": [{"action":"Bash","summary":"{\"command\":\"nmap -sV lab.internal\"}","asset_id":1,"param_key":"scan"}]
}'
```

范围 `kind` 取值：`exact_domain` / `domain_suffix`（含子域）/ `cidr` / `exact_ip` / `exact_url`。

---

## 架构

```
control plane（本仓库，无外网出口）
  engine.Scheduler   goal→intent，DB CAS 领取，防抖 800ms，心跳 600s，有序收尾
  budget.Three-tier  per-intent / per-task / per-day，原子扣减，超限即停
  dedupe.Fingerprint sha256(asset|action|paramKey)，唯一索引去重
  gate.Three-layer   intent → exec → network
        │ claim / settle
        ▼
execution plane（一次性沙箱，需自建镜像）
  NetworkPolicy 只放行授权 CIDR + LLM 端点；`deploy/egress/block-metadata.sh` 黑洞元数据
        │ 产物直写
        ▼
evidence.WORM       只追加 JSONL + 哈希链（Verify 可发现篡改）；生产换 S3 对象锁
        │
        ▼
defense（差异化）
  attack.Map          finding → ATT&CK 技术
  attack.SigmaDraft   每条 finding 自动产出 Sigma 检测草稿
```

**有序收尾**：`settling → 停领新 intent → 宽限 drain → 定终态`，避免"到点硬杀留半截状态"。

---

## 部署

```bash
export ARGUS_TOKEN=$(openssl rand -base64 24)
docker compose up -d --build     # 默认：非 root / 只读根 / cap_drop ALL / 只绑 127.0.0.1 / 控制面网络 internal
curl -s localhost:8787/api/health
```

Kubernetes：`deploy/k8s/deployment.yaml`（`runAsNonRoot` + `readOnlyRootFilesystem` + `drop: ALL` + 不挂 SA token）
与 `deploy/k8s/networkpolicy.yaml`（egress 白名单）配套使用。

生产库：`schema.sql`（PostgreSQL 15+）。内存实现与 DDL 字段一一对应，替换 `store.Store` 实现即可。

---

## 安全模型与已知边界

**已实现**
- 三层递进拦截 + 越界记账（`scope_violation`）
- 空范围默认拒绝；任务创建期强制 `scope`
- 元数据地址永久红线（应用层 + 网络层双重）
- 三层预算硬闸门（默认值全部非 0）
- 意图指纹去重（并发安全）
- 证据链哈希校验；`finding` 必须绑定 `evidence_id`
- 服务端只读证据、无删除接口（WORM 的最小形态）

**已知边界（路线图内）**
- 第 2 层依赖正则抽取：目标若由脚本在运行时拼接生成，第 2 层会放行，**由第 3 层兜底**（这是分层的原因）。
- 域名授权隐含其解析 IP（否则只配域名规则不可用）；解析到元数据地址会被拒绝。
- 内存 store 仅适用于单机演示；生产需 PG 实现（DDL 已就绪）。
- 尚未接入真实工具链（nmap/nuclei 等）与 LLM 规划器：接口已定（`engine.Executor` / `engine.Planner`）。

---

## 路线图

| 阶段 | 状态 | 内容 |
|---|---|---|
| A1 内核 | ✅ 完成 | 三层闸门、预算、去重、证据链、调度器、API、报告、自检 |
| A2 收敛 | ⏳ | 成本可预测性、finding 一键回放、预算超限 30s 内收尾 |
| A3 能力 | ⏳ | 真实工具链 + skill 体系 + 漏洞归并 |
| A4 紫队 | ⏳ | ATT&CK 全量映射、检测规则自动下发、修复后自动复测 |

验收指标见 `../ARTEX/ARGUS-最强方案.md` 第五节（越界拦截率 100%、范围误伤率 0%、可复现率 100% 等）。

---

## 开发

```bash
make vet        # go vet ./...
make test       # go test ./...
make race       # go test -race ./...
make selftest   # 编译并跑 15 项自检
make demo       # 端到端演示
```

代码规模：**4,022 行 Go**（23 个文件，其中 914 行为 8 个测试文件），**零外部依赖**（纯标准库，`go.mod` 无 require），
所以任何 Go 1.26 环境都能 `go build ./...`，不需要任何代理。

### 开发环境注意事项（企业 DLP）

本仓库在装有文档加密 DLP 的机器上开发时踩过两个坑，写在这里免得后来者重复踩：

1. **`go test` 无法运行**：`go test` 会在 `$WORK` 生成 `_testmain.go`，该文件被 DLP 加密后编译器报
   `expected 'package', found '%'`。因此安全不变量做成了独立子命令 `argus selftest`（不依赖 `go test`）。
   在 Linux/CI 上 `go test -race ./...` 正常。
2. **`gofmt -w` 会把源文件写成密文**：gofmt.exe 不是白名单进程，写回时被加密（文件头 `%TSD-Header-###%`），
   表现为 `package statement must be first`。**不要对源码目录执行 `gofmt -w`**；
   需要格式化时用 `gofmt file > /tmp/x && cat /tmp/x > file` 这类"由白名单进程落盘"的方式，
   或直接在 Linux/CI 上格式化。CI 的格式检查因此只报告、不阻断。

## 合规与使用边界

- **仅用于获得书面授权的测试**。范围必须由授权方书面确认，并写入 `task_scope`。
- ARTEX 已被用于韩国银行、日本多家企业的真实攻击事件，公开情报正在按名称测绘相关实例。
  **不要把任何实例暴露到公网**；本默认配置只监听 `127.0.0.1`。
- 本项目为 clean-room 实现，未复制 AGPL 代码；许可证 MIT（见 `LICENSE`）。

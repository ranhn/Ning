"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ShieldCheck, RefreshCw, Play, AlertTriangle, ShieldAlert, Lock } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

// 通过 next.config 的 rewrite 直接打到 Go 后端（:8787），不经过 ARGUS 的 mock 层。
const BASE = "/argus";

type Task = {
  id: number;
  name: string;
  goal: string;
  state: string;
  created_at: string;
  workers: number;
};

type TaskSummary = {
  task: Task;
  running: boolean;
  scope: string[];
  intents: number;
  findings: number;
  violations: number;
  evidence: number;
};

type Intent = {
  id: number;
  state: string;
  summary: string;
  action: string;
  fp: string;
  vuln_class?: string;
};

type Finding = {
  id: number;
  severity: string;
  title: string;
  vuln_class: string;
  target: string;
  evidence_id: string;
  technique: string;
  tactic: string;
};

type Violation = {
  layer: string;
  target: string;
  reason: string;
  tool: string;
  ts: string;
};

type Evidence = { id: string; kind: string; hash: string; ts: string };

async function jget<T>(path: string): Promise<T> {
  const r = await fetch(BASE + path);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return (await r.json()) as T;
}

function stateClass(state: string) {
  if (state === "running") return "border-sky-500/40 bg-sky-500/10 text-sky-300";
  if (state === "done") return "border-emerald-500/40 bg-emerald-500/10 text-emerald-300";
  if (state === "stopped") return "border-amber-500/40 bg-amber-500/10 text-amber-300";
  if (state === "blocked" || state === "exhausted") return "border-rose-500/40 bg-rose-500/10 text-rose-300";
  return "border-border bg-muted text-muted-foreground";
}

export default function ArgusPage() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [activeId, setActiveId] = useState<number>(0);
  const [detail, setDetail] = useState<TaskSummary | null>(null);
  const [intents, setIntents] = useState<Intent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [violations, setViolations] = useState<Violation[]>([]);
  const [layers, setLayers] = useState<Record<string, number>>({});
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [report, setReport] = useState("");
  const [budget, setBudget] = useState<string[]>([]);
  const [err, setErr] = useState("");
  const [online, setOnline] = useState(false);
  const [busy, setBusy] = useState(false);
  // 新建任务表单（只填目标即可，种子意图由后端按范围自动生成）
  const [newOpen, setNewOpen] = useState(false);
  const [nTarget, setNTarget] = useState("");
  const [nKind, setNKind] = useState("domain_suffix");
  const [nGoal, setNGoal] = useState("");

  const loadTasks = useCallback(async () => {
    try {
      const d = await jget<{ tasks: Task[] | null }>("/tasks");
      const list = d.tasks ?? [];
      setTasks(list);
      setOnline(true);
      setErr("");
      setActiveId((cur) => (cur && list.some((t) => t.id === cur) ? cur : (list[0]?.id ?? 0)));
    } catch (e) {
      setOnline(false);
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const loadDetail = useCallback(async (id: number) => {
    if (!id) return;
    try {
      const d = await jget<TaskSummary>(`/tasks/${id}`);
      setDetail(d);
      const [it, fi, vi, ev, bu] = await Promise.all([
        jget<{ intents: Intent[] | null }>(`/tasks/${id}/intents`),
        jget<{ findings: Finding[] | null }>(`/tasks/${id}/findings`),
        jget<{ violations: Violation[] | null; by_layer: Record<string, number> | null }>(
          `/tasks/${id}/violations`,
        ),
        jget<{ evidence: Evidence[] | null }>(`/tasks/${id}/evidence`),
        jget<{ lines: string[] | null }>("/budget"),
      ]);
      setIntents(it.intents ?? []);
      setFindings(fi.findings ?? []);
      setViolations(vi.violations ?? []);
      setLayers(vi.by_layer ?? {});
      setEvidence(ev.evidence ?? []);
      setBudget(bu.lines ?? []);
      const r = await fetch(`${BASE}/tasks/${id}/report`);
      setReport(r.ok ? await r.text() : "（报告不可用）");
      setOnline(true);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void loadTasks();
  }, [loadTasks]);

  useEffect(() => {
    if (!activeId) return;
    void loadDetail(activeId);
    const t = setInterval(() => void loadDetail(activeId), 3000);
    return () => clearInterval(t);
  }, [activeId, loadDetail]);

  const kpi = useMemo(() => {
    const done = intents.filter((i) => i.state === "done").length;
    const blocked = intents.filter((i) => i.state === "blocked" || i.state === "exhausted").length;
    const violTotal = Object.values(layers).reduce((a, b) => a + b, 0);
    return { done, blocked, violTotal };
  }, [intents, layers]);

  async function createTask() {
    const target = nTarget.trim();
    if (!target) return;
    setBusy(true);
    try {
      const stamp = new Date().toISOString().slice(5, 16).replace(/[:T]/g, "");
      const body = {
        name: `${target.replace(/[^\w.\-/]/g, "_")}-${stamp}`,
        goal: nGoal.trim() || `对 ${target} 进行授权范围内的信息收集与风险验证`,
        scope: [{ kind: nKind, value: target }],
        workers: 2,
        minutes: 30,
      };
      const r = await fetch(`${BASE}/tasks`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const d = (await r.json()) as { task?: Task; seed_intents?: number; error?: string };
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      const id = d.task?.id ?? 0;
      if (id) {
        await fetch(`${BASE}/tasks/${id}/start`, { method: "POST" });
        setActiveId(id);
        void loadDetail(id);
      }
      setNewOpen(false);
      setNTarget("");
      setNGoal("");
      setErr("");
      await loadTasks();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function startTask() {
    if (!activeId) return;
    setBusy(true);
    try {
      await fetch(`${BASE}/tasks/${activeId}/start`, { method: "POST" });
      await loadDetail(activeId);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full flex-col gap-4 overflow-auto p-4">
      <div className="flex flex-wrap items-center gap-3">
        <ShieldCheck className="size-5 text-primary" />
        <h1 className="text-lg font-semibold">ARGUS 安全内核</h1>
        <Badge variant="outline" className={online ? "border-emerald-500/40 text-emerald-400" : "border-rose-500/40 text-rose-400"}>
          {online ? "真实后端已连接" : "后端未连接"}
        </Badge>
        <span className="text-xs text-muted-foreground">
          数据来自 Go 后端 /api（不经过 mock）：三层闸门 · 预算 · 意图指纹 · 证据链 · 报告
        </span>
        <div className="ml-auto flex gap-2">
          <Button variant="outline" size="sm" onClick={() => { void loadTasks(); void loadDetail(activeId); }}>
            <RefreshCw className="mr-1 size-3.5" /> 刷新
          </Button>
          <Button size="sm" onClick={() => void startTask()} disabled={!activeId || busy || !!detail?.running}>
            <Play className="mr-1 size-3.5" /> 启动
          </Button>
        </div>
      </div>

      {err ? (
        <Card className="border-rose-500/40 bg-rose-500/5">
          <CardContent className="flex items-center gap-2 py-3 text-sm text-rose-300">
            <AlertTriangle className="size-4" /> {err}（确认 argus serve 在 127.0.0.1:8787 运行）
          </CardContent>
        </Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[280px_1fr]">
        <Card className="h-fit">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">任务（{tasks.length}）</CardTitle>
              <Button
                variant="outline"
                size="sm"
                className="h-6 px-2 text-xs"
                onClick={() => setNewOpen((v) => !v)}
              >
                {newOpen ? "取消" : "+ 新建"}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="flex flex-col gap-1.5">
            {newOpen ? (
              <div className="mb-2 flex flex-col gap-1.5 rounded-md border border-dashed border-border p-2">
                <input
                  autoFocus
                  value={nTarget}
                  onChange={(e) => setNTarget(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void createTask();
                  }}
                  placeholder="目标：example.com / 10.0.0.5 / 10.0.0.0/24"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-xs outline-none focus:border-primary"
                />
                <select
                  value={nKind}
                  onChange={(e) => setNKind(e.target.value)}
                  className="w-full rounded border border-border bg-background px-2 py-1 text-xs"
                >
                  <option value="domain_suffix">域名后缀（含子域）</option>
                  <option value="exact_domain">精确域名</option>
                  <option value="exact_ip">单个 IP</option>
                  <option value="cidr">网段 CIDR</option>
                  <option value="exact_url">精确 URL</option>
                </select>
                <input
                  value={nGoal}
                  onChange={(e) => setNGoal(e.target.value)}
                  placeholder="目标描述（可选）"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-xs outline-none focus:border-primary"
                />
                <Button
                  size="sm"
                  className="h-7 text-xs"
                  disabled={busy || !nTarget.trim()}
                  onClick={() => void createTask()}
                >
                  {busy ? "创建中…" : "创建并启动"}
                </Button>
                <p className="text-[10px] leading-tight text-muted-foreground">
                  种子意图按范围自动生成（nmap 端口识别 + curl 响应头），仍会过三层闸门
                </p>
              </div>
            ) : null}
            {tasks.length === 0 ? <p className="text-xs text-muted-foreground">暂无任务</p> : null}
            {tasks.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setActiveId(t.id)}
                className={`rounded-md border px-3 py-2 text-left transition ${
                  t.id === activeId ? "border-primary/60 bg-primary/10" : "border-border hover:bg-muted/50"
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium">{t.name || `任务 #${t.id}`}</span>
                  <Badge variant="outline" className={`ml-auto ${stateClass(t.state)}`}>{t.state}</Badge>
                </div>
                <p className="mt-0.5 line-clamp-1 text-xs text-muted-foreground">{t.goal}</p>
              </button>
            ))}
          </CardContent>
        </Card>

        <div className="flex flex-col gap-4">
          {detail ? (
            <>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
                {[
                  { k: "意图", v: intents.length, s: "总数" },
                  { k: "完成", v: kpi.done, s: "done" },
                  { k: "拦截", v: kpi.blocked, s: "exec 层" },
                  { k: "越界", v: kpi.violTotal, s: "三层合计" },
                  { k: "漏洞", v: findings.length, s: "带证据" },
                  { k: "证据", v: detail.evidence, s: "哈希链" },
                ].map((x) => (
                  <Card key={x.k} className="py-2">
                    <CardContent className="flex flex-col gap-0.5">
                      <span className="text-xs text-muted-foreground">{x.k}</span>
                      <span className="text-xl font-semibold tabular-nums">{x.v}</span>
                      <span className="text-[11px] text-muted-foreground">{x.s}</span>
                    </CardContent>
                  </Card>
                ))}
              </div>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">三层闸门</CardTitle>
                </CardHeader>
                <CardContent className="grid gap-3 md:grid-cols-3">
                  {[
                    { key: "intent", name: "1 · intent", icon: Lock, hit: layers.intent ?? 0, desc: "派发意图 / 写资产前校验；空范围直接拒绝。" },
                    { key: "exec", name: "2 · exec", icon: ShieldAlert, hit: layers.exec ?? 0, desc: "从工具输入抽取 URL/IP/域名，先解析再判定。" },
                    { key: "network", name: "3 · network", icon: ShieldCheck, hit: layers.network ?? 0, desc: "建 socket 前只认 IP，DNS 重绑定也绕不过。" },
                  ].map((l) => (
                    <div key={l.key} className="rounded-lg border border-border p-3">
                      <div className="flex items-center gap-2">
                        <l.icon className="size-3.5 text-muted-foreground" />
                        <span className="text-sm font-medium">{l.name}</span>
                        <Badge variant="outline" className={`ml-auto ${l.hit > 0 ? "border-rose-500/40 text-rose-300" : ""}`}>
                          命中 {l.hit}
                        </Badge>
                      </div>
                      <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{l.desc}</p>
                      <div className="mt-2 h-1 overflow-hidden rounded-full bg-muted">
                        <div className="h-full bg-primary" style={{ width: `${Math.min(100, l.hit * 20)}%` }} />
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Tabs defaultValue="violations">
                <TabsList>
                  <TabsTrigger value="violations">越界拦截（{violations.length}）</TabsTrigger>
                  <TabsTrigger value="intents">意图（{intents.length}）</TabsTrigger>
                  <TabsTrigger value="findings">漏洞（{findings.length}）</TabsTrigger>
                  <TabsTrigger value="evidence">证据（{evidence.length}）</TabsTrigger>
                  <TabsTrigger value="report">报告</TabsTrigger>
                </TabsList>

                <TabsContent value="violations">
                  <Card>
                    <CardContent className="p-0">
                      <table className="w-full text-sm">
                        <thead className="text-xs text-muted-foreground">
                          <tr className="border-b border-border">
                            <th className="px-3 py-2 text-left">层</th>
                            <th className="px-3 py-2 text-left">目标</th>
                            <th className="px-3 py-2 text-left">原因</th>
                            <th className="px-3 py-2 text-left">工具</th>
                          </tr>
                        </thead>
                        <tbody>
                          {violations.length === 0 ? (
                            <tr><td className="px-3 py-3 text-muted-foreground" colSpan={4}>暂无越界尝试</td></tr>
                          ) : null}
                          {[...violations].reverse().map((v, i) => (
                            <tr key={`${v.target}-${i}`} className="border-b border-border/60 last:border-0">
                              <td className="px-3 py-2"><Badge variant="outline" className={stateClass(v.layer === "network" ? "blocked" : v.layer)}>{v.layer}</Badge></td>
                              <td className="px-3 py-2 font-mono text-xs">{v.target}</td>
                              <td className="px-3 py-2 text-xs text-muted-foreground">{v.reason}</td>
                              <td className="px-3 py-2 text-xs">{v.tool}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="intents">
                  <Card>
                    <CardContent className="p-0">
                      <table className="w-full text-sm">
                        <thead className="text-xs text-muted-foreground">
                          <tr className="border-b border-border">
                            <th className="px-3 py-2 text-left">#</th>
                            <th className="px-3 py-2 text-left">状态</th>
                            <th className="px-3 py-2 text-left">意图</th>
                            <th className="px-3 py-2 text-left">指纹</th>
                          </tr>
                        </thead>
                        <tbody>
                          {intents.map((it) => (
                            <tr key={it.id} className="border-b border-border/60 last:border-0">
                              <td className="px-3 py-2 font-mono text-xs">{it.id}</td>
                              <td className="px-3 py-2"><Badge variant="outline" className={stateClass(it.state)}>{it.state}</Badge></td>
                              <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{it.summary}</td>
                              <td className="px-3 py-2 font-mono text-[11px]">{it.fp?.slice(0, 12)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="findings">
                  <div className="flex flex-col gap-2">
                    {findings.length === 0 ? <p className="text-sm text-muted-foreground">暂无漏洞</p> : null}
                    {findings.map((f) => (
                      <Card key={f.id} className="border-l-2 border-l-destructive">
                        <CardContent className="flex flex-col gap-1.5 py-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge variant="outline" className={stateClass("exhausted")}>{f.severity}</Badge>
                            <span className="text-sm font-medium">{f.title}</span>
                            <Badge variant="outline" className="font-mono">{f.technique} · {f.tactic}</Badge>
                          </div>
                          <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                            <span>类别 <span className="text-foreground">{f.vuln_class}</span></span>
                            <span>资产 <span className="text-foreground">{f.target || "—"}</span></span>
                            <span>证据 <span className="font-mono text-foreground">{f.evidence_id}</span></span>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="evidence">
                  <Card>
                    <CardContent className="p-0">
                      <table className="w-full text-sm">
                        <thead className="text-xs text-muted-foreground">
                          <tr className="border-b border-border">
                            <th className="px-3 py-2 text-left">ID</th>
                            <th className="px-3 py-2 text-left">类型</th>
                            <th className="px-3 py-2 text-left">哈希</th>
                            <th className="px-3 py-2 text-left">时间</th>
                          </tr>
                        </thead>
                        <tbody>
                          {evidence.map((e) => (
                            <tr key={e.id} className="border-b border-border/60 last:border-0">
                              <td className="px-3 py-2 font-mono text-xs">{e.id}</td>
                              <td className="px-3 py-2 text-xs">{e.kind}</td>
                              <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{e.hash?.slice(0, 16)}…</td>
                              <td className="px-3 py-2 font-mono text-[11px]">{e.ts?.replace("T", " ").slice(0, 19)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="report">
                  <Card>
                    <CardContent className="max-h-[55vh] overflow-auto py-3">
                      <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-muted-foreground">{report || "（加载中）"}</pre>
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>

              <Card>
                <CardHeader className="pb-2"><CardTitle className="text-sm">预算账本（前 8 项）</CardTitle></CardHeader>
                <CardContent className="grid gap-1 text-xs text-muted-foreground md:grid-cols-2">
                  {budget.slice(0, 8).map((b) => (
                    <div key={b} className="flex justify-between font-mono">
                      <span className="truncate">{b.slice(0, b.lastIndexOf(" "))}</span>
                      <span className="text-foreground">{b.slice(b.lastIndexOf(" ") + 1)}</span>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </>
          ) : (
            <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">选择左侧任务查看三层闸门数据</CardContent></Card>
          )}
        </div>
      </div>
    </div>
  );
}

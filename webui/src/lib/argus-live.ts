// ARGUS 实时数据适配层。
//
// ARGUS 前端原本只认它自己的后端契约（Task / Finding 等 200+ 接口）。
// 这里把 ARGUS（Go 后端）的极简模型映射成 ARGUS 前端需要的形状，
// 由 lib/mock/handler.ts 在命中 /tasks、/exploration/findings、/report 时优先尝试。
//
// 设计原则：**任何失败都返回 null**，调用方回落到原有 mock 数据 ——
// 后端没起、字段不匹配、超时，都不会让界面崩掉或空白。
import type { Finding, Severity, Task, TaskStatus } from "@/lib/types";

const BASE = "/argus";
const TIMEOUT_MS = 2500;

type ArgTask = {
  id: number;
  name: string;
  goal: string;
  state: string;
  created_at: string;
  workers: number;
};

type ArgFinding = {
  id: number;
  task_id: number;
  vuln_class: string;
  severity: string;
  title: string;
  target: string;
  evidence_id: string;
  technique: string;
  tactic: string;
  created_at: string;
};

type ArgTaskSummary = {
  task: ArgTask;
  running: boolean;
  scope: string[] | null;
  intents: number;
  findings: number;
  violations: number;
  evidence: number;
};

async function getJSON<T>(path: string): Promise<T | null> {
  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
    const r = await fetch(BASE + path, { signal: ac.signal });
    clearTimeout(timer);
    if (!r.ok) return null;
    return (await r.json()) as T;
  } catch {
    return null;
  }
}

function toStatus(state: string): TaskStatus {
  switch (state) {
    case "running":
      return "running";
    case "done":
      return "done";
    case "stopped":
      return "timeout";
    case "pending":
      return "created";
    default:
      return "created";
  }
}

function unixOf(iso: string): number {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? 0 : Math.floor(ms / 1000);
}

function toTask(t: ArgTask): Task {
  const ts = unixOf(t.created_at);
  const finished = t.state === "done";
  return {
    id: String(t.id),
    name: t.name || `task-${t.id}`,
    description: t.goal,
    goal: t.goal,
    status: toStatus(t.state),
    created_at: t.created_at,
    created_unix: ts,
    completed_at: finished ? t.created_at : "",
    completed_unix: finished ? ts : 0,
    last_activity: t.created_at,
    last_activity_unix: ts,
    paused: false,
    queued: false,
    active: t.state === "running",
    in_flight: 0,
    engine_mode: t.state === "running" ? "exploring" : "idle",
    findings: { critical: 0, high: 0, medium: 0, low: 0 },
  };
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

function toSeverity(raw: string): Severity {
  const s = (raw || "").toLowerCase() as Severity;
  return SEVERITIES.includes(s) ? s : "medium";
}

function toFinding(f: ArgFinding): Finding {
  const bits = [f.technique && `${f.technique} ${f.tactic}`.trim(), f.target].filter(Boolean);
  return {
    id: String(f.id),
    finding_id: String(f.id),
    vulnclass: f.vuln_class || "unknown",
    name: f.title,
    severity: toSeverity(f.severity),
    status: "confirmed",
    summary: bits.join(" · "),
    evidence: f.evidence_id || "",
    ts: f.created_at,
    task_id: String(f.task_id),
  };
}

/** 通用兼容接口读取：Go 侧已按 ARGUS 原生形状返回，命中即直接给前端用；失败返回 null。 */
export async function liveGet<T>(path: string): Promise<T | null> {
  return getJSON<T>(path);
}

/** 任务列表。后端不可用返回 null（调用方回落 mock）。 */
export async function liveTasks(): Promise<{ tasks: Task[]; active: string } | null> {
  const d = await getJSON<{ tasks: ArgTask[] | null }>("/tasks");
  if (!d) return null;
  const list = (d.tasks ?? []).map(toTask);
  const active = list.find((t) => t.status === "running")?.id ?? "";
  return { tasks: list, active };
}

/** 单个任务详情。 */
export async function liveTask(id: string): Promise<Task | null> {
  const d = await getJSON<ArgTaskSummary>(`/tasks/${encodeURIComponent(id)}`);
  if (!d || !d.task) return null;
  return toTask(d.task);
}

/** 漏洞列表：task 为空时取全量。 */
export async function liveFindings(task?: string): Promise<Finding[] | null> {
  const d = task
    ? await getJSON<{ findings: ArgFinding[] | null }>(`/tasks/${encodeURIComponent(task)}/findings`)
    : await getJSON<{ findings: ArgFinding[] | null }>("/findings");
  if (!d) return null;
  return (d.findings ?? []).map(toFinding);
}

/** 报告（Markdown 文本）。 */
export async function liveReport(task?: string): Promise<string | null> {
  let id = task;
  if (!id) {
    const d = await getJSON<{ tasks: ArgTask[] | null }>("/tasks");
    id = d?.tasks?.[0] ? String(d.tasks[0].id) : undefined;
  }
  if (!id) return null;
  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
    const r = await fetch(`${BASE}/tasks/${encodeURIComponent(id)}/report`, { signal: ac.signal });
    clearTimeout(timer);
    if (!r.ok) return null;
    return await r.text();
  } catch {
    return null;
  }
}

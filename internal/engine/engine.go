// Package engine 是 ARGUS 的控制面：把 goal 变成 intent，把 intent 派给 worker，
// 并在预算/时间耗尽时按固定顺序干净收尾。
//
// 借鉴了 ARTEX 三个扎实的设计：DB CAS 领取、防抖唤醒、有序收尾状态机；
// 并补上它缺的两件事：全局预算闸门、意图指纹去重。
package engine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/argus/argus/internal/budget"
	"github.com/argus/argus/internal/dedupe"
	"github.com/argus/argus/internal/store"
)

// Result 是一次 intent 执行的结果。
type Result struct {
	State    string `json:"state"`
	Steps    int    `json:"steps"`
	Tokens   int64  `json:"tokens"`
	Cost     int64  `json:"cost"`
	Findings int    `json:"findings"`
	Note     string `json:"note,omitempty"`
}

// Executor 执行一条意图。实现方负责调用工具，但**必须先过闸门**。
type Executor interface {
	Run(ctx context.Context, t store.Task, it store.Intent) (Result, error)
}

// Planner 产出下一批意图。返回空切片表示"这轮没想到新东西"。
type Planner interface {
	Next(ctx context.Context, t store.Task, st store.Store) ([]store.Intent, error)
}

// MeteredPlanner 是可选能力：规划器若调用模型消耗 token，实现它让调度器记账。
// 这样"规划成本"和"执行成本"进的是同一本预算账，超限一样熔断。
type MeteredPlanner interface {
	LastUsage() (tokens int64, cost int64)
}

// Config 是调度参数。
type Config struct {
	Workers    int
	Debounce   time.Duration
	Heartbeat  time.Duration
	Grace      time.Duration
	MaxRounds  int
	IdleRounds int
}

// DefaultConfig 返回默认参数（worker 3、防抖 800ms、心跳 600s、收敛 3 轮）。
func DefaultConfig() Config {
	return Config{
		Workers:    3,
		Debounce:   800 * time.Millisecond,
		Heartbeat:  600 * time.Second,
		Grace:      30 * time.Second,
		MaxRounds:  200,
		IdleRounds: 3,
	}
}

// Summary 是一次任务执行的汇总。
type Summary struct {
	TaskID     int64  `json:"task_id"`
	State      string `json:"state"`
	Rounds     int    `json:"rounds"`
	Dispatched int    `json:"dispatched"`
	Duplicates int    `json:"duplicates"`
	Done       int    `json:"done"`
	Blocked    int    `json:"blocked"`
	Exhausted  bool   `json:"exhausted"`
	ElapsedMS  int64  `json:"elapsed_ms"`
}

// Engine 是单任务调度器（每个任务一个实例）。
type Engine struct {
	st   store.Store
	exec Executor
	pl   Planner
	b    *budget.Budget
	reg  *dedupe.Registry
	cfg  Config

	taskID    int64
	dayKey    string
	exhausted atomic.Bool
	notify    chan struct{}

	mu         sync.Mutex
	dispatched int
	duplicates int
	rounds     int
}

// New 构造调度器。
func New(st store.Store, exec Executor, pl Planner, b *budget.Budget, cfg Config) *Engine {
	if cfg.Workers <= 0 {
		cfg.Workers = 3
	}
	if cfg.Debounce <= 0 {
		cfg.Debounce = 800 * time.Millisecond
	}
	if cfg.Heartbeat <= 0 {
		cfg.Heartbeat = 600 * time.Second
	}
	if cfg.Grace <= 0 {
		cfg.Grace = 30 * time.Second
	}
	if cfg.IdleRounds <= 0 {
		cfg.IdleRounds = 3
	}
	if cfg.MaxRounds <= 0 {
		cfg.MaxRounds = 200
	}
	if b == nil {
		b = budget.New()
	}
	return &Engine{
		st: st, exec: exec, pl: pl, b: b, reg: dedupe.New(), cfg: cfg,
		notify: make(chan struct{}, 64),
	}
}

// Registry 暴露指纹表（观测用）。
func (e *Engine) Registry() *dedupe.Registry { return e.reg }

// RunTask 执行一个任务直到收敛、预算耗尽或截止时间到达。
func (e *Engine) RunTask(ctx context.Context, taskID int64) (Summary, error) {
	start := time.Now()
	t, ok := e.st.GetTask(taskID)
	if !ok {
		return Summary{}, store.ErrNotFound
	}
	e.taskID = taskID
	e.dayKey = start.UTC().Format("2006-01-02")
	e.applyDefaultCaps(taskID)

	runCtx := ctx
	var cancel context.CancelFunc
	if t.Deadline != nil {
		runCtx, cancel = context.WithDeadline(ctx, *t.Deadline)
	} else {
		runCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	e.st.SetTaskState(taskID, store.TaskRunning)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	workers := t.Workers
	if workers <= 0 {
		workers = e.cfg.Workers
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			e.workerLoop(runCtx, t, n, stop)
		}(i)
	}

	planDone := make(chan struct{})
	go e.plannerLoop(runCtx, t, stop, planDone)

	<-planDone
	// 有序收尾：停领 → 宽限等待 → 定终态。
	close(stop)
	graceCtx, cancelGrace := context.WithTimeout(context.Background(), e.cfg.Grace)
	defer cancelGrace()
	waitCh := make(chan struct{})
	go func() { wg.Wait(); close(waitCh) }()
	select {
	case <-waitCh:
	case <-graceCtx.Done():
	}

	final := store.TaskDone
	if runCtx.Err() != nil {
		final = store.TaskStopped
	}
	e.st.SetTaskState(taskID, final)

	var done, blocked int
	for _, it := range e.st.Intents(taskID) {
		switch it.State {
		case store.IntentDone:
			done++
		case store.IntentBlocked, store.IntentExhausted:
			blocked++
		}
	}
	e.mu.Lock()
	s := Summary{
		TaskID: taskID, State: final, Rounds: e.rounds,
		Dispatched: e.dispatched, Duplicates: e.duplicates,
		Done: done, Blocked: blocked, Exhausted: e.exhausted.Load(),
		ElapsedMS: time.Since(start).Milliseconds(),
	}
	e.mu.Unlock()
	return s, nil
}

func (e *Engine) applyDefaultCaps(taskID int64) {
	caps := budget.DefaultCaps(
		fmt.Sprintf("%d", taskID),
		"*", // 单 intent 上限在 charge 时按 intent id 精确设置
		e.dayKey,
	)
	for _, c := range caps {
		e.b.SetCap(c.Scope, c.ID, c.Kind, c.N)
	}
}

// workerLoop 是 worker 主循环：领取 → 执行 → 回写 → 唤醒 planner。
func (e *Engine) workerLoop(ctx context.Context, t store.Task, n int, stop <-chan struct{}) {
	owner := fmt.Sprintf("work#%d", n)
	tick := time.NewTicker(120 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-tick.C:
		}
		if e.exhausted.Load() {
			return
		}
		it, ok := e.claimNext(t.ID, owner)
		if !ok {
			continue
		}
		res, err := e.exec.Run(ctx, t, it)
		state := res.State
		if err != nil {
			state = store.IntentBlocked
			if res.Note == "" {
				res.Note = err.Error()
			}
		}
		if state == "" {
			state = store.IntentDone
		}
		e.st.CompleteIntent(it.ID, state)
		e.charge(it, res)
		select {
		case e.notify <- struct{}{}:
		default:
		}
	}
}

func (e *Engine) claimNext(taskID int64, owner string) (store.Intent, bool) {
	for _, it := range e.st.Frontier(taskID, 20) {
		if e.st.ClaimIntent(taskID, it.ID, owner) {
			return it, true
		}
	}
	return store.Intent{}, false
}

// charge 记账：intent / task / day 三层一起扣，任何一层超限就标记耗尽。
func (e *Engine) charge(it store.Intent, res Result) {
	if res.Steps == 0 && res.Tokens == 0 && res.Cost == 0 {
		return
	}
	intentID := fmt.Sprintf("%d", it.ID)
	e.b.SetCap(budget.ScopeIntent, intentID, budget.KindSteps, 60)
	e.b.SetCap(budget.ScopeIntent, intentID, budget.KindTokens, 120000)
	taskID := fmt.Sprintf("%d", e.taskID)
	items := []budget.ChargeItem{
		{Scope: budget.ScopeIntent, ID: intentID, Kind: budget.KindSteps, N: int64(res.Steps)},
		{Scope: budget.ScopeTask, ID: taskID, Kind: budget.KindSteps, N: int64(res.Steps)},
		{Scope: budget.ScopeDay, ID: e.dayKey, Kind: budget.KindSteps, N: int64(res.Steps)},
		{Scope: budget.ScopeIntent, ID: intentID, Kind: budget.KindTokens, N: res.Tokens},
		{Scope: budget.ScopeTask, ID: taskID, Kind: budget.KindTokens, N: res.Tokens},
		{Scope: budget.ScopeDay, ID: e.dayKey, Kind: budget.KindTokens, N: res.Tokens},
	}
	if res.Cost > 0 {
		items = append(items,
			budget.ChargeItem{Scope: budget.ScopeTask, ID: taskID, Kind: budget.KindCost, N: res.Cost},
			budget.ChargeItem{Scope: budget.ScopeDay, ID: e.dayKey, Kind: budget.KindCost, N: res.Cost},
		)
	}
	if err := e.b.ChargeAll(items); err != nil {
		e.exhausted.Store(true)
	}
}

// chargePlan 给"规划"记账（没有 intent 归属，只记 task/day 两层）。
func (e *Engine) chargePlan(tokens, cost int64) {
	taskID := fmt.Sprintf("%d", e.taskID)
	items := []budget.ChargeItem{
		{Scope: budget.ScopeTask, ID: taskID, Kind: budget.KindTokens, N: tokens},
		{Scope: budget.ScopeDay, ID: e.dayKey, Kind: budget.KindTokens, N: tokens},
	}
	if cost > 0 {
		items = append(items,
			budget.ChargeItem{Scope: budget.ScopeTask, ID: taskID, Kind: budget.KindCost, N: cost},
			budget.ChargeItem{Scope: budget.ScopeDay, ID: e.dayKey, Kind: budget.KindCost, N: cost},
		)
	}
	if err := e.b.ChargeAll(items); err != nil {
		e.exhausted.Store(true)
	}
}

// plannerLoop 负责规划：首轮 kick + 防抖 + 心跳 + 收敛判定。
func (e *Engine) plannerLoop(ctx context.Context, t store.Task, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	idle := 0
	e.notify <- struct{}{} // 首轮 kick
	debounce := time.NewTimer(e.cfg.Debounce)
	defer debounce.Stop()
	heartbeat := time.NewTicker(e.cfg.Heartbeat)
	defer heartbeat.Stop()

	runRound := func() (converged bool) {
		e.mu.Lock()
		e.rounds++
		round := e.rounds
		e.mu.Unlock()
		if round > e.cfg.MaxRounds {
			return true
		}
		if e.exhausted.Load() {
			return true
		}
		intents, err := e.pl.Next(ctx, t, e.st)
		if mp, ok := e.pl.(MeteredPlanner); ok {
			if tok, cost := mp.LastUsage(); tok > 0 || cost > 0 {
				e.chargePlan(tok, cost)
			}
		}
		if err != nil {
			return false
		}
		added := 0
		for _, it := range intents {
			it.TaskID = t.ID
			fp := it.FP
			if fp == "" {
				fp = dedupe.Fingerprint(it.AssetID, it.Action, it.ParamKey)
			}
			it.FP = fp
			e.mu.Lock()
			if _, dup := e.reg.Claim(fp, 0); dup {
				e.duplicates++
				e.mu.Unlock()
				continue
			}
			e.mu.Unlock()
			saved, err := e.st.AddIntent(it)
			if err != nil {
				continue
			}
			e.mu.Lock()
			e.reg.Bind(fp, saved.ID)
			e.dispatched++
			e.mu.Unlock()
			added++
		}
		if added == 0 && e.st.ActiveIntents(t.ID) == 0 {
			idle++
		} else {
			idle = 0
		}
		return idle >= e.cfg.IdleRounds
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-heartbeat.C:
			if runRound() {
				return
			}
		case <-e.notify:
			// 防抖：把一串图变更合并成一轮。
			debounce.Reset(e.cfg.Debounce)
			select {
			case <-debounce.C:
				if runRound() {
					return
				}
				// 空转时自唤醒，避免"没有新事件就靠心跳才收敛"。
				if idle > 0 {
					select {
					case e.notify <- struct{}{}:
					default:
					}
				}
			case <-ctx.Done():
				return
			case <-stop:
				return
			}
		}
	}
}

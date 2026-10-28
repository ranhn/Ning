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

// StagnationAware 是可选能力：调度器把"连续几轮没有新产出"告诉规划器，
// 规划器据此在提示词里要求换方向。
//
// 这是 ARTEX 的做法：停滞不结束任务，只用来纠偏。我们之前把停滞直接当收敛条件，
// 结果目标还没打完任务就 done 了。
type StagnationAware interface {
	SetStagnation(rounds, threshold int)
}

// GoalMet 是可选能力：规划器显式声明"任务目标已被证据证明达成"。
// 这是唯一的正常结束路径（其余是超时与手动停止）。
type GoalMet interface {
	GoalMet() bool
}

// GoalRejectAware 是可选能力：调度器拒绝收尾时，把理由告诉规划器，
// 让它在下一轮补证据，而不是反复声明"已完成"。
type GoalRejectAware interface {
	SetGoalRejected(reason string)
}

// Config 是调度参数。
type Config struct {
	Workers   int
	Debounce  time.Duration
	Heartbeat time.Duration
	Grace     time.Duration
	MaxRounds int
	// IdleRounds：连续空轮达到该值就结束。0 = 不因空轮结束（生产默认）。
	// 语义对齐 ARTEX：任务只在「目标达成 / 超时 / 用户停止」时结束，
	// 而不是「几轮没有新产出」——后者会让一个还没打完的目标提前收工。
	IdleRounds int
	// StagnantRounds：连续多少轮没有新增产出就提示规划器「换方向」（只提示，不结束）。
	StagnantRounds int
	// MinDoneBeforeGoalMet 是"模型声明目标达成"的产出门槛。
	//
	// 为什么需要：模型可以在一事无成时也返回 goal_met=true，任务就悄悄结束了——
	// 用户看到的是"跑了一会儿，什么也没挖到"。
	// >0 时要求「至少这么多条动作完成」或「已有漏洞」，否则拒绝收尾并告诉它补证据。
	// 0 = 不检查（沿用旧行为）。
	MinDoneBeforeGoalMet int
}

// DefaultConfig 返回默认参数（worker 3、防抖 800ms、心跳 600s）。
//
// 关键：IdleRounds=0，即不做「无产出收敛」。任务会一直推进到 deadline 或被手动停止；
// 停滞只换来一句「换个方向」的提示。
func DefaultConfig() Config {
	return Config{
		Workers:        3,
		Debounce:       800 * time.Millisecond,
		Heartbeat:      600 * time.Second,
		Grace:          30 * time.Second,
		MaxRounds:      200,
		IdleRounds:     0,
		StagnantRounds: 3,
		// 至少跑过 10 条动作、或已经拿到漏洞，才允许模型宣布结束。
		// 这个数字刻意不高：既不让"什么都没做就收工"发生，也不会把长任务卡死。
		MinDoneBeforeGoalMet: 10,
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

	// 续跑准备：上次被停止或进程崩溃时可能留下 running 状态的意图，
	// 它们不会再被领取——退回 open 才能继续做（否则"停止→启动"就永远缺那几条）。
	for _, it := range e.st.Intents(taskID) {
		if it.State == store.IntentRunning {
			e.st.CompleteIntent(it.ID, store.IntentOpen)
		}
	}

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

// idleBackoff 决定"连续第 n 轮空转"之后等多久再试。
//
// 目的：任务不该因为暂时没思路而结束（ARTEX 模型），但也不能每 800ms 空烧一次模型调用。
func idleBackoff(idle int) time.Duration {
	switch {
	case idle <= 1:
		return 5 * time.Second
	case idle == 2:
		return 15 * time.Second
	case idle == 3:
		return 60 * time.Second
	case idle <= 5:
		return 180 * time.Second
	default:
		return 300 * time.Second
	}
}

// progress 返回任务的"有效产出"计数（完成意图 + 漏洞）。
// 用它判断是否还在推进；只有 blocked 意图增加不算进展。
func (e *Engine) progress(taskID int64) int {
	done := 0
	for _, it := range e.st.Intents(taskID) {
		if it.State == store.IntentDone {
			done++
		}
	}
	return done + len(e.st.Findings(taskID))
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

	// 停滞检测（对齐 ARTEX）：连续几轮没有新增产出时，只告诉规划器"换个方向"，
	// 绝不因此结束任务。结束只由「目标达成 / 超时 / 手动停止」决定。
	lastProgress := -1
	stagnant := 0

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
		// 停滞只累计计数并告知规划器，不结束任务。
		if prog := e.progress(t.ID); lastProgress >= 0 && prog <= lastProgress {
			stagnant++
		} else {
			stagnant = 0
			lastProgress = prog
		}
		if sa, ok := e.pl.(StagnationAware); ok {
			sa.SetStagnation(stagnant, e.cfg.StagnantRounds)
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
		// 模型显式声明"目标已被证据证明达成" → 唯一的正常结束路径。
		// 但"声明"不等于"达成"：零产出的收尾必须被挡住，否则任务会在什么都没做的情况下结束。
		if gm, ok := e.pl.(GoalMet); ok && gm.GoalMet() {
			if e.cfg.MinDoneBeforeGoalMet > 0 {
				done := 0
				for _, it := range e.st.Intents(t.ID) {
					if it.State == store.IntentDone {
						done++
					}
				}
				findings := len(e.st.Findings(t.ID))
				if findings == 0 && done < e.cfg.MinDoneBeforeGoalMet {
					reason := fmt.Sprintf(
						"当前只有 %d 条动作完成、0 个已确认漏洞，未达到收尾门槛（%d 条）。请继续执行能产生证据的动作：先扩面（子域/端点），再做模板验证。",
						done, e.cfg.MinDoneBeforeGoalMet)
					if ga, ok := e.pl.(GoalRejectAware); ok {
						ga.SetGoalRejected(reason)
					}
					return false
				}
			}
			return true
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
		// IdleRounds<=0（生产默认）表示"不因空轮结束"：任务会继续等心跳/防抖，
		// 直到目标达成、超时或被手动停止。只有测试与显式配置才让它收敛。
		if e.cfg.IdleRounds <= 0 {
			return false
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
				// 空转时**退避后**自唤醒：既不让任务停在这里，也不每 800ms 空烧一次模型。
				// 连续空轮越多、间隔越长，最后与心跳同量级。
				if idle > 0 {
					t := time.NewTimer(idleBackoff(idle))
					select {
					case <-t.C:
					case <-ctx.Done():
						t.Stop()
						return
					case <-stop:
						t.Stop()
						return
					}
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

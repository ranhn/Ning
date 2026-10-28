package store

// DeleteTask 删除任务及其全部关联数据（意图 / 漏洞 / 资产）。
//
// 越界记录与证据不在这里删除：它们是审计依据，不应随着"删任务"消失
// （证据库另有归档机制）。这里只清掉任务本体与派生物。
func (m *Memory) DeleteTask(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tasks[id]; !ok {
		return false
	}
	delete(m.tasks, id)

	order := m.taskOrder[:0]
	for _, tid := range m.taskOrder {
		if tid != id {
			order = append(order, tid)
		}
	}
	m.taskOrder = order

	iorder := m.intentOrder[:0]
	for _, iid := range m.intentOrder {
		if it, ok := m.intents[iid]; ok && it.TaskID == id {
			delete(m.intents, iid)
			continue
		}
		iorder = append(iorder, iid)
	}
	m.intentOrder = iorder

	delete(m.findings, id)

	aorder := m.assetOrder[:0]
	for _, k := range m.assetOrder {
		if a, ok := m.assets[k]; ok && a.TaskID == id {
			delete(m.assets, k)
			continue
		}
		aorder = append(aorder, k)
	}
	m.assetOrder = aorder

	m.touch()
	return true
}

// ReconcileRunning 在进程启动时把"上次没跑完"的任务标记为 stopped。
//
// 为什么需要：引擎只存在于进程内存里，进程重启后 running 的任务实际已经停了，
// 但快照里的状态还是 running —— 界面上就是一个永远转圈、点删除也删不掉的僵尸任务。
func (m *Memory) ReconcileRunning() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, t := range m.tasks {
		if t.State == "running" || t.State == "pending" {
			t.State = "stopped"
			m.tasks[id] = t
			n++
		}
	}
	if n > 0 {
		m.touch()
	}
	return n
}

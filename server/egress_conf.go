package server

import (
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/internal/egress"
	"github.com/Autumn-27/artex/internal/scope"
)

// Egress 是出口白名单的对外视图。
type Egress struct {
	Rules     int    `json:"rules"`
	Proxy     string `json:"proxy"`
	SquidConf string `json:"squid_conf"`
	HostsFile string `json:"hosts_file"`
}

// EgressConf 按任务范围生成出口白名单。
//
// 网络层的最终形态：工具子进程没有直连出口，唯一出口是 squid 网关，
// 而网关的放行清单来自 task_scope。这样"任务声明的范围"和"网关实际放行的目标"
// 永远是同一份数据 —— 两者不一致时，要么拦太多（误伤），要么放太多（越权）。
func (m *Manager) EgressConf(taskID int64) (Egress, error) {
	var out Egress
	if m.assets == nil || taskID <= 0 {
		return out, nil
	}
	rows, err := m.assets.ListTaskScope(taskID)
	if err != nil {
		return out, err
	}
	rules := taskScopeRules(rows)
	if len(rules) == 0 {
		return out, nil
	}
	sc, err := scope.New(rules)
	if err != nil {
		return out, err
	}
	al := egress.FromScope(sc)
	out.Rules = len(rules)
	out.Proxy = m.ProxyAddr()
	out.SquidConf = al.SquidConf()
	out.HostsFile = al.HostsFile()
	return out, nil
}

// taskEgress 返回该任务的出口网关配置（可直接喂给 squid 的 include 文件）。
func (s *Server) taskEgress(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "任务 ID 非法"})
		return
	}
	conf, err := s.m.EgressConf(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if r.URL.Query().Get("format") == "squid" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(conf.SquidConf))
		return
	}
	writeJSON(w, http.StatusOK, conf)
}

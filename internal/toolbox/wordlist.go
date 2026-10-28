package toolbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// commonPaths 是内置的目录/路径字典。
//
// 为什么内置而不让用户下载 SecLists：ffuf 没有字典就完全用不了，而"找字典、下载、
// 解压、放到正确位置"这一步会卡住绝大多数人。这里内置一份精简但高命中的路径表
// （约 200 条），覆盖管理后台、API 文档、配置文件、备份、运维端点、常见业务路径。
//
// 它不追求"全"，只追求"第一次扫就能扫出东西"——先把链路跑通，需要更全的字典
// 时用户可以把文件覆盖到同一路径。
var commonPaths = []string{
	// 管理后台与登录
	"admin", "administrator", "manage", "manager", "console", "dashboard",
	"login", "logout", "signin", "signup", "register",
	"admin/login", "admin/index", "admin.php", "admin.aspx",
	"wp-admin", "wp-login.php", "wp-config.php", "xmlrpc.php", "wp-content", "wp-includes",
	"phpmyadmin", "adminer", "manager/html", "host-manager/html", "console/login",
	"login.php", "login.jsp", "login.aspx",

	// API 与文档
	"api", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger", "api/openapi.json",
	"swagger", "swagger-ui.html", "swagger.json", "swagger-ui", "openapi.json",
	"graphql", "graphiql", "rest", "v1", "v2", "v3", "api/graphql",

	// 配置文件（泄露即高危）
	".env", ".env.local", ".env.production", ".git/config", ".git/HEAD", ".git/index",
	".svn/entries", ".DS_Store", ".htaccess", ".bash_history", ".ssh/id_rsa",
	"config.json", "config.yaml", "config.yml", "config.php", "config.inc.php",
	"web.config", "appsettings.json", "application.yml", "application.properties",
	"package.json", "composer.json", "Gemfile", "requirements.txt", "Dockerfile",
	"docker-compose.yml", "Makefile", "CHANGELOG.md", "README.md", "LICENSE",

	// 备份与导出（最容易捞到源码/数据）
	"backup", "backups", "backup.zip", "backup.tar.gz", "backup.sql",
	"db.sql", "dump.sql", "database.sql", "www.zip", "site.zip", "web.zip",
	"export", "export.csv", "export.xml", "data.json", "data.csv",

	// 运维与监控端点
	"actuator", "actuator/health", "actuator/env", "actuator/mappings", "actuator/beans",
	"metrics", "health", "healthz", "status", "ping", "version", "VERSION",
	"debug", "debug/vars", "pprof", "pprof/heap", "jmx-console", "web-console",
	"server-status", "server-info", "phpinfo.php", "info.php", "test.php",
	"solr", "elasticsearch", "kibana", "grafana", "jenkins", "gitlab", "nexus", "harbor",
	"nacos", "eureka", "consul", "zookeeper", "rabbitmq", "druid",

	// 目录与静态资源
	"upload", "uploads", "files", "file", "download", "downloads",
	"static", "assets", "images", "img", "css", "js", "media",
	"docs", "doc", "documentation", "test", "tests", "demo",
	"dev", "staging", "prod", "internal", "private", "secret", "secrets", "keys", "tmp", "temp", "log", "logs",

	// 业务与账户
	"user", "users", "account", "accounts", "profile", "settings",
	"search", "order", "orders", "cart", "checkout", "payment", "pay",
	"invoice", "report", "reports", "auth", "oauth", "oauth2", "sso",
	"token", "tokens", "callback", "webhook", "webhooks", "verify", "activate", "reset", "forgot",

	// 站点基础
	"index.php", "index.html", "index.jsp", "index.aspx", "default.aspx",
	"home", "about", "contact", "news", "blog", "faq", "help", "support",
	"terms", "privacy", "sitemap.xml", "robots.txt", "crossdomain.xml",
	"error", "errors", "404", "500", "trace",
	"cgi-bin", "shell", "cmd", "exec", "run", "system", "root",
}

// CommonPaths 返回内置字典的副本（测试与提示词用）。
func CommonPaths() []string {
	out := make([]string, len(commonPaths))
	copy(out, commonPaths)
	return out
}

// EnsureWordlist 准备 ffuf 用的字典文件：<dir>/wordlists/common.txt。
//
// 优先级（逐级回退，保证任何部署形态都有可用字典）：
//  1. 工作目录里已有全量字典（>= fullWordlistThreshold 条）→ 直接用，不覆盖用户替换的版本
//  2. 仓库/部署自带的 wordlists/common.txt（SecLists 精选，4752 条）→ 复制过去
//  3. 内置的 commonPaths（221 条）→ 兜底，保证新环境开箱能扫
//
// 写在**工作目录内**是关键：沙箱禁止绝对路径参数，而 ffuf 的 -w 需要文件；
// 用相对路径 `-w wordlists/common.txt` 即可（cwd 就是工作目录）。
func EnsureWordlist(dir string) (string, int, error) {
	if strings.TrimSpace(dir) == "" {
		return "", 0, fmt.Errorf("空工作目录")
	}
	wlDir := filepath.Join(dir, "wordlists")
	if err := os.MkdirAll(wlDir, 0o750); err != nil {
		return "", 0, err
	}
	target := filepath.Join(wlDir, "common.txt")

	// ① 已有足够全的字典就保留（尊重用户手工替换的版本），
	//    但仍要把 bundled 目录里的其它规模字典补齐（缺哪个补哪个，不覆盖）。
	if n, ok := lineCount(target); ok && n >= fullWordlistThreshold {
		copyBundledExtras(wlDir)
		return target, n, nil
	}

	// ② 仓库/部署自带的字典：整目录复制，让 ffuf 能按需选规模
	//    common.txt（4752 条，默认）/ raft-small-directories.txt（20114 条，更深）/ api-endpoints.txt（接口专用）
	for _, src := range bundledWordlists() {
		if data, err := os.ReadFile(src); err != nil || len(data) == 0 {
			continue
		}
		srcDir := filepath.Dir(src)
		if entries, derr := os.ReadDir(srcDir); derr == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
					continue
				}
				if b, rerr := os.ReadFile(filepath.Join(srcDir, e.Name())); rerr == nil {
					_ = os.WriteFile(filepath.Join(wlDir, e.Name()), b, 0o640)
				}
			}
		}
		n, _ := lineCount(target)
		return target, n, nil
	}

	// ③ 内置兜底
	body := strings.Join(commonPaths, "\n") + "\n"
	if err := os.WriteFile(target, []byte(body), 0o640); err != nil {
		return "", 0, err
	}
	return target, len(commonPaths), nil
}

// copyBundledExtras 把 bundled 目录里除 common.txt 外的字典补齐到工作目录（已存在则跳过）。
//
// 为什么要补齐：common.txt 只够"第一次扫"，真实项目常需要更深的 raft-small（2 万条）
// 或 API 专项字典。启动时就位，模型才能按需切换，而不是每次都要人手工拷文件。
func copyBundledExtras(wlDir string) {
	for _, src := range bundledWordlists() {
		srcDir := filepath.Dir(src)
		entries, err := os.ReadDir(srcDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
				continue
			}
			dst := filepath.Join(wlDir, e.Name())
			if _, serr := os.Stat(dst); serr == nil {
				continue
			}
			if b, rerr := os.ReadFile(filepath.Join(srcDir, e.Name())); rerr == nil {
				_ = os.WriteFile(dst, b, 0o640)
			}
		}
		return
	}
}

// fullWordlistThreshold 判定"已经是全量字典"的条目下限。
// 内置兜底只有 221 条，SecLists 精选 4752 条，取中间的 1000 作为分界。
const fullWordlistThreshold = 1000

// bundledWordlists 按优先级返回可能存在的自带字典路径（可执行文件旁 / 当前目录）。
func bundledWordlists() []string {
	cands := []string{
		filepath.Join("wordlists", "common.txt"),
	}
	if exe, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(exe), "wordlists", "common.txt"))
		cands = append(cands, filepath.Join(filepath.Dir(exe), "..", "wordlists", "common.txt"))
	}
	return cands
}

// lineCount 统计文件非空行数。
func lineCount(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n, true
}

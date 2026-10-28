package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashChain(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	r1, err := s.Append(1, 1, "command", map[string]string{"cmd": "echo hi"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Append(1, 2, "finding", map[string]string{"v": "sqli"})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Hash == "" || r1.PrevHash != "" {
		t.Fatalf("首条记录哈希/前驱不对: %+v", r1)
	}
	if r2.PrevHash != r1.Hash {
		t.Fatalf("哈希链未链接: %s != %s", r2.PrevHash, r1.Hash)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("链校验失败: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("应有 2 条，实际 %d", s.Len())
	}
	if _, ok := s.Get(r1.ID); !ok {
		t.Fatal("按 ID 取证据失败")
	}
}

func TestTamperDetected(t *testing.T) {
	s, _ := Open("")
	if _, err := s.Append(1, 1, "command", map[string]string{"cmd": "ls"}); err != nil {
		t.Fatal(err)
	}
	// 直接改内存记录，模拟磁盘被篡改后重新加载的情形。
	s.recs[0].Payload = []byte(`{"cmd":"rm -rf /"}`)
	if err := s.Verify(); err == nil {
		t.Fatal("篡改后必须校验失败")
	}
}

func TestPersistAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "evidence.jsonl")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(1, 1, "command", map[string]string{"a": "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(2, 2, "command", map[string]string{"a": "2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("证据文件未落盘: %v", err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("重新打开失败: %v", err)
	}
	defer s2.Close()
	if s2.Len() != 2 {
		t.Fatalf("重启后应恢复 2 条，实际 %d", s2.Len())
	}
	if err := s2.Verify(); err != nil {
		t.Fatalf("重启后链校验失败: %v", err)
	}
	r3, err := s2.Append(3, 3, "command", map[string]string{"a": "3"})
	if err != nil {
		t.Fatal(err)
	}
	if r3.Seq != 3 {
		t.Fatalf("续写序号应为 3，实际 %d", r3.Seq)
	}
	if err := s2.Verify(); err != nil {
		t.Fatalf("续写后链校验失败: %v", err)
	}
}

func TestListByTask(t *testing.T) {
	s, _ := Open("")
	_, _ = s.Append(1, 0, "a", 1)
	_, _ = s.Append(2, 0, "b", 2)
	_, _ = s.Append(1, 0, "c", 3)
	got := s.List(1, 0)
	if len(got) != 2 {
		t.Fatalf("任务 1 应有 2 条，实际 %d", len(got))
	}
	if got[0].Kind != "c" {
		t.Fatalf("应按时间倒序返回，首条为 %s", got[0].Kind)
	}
}

// Package evidence 实现只追加、带哈希链的证据存储（WORM 的本地形态）。
//
// 设计要点：
//   - 每条记录带 PrevHash，形成哈希链，任何篡改都会在 Verify 时暴露；
//   - 记录一旦写入只能追加，不提供 Update/Delete；
//   - 落盘为 JSONL，可整体搬到对象存储（S3 的对象锁）做真正的 WORM。
package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record 是一条证据。
type Record struct {
	Seq      int64           `json:"seq"`
	ID       string          `json:"id"`
	TaskID   int64           `json:"task_id"`
	IntentID int64           `json:"intent_id,omitempty"`
	Kind     string          `json:"kind"`
	TS       time.Time       `json:"ts"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
	Payload  json.RawMessage `json:"payload"`
}

// Store 是证据库。path 为空时退化为纯内存（测试/演示）。
type Store struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	recs   []Record
	byID   map[string]int
	seq    int64
	last   string
	closed bool
}

// Open 打开（或创建）证据库，并重建哈希链状态。
func Open(path string) (*Store, error) {
	s := &Store{path: path, byID: map[string]int{}}
	if path == "" {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("创建证据目录: %w", err)
	}
	if err := s.load(); err != nil {
		// 历史证据不可读时保留现场并重新开始，而不是让服务起不来。
		// 典型场景：企业 DLP 把落盘文件加密（文件头 %TSD-Header-###%）。
		bak := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		_ = os.Rename(path, bak)
		fmt.Fprintf(os.Stderr, "argus: 证据文件不可读（%v），已备份到 %s 并新建\n", err, bak)
		s.recs = nil
		s.byID = map[string]int{}
		s.seq, s.last = 0, ""
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("打开证据文件: %w", err)
	}
	s.f = f
	return s, nil
}

func (s *Store) load() error {
	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return fmt.Errorf("证据文件第 %d 行损坏: %w", len(s.recs)+1, err)
		}
		s.recs = append(s.recs, r)
		s.byID[r.ID] = len(s.recs) - 1
		s.seq = r.Seq
		s.last = r.Hash
	}
	return sc.Err()
}

// Append 追加一条证据并返回落库结果。
func (s *Store) Append(taskID, intentID int64, kind string, payload any) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Record{}, errors.New("证据库已关闭")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Record{}, fmt.Errorf("序列化证据: %w", err)
	}
	seq := s.seq + 1
	ts := time.Now().UTC()
	hash := chainHash(s.last, seq, kind, body)
	r := Record{
		Seq: seq, ID: fmt.Sprintf("ev-%06d", seq), TaskID: taskID, IntentID: intentID,
		Kind: kind, TS: ts, PrevHash: s.last, Hash: hash, Payload: body,
	}
	if s.f != nil {
		line, err := json.Marshal(r)
		if err != nil {
			return Record{}, err
		}
		if _, err := s.f.Write(append(line, '\n')); err != nil {
			return Record{}, fmt.Errorf("写证据: %w", err)
		}
		if err := s.f.Sync(); err != nil {
			return Record{}, fmt.Errorf("刷盘证据: %w", err)
		}
	}
	s.recs = append(s.recs, r)
	s.byID[r.ID] = len(s.recs) - 1
	s.seq = seq
	s.last = hash
	return r, nil
}

func chainHash(prev string, seq int64, kind string, payload []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%s|", prev, seq, kind)
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify 校验整条哈希链，任何一处被改动都会报错。
func (s *Store) Verify() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := ""
	for i, r := range s.recs {
		if r.Seq != int64(i+1) {
			return fmt.Errorf("序号断裂: 第 %d 条 seq=%d", i+1, r.Seq)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("第 %d 条 PrevHash 不匹配", r.Seq)
		}
		if want := chainHash(prev, r.Seq, r.Kind, r.Payload); want != r.Hash {
			return fmt.Errorf("第 %d 条哈希不匹配（内容被篡改）", r.Seq)
		}
		prev = r.Hash
	}
	return nil
}

// List 返回某任务的证据（limit<=0 表示全部），按时间倒序。
func (s *Store) List(taskID int64, limit int) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.recs))
	for i := len(s.recs) - 1; i >= 0; i-- {
		if taskID == 0 || s.recs[i].TaskID == taskID {
			out = append(out, s.recs[i])
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

// Get 按 ID 取证据。
func (s *Store) Get(id string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.byID[id]
	if !ok {
		return Record{}, false
	}
	return s.recs[i], true
}

// Len 返回证据条数。
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.recs)
}

// Close 关闭文件句柄。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.f == nil {
		s.closed = true
		return nil
	}
	s.closed = true
	return s.f.Close()
}

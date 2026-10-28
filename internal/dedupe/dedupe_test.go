package dedupe

import "testing"

func TestFingerprintNormalization(t *testing.T) {
	a := Fingerprint(9, "Bash", "b=2&a=1")
	b := Fingerprint(9, "bash", " a=1 & b=2 ")
	if a != b {
		t.Fatalf("参数顺序/大小写/空格不应影响指纹: %s != %s", a, b)
	}
	c := Fingerprint(9, "Bash", "a=1&b=3")
	if a == c {
		t.Fatal("参数值不同应为不同指纹")
	}
	d := Fingerprint(10, "Bash", "b=2&a=1")
	if a == d {
		t.Fatal("资产不同应为不同指纹")
	}
	if len(a) != 64 {
		t.Fatalf("指纹应为 64 位十六进制，实际 %d", len(a))
	}
}

func TestClaim(t *testing.T) {
	r := New()
	fp := Fingerprint(1, "WebFetch", "u=1")
	if id, dup := r.Claim(fp, 0); dup || id != 0 {
		t.Fatal("首次占用不应判重")
	}
	r.Bind(fp, 42)
	id, dup := r.Claim(fp, 0)
	if !dup || id != 42 {
		t.Fatalf("第二次应判重并返回已有 ID，实际 id=%d dup=%v", id, dup)
	}
	if r.Len() != 1 {
		t.Fatalf("指纹表应为 1，实际 %d", r.Len())
	}
	r.Reset()
	if r.Len() != 0 {
		t.Fatal("Reset 后应为空")
	}
}

func TestConcurrentClaim(t *testing.T) {
	r := New()
	fp := Fingerprint(1, "Bash", "x=1")
	const n = 64
	results := make(chan bool, n)
	for i := 0; i < n; i++ {
		go func() {
			_, dup := r.Claim(fp, 0)
			results <- dup
		}()
	}
	wins := 0
	for i := 0; i < n; i++ {
		if !<-results {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("并发下应只有 1 个赢家，实际 %d", wins)
	}
}

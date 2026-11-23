package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingWriter 记录 WriteHeader / Write / Flush 的次数，并发安全（保活 goroutine 与测试同时访问）。
type countingWriter struct {
	mu          sync.Mutex
	header      http.Header
	headerCalls int
	writes      int
	flushes     int
	body        []byte
	failWrites  bool
}

func newCountingWriter() *countingWriter { return &countingWriter{header: http.Header{}} }

func (c *countingWriter) Header() http.Header { return c.header }

func (c *countingWriter) WriteHeader(int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headerCalls++
}

func (c *countingWriter) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.failWrites {
		return 0, errors.New("client went away")
	}
	c.body = append(c.body, b...)
	return len(b), nil
}

func (c *countingWriter) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushes++
}

func (c *countingWriter) snapshot() (headerCalls, writes, flushes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.headerCalls, c.writes, c.flushes
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func newTestSession(w http.ResponseWriter, interval time.Duration, prepare func()) *keepaliveSession {
	return newKeepaliveSession(w, interval, defaultStreamKeepaliveSpec(), prepare)
}

// 重复 Start 不会再起第二个保活器：按行为断言，不统计 goroutine 数量（全量并行时 goroutine 总数会被其他用例扰动）。
// 若有两个保活器同时在跑，写入次数会翻倍；头只提交一次，prepare 也只调用一次。
func TestKeepaliveSessionRepeatedStartRunsSingleGoroutine(t *testing.T) {
	const interval = 20 * time.Millisecond
	w := newCountingWriter()
	var prepares atomic.Int32
	s := newTestSession(w, interval, func() { prepares.Add(1) })

	started := time.Now()
	s.Start()
	first := s.active
	for i := 0; i < 5; i++ {
		s.Start()
	}
	if s.active != first {
		t.Fatalf("repeated Start must keep the running keepalive")
	}

	time.Sleep(5 * interval)
	committed := s.Stop()
	elapsed := time.Since(started)

	if !committed {
		t.Fatal("headers were committed by the keepalive ticks")
	}
	headerCalls, writes, _ := w.snapshot()
	if headerCalls != 1 {
		t.Fatalf("WriteHeader must happen exactly once, got %d", headerCalls)
	}
	// 单个保活器在 elapsed 内最多 tick elapsed/interval 次；两个保活器同时跑会明显超过这个数。
	if maxWrites := int(elapsed/interval) + 1; writes < 1 || writes > maxWrites {
		t.Fatalf("expected 1..%d keepalive writes from a single keepalive, got %d (elapsed %v)", maxWrites, writes, elapsed)
	}
	if got := prepares.Load(); got != 1 {
		t.Fatalf("prepare must run once, ran %d times", got)
	}
}

// Stop 之后再 Start（实时流回退到缓冲的路径）：只续写保活字节，WriteHeader 全程只发生一次。
func TestKeepaliveSessionStartAfterStopWritesHeaderOnce(t *testing.T) {
	w := newCountingWriter()
	var prepares atomic.Int32
	s := newTestSession(w, 10*time.Millisecond, func() { prepares.Add(1) })

	s.Start()
	waitFor(t, "headers committed", func() bool { headerCalls, _, _ := w.snapshot(); return headerCalls == 1 })
	if !s.Stop() {
		t.Fatal("expected committed after the first tick")
	}
	_, writesAfterStop, _ := w.snapshot()

	s.Start() // 头已提交：续写，不再提交头
	waitFor(t, "keepalive resumed", func() bool { _, writes, _ := w.snapshot(); return writes > writesAfterStop+1 })
	if !s.Stop() {
		t.Fatal("committed state must persist across Stop/Start")
	}
	if headerCalls, _, _ := w.snapshot(); headerCalls != 1 {
		t.Fatalf("WriteHeader must happen exactly once, got %d", headerCalls)
	}
	if prepares.Load() != 1 {
		t.Fatalf("prepare must run once, ran %d times", prepares.Load())
	}
}

// 从未 tick 就 Stop：返回 false，零写入（快请求与关闭保活时逐字节一致的根基）。
func TestKeepaliveSessionStopBeforeFirstTickWritesNothing(t *testing.T) {
	w := newCountingWriter()
	var prepares atomic.Int32
	s := newTestSession(w, time.Hour, func() { prepares.Add(1) })

	s.Start()
	if s.Stop() {
		t.Fatal("no tick happened, headers must not be committed")
	}
	if headerCalls, writes, flushes := w.snapshot(); headerCalls != 0 || writes != 0 || flushes != 0 {
		t.Fatalf("expected zero writes, got header=%d writes=%d flushes=%d", headerCalls, writes, flushes)
	}
	if prepares.Load() != 0 || len(w.header) != 0 {
		t.Fatalf("prepare/headers must stay untouched: prepares=%d header=%v", prepares.Load(), w.header)
	}
	if s.Stop() {
		t.Fatal("Stop must be repeatable")
	}
}

// nil、间隔 0、writer 不支持 Flush：都不会提交头。
func TestKeepaliveSessionDisabledVariantsNeverCommit(t *testing.T) {
	var nilSession *keepaliveSession
	nilSession.Start()
	if nilSession.Stop() {
		t.Fatal("nil session must report not committed")
	}

	if s := newTestSession(httptest.NewRecorder(), 0, nil); s != nil {
		t.Fatalf("interval 0 must not create a session")
	}

	plain := &nonFlusherWriter{httptest.NewRecorder()}
	s := newTestSession(plain, 5*time.Millisecond, nil)
	s.Start()
	time.Sleep(30 * time.Millisecond)
	if s.active != nil {
		t.Fatalf("a writer without Flush must not start a keepalive")
	}
	if s.Stop() {
		t.Fatal("a writer without Flush must never commit")
	}
	if rec := plain.ResponseWriter.(*httptest.ResponseRecorder); rec.Body.Len() != 0 || rec.Flushed {
		t.Fatalf("nothing may be written: %q", rec.Body.String())
	}
}

// 写失败后保活自行退出：Stop 很快返回（不会卡在已退出的保活上），之后不再有写入。按行为断言，不统计 goroutine 数量。
func TestKeepaliveSessionWriteFailureExitsGoroutine(t *testing.T) {
	const interval = 5 * time.Millisecond
	w := newCountingWriter()
	w.failWrites = true
	s := newTestSession(w, interval, nil)

	s.Start()
	waitFor(t, "failed write", func() bool { _, writes, _ := w.snapshot(); return writes >= 1 })

	done := make(chan bool, 1)
	go func() { done <- s.Stop() }()
	select {
	case committed := <-done:
		if !committed {
			t.Fatal("headers were written before the write failure")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Stop blocked after the write failure")
	}

	time.Sleep(6 * interval)
	if _, writes, _ := w.snapshot(); writes != 1 {
		t.Fatalf("keepalive must stop after the first failed write, writes=%d", writes)
	}
}

// TryLive：头已由保活提交 -> try 不被调用，保活不停也不重启（同一个保活器继续写，写入不中断）。
func TestKeepaliveSessionTryLiveSkipsTryWhenHeadersCommitted(t *testing.T) {
	const interval = 10 * time.Millisecond
	w := newCountingWriter()
	s := newTestSession(w, interval, nil)
	s.Start()
	waitFor(t, "headers committed", func() bool { headerCalls, _, _ := w.snapshot(); return headerCalls == 1 })
	running := s.active

	called := false
	attempted, err := s.TryLive(func() (bool, error) { called = true; return true, nil })

	if attempted || err != nil || called {
		t.Fatalf("committed headers must forbid the live stream: attempted=%v err=%v called=%v", attempted, err, called)
	}
	if s.active != running {
		t.Fatal("keepalive must keep running untouched (no Stop/Start) when TryLive declines")
	}
	_, writesNow, _ := w.snapshot()
	waitFor(t, "keepalive writes keep growing", func() bool { _, writes, _ := w.snapshot(); return writes >= writesNow+3 })
	if headerCalls, _, _ := w.snapshot(); headerCalls != 1 {
		t.Fatalf("WriteHeader must stay at one call, got %d", headerCalls)
	}
	s.Stop()
}

// Committed：保活运行中也能读到头是否已发出，且不会停掉保活；nil 会话为 false。
func TestKeepaliveSessionCommittedReadsWithoutStopping(t *testing.T) {
	var nilSession *keepaliveSession
	if nilSession.Committed() {
		t.Fatal("nil session must report not committed")
	}

	w := newCountingWriter()
	s := newTestSession(w, 10*time.Millisecond, nil)
	if s.Committed() {
		t.Fatal("nothing started yet")
	}
	s.Start()
	running := s.active
	waitFor(t, "headers committed", func() bool { return s.Committed() })
	if s.active != running {
		t.Fatal("Committed must not stop or restart the keepalive")
	}
	s.Stop()
	if !s.Committed() {
		t.Fatal("committed state must persist after Stop")
	}
}

// TryLive：头未提交 -> 保活先停，再调 try；try 返回 not attempted 时保活恢复。
func TestKeepaliveSessionTryLiveResumesKeepaliveWhenNotAttempted(t *testing.T) {
	w := newCountingWriter()
	s := newTestSession(w, time.Hour, nil)
	s.Start()
	first := s.active

	var activeDuringTry *streamKeepalive
	wantErr := errors.New("passthrough")
	attempted, err := s.TryLive(func() (bool, error) {
		activeDuringTry = s.active
		return false, wantErr
	})

	if attempted || !errors.Is(err, wantErr) {
		t.Fatalf("TryLive must return try's result: attempted=%v err=%v", attempted, err)
	}
	if activeDuringTry != nil {
		t.Fatal("keepalive must be stopped while try runs (try may write w)")
	}
	if s.active == nil || s.active == first {
		t.Fatal("a fresh keepalive must be running after a not-attempted try")
	}
	s.Stop()
}

// TryLive：try 返回 attempted=true 后保活不再恢复（实时流已接管 w），结果原样返回。
func TestKeepaliveSessionTryLiveDoesNotResumeWhenAttempted(t *testing.T) {
	w := newCountingWriter()
	s := newTestSession(w, time.Hour, nil)
	s.Start()

	wantErr := errors.New("live stream failed")
	attempted, err := s.TryLive(func() (bool, error) { return true, wantErr })

	if !attempted || !errors.Is(err, wantErr) {
		t.Fatalf("TryLive must return try's result: attempted=%v err=%v", attempted, err)
	}
	if s.active != nil {
		t.Fatal("keepalive must not resume once the live stream owns w")
	}
	if s.Stop() {
		t.Fatal("no tick happened, nothing committed")
	}
}

// TryLive 对 nil 会话（保活关闭 / 非流式）直接透传 try。
func TestKeepaliveSessionTryLiveNilSessionPassesThrough(t *testing.T) {
	var s *keepaliveSession
	wantErr := errors.New("boom")
	attempted, err := s.TryLive(func() (bool, error) { return true, wantErr })
	if !attempted || !errors.Is(err, wantErr) {
		t.Fatalf("nil session must call try directly: attempted=%v err=%v", attempted, err)
	}
	attempted, err = s.TryLive(func() (bool, error) { return false, nil })
	if attempted || err != nil {
		t.Fatalf("attempted=%v err=%v", attempted, err)
	}
}

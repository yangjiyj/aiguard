package ratelog

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestLogsFirstThenEveryNth(t *testing.T) {
	buf := capture(t)
	l := New(10)
	for i := 0; i < 25; i++ {
		l.Printf("reason_a", "rejected reason=a")
	}
	lines := strings.Count(buf.String(), "rejected reason=a")
	if lines != 3 { // 第 1、10、20 次
		t.Fatalf("lines=%d want 3\n%s", lines, buf.String())
	}
	if !strings.Contains(buf.String(), "total=10") || !strings.Contains(buf.String(), "total=20") {
		t.Fatalf("累计次数缺失:\n%s", buf.String())
	}
}

func TestKeysAreIndependent(t *testing.T) {
	buf := capture(t)
	l := New(100)
	l.Printf("a", "event a")
	l.Printf("b", "event b")
	l.Printf("a", "event a")
	if strings.Count(buf.String(), "event a") != 1 || strings.Count(buf.String(), "event b") != 1 {
		t.Fatalf("keys not independent:\n%s", buf.String())
	}
}

func TestCountReportsTotalIncludingSuppressed(t *testing.T) {
	capture(t)
	l := New(50)
	for i := 0; i < 7; i++ {
		l.Printf("k", "x")
	}
	if got := l.Count("k"); got != 7 {
		t.Fatalf("count=%d", got)
	}
	if got := l.Count("never"); got != 0 {
		t.Fatalf("unknown key count=%d", got)
	}
}

func TestKeySpaceIsBounded(t *testing.T) {
	capture(t)
	l := New(10)
	for i := 0; i < maxKeys*3; i++ {
		l.Printf(strings.Repeat("k", 1)+string(rune('a'+i%26))+strings.Repeat("x", i%97)+string(rune(i)), "x")
	}
	if l.Keys() > maxKeys {
		t.Fatalf("keys=%d exceeds %d", l.Keys(), maxKeys)
	}
}

func TestZeroEveryDefaultsToSafeValue(t *testing.T) {
	buf := capture(t)
	l := New(0)
	for i := 0; i < 5; i++ {
		l.Printf("k", "only first")
	}
	if strings.Count(buf.String(), "only first") != 1 {
		t.Fatalf("expected a single line:\n%s", buf.String())
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// 静默超过窗口后，同一 key 的计数归零：新一轮故障的第一条日志必须能打出来。
func TestQuietWindowResetsCountSoNewIncidentLogsFirstLine(t *testing.T) {
	buf := capture(t)
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := NewWithWindow(100, 10*time.Minute, clock.now)
	for i := 0; i < 37; i++ { // 第一轮：只有第 1 条会打
		l.Printf("k", "incident")
		clock.advance(time.Second)
	}
	if got := strings.Count(buf.String(), "incident"); got != 1 {
		t.Fatalf("round 1 lines=%d want 1\n%s", got, buf.String())
	}
	clock.advance(10*time.Minute + time.Second) // 静默超过窗口
	l.Printf("k", "incident")
	if got := strings.Count(buf.String(), "incident"); got != 2 {
		t.Fatalf("new incident first line suppressed, lines=%d\n%s", got, buf.String())
	}
	if !strings.HasSuffix(strings.TrimSpace(buf.String()), "total=1") {
		t.Fatalf("new round should restart at total=1:\n%s", buf.String())
	}
	if l.Count("k") != 1 {
		t.Fatalf("count=%d want 1", l.Count("k"))
	}
}

// 持续出现（每次间隔都小于窗口）时不归零，仍按「首条 + 每 N 条」打印。
func TestQuietWindowDoesNotResetWhileErrorsKeepComing(t *testing.T) {
	buf := capture(t)
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := NewWithWindow(10, 10*time.Minute, clock.now)
	for i := 0; i < 25; i++ {
		l.Printf("k", "incident")
		clock.advance(9 * time.Minute) // 总时长远超窗口，但每次间隔都在窗口内
	}
	if got := strings.Count(buf.String(), "incident"); got != 3 {
		t.Fatalf("lines=%d want 3 (1st,10th,20th)\n%s", got, buf.String())
	}
	if l.Count("k") != 25 {
		t.Fatalf("count=%d want 25", l.Count("k"))
	}
}

// 恰好等于窗口不算「超过」；key 之间的静默判定互不影响。
func TestQuietWindowBoundaryAndKeyIsolation(t *testing.T) {
	capture(t)
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := NewWithWindow(100, 10*time.Minute, clock.now)
	l.Printf("a", "x")
	l.Printf("b", "x")
	clock.advance(10 * time.Minute) // 等于窗口
	l.Printf("a", "x")
	if l.Count("a") != 2 {
		t.Fatalf("exactly-window must not reset, a=%d", l.Count("a"))
	}
	clock.advance(time.Second) // b 已静默 10min+1s，a 只静默 1s
	l.Printf("a", "x")
	l.Printf("b", "x")
	if l.Count("a") != 3 || l.Count("b") != 1 {
		t.Fatalf("a=%d (want 3) b=%d (want 1)", l.Count("a"), l.Count("b"))
	}
}

func TestZeroWindowNeverResets(t *testing.T) {
	capture(t)
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := NewWithWindow(100, 0, clock.now)
	l.Printf("k", "x")
	clock.advance(24 * time.Hour)
	l.Printf("k", "x")
	if l.Count("k") != 2 {
		t.Fatalf("count=%d want 2", l.Count("k"))
	}
}

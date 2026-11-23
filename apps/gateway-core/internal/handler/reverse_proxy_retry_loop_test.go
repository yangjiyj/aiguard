package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// 退避器：成功/无任务保持原来的 2 秒节奏；连续失败按指数拉长并封顶。
func TestInspectionRetryPacerKeepsBaseCadenceWhenHealthy(t *testing.T) {
	pacer := newInspectionRetryPacer()
	for _, err := range []error{nil, pgx.ErrNoRows, fmt.Errorf("claim: %w", pgx.ErrNoRows)} {
		if d := pacer.after(err); d != inspectionRetryBaseInterval {
			t.Fatalf("err=%v delay=%s want %s", err, d, inspectionRetryBaseInterval)
		}
	}
}

func TestInspectionRetryPacerBacksOffOnConnectionExhaustionAndResets(t *testing.T) {
	pacer := newInspectionRetryPacer()
	tooMany := &pgconn.PgError{Code: "53300", Message: "sorry, too many clients already"}
	var last time.Duration
	grew := false
	for i := 0; i < 10; i++ {
		d := pacer.after(tooMany)
		if d > inspectionRetryMaxInterval {
			t.Fatalf("delay %s exceeds cap %s", d, inspectionRetryMaxInterval)
		}
		if d > inspectionRetryBaseInterval*2 {
			grew = true
		}
		last = d
	}
	if !grew {
		t.Fatalf("delay never grew; last=%s", last)
	}
	if d := pacer.after(nil); d != inspectionRetryBaseInterval {
		t.Fatalf("delay after recovery=%s", d)
	}
}

// 抖动：多个 worker 同时失败时不应同步重试。
func TestInspectionRetryPacerJittersAcrossWorkers(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 30; i++ {
		p := newInspectionRetryPacer()
		p.after(errors.New("x"))
		seen[p.after(errors.New("x"))] = true
	}
	if len(seen) < 5 {
		t.Fatalf("only %d distinct delays across 30 workers; jitter missing", len(seen))
	}
}

// 失败日志要带类别且限频，不带连接串。
func TestInspectionRetryFailureLogCarriesClassAndIsThrottled(t *testing.T) {
	buf := captureGatewayLog(t)
	err := fmt.Errorf("failed to connect to `host=db.internal user=leaky_user database=leaky_db`: %w", &pgconn.PgError{Code: "53300"})
	for i := 0; i < 25; i++ {
		logInspectionRetryFailure("Inspection retry worker", err)
	}
	out := buf.String()
	// 限频是「首条 + 每 20 条」：25 次失败只会在第 1、20 次打印。
	if got := strings.Count(out, "Inspection retry worker"); got != 2 {
		t.Fatalf("lines=%d want 2\n%s", got, out)
	}
	if !strings.Contains(out, "class=too_many_clients") || !strings.Contains(out, "sqlstate=53300") {
		t.Fatalf("log=%q", out)
	}
	for _, leaked := range []string{"leaky_user", "leaky_db", "db.internal"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("log leaks %q", leaked)
		}
	}
}

// 循环本身：失败时调用间隔变长；ctx 取消立即退出；无任务（ErrNoRows）不当作失败。
func TestInspectionRetryLoopSlowsDownOnFailureAndStopsOnCancel(t *testing.T) {
	var calls atomic.Int64
	var stamps []time.Time
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runInspectionRetryLoop(ctx, newInspectionRetryPacerWith(5*time.Millisecond, 80*time.Millisecond), func(context.Context) error {
			stamps = append(stamps, time.Now())
			if calls.Add(1) >= 6 {
				cancel()
			}
			return errors.New("down")
		}, func(error) {})
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("loop did not stop after cancel")
	}
	if len(stamps) < 6 {
		t.Fatalf("calls=%d", len(stamps))
	}
	firstGap := stamps[1].Sub(stamps[0])
	lastGap := stamps[len(stamps)-1].Sub(stamps[len(stamps)-2])
	if lastGap <= firstGap {
		t.Fatalf("gaps did not grow: first=%s last=%s", firstGap, lastGap)
	}
}

func TestInspectionRetryLoopTreatsNoRowsAsIdleNotFailure(t *testing.T) {
	var calls, reported atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		runInspectionRetryLoop(ctx, newInspectionRetryPacerWith(2*time.Millisecond, 40*time.Millisecond), func(context.Context) error {
			if calls.Add(1) >= 8 {
				cancel()
			}
			return pgx.ErrNoRows
		}, func(error) { reported.Add(1) })
	}()
	<-runDone
	if reported.Load() != 0 {
		t.Fatalf("ErrNoRows reported as failure %d times", reported.Load())
	}
}

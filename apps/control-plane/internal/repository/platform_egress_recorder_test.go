package repository

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type flakyEgressDB struct {
	execs atomic.Int32
	fail  atomic.Bool
}

func (d *flakyEgressDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	d.execs.Add(1)
	time.Sleep(5 * time.Millisecond) // 让并发写在“判断通过”和“写完登记”之间交错
	if d.fail.Load() {
		return pgconn.CommandTag{}, errors.New("db down")
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (d *flakyEgressDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return projectRow("proj_x")
}

type projectRow string

func (r projectRow) Scan(dest ...any) error {
	*(dest[0].(*string)) = string(r)
	return nil
}

// 按“租户+类型+目标主机”在时间窗内限频；写成功后才登记，失败的下次照常重试。
func TestPlatformEgressRecorderRateLimitsAfterSuccessfulWrite(t *testing.T) {
	db := &flakyEgressDB{}
	db.fail.Store(true)
	now := time.Now()
	recorder := NewPlatformEgressEventRecorder(db, 10*time.Minute)
	recorder.now = func() time.Time { return now }
	if ok, err := recorder.Record(context.Background(), "t1", "", "notify_channel:webhook", "10.0.0.5"); ok || err == nil {
		t.Fatalf("failed write: ok=%v err=%v", ok, err)
	}
	db.fail.Store(false)
	if ok, _ := recorder.Record(context.Background(), "t1", "", "notify_channel:webhook", "10.0.0.5"); !ok {
		t.Fatal("a failed write must not be registered; the retry must be recorded")
	}
	if ok, _ := recorder.Record(context.Background(), "t1", "", "notify_channel:webhook", "10.0.0.5"); ok {
		t.Fatal("the same kind and target within the window must be rate limited")
	}
	if ok, _ := recorder.Record(context.Background(), "t1", "", "notify_channel:webhook", "10.0.0.6"); !ok {
		t.Fatal("another target is a separate key")
	}
	now = now.Add(11 * time.Minute)
	if ok, _ := recorder.Record(context.Background(), "t1", "", "notify_channel:webhook", "10.0.0.5"); !ok {
		t.Fatal("after the window the event is recorded again")
	}
}

// 同键 20 路并发只写 1 条；并发里那次写失败后，下次能重试。
func TestPlatformEgressRecorderConcurrentSameKeyWritesOnce(t *testing.T) {
	run := func(db *flakyEgressDB, recorder *PlatformEgressEventRecorder) int32 {
		var wg sync.WaitGroup
		var recorded atomic.Int32
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, _ := recorder.Record(context.Background(), "t1", "", "notify_channel:webhook", "10.0.0.5"); ok {
					recorded.Add(1)
				}
			}()
		}
		wg.Wait()
		return recorded.Load()
	}
	db := &flakyEgressDB{}
	recorder := NewPlatformEgressEventRecorder(db, 10*time.Minute)
	if recorded := run(db, recorder); recorded != 1 || db.execs.Load() != 1 {
		t.Fatalf("20 concurrent records of one key: recorded=%d execs=%d, want 1/1", recorded, db.execs.Load())
	}
	failing := &flakyEgressDB{}
	failing.fail.Store(true)
	recorder = NewPlatformEgressEventRecorder(failing, 10*time.Minute)
	if recorded := run(failing, recorder); recorded != 0 || failing.execs.Load() != 1 {
		t.Fatalf("concurrent failing writes: recorded=%d execs=%d, want 0/1", recorded, failing.execs.Load())
	}
	failing.fail.Store(false)
	if ok, err := recorder.Record(context.Background(), "t1", "", "notify_channel:webhook", "10.0.0.5"); !ok || err != nil {
		t.Fatalf("after a failed write the next attempt must retry: ok=%v err=%v", ok, err)
	}
}

type panicEgressDB struct{ flakyEgressDB }

func (d *panicEgressDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	d.execs.Add(1)
	panic("driver panic")
}

// 写库 panic 时占位也要清掉：下一次照常写，不会被一直卡在“写入中”。
func TestPlatformEgressRecorderClearsPlaceholderOnPanic(t *testing.T) {
	db := &panicEgressDB{}
	recorder := NewPlatformEgressEventRecorder(db, 10*time.Minute)
	func() {
		defer func() { _ = recover() }()
		_, _ = recorder.Record(context.Background(), "t1", "", "ldap", "dc.example")
	}()
	func() {
		defer func() { _ = recover() }()
		_, _ = recorder.Record(context.Background(), "t1", "", "ldap", "dc.example")
	}()
	if db.execs.Load() != 2 {
		t.Fatalf("placeholder left behind after panic: execs=%d, want 2", db.execs.Load())
	}
}

type noProjectEgressDB struct{ flakyEgressDB }

func (d *noProjectEgressDB) QueryRow(context.Context, string, ...any) pgx.Row { return noProjectRow{} }

type noProjectRow struct{}

func (noProjectRow) Scan(...any) error { return pgx.ErrNoRows }

// 没有项目的租户只打日志，日志也按同一限频：窗口内同键只打一次。
func TestPlatformEgressRecorderRateLimitsNoProjectLog(t *testing.T) {
	db := &noProjectEgressDB{}
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(original)
	recorder := NewPlatformEgressEventRecorder(db, 10*time.Minute)
	for i := 0; i < 3; i++ {
		_, _ = recorder.Record(context.Background(), "t_noproj", "", "ldap", "dc.example")
	}
	if got := strings.Count(logs.String(), "t_noproj"); got != 1 || db.execs.Load() != 0 {
		t.Fatalf("log lines=%d execs=%d, want 1/0: %s", got, db.execs.Load(), logs.String())
	}
}

package handler

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 审查 5：读路径不加锁，缓存过期时先返回旧值；同一时刻只有一次刷新（singleflight）。
func TestEgressSettingsReaderServesStaleValuesWhileOneRefreshRuns(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	reader := &EgressSettingsReader{ttl: time.Millisecond, load: func(ctx context.Context) (map[string]string, error) {
		if calls.Add(1) == 1 {
			return map[string]string{"k": "old"}, nil
		}
		<-release
		return map[string]string{"k": "new"}, nil
	}}
	if got := reader.Values(context.Background()); got["k"] != "old" {
		t.Fatalf("first read = %v", got)
	}
	time.Sleep(5 * time.Millisecond)
	var wg sync.WaitGroup
	results := make(chan string, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- reader.Values(context.Background())["k"]
		}()
	}
	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("readers must not wait for the refresh while a previous value exists")
	}
	close(results)
	for got := range results {
		if got != "old" {
			t.Fatalf("stale read = %q, want old", got)
		}
	}
	// 刷新在后台跑：等它开始读库，再确认没有第二次刷新。
	for wait := time.Now().Add(time.Second); calls.Load() < 2 && time.Now().Before(wait); {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	if n := calls.Load(); n != 2 {
		t.Fatalf("expired cache must trigger exactly one refresh, got %d loads", n)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for reader.Values(context.Background())["k"] != "new" {
		if time.Now().After(deadline) {
			t.Fatal("refreshed values never became visible")
		}
		time.Sleep(time.Millisecond)
	}
}

// 刷新用独立的 ctx：调用方已取消也照常读库，最多 2 秒。
func TestEgressSettingsReaderRefreshUsesIndependentContext(t *testing.T) {
	type seen struct {
		err      error
		deadline time.Duration
	}
	got := make(chan seen, 1)
	reader := &EgressSettingsReader{ttl: time.Minute, load: func(ctx context.Context) (map[string]string, error) {
		deadline, _ := ctx.Deadline()
		got <- seen{err: ctx.Err(), deadline: time.Until(deadline)}
		return map[string]string{"k": "v"}, nil
	}}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	reader.Values(canceled)
	select {
	case s := <-got:
		if s.err != nil || s.deadline <= 0 || s.deadline > 2*time.Second {
			t.Fatalf("refresh ctx err=%v deadline=%v, want live ctx with <=2s", s.err, s.deadline)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh did not run")
	}
	if v := reader.Values(context.Background()); v["k"] != "v" {
		t.Fatalf("values = %v", v)
	}
}

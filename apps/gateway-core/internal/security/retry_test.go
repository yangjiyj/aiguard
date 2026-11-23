package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newRetryTestClient(url string) (*Client, *[]time.Duration) {
	var sleeps []time.Duration
	c := NewClient(url)
	c.retryBackoff = 200 * time.Millisecond
	c.jitter = func() float64 { return 0.5 } // 倍率 1.0
	c.sleep = func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }
	return c, &sleeps
}

func batchServer(t *testing.T, item string, single *atomic.Int32, singleBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/check-input/" {
			single.Add(1)
			if singleBody == "" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(singleBody))
			return
		}
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write([]byte("[" + item + "]"))
	}))
}

func TestRetrySkippedForNonSemanticReasons(t *testing.T) {
	for _, reason := range []string{"engine_scan_incomplete", "catalog_regex_timeout", "catalog_budget_exhausted",
		"catalog_candidate_limit", "input_timeout", "input_capacity_overflow", "triage_total_budget_exhausted",
		"engine_scan_incomplete,judge_timeout", "judge_timeout,catalog_regex_timeout", "batch_timeout,engine_scan_incomplete", "batch_failed", ""} {
		t.Run(reason, func(t *testing.T) {
			var single atomic.Int32
			item := `{"request_id":"r","findings":[],"action":"audit","inspection_status":"incomplete","inspection_reason":"` + reason + `"}`
			srv := batchServer(t, item, &single, "")
			defer srv.Close()
			c, sleeps := newRetryTestClient(srv.URL)
			got, err := c.CheckInputBatch(context.Background(), []*CheckInputRequest{{RequestID: "r", Content: "x"}})
			if err != nil || len(got) != 1 || got[0].InspectionStatus != "incomplete" || got[0].InspectionReason != reason {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			if single.Load() != 0 || len(*sleeps) != 0 {
				t.Fatalf("不应重试: single=%d sleeps=%v", single.Load(), *sleeps)
			}
		})
	}
}

func TestRetrySemanticTransientBackoffAndMixedWithCompletedInspection(t *testing.T) {
	for _, reason := range []string{"judge_timeout", "window_timeout", "judge_capacity_deferred", "judge_capacity_overflow", "batch_timeout", "batch_capacity_overflow"} {
		t.Run(reason, func(t *testing.T) {
			var single atomic.Int32
			item := `{"request_id":"r","findings":[],"action":"audit","inspection_status":"completed","semantic_status":"incomplete","semantic_reason":"` + reason + `"}`
			srv := batchServer(t, item, &single, `{"request_id":"r","findings":[],"action":"audit","inspection_status":"completed","semantic_status":"incomplete","semantic_reason":"`+reason+`"}`)
			defer srv.Close()
			c, sleeps := newRetryTestClient(srv.URL)
			got, err := c.CheckInputBatch(context.Background(), []*CheckInputRequest{{RequestID: "r", Content: "x"}})
			if err != nil || got[0].SemanticStatus != "incomplete" {
				t.Fatalf("失败策略输入应保持原样: got=%+v err=%v", got, err)
			}
			if single.Load() != 2 || len(*sleeps) != 2 {
				t.Fatalf("single=%d sleeps=%v", single.Load(), *sleeps)
			}
			if (*sleeps)[0] != 200*time.Millisecond || (*sleeps)[1] != 600*time.Millisecond {
				t.Fatalf("指数退避不符: %v", *sleeps)
			}
		})
	}
}

func TestRetryIncompleteInspectionWithSemanticOnlyReasonRetries(t *testing.T) {
	var single atomic.Int32
	item := `{"request_id":"r","findings":[],"action":"audit","inspection_status":"incomplete","inspection_reason":"judge_timeout"}`
	srv := batchServer(t, item, &single, `{"request_id":"r","findings":[],"action":"allow","inspection_status":"completed"}`)
	defer srv.Close()
	c, _ := newRetryTestClient(srv.URL)
	got, _ := c.CheckInputBatch(context.Background(), []*CheckInputRequest{{RequestID: "r", Content: "x"}})
	if single.Load() != 1 || got[0].InspectionStatus != "completed" || got[0].Action != "allow" {
		t.Fatalf("single=%d got=%+v", single.Load(), got[0])
	}
}

func TestRetryWaitRangeAndJitter(t *testing.T) {
	base := 200 * time.Millisecond
	for attempt, center := range []time.Duration{200 * time.Millisecond, 600 * time.Millisecond} {
		lo := retryWait(base, attempt, func() float64 { return 0 })
		hi := retryWait(base, attempt, func() float64 { return 0.999999 })
		if lo != center/2 || hi < center*149/100 || hi >= center*3/2+time.Microsecond {
			t.Fatalf("attempt=%d lo=%v hi=%v", attempt, lo, hi)
		}
	}
}

func TestRetryRespectsDeadline(t *testing.T) {
	var single atomic.Int32
	item := `{"request_id":"r","findings":[],"action":"audit","inspection_status":"completed","semantic_status":"incomplete","semantic_reason":"judge_timeout"}`
	srv := batchServer(t, item, &single, "")
	defer srv.Close()
	c, sleeps := newRetryTestClient(srv.URL)
	now := time.Now()
	c.now = func() time.Time { return now }
	// 剩余 600ms < 退避 200ms + 最小请求预算 500ms
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(600*time.Millisecond))
	defer cancel()
	// ctx 的真实 deadline 以真实时钟为准，这里 deadline 在 now 之后 600ms
	got, err := c.CheckInputBatch(ctx, []*CheckInputRequest{{RequestID: "r", Content: "x"}})
	if err != nil || got[0].SemanticStatus != "incomplete" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if single.Load() != 0 || len(*sleeps) != 0 {
		t.Fatalf("deadline 不足不应重试: single=%d sleeps=%v", single.Load(), *sleeps)
	}
}

func TestResolveRetryBackoffEnv(t *testing.T) {
	t.Setenv("GATEWAY_SECURITY_RETRY_BACKOFF", "50ms")
	if resolveRetryBackoff() != 50*time.Millisecond {
		t.Fatal("env 未生效")
	}
	for _, bad := range []string{"abc", "-1s", "0"} {
		t.Setenv("GATEWAY_SECURITY_RETRY_BACKOFF", bad)
		if resolveRetryBackoff() != defaultRetryBackoff {
			t.Fatalf("非法值 %q 应回落默认", bad)
		}
	}
}

func TestRetryStatsCountsByReason(t *testing.T) {
	before, _ := GlobalRetryStats.Snapshot()
	var single atomic.Int32
	item := `{"request_id":"r","findings":[],"action":"audit","inspection_status":"incomplete","inspection_reason":"catalog_regex_timeout"}`
	srv := batchServer(t, item, &single, "")
	defer srv.Close()
	c, _ := newRetryTestClient(srv.URL)
	_, _ = c.CheckInputBatch(context.Background(), []*CheckInputRequest{{RequestID: "r", Content: "x"}})
	after, _ := GlobalRetryStats.Snapshot()
	if after["catalog_regex_timeout"] != before["catalog_regex_timeout"]+1 {
		t.Fatalf("计数未增加: %v", after)
	}
}

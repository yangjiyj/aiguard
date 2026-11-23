package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// singleOutcomeServer：batch 全部返回语义超时；单条接口由 single 决定响应。
func singleOutcomeServer(t *testing.T, single func(id string, nth int, w http.ResponseWriter)) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	var calls []string
	count := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/check-input/" {
			var req CheckInputRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			calls = append(calls, req.RequestID)
			count[req.RequestID]++
			nth := count[req.RequestID]
			mu.Unlock()
			single(req.RequestID, nth, w)
			return
		}
		var reqs []CheckInputRequest
		_ = json.NewDecoder(r.Body).Decode(&reqs)
		parts := make([]string, 0, len(reqs))
		for _, q := range reqs {
			parts = append(parts, fmt.Sprintf(`{"request_id":%q,"findings":[],"action":"audit",%s}`, q.RequestID, itemSemanticTimeout))
		}
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write([]byte("[" + strings.Join(parts, ",") + "]"))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func writeSingle(w http.ResponseWriter, id, body string) {
	_, _ = w.Write([]byte(fmt.Sprintf(`{"request_id":%q,"findings":[],"action":"audit",%s}`, id, body)))
}

func TestRetrySingleErrorNotCarriedToNextRound(t *testing.T) {
	srv, calls := singleOutcomeServer(t, func(_ string, _ int, w http.ResponseWriter) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c, sleeps := newRetryTestClient(srv.URL)
	got, err := c.CheckInputBatch(context.Background(), reqs("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || len(*sleeps) != 1 {
		t.Fatalf("出错的单条只应调用 1 次、只睡 1 轮: calls=%v sleeps=%v", *calls, *sleeps)
	}
	if got[0].SemanticStatus != "incomplete" {
		t.Fatalf("应保留原结果: %+v", got[0])
	}
}

func TestRetrySingleNonCompletedNotCarriedToNextRound(t *testing.T) {
	srv, calls := singleOutcomeServer(t, func(id string, _ int, w http.ResponseWriter) {
		writeSingle(w, id, itemNonRetryable)
	})
	c, sleeps := newRetryTestClient(srv.URL)
	got, err := c.CheckInputBatch(context.Background(), reqs("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || len(*sleeps) != 1 {
		t.Fatalf("非 completed 的单条只应调用 1 次: calls=%v sleeps=%v", *calls, *sleeps)
	}
	if got[0].InspectionStatus != "completed" || got[0].SemanticStatus != "incomplete" {
		t.Fatalf("应保留原结果: %+v", got[0])
	}
}

func TestRetrySingleCompletedWithGapGoesNextRound(t *testing.T) {
	srv, calls := singleOutcomeServer(t, func(id string, nth int, w http.ResponseWriter) {
		if nth >= 2 {
			writeSingle(w, id, itemOK)
			return
		}
		writeSingle(w, id, itemSemanticTimeout)
	})
	c, sleeps := newRetryTestClient(srv.URL)
	got, err := c.CheckInputBatch(context.Background(), reqs("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 || len(*sleeps) != 2 {
		t.Fatalf("completed 但仍有缺口应进入第二轮: calls=%v sleeps=%v", *calls, *sleeps)
	}
	if got[0].SemanticStatus == "incomplete" {
		t.Fatalf("第二轮应恢复: %+v", got[0])
	}
}

func TestRetryInRoundDeadlineSkipsRemainingItems(t *testing.T) {
	var mu sync.Mutex
	base := time.Now()
	cur := base
	srv, calls := singleOutcomeServer(t, func(id string, _ int, w http.ResponseWriter) {
		mu.Lock()
		cur = base.Add(500 * time.Millisecond) // 第 1 条耗时后，剩余 300ms < 500ms 预算
		mu.Unlock()
		writeSingle(w, id, itemOK)
	})
	c, sleeps := newRetryTestClient(srv.URL)
	c.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return cur }
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(800*time.Millisecond))
	defer cancel()
	beforeSkip, _ := GlobalRetryStats.Snapshot()
	got, err := c.CheckInputBatch(ctx, reqs("t1", "t2", "t3"))
	if err != nil {
		t.Fatal(err)
	}
	afterSkip, _ := GlobalRetryStats.Snapshot()
	if strings.Join(*calls, ",") != "t1" || len(*sleeps) != 1 {
		t.Fatalf("t2/t3 不应发请求: calls=%v sleeps=%v", *calls, *sleeps)
	}
	if d := afterSkip["judge_timeout"] - beforeSkip["judge_timeout"]; d != 2 {
		t.Fatalf("t2/t3 应各记 1 次 skip: %d", d)
	}
	if got[0].SemanticStatus == "incomplete" || got[1].SemanticStatus != "incomplete" || got[2].SemanticStatus != "incomplete" {
		t.Fatalf("结果不符: %+v %+v %+v", got[0], got[1], got[2])
	}
}

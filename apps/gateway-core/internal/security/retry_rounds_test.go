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

const (
	itemSemanticTimeout = `"inspection_status":"completed","semantic_status":"incomplete","semantic_reason":"judge_timeout"`
	itemNonRetryable    = `"inspection_status":"incomplete","inspection_reason":"engine_scan_incomplete"`
	itemOK              = `"inspection_status":"completed"`
)

// roundsServer：batch 按请求 ID 前缀返回（t=可重试，n=不可重试，其余完成）；
// 单条接口对 recoverOK 为 true 的返回完成，否则仍为语义未完成。
type roundsServer struct {
	*httptest.Server
	mu      sync.Mutex
	singles []string
}

func newRoundsServer(t *testing.T, recoverOK func(id string, nth int) bool) *roundsServer {
	rs := &roundsServer{}
	count := map[string]int{}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/check-input/" {
			var req CheckInputRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			rs.mu.Lock()
			rs.singles = append(rs.singles, req.RequestID)
			count[req.RequestID]++
			nth := count[req.RequestID]
			rs.mu.Unlock()
			body := itemSemanticTimeout
			if recoverOK(req.RequestID, nth) {
				body = itemOK
			}
			_, _ = w.Write([]byte(fmt.Sprintf(`{"request_id":%q,"findings":[],"action":"audit",%s}`, req.RequestID, body)))
			return
		}
		var reqs []CheckInputRequest
		_ = json.NewDecoder(r.Body).Decode(&reqs)
		parts := make([]string, 0, len(reqs))
		for _, q := range reqs {
			body := itemOK
			switch {
			case strings.HasPrefix(q.RequestID, "t"):
				body = itemSemanticTimeout
			case strings.HasPrefix(q.RequestID, "n"):
				body = itemNonRetryable
			}
			parts = append(parts, fmt.Sprintf(`{"request_id":%q,"findings":[],"action":"audit",%s}`, q.RequestID, body))
		}
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write([]byte("[" + strings.Join(parts, ",") + "]"))
	}))
	t.Cleanup(rs.Close)
	return rs
}

func reqs(ids ...string) []*CheckInputRequest {
	out := make([]*CheckInputRequest, 0, len(ids))
	for _, id := range ids {
		out = append(out, &CheckInputRequest{RequestID: id, Content: "x"})
	}
	return out
}

func TestRetryRoundSleepsOncePerRound(t *testing.T) {
	rs := newRoundsServer(t, func(string, int) bool { return true })
	c, sleeps := newRetryTestClient(rs.URL)
	got, err := c.CheckInputBatch(context.Background(), reqs("t1", "t2", "t3", "t4", "t5"))
	if err != nil {
		t.Fatal(err)
	}
	if len(*sleeps) != 1 || (*sleeps)[0] != 200*time.Millisecond {
		t.Fatalf("第一轮应只睡 1 次: %v", *sleeps)
	}
	if len(rs.singles) != 5 {
		t.Fatalf("5 条都应重试: %v", rs.singles)
	}
	for _, g := range got {
		if g.InspectionStatus != "completed" || g.SemanticStatus == "incomplete" {
			t.Fatalf("应已恢复: %+v", g)
		}
	}
}

func TestRetryRoundsTwoRoundsSecondTier(t *testing.T) {
	// 第二次单条调用才恢复：两轮共睡 2 次，第二次为 600ms
	rs := newRoundsServer(t, func(_ string, nth int) bool { return nth >= 2 })
	c, sleeps := newRetryTestClient(rs.URL)
	got, err := c.CheckInputBatch(context.Background(), reqs("t1", "t2", "t3"))
	if err != nil {
		t.Fatal(err)
	}
	if len(*sleeps) != 2 || (*sleeps)[0] != 200*time.Millisecond || (*sleeps)[1] != 600*time.Millisecond {
		t.Fatalf("两轮退避不符: %v", *sleeps)
	}
	if len(rs.singles) != 6 {
		t.Fatalf("应共 6 次单条调用: %v", rs.singles)
	}
	for _, g := range got {
		if g.SemanticStatus == "incomplete" {
			t.Fatalf("第二轮应恢复: %+v", g)
		}
	}
}

func TestRetryRoundSecondRoundOnlyUnrecovered(t *testing.T) {
	// t1 第一轮恢复，t2 第二轮才恢复
	rs := newRoundsServer(t, func(id string, nth int) bool { return id == "t1" || nth >= 2 })
	c, sleeps := newRetryTestClient(rs.URL)
	if _, err := c.CheckInputBatch(context.Background(), reqs("t1", "t2")); err != nil {
		t.Fatal(err)
	}
	if len(*sleeps) != 2 {
		t.Fatalf("sleeps=%v", *sleeps)
	}
	if strings.Join(rs.singles, ",") != "t1,t2,t2" {
		t.Fatalf("第二轮只应重试 t2: %v", rs.singles)
	}
}

func TestRetryRoundDeadlineSkipsAllWithoutSleep(t *testing.T) {
	rs := newRoundsServer(t, func(string, int) bool { return true })
	c, sleeps := newRetryTestClient(rs.URL)
	now := time.Now()
	c.now = func() time.Time { return now }
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(600*time.Millisecond))
	defer cancel()
	before, _ := GlobalRetryStats.Snapshot()
	got, err := c.CheckInputBatch(ctx, reqs("t1", "t2", "t3", "t4", "t5"))
	if err != nil {
		t.Fatal(err)
	}
	after, _ := GlobalRetryStats.Snapshot()
	if len(*sleeps) != 0 || len(rs.singles) != 0 {
		t.Fatalf("不应睡眠/重试: sleeps=%v singles=%v", *sleeps, rs.singles)
	}
	if after["judge_timeout"]-before["judge_timeout"] != 5 {
		t.Fatalf("5 条都应记 skip: before=%v after=%v", before, after)
	}
	for _, g := range got {
		if g.SemanticStatus != "incomplete" {
			t.Fatalf("应保持原结果: %+v", g)
		}
	}
}

func TestRetryRoundMixedOnlyRetriesRetryable(t *testing.T) {
	rs := newRoundsServer(t, func(string, int) bool { return true })
	c, sleeps := newRetryTestClient(rs.URL)
	beforeSkip, beforeRetry := GlobalRetryStats.Snapshot()
	got, err := c.CheckInputBatch(context.Background(), reqs("n1", "t1", "ok", "t2", "n2"))
	if err != nil {
		t.Fatal(err)
	}
	afterSkip, afterRetry := GlobalRetryStats.Snapshot()
	if strings.Join(rs.singles, ",") != "t1,t2" || len(*sleeps) != 1 {
		t.Fatalf("singles=%v sleeps=%v", rs.singles, *sleeps)
	}
	if d := afterSkip["engine_scan_incomplete"] - beforeSkip["engine_scan_incomplete"]; d != 2 {
		t.Fatalf("不可重试条目应各记 1 次 skip: %d", d)
	}
	if d := afterRetry["judge_timeout"] - beforeRetry["judge_timeout"]; d != 2 {
		t.Fatalf("retry 计数应为 2: %d", d)
	}
	if got[0].InspectionStatus != "incomplete" || got[4].InspectionStatus != "incomplete" {
		t.Fatalf("不可重试条目应保持原样")
	}
}

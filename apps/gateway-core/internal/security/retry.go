package security

import (
	"context"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// 批量条目 incomplete 后的单条恢复策略。
//
// 背景：security-engine 单进程受 GIL 限制，CPU 打满时快层（正则/目录检测）按墙钟计的
// 预算会超时。此时立即逐条重试会把整套快层再跑一遍，放大负载。因此：
//   - 只对语义瞬时原因（judge_timeout 等）做「指数退避 + 抖动」重试；
//   - 快层预算类、引擎容量类、未知原因一律不重试，直接交给原有失败策略；
//   - 同一条目含任何非语义瞬时原因（混合）也不重试。
const (
	defaultRetryBackoff = 200 * time.Millisecond
	retryBackoffFactor  = 3
	// 退避之后还需留给一次单条请求的最短时间；不足则不重试。
	minRetryRequestBudget = 500 * time.Millisecond
	maxRetryAttempts      = 2
)

var semanticTransientReasons = map[string]struct{}{
	"judge_timeout":           {},
	"window_timeout":          {},
	"judge_capacity_deferred": {},
	"judge_capacity_overflow": {},
	// batch 调度类：条目在 batch 内因共享截止时间未跑完或未被接纳，没有重复已完成的快层工作，
	// 单条重试自带完整预算。input_timeout/input_capacity_overflow 只出现在单条接口的 503 里
	// （单条已用满自己的预算），batch 条目不会带这些码，故不算同类、不重试。
	"batch_timeout":           {},
	"batch_capacity_overflow": {},
}

// resolveRetryBackoff 读 GATEWAY_SECURITY_RETRY_BACKOFF（Go duration），非法/非正值回落默认。
func resolveRetryBackoff() time.Duration {
	raw := strings.TrimSpace(os.Getenv("GATEWAY_SECURITY_RETRY_BACKOFF"))
	if raw == "" {
		return defaultRetryBackoff
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return defaultRetryBackoff
	}
	return parsed
}

func splitReasons(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func allSemanticTransient(reasons []string) bool {
	for _, r := range reasons {
		if _, ok := semanticTransientReasons[r]; !ok {
			return false
		}
	}
	return true
}

// retryDecision 返回是否值得退避重试，以及（用于计数/日志的）原因标签。
// needsAction=false 表示条目已完整且无语义缺口，调用方无需任何处理。
func retryDecision(r *CheckInputResponse) (retry bool, needsAction bool, reason string) {
	semanticIncomplete := strings.EqualFold(r.SemanticStatus, "incomplete")
	inspectionDone := strings.EqualFold(r.InspectionStatus, "completed")
	if inspectionDone && !semanticIncomplete {
		return false, false, ""
	}
	inspReasons := splitReasons(r.InspectionReason)
	semReasons := splitReasons(r.SemanticReason)
	if !inspectionDone {
		// 整体检测未完成：只有当全部原因都是语义瞬时原因时才重试，其余（快层/容量/未知）一律不重试。
		reasons := inspReasons
		if len(reasons) == 0 {
			return false, true, "unknown"
		}
		return allSemanticTransient(reasons), true, strings.Join(reasons, ",")
	}
	// 检测已完成，仅语义缺口。
	if len(semReasons) == 0 {
		return false, true, "unknown"
	}
	return allSemanticTransient(semReasons) && allSemanticTransient(inspReasons), true, strings.Join(semReasons, ",")
}

// retryWait 计算第 attempt（从 0 起）次重试前的退避：base*factor^attempt，乘以 [0.5,1.5) 抖动。
func retryWait(base time.Duration, attempt int, jitter func() float64) time.Duration {
	d := base
	for i := 0; i < attempt; i++ {
		d *= retryBackoffFactor
	}
	return time.Duration(float64(d) * (0.5 + jitter()))
}

// canRetryWithin 剩余时间不足「退避 + 一次合理请求」时返回 false。无 deadline 视为足够。
func canRetryWithin(ctx context.Context, now time.Time, wait time.Duration) bool {
	dl, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return dl.Sub(now) >= wait+minRetryRequestBudget
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// RetryStats 按原因统计跳过/退避重试次数（进程内累计）。
type RetryStats struct {
	mu      sync.Mutex
	skipped map[string]int64
	retried map[string]int64
}

func (s *RetryStats) add(kind, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := &s.skipped
	if kind == "retry" {
		m = &s.retried
	}
	if *m == nil {
		*m = map[string]int64{}
	}
	(*m)[reason]++
}

// Snapshot 返回累计计数副本。
func (s *RetryStats) Snapshot() (skipped, retried map[string]int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	skipped, retried = map[string]int64{}, map[string]int64{}
	for k, v := range s.skipped {
		skipped[k] = v
	}
	for k, v := range s.retried {
		retried[k] = v
	}
	return
}

// GlobalRetryStats 为进程级计数器。
var GlobalRetryStats = &RetryStats{}

func (c *Client) recordRetry(kind, reason, cause string, attempt int, wait time.Duration) {
	GlobalRetryStats.add(kind, reason)
	// 只记录原因码与时长，不含请求内容。
	log.Printf("security_batch_retry kind=%s reason=%s cause=%s attempt=%d wait_ms=%d", kind, reason, cause, attempt, wait.Milliseconds())
}

// recoverIncompleteItems 按「轮」对 batch 中未完成的条目做单条恢复。
//
// 每轮先收集全部可重试条目，整轮只做一次退避睡眠，再对它们串行单条重试
// （串行避免再次压垮引擎）。按条目逐个睡眠会让 N 个尾部条目累计等待 N×退避，
// 后面的条目因剩余时间不足被跳过，fail-open 下等于未检测完就放行。
// 恢复受轮数和调用方 deadline 双重约束；已完成的精确窗口由引擎复用。
func (c *Client) recoverIncompleteItems(ctx context.Context, requests []*CheckInputRequest, results []*CheckInputResponse) {
	pending := make([]int, len(results))
	for i := range results {
		pending[i] = i
	}
	type candidate struct {
		idx    int
		reason string
	}
	for attempt := 0; attempt < maxRetryAttempts && len(pending) > 0 && ctx.Err() == nil; attempt++ {
		var cands []candidate
		for _, i := range pending {
			retry, needsAction, reason := retryDecision(results[i])
			if !needsAction {
				continue
			}
			if !retry {
				// 快层预算/引擎容量/未知/混合原因：不重跑整套检测，交给原失败策略。
				c.recordRetry("skip", reason, "non_semantic_transient", attempt, 0)
				continue
			}
			cands = append(cands, candidate{i, reason})
		}
		if len(cands) == 0 {
			return
		}
		wait := retryWait(c.retryBackoff, attempt, c.jitter)
		if !canRetryWithin(ctx, c.now(), wait) {
			for _, cd := range cands {
				c.recordRetry("skip", cd.reason, "deadline", attempt, wait)
			}
			return
		}
		if err := c.sleep(ctx, wait); err != nil {
			return
		}
		pending = pending[:0]
		for _, cd := range cands {
			if ctx.Err() != nil {
				return
			}
			// 轮内串行，逐条检查剩余时间；不足则只记 skip，不发请求。
			if !canRetryWithin(ctx, c.now(), 0) {
				c.recordRetry("skip", cd.reason, "deadline", attempt, 0)
				continue
			}
			c.recordRetry("retry", cd.reason, "semantic_transient", attempt, wait)
			recovered, err := c.CheckInput(ctx, requests[cd.idx])
			if err == nil && recovered != nil && strings.EqualFold(recovered.InspectionStatus, "completed") {
				// A fresh complete inspection retains its own explicit semantic gap;
				// successful HTTP transport alone never clears the coverage status.
				results[cd.idx] = recovered
				// 仅拿到 completed 结果的条目进入下一轮，由 retryDecision 判断是否仍需重试；
				// 出错/非 completed 的条目保留原结果，不再重试。
				pending = append(pending, cd.idx)
			}
		}
	}
}

package agentguard

import (
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// ToolFailureLoopReason 是失败循环命中的统一 reason 值，检测与审计共用。
const ToolFailureLoopReason = protection.ReasonToolFailureLoop

// ToolFailureEvent 记一次失败的工具执行。
type ToolFailureEvent struct {
	ActorKey string
	ToolName string
	Target   string
	Now      time.Time
}

// ToolFailureWindow 只记录失败事件：窗口内同 actor+tool 的不同工具调用失败次数达到阈值，
// 即视为陷入工具调用失败循环（智能体反复重试同一失败调用）。进程内滑窗，重启即清。
//
// 同一个工具调用编号只计一次：Claude Code 等客户端每轮都会重发完整历史，历史里早已失败的
// 工具结果不能被重复计数（客户现场 2.9.16：82 个请求累计出 375 次“失败”）。
type ToolFailureWindow struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	events    map[string][]toolFailureStamp
	// reported 是每个键最近一次报告循环的时间：本窗口内报告过就不再报。
	reported map[string]time.Time
	// records 计记录次数，每 toolFailureSweepEvery 次按键清扫一遍 events、reported。
	records int
}

// toolFailureSweepEvery：每记录这么多次失败，清扫一遍过了去重记忆期的键（不同 actor/工具的键
// 不再出现时，靠它回收）。
const toolFailureSweepEvery = 256

// toolFailureDedupeRetention：带编号的失败记录保留这么久只用于去重，计数只算窗口内的。
// 长会话里客户端会重发早已失败的历史，去重记忆不能随计数窗口一起过期。
const toolFailureDedupeRetention = 24 * time.Hour

type toolFailureStamp struct {
	at     time.Time
	target string
}

func NewToolFailureWindow(window time.Duration, threshold int) *ToolFailureWindow {
	// 缺省取防护项 agent.tool_failure_loop 的注册表默认值。
	if window <= 0 {
		window = time.Duration(protection.DefaultIntParam(protection.KeyToolFailureLoop, protection.ParamWindowSeconds)) * time.Second
	}
	if threshold <= 0 {
		threshold = protection.DefaultIntParam(protection.KeyToolFailureLoop, protection.ParamThreshold)
	}
	return &ToolFailureWindow{window: window, threshold: threshold, events: map[string][]toolFailureStamp{}, reported: map[string]time.Time{}}
}

// RecordFailure 记录一次失败，返回窗口内累计失败次数，以及这一次是否该报告循环：计数达到或超过
// 阈值，且本窗口内还没报告过（阈值调低到已有次数以下时也报告一次）。已记录过的工具调用编号
// （Target）不再累加（去重记忆保留 toolFailureDedupeRetention）。
// 约定：Target 在 actor+tool 范围内必须唯一，由调用方保证；空 Target 每次都计数，
// 调用方需自行保证不会重放。
func (w *ToolFailureWindow) RecordFailure(event ToolFailureEvent) (int, bool) {
	if w == nil {
		return 0, false
	}
	return w.RecordFailureWithin(event, w.window, w.threshold)
}

// RecordFailureWithin 同 RecordFailure，窗口和阈值取调用方传入的租户配置（防护项
// agent.tool_failure_loop）；不大于 0 时取构造时的默认值。窗口最长与去重记忆一致（24 小时）。
func (w *ToolFailureWindow) RecordFailureWithin(event ToolFailureEvent, window time.Duration, threshold int) (int, bool) {
	if w == nil || strings.TrimSpace(event.ActorKey) == "" || strings.TrimSpace(event.ToolName) == "" {
		return 0, false
	}
	window, threshold = w.limits(window, threshold)
	now := event.Now
	if now.IsZero() {
		now = time.Now()
	}
	target := strings.TrimSpace(event.Target)
	key := event.ActorKey + ":" + event.ToolName
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records++
	if w.records%toolFailureSweepEvery == 0 {
		w.sweepLocked(now)
	}
	cutoff := now.Add(-window)
	retain := now.Add(-toolFailureDedupeRetention)
	kept := w.events[key][:0]
	seen, inWindow := false, 0
	for _, stamp := range w.events[key] {
		live := stamp.at.After(cutoff)
		if !live && (stamp.target == "" || !stamp.at.After(retain)) {
			continue
		}
		if target != "" && stamp.target == target {
			seen = true
		}
		if live {
			inWindow++
		}
		kept = append(kept, stamp)
	}
	if !seen {
		kept = append(kept, toolFailureStamp{at: now, target: target})
		inWindow++
	}
	w.events[key] = kept
	if last, ok := w.reported[key]; ok && !last.After(cutoff) {
		delete(w.reported, key)
	}
	if seen || inWindow < threshold {
		return inWindow, false
	}
	if _, reportedInWindow := w.reported[key]; reportedInWindow {
		return inWindow, false
	}
	if w.reported == nil {
		w.reported = map[string]time.Time{}
	}
	w.reported[key] = now
	return inWindow, true
}

// sweepLocked 按键清扫：去掉过了去重记忆期（窗口最长也不超过它）的时间戳，空了的键和过期的报告
// 记录整个删掉。
func (w *ToolFailureWindow) sweepLocked(now time.Time) {
	retain := now.Add(-toolFailureDedupeRetention)
	for key, stamps := range w.events {
		kept := stamps[:0]
		for _, stamp := range stamps {
			if stamp.at.After(retain) {
				kept = append(kept, stamp)
			}
		}
		if len(kept) == 0 {
			delete(w.events, key)
		} else {
			w.events[key] = kept
		}
	}
	for key, at := range w.reported {
		if !at.After(retain) {
			delete(w.reported, key)
		}
	}
}

func (w *ToolFailureWindow) limits(window time.Duration, threshold int) (time.Duration, int) {
	if window <= 0 {
		window = w.window
	}
	if window > toolFailureDedupeRetention {
		window = toolFailureDedupeRetention
	}
	if threshold <= 0 {
		threshold = w.threshold
	}
	return window, threshold
}

// Count 返回当前窗口内失败次数（不追加事件），供执行侧判定是否升级处置。
func (w *ToolFailureWindow) Count(actorKey, toolName string, now time.Time) int {
	if w == nil {
		return 0
	}
	return w.CountWithin(actorKey, toolName, now, w.window)
}

// CountWithin 同 Count，窗口取调用方传入的租户配置；不大于 0 时取默认值。
func (w *ToolFailureWindow) CountWithin(actorKey, toolName string, now time.Time, window time.Duration) int {
	if w == nil || strings.TrimSpace(actorKey) == "" || strings.TrimSpace(toolName) == "" {
		return 0
	}
	window, _ = w.limits(window, 0)
	if now.IsZero() {
		now = time.Now()
	}
	key := actorKey + ":" + toolName
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := now.Add(-window)
	count := 0
	for _, stamp := range w.events[key] {
		if stamp.at.After(cutoff) {
			count++
		}
	}
	return count
}

// Threshold 返回配置的循环阈值。
func (w *ToolFailureWindow) Threshold() int {
	if w == nil {
		return 0
	}
	return w.threshold
}

// toolResultFailureMarkers 是工具结果文本中判定失败的保守信号：
// 显式 is_error 标记、Python 回溯、结构化 error/status 字段、行首 Error/Exception 前缀。
// 只收高置信模式，宁可漏判也不把正常输出当失败。
var toolResultFailureMarkers = []string{
	`"is_error": true`,
	`"is_error":true`,
	"traceback (most recent call last)",
	`"status": "error"`,
	`"status":"error"`,
	`"status": "failed"`,
	`"status":"failed"`,
	`"success": false`,
	`"success":false`,
	`"error": "`,
	`"error":"`,
	`"error": {`,
	`"error":{`,
}

// ToolResultLooksLikeFailure 依据结果文本保守判定一次工具执行是否失败。
// 输入应为工具结果消息的纯文本（messageText 已提取）。
func ToolResultLooksLikeFailure(content string) bool {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	for _, marker := range toolResultFailureMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, line := range strings.Split(lower, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "error:") || strings.HasPrefix(line, "exception:") {
			return true
		}
	}
	return false
}

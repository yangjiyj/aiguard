package agentguard

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

type BehaviorKind string

const (
	BehaviorFileRead       BehaviorKind = "file_read"
	BehaviorFileDelete     BehaviorKind = "file_delete"
	BehaviorNetworkEgress  BehaviorKind = "network_egress"
	BehaviorCommandExecute BehaviorKind = "command_execute"
)

type BehaviorThresholds struct {
	FileReadBurst       int
	FileDeleteBurst     int
	NetworkEgressBurst  int
	CommandExecuteBurst int
	// Window 是突发计数窗口（防护项 agent.burst 的 window_seconds）；0 取窗口构造时的默认值。
	Window time.Duration
	// SensitiveReadEgressWindow enables the cross-step sequence rule (W5 5.5):
	// a network egress within this window after the same actor read a
	// sensitive / restricted file needs confirmation. Zero disables it.
	SensitiveReadEgressWindow time.Duration
}

type BehaviorEvent struct {
	ActorKey string
	Kind     BehaviorKind
	Target   string
	Now      time.Time
	// Sensitive marks a read (file tool or shell command) that touched a
	// sensitive or restricted target; it arms the sensitive-read -> egress
	// sequence rule for this actor.
	Sensitive bool
	// Egress marks an outbound transfer that is not a network tool, e.g. a
	// shell command running curl/wget/scp. Network tools are always egress.
	Egress bool
	// SequenceOnly 只布防“读敏感文件后外发”的序列规则，不计入突发（没有突发类别、只因命中敏感
	// 目标才记下的调用，2.9.21 不把它算成读文件突发）。
	SequenceOnly bool
}

const (
	// DefaultBehaviorMaxKeys bounds the number of tracked actor/kind keys
	// (and armed sensitive-read actors) so memory stays bounded (W5 5.4).
	DefaultBehaviorMaxKeys = 50_000
	// behaviorSweepEvery triggers a full expiry sweep every N records.
	behaviorSweepEvery = 1024
	// maxSensitiveReadEgressWindow caps the sequence window so an armed
	// actor never lives forever.
	maxSensitiveReadEgressWindow = 24 * time.Hour

	behaviorReasonSensitiveReadEgress = "behavior_sensitive_read_then_egress"
	// behaviorBurstReason 是防护项 agent.burst 的原因码：突发只记命中，动作按租户配置。
	behaviorBurstReason = protection.ReasonBehaviorBurst
	// maxBehaviorBurstWindow 与注册表 agent.burst.window_seconds 的上限一致。
	maxBehaviorBurstWindow = time.Hour
	// burstStampsWithoutThreshold 是没配突发阈值的调用类别每个键保留的时间戳条数：与最宽松预设的最大
	// 阈值（200）一致，在注册表次数参数上限（1000）之内；之后配上阈值时最近的调用照样计数。
	burstStampsWithoutThreshold = 200
)

type BehaviorWindow struct {
	mu         sync.Mutex
	window     time.Duration
	thresholds BehaviorThresholds
	// events 每个键只留最近 threshold 条时间戳（没配阈值时 burstStampsWithoutThreshold 条）。
	events map[string][]time.Time
	// windows 是每个键最近一次按当前配置算出的突发窗口：清扫按它算，配置调短后不再被旧的长窗口拖住。
	windows map[string]time.Duration
	// sensitiveReads: actor -> time of the latest sensitive read (W5 5.5).
	sensitiveReads map[string]time.Time
	maxKeys        int
	records        int
	// now 只给测试注入时钟；为空取 time.Now。
	now func() time.Time
}

func NewBehaviorWindow(window time.Duration, thresholds BehaviorThresholds) *BehaviorWindow {
	if window <= 0 {
		window = 10 * time.Second
	}
	return &BehaviorWindow{
		window: window, thresholds: thresholds,
		events: map[string][]time.Time{}, windows: map[string]time.Duration{}, sensitiveReads: map[string]time.Time{},
		maxKeys: DefaultBehaviorMaxKeys,
	}
}

// Thresholds 返回窗口构造时的默认阈值；窗口为空时返回零值（不判突发）。
func (w *BehaviorWindow) Thresholds() BehaviorThresholds {
	if w == nil {
		return BehaviorThresholds{}
	}
	return w.thresholds
}

// SetMaxKeys overrides the key cap (tests / tuning). Values <= 0 keep the default.
func (w *BehaviorWindow) SetMaxKeys(max int) {
	if w == nil || max <= 0 {
		return
	}
	w.mu.Lock()
	w.maxKeys = max
	w.mu.Unlock()
}

// TrackedKeys reports how many burst keys and armed sequence actors are held.
func (w *BehaviorWindow) TrackedKeys() (burstKeys, sequenceActors int) {
	if w == nil {
		return 0, 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.events), len(w.sensitiveReads)
}

func (w *BehaviorWindow) Record(event BehaviorEvent) Decision {
	if w == nil {
		return Decision{RawDecision: DecisionAllow, Reason: "behavior_noop", RiskLevel: "low", Confidence: 0.5}
	}
	return w.RecordWithThresholds(event, w.thresholds)
}

// RecordWithThresholds 用调用方注入的阈值（来自租户基线 EffectivePolicy.Behavior）判定突发，
// 而非窗口构造时硬编码的默认阈值——让“按租户配置的行为基线”真正生效。窗口本身仍只承载运行时
// 滑动事件计数（进程内、重启即清，本就该清）；基线阈值随每次调用从配置注入。
func (w *BehaviorWindow) RecordWithThresholds(event BehaviorEvent, thresholds BehaviorThresholds) Decision {
	if w == nil || strings.TrimSpace(event.ActorKey) == "" || event.Kind == "" {
		return Decision{RawDecision: DecisionAllow, Reason: "behavior_noop", RiskLevel: "low", Confidence: 0.5}
	}
	now := event.Now
	if now.IsZero() {
		now = w.clock()
	}
	sequenceWindow := thresholds.SensitiveReadEgressWindow
	if sequenceWindow > maxSensitiveReadEgressWindow {
		sequenceWindow = maxSensitiveReadEgressWindow
	}
	key := event.ActorKey + ":" + string(event.Kind)
	window := w.window
	if thresholds.Window > 0 {
		window = min(thresholds.Window, maxBehaviorBurstWindow)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records++
	if w.records%behaviorSweepEvery == 0 {
		w.sweepLocked(now)
	}
	cutoff := now.Add(-window)
	kept := w.events[key][:0]
	for _, ts := range w.events[key] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if !event.SequenceOnly {
		kept = append(kept, now)
	}
	threshold := thresholds.thresholdFor(event.Kind)
	limit := threshold
	if limit <= 0 {
		limit = burstStampsWithoutThreshold
	}
	if len(kept) > limit {
		kept = kept[:copy(kept, kept[len(kept)-limit:])]
	}
	if len(kept) == 0 {
		delete(w.events, key)
		delete(w.windows, key)
	} else {
		w.events[key] = kept
		w.windows[key] = window
	}
	isEgress := event.Kind == BehaviorNetworkEgress || event.Egress
	if event.Sensitive && !isEgress && sequenceWindow > 0 {
		w.sensitiveReads[event.ActorKey] = now
	}
	w.enforceCapLocked(now)

	burst := Decision{RawDecision: DecisionAllow, Reason: "behavior_under_threshold", RiskLevel: "low", Confidence: 0.55}
	if !event.SequenceOnly && threshold > 0 && len(kept) >= threshold {
		// 防护项 agent.burst 的命中：动作（含确认、阻断）与例外都按租户配置统一处理。目标只用于
		// 例外比对，不进命中摘要（命令类目标可能带参数原文），证据里是脱敏值。
		burst = protectionFindingFor(ProtectionHit{
			Reason: behaviorBurstReason, RiskLevel: "high", Confidence: 0.75, MatchTarget: event.Target,
			Subtype: string(event.Kind),
		}, []Evidence{sanitizedEvidence(string(event.Kind)+"_burst", "behavior", "target", event.Target)})
	}
	if isEgress && sequenceWindow > 0 {
		if readAt, ok := w.sensitiveReads[event.ActorKey]; ok {
			if now.Sub(readAt) <= sequenceWindow && !readAt.After(now) {
				sequence := Decision{
					RawDecision: DecisionConfirm,
					Reason:      behaviorReasonSensitiveReadEgress,
					RiskLevel:   "high",
					Confidence:  0.8,
					// The sequence rule only exists when an administrator
					// enabled it, so its verdict is a configured action.
					ConfiguredEnforcement: true,
					Evidence: []Evidence{sanitizedEvidence(
						behaviorReasonSensitiveReadEgress,
						"behavior",
						"target",
						event.Target,
					)},
				}
				return mergeAnalyzerDecision(burst, sequence)
			}
			delete(w.sensitiveReads, event.ActorKey)
		}
	}
	return burst
}

func (w *BehaviorWindow) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

// sweepLocked drops burst keys with no timestamp inside the window currently
// configured for that key and sequence entries older than the maximum sequence window.
func (w *BehaviorWindow) sweepLocked(now time.Time) {
	for key, stamps := range w.events {
		window := w.windows[key]
		if window <= 0 {
			window = w.window
		}
		if len(stamps) == 0 || !stamps[len(stamps)-1].After(now.Add(-window)) {
			delete(w.events, key)
			delete(w.windows, key)
		}
	}
	sequenceCutoff := now.Add(-maxSensitiveReadEgressWindow)
	for actor, readAt := range w.sensitiveReads {
		if !readAt.After(sequenceCutoff) {
			delete(w.sensitiveReads, actor)
		}
	}
}

// enforceCapLocked keeps both maps under maxKeys: first an expiry sweep,
// then oldest-first eviction down to 90% of the cap so the O(n) work is
// amortised instead of repeated on every call.
func (w *BehaviorWindow) enforceCapLocked(now time.Time) {
	max := w.maxKeys
	if max <= 0 {
		max = DefaultBehaviorMaxKeys
	}
	if len(w.events) <= max && len(w.sensitiveReads) <= max {
		return
	}
	w.sweepLocked(now)
	target := max - max/10
	if target < 1 {
		target = 1
	}
	if len(w.events) > max {
		type entry struct {
			key  string
			last time.Time
		}
		entries := make([]entry, 0, len(w.events))
		for key, stamps := range w.events {
			var last time.Time
			if len(stamps) > 0 {
				last = stamps[len(stamps)-1]
			}
			entries = append(entries, entry{key, last})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].last.Before(entries[j].last) })
		for _, e := range entries[:len(entries)-target] {
			delete(w.events, e.key)
			delete(w.windows, e.key)
		}
	}
	if len(w.sensitiveReads) > max {
		type entry struct {
			actor string
			at    time.Time
		}
		entries := make([]entry, 0, len(w.sensitiveReads))
		for actor, at := range w.sensitiveReads {
			entries = append(entries, entry{actor, at})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })
		for _, e := range entries[:len(entries)-target] {
			delete(w.sensitiveReads, e.actor)
		}
	}
}

func (t BehaviorThresholds) thresholdFor(kind BehaviorKind) int {
	switch kind {
	case BehaviorFileRead:
		return t.FileReadBurst
	case BehaviorFileDelete:
		return t.FileDeleteBurst
	case BehaviorNetworkEgress:
		return t.NetworkEgressBurst
	case BehaviorCommandExecute:
		return t.CommandExecuteBurst
	default:
		return 0
	}
}

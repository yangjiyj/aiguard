// Package filereference 统一网关和独立代理对“只带文件 id 的附件”的处置（2.9.22 任务 4.2）。
//
// 两处都先向安全引擎查该文件引用的检测结论，再按租户文件策略
// （content_file_policy_json）里的两项处置决定放行、告警放行或阻断：
//   - unverified_file_reference_action：没有检测记录或检测未完成；
//   - file_reference_lookup_failure_action：检测结论查询失败。
//
// 缺省都是告警放行（设计 D2）。检测结论本身为阻断时照拦（那是策略算出来的结论）。
package filereference

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// 处置档位，与控制面文件策略字段取值一致。
const (
	Allow      = "allow"
	AlertAllow = "alert_allow"
	Block      = "block"
)

// 判定原因，写进拦截或告警记录。
const (
	ReasonVerdictBlock = "file_verdict_block"
	ReasonPending      = "file_verdict_pending"
	ReasonNotFound     = "file_verdict_not_found"
	ReasonLookupFailed = "file_verdict_lookup_failed"
)

const settingKey = "content_file_policy_json"

// SettingKey 与 control-plane contentFilePolicySettingKeyForTenant 同算法。
func SettingKey(tenantID string) string {
	if tenantID == "" || tenantID == "tenant_default" {
		return settingKey
	}
	sum := sha256.Sum256([]byte(tenantID))
	return settingKey + ":" + hex.EncodeToString(sum[:])
}

// Policy 是文件策略里与文件引用有关的两项处置。
type Policy struct {
	Unverified    string
	LookupFailure string
}

// DefaultPolicy 两项都告警放行。
func DefaultPolicy() Policy {
	return Policy{Unverified: AlertAllow, LookupFailure: AlertAllow}
}

func validAction(value string) bool {
	return value == Allow || value == AlertAllow || value == Block
}

// ParsePolicy 从文件策略 JSON 取两项处置；缺字段、非法值或整份解析失败都按缺省。
func ParsePolicy(raw string) Policy {
	policy := DefaultPolicy()
	var decoded struct {
		Unverified    string `json:"unverified_file_reference_action"`
		LookupFailure string `json:"file_reference_lookup_failure_action"`
	}
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &decoded) != nil {
		return policy
	}
	if validAction(decoded.Unverified) {
		policy.Unverified = decoded.Unverified
	}
	if validAction(decoded.LookupFailure) {
		policy.LookupFailure = decoded.LookupFailure
	}
	return policy
}

// Outcome 是一个文件引用的处置。Action 为 allow 时 Reason 为空。
type Outcome struct {
	Action  string
	Reason  string
	Message string
	// ExceptionID 非空表示命中了内容例外：不拦不告警，只记录（见 WithException）。
	ExceptionID string
	// exceptionChecked 表示本次请求里已经核对过内容例外（含核对失败），不再重复核对。
	exceptionChecked bool
}

// Decide 按检测结论状态（allow / block / pending / not_found）或查询错误给出处置。
func Decide(status string, lookupErr error, policy Policy) Outcome {
	if !validAction(policy.Unverified) || !validAction(policy.LookupFailure) {
		policy = DefaultPolicy()
	}
	if lookupErr != nil {
		return Outcome{Action: policy.LookupFailure, Reason: ReasonLookupFailed, Message: "引用文件的安全检测结果查询失败"}
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "allow":
		return Outcome{Action: Allow}
	case "block":
		return Outcome{Action: Block, Reason: ReasonVerdictBlock, Message: "引用的文件已被安全检测判定为阻断"}
	case "pending":
		return Outcome{Action: policy.Unverified, Reason: ReasonPending, Message: "引用的文件安全检测尚未完成"}
	default:
		return Outcome{Action: policy.Unverified, Reason: ReasonNotFound, Message: "引用的文件没有安全检测记录"}
	}
}

// Finding 是一个处置写进拦截或告警记录的命中形态，网关和独立代理共用。
type Finding struct {
	Category string
	RuleID   string
	RuleName string
	Severity string
	// Action 是命中动作：block、alert，命中内容例外时为 audit（只记录）。
	Action string
	// ExceptionID 是命中的内容例外编号；告警桥据此不提升告警。
	ExceptionID string
}

var findingShapes = map[string]Finding{
	ReasonVerdictBlock: {Category: "file_id_verdict_block", RuleID: "file-id-verdict-block", RuleName: "文件引用安全判决"},
	ReasonPending:      {Category: "file_id_unverified", RuleID: "file-id-unverified", RuleName: "未经扫描的文件引用"},
	ReasonNotFound:     {Category: "file_id_unverified", RuleID: "file-id-unverified", RuleName: "未经扫描的文件引用"},
	ReasonLookupFailed: {Category: "file_id_lookup_failed", RuleID: "file-id-lookup-failed", RuleName: "文件引用查询失败"},
}

// Finding 返回该处置的命中形态；放行没有命中，返回零值。
func (o Outcome) Finding() Finding {
	if o.Action == Allow || o.Action == "" {
		return Finding{}
	}
	shape, ok := findingShapes[o.Reason]
	if !ok {
		shape = findingShapes[ReasonNotFound]
	}
	shape.Severity = "high"
	shape.Action = "alert"
	if o.Action == Block {
		shape.Action = "block"
	}
	if o.ExceptionID != "" {
		shape.Action = "audit"
		shape.ExceptionID = o.ExceptionID
	}
	return shape
}

// Blocks 报告该处置是否拦截请求：动作为 block 且没有命中内容例外。
func (o Outcome) Blocks() bool {
	return o.Action == Block && o.ExceptionID == ""
}

// ExceptionEligible 报告该处置的命中是否先过内容例外：只有未经扫描的文件引用（没有检测记录或检测
// 未完成，file-id-unverified）且处置不是放行。查询失败（file-id-lookup-failed）是故障类，检测结论
// 阻断是引擎已按策略和例外算出的结论，都不过例外。
func (o Outcome) ExceptionEligible() bool {
	return o.Action != Allow && o.Action != "" && (o.Reason == ReasonPending || o.Reason == ReasonNotFound)
}

// NeedsExceptionCheck 报告该处置是否还要核对内容例外：可过例外且本次请求里还没核对过。
func (o Outcome) NeedsExceptionCheck() bool {
	return o.ExceptionEligible() && !o.exceptionChecked
}

// WithException 返回命中内容例外后的处置：不拦不告警，只留一条带例外编号的记录。
func (o Outcome) WithException(exceptionID string) Outcome {
	o.ExceptionID = exceptionID
	return o
}

// ExceptionProbe 返回送安全引擎 /apply-context/ 过内容例外的原始命中（引擎 SecurityFinding 形态，
// 字段受引擎严格校验）。例外按 rule_ref（rule_id）匹配，口径与引擎文件类命中一致。
func (o Outcome) ExceptionProbe() map[string]any {
	f := o.WithException("").Finding()
	return map[string]any{
		"type": "file", "category": f.Category, "severity": f.Severity, "rule_id": f.RuleID,
		"rule_name": f.RuleName, "rule_type": "file_reference", "action": f.Action,
		"matched_text_preview": o.Message, "redacted_evidence": o.Message, "evidence_reason": o.Message,
		"matched_location": "file_reference",
	}
}

// Loader 按键读 system_settings；found=false 表示库里没有该键。
type Loader func(ctx context.Context, key string) (value string, found bool, err error)

// DefaultLoadTimeout 是读取一次租户文件策略的上限。
const DefaultLoadTimeout = 2 * time.Second

// FailureRetryAfter 是读取超时或 panic 后的短缓存：期间按上次值或缺省，不让每个请求都卡在读库上，
// 过了这段时间再读。
const FailureRetryAfter = 5 * time.Second

type cachedPolicy struct {
	policy    Policy
	expiresAt time.Time
}

type inflightLoad struct {
	done   chan struct{}
	policy Policy
}

// CachedReader 按租户读文件引用处置，带 TTL。
//
// 读取与请求生命周期脱钩（客户端断开不会让读取失败），只受 DefaultLoadTimeout 约束；
// 同一租户的并发读取合并成一次。读库报错时保留上次值（从未读到取缺省）并按 TTL 缓存；
// 读取超时或 panic 只短缓存 FailureRetryAfter（5 秒）后重读。
type CachedReader struct {
	load    Loader
	ttl     time.Duration
	timeout time.Duration

	mu       sync.Mutex
	cache    map[string]cachedPolicy
	inflight map[string]*inflightLoad
	now      func() time.Time
}

func NewCachedReader(load Loader, ttl time.Duration) *CachedReader {
	return &CachedReader{load: load, ttl: ttl, timeout: DefaultLoadTimeout, cache: map[string]cachedPolicy{}, inflight: map[string]*inflightLoad{}, now: time.Now}
}

func (r *CachedReader) Policy(ctx context.Context, tenantID string) Policy {
	if r == nil || r.load == nil {
		return DefaultPolicy()
	}
	r.mu.Lock()
	cached, ok := r.cache[tenantID]
	if ok && r.clock().Before(cached.expiresAt) {
		r.mu.Unlock()
		return cached.policy
	}
	if call, loading := r.inflight[tenantID]; loading {
		r.mu.Unlock()
		select {
		case <-call.done:
			return call.policy
		case <-ctx.Done():
			if ok {
				return cached.policy
			}
			return DefaultPolicy()
		}
	}
	call := &inflightLoad{done: make(chan struct{})}
	r.inflight[tenantID] = call
	r.mu.Unlock()

	fallback := DefaultPolicy()
	if ok {
		fallback = cached.policy
	}
	policy, ttl := r.loadPolicy(ctx, tenantID, fallback)

	r.mu.Lock()
	r.cache[tenantID] = cachedPolicy{policy: policy, expiresAt: r.clock().Add(ttl)}
	delete(r.inflight, tenantID)
	r.mu.Unlock()
	call.policy = policy
	close(call.done)
	return policy
}

// loadPolicy 读一次并给出缓存时长。读库报错保留 fallback（上次值或缺省）按 TTL 缓存；读取超时或
// panic 保留 fallback 只短缓存 FailureRetryAfter。panic 在这里收住，调用方照常清掉在途占位。
func (r *CachedReader) loadPolicy(ctx context.Context, tenantID string, fallback Policy) (policy Policy, ttl time.Duration) {
	policy, ttl = fallback, FailureRetryAfter
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("file reference policy load panicked (tenant=%s): %v\n%s", tenantID, recovered, debug.Stack())
			policy, ttl = fallback, FailureRetryAfter
		}
	}()
	loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timeout)
	defer cancel()
	raw, found, err := r.load(loadCtx, SettingKey(tenantID))
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return fallback, FailureRetryAfter
	case err != nil:
		return fallback, r.ttl
	case found:
		return ParsePolicy(raw), r.ttl
	default:
		return DefaultPolicy(), r.ttl
	}
}

func (r *CachedReader) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// ExceptionCheckTimeout 是一次请求里核对内容例外的引擎调用上限；超时或调不通按文件策略原处置。
const ExceptionCheckTimeout = 2 * time.Second

// ExceptionResult 是引擎 /apply-context/ 回给的一条命中里与例外有关的字段。
type ExceptionResult struct {
	RuleID          string
	AttachmentIndex *int
	ExceptionID     string
}

// ExceptionBatch 收集一次请求里还要核对内容例外的文件引用处置，合成一次引擎调用。送引擎的命中用
// attachment_index 带批次内序号，结果按序号对回。零值可用。
type ExceptionBatch struct {
	outcomes []*Outcome
}

// Add 收进一条处置；不需要核对（不可过例外或已核对）的忽略。
func (b *ExceptionBatch) Add(o *Outcome) {
	if o != nil && o.NeedsExceptionCheck() {
		b.outcomes = append(b.outcomes, o)
	}
}

// Len 是批次里的处置数。
func (b *ExceptionBatch) Len() int {
	return len(b.outcomes)
}

// Blocking 报告批次里是否有按 block 处置的：有则必须在决定拦不拦之前核对。
func (b *ExceptionBatch) Blocking() bool {
	for _, o := range b.outcomes {
		if o.Action == Block {
			return true
		}
	}
	return false
}

// Probes 返回送引擎的原始命中，attachment_index 为批次内序号。
func (b *ExceptionBatch) Probes() []map[string]any {
	probes := make([]map[string]any, 0, len(b.outcomes))
	for seq, o := range b.outcomes {
		probe := o.ExceptionProbe()
		probe["attachment_index"] = seq
		probes = append(probes, probe)
	}
	return probes
}

// Apply 按引擎结果给命中例外的处置标上例外编号，并把批次里所有处置记为已核对。results 为 nil
// （引擎调不通、超时）时整批按原处置。
func (b *ExceptionBatch) Apply(results []ExceptionResult) {
	for _, result := range results {
		if result.ExceptionID == "" || result.AttachmentIndex == nil {
			continue
		}
		seq := *result.AttachmentIndex
		if seq < 0 || seq >= len(b.outcomes) || result.RuleID != b.outcomes[seq].ExceptionProbe()["rule_id"] {
			continue
		}
		b.outcomes[seq].ExceptionID = result.ExceptionID
	}
	for _, o := range b.outcomes {
		o.exceptionChecked = true
	}
	b.outcomes = nil
}

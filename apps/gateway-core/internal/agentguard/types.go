package agentguard

import "github.com/yangjiyj/aiguard/packages/shared-go/protection"

// DecisionAction is the governance action produced by analyzers or policies.
type DecisionAction string

const (
	DecisionAllow   DecisionAction = "allow"
	DecisionAudit   DecisionAction = "audit"
	DecisionConfirm DecisionAction = "confirm"
	DecisionBlock   DecisionAction = "block"
)

// Mode controls how raw decisions are enforced.
type Mode string

const (
	ModeObserve Mode = "observe"
	ModeAudit   Mode = "audit"
	ModeLight   Mode = "light"
	ModeStrict  Mode = "strict"
)

// Provenance describes whether a tool argument is tied to trusted or untrusted context.
type Provenance string

const (
	ProvenanceUnknown   Provenance = "unknown"
	ProvenanceTrusted   Provenance = "trusted"
	ProvenanceUntrusted Provenance = "untrusted"
	ProvenanceMixed     Provenance = "mixed"
	ProvenanceTainted   Provenance = "tainted"
)

// Scope is used to resolve same-kind policy conflicts.
type Scope string

const (
	ScopeGlobalTemplate Scope = "global_template"
	ScopeTenant         Scope = "tenant"
	ScopeProject        Scope = "project"
	ScopeUser           Scope = "user"
	ScopeAgent          Scope = "agent"
	ScopeKey            Scope = "key"
	ScopeSession        Scope = "session"
)

// Evidence is safe-to-store audit material. Raw secret values must never be stored here.
type Evidence struct {
	RuleID        string `json:"rule_id,omitempty"`
	Category      string `json:"category,omitempty"`
	SourceField   string `json:"source_field,omitempty"`
	MaskedPreview string `json:"masked_preview,omitempty"`
	Hash          string `json:"hash,omitempty"`
	Length        int    `json:"length,omitempty"`
	// LiteralPath 是文件类目标命中时参数里的字面写法（未经 URL 解码、未折叠）。规范化目标
	// 是解码后的路径，与内核实际读的可能不同，审计同时展示两者；不参与判定。
	LiteralPath string `json:"literal_path,omitempty"`
}

// Decision keeps both the analyzer judgment and the action that will actually be enforced.
type Decision struct {
	RestrictedFileMatched bool           `json:"restricted_file_matched,omitempty"`
	RestrictedFilePattern string         `json:"restricted_file_pattern,omitempty"`
	RawDecision           DecisionAction `json:"raw_decision"`
	EffectiveDecision     DecisionAction `json:"effective_decision"`
	Mode                  Mode           `json:"mode"`
	Reason                string         `json:"reason,omitempty"`
	EffectiveReason       string         `json:"effective_reason,omitempty"`
	// PolicyReason 是执行模式改写之前的处置原因：防护模式下的人工确认会把 EffectiveReason
	// 改写成 confirm_channel_available，阻断记录要靠它说明当初为什么需要确认。
	PolicyReason     string     `json:"policy_reason,omitempty"`
	RiskLevel        string     `json:"risk_level,omitempty"`
	Confidence       float64    `json:"confidence,omitempty"`
	Evidence         []Evidence `json:"evidence_json,omitempty"`
	PolicyVersion    string     `json:"policy_version,omitempty"`
	OperationID      string     `json:"operation_id,omitempty"`
	TraceID          string     `json:"trace_id,omitempty"`
	NormalizedTarget string     `json:"normalized_target,omitempty"`
	// EvidenceSegments 是破坏性分析判定为破坏性的那几段命令（结构化，未渲染），告警证据只渲染这些。
	EvidenceSegments  []EvidenceSegment `json:"-"`
	Provenance        Provenance        `json:"provenance,omitempty"`
	TaintedArguments  []string          `json:"tainted_arguments,omitempty"`
	MatchedRuleID     string            `json:"matched_rule_id,omitempty"`
	MatchedPolicyID   string            `json:"matched_policy_id,omitempty"`
	MatchedPolicyName string            `json:"matched_policy_name,omitempty"`
	SkillAssetID      string            `json:"skill_asset_id,omitempty"`
	SkillVersionID    string            `json:"skill_version_id,omitempty"`
	SkillName         string            `json:"skill_name,omitempty"`
	SkillVersion      string            `json:"skill_version,omitempty"`
	SkillBundleHash   string            `json:"skill_bundle_hash,omitempty"`
	SkillSource       string            `json:"skill_source,omitempty"`
	SkillAdmission    string            `json:"skill_admission,omitempty"`
	// ProtectionHits 是本次调用命中的全部防护项（敏感目标、受限文件、Skill 等）。
	// 分析器只记命中，动作由 ApplyEffectivePolicy 按租户的防护项配置统一给出。
	ProtectionHits []ProtectionHit `json:"protection_hits,omitempty"`
	// ProtectionItem / ProtectionAction 是命中里动作最严的那一项及其生效动作
	// （已套用只针对该项的例外）。
	ProtectionItem   string `json:"protection_item,omitempty"`
	ProtectionAction string `json:"protection_action,omitempty"`
	// 是否告警放行（ProtectionAlert()）、套用了哪些例外（ProtectionExceptionIDs()）
	// 都由上面两项和命中推出，不另存字段。
	// ConfiguredEnforcement marks an analyzer verdict whose action comes from a
	// setting an administrator saved in the console (protection items, restricted
	// files, Skill quarantine/revocation, MCP admission status). Only such
	// verdicts, explicit policy rules, and the policy's configured default may
	// exceed "audit".
	ConfiguredEnforcement  bool              `json:"configured_enforcement,omitempty"`
	ConfigSource           ConfigSource      `json:"config_source,omitempty"`
	ModeDefaultAction      DestructiveAction `json:"mode_default_action,omitempty"`
	CustomAction           DestructiveAction `json:"custom_action,omitempty"`
	FinalAction            DestructiveAction `json:"final_action,omitempty"`
	NotificationRequired   bool              `json:"notification_required,omitempty"`
	NotifyChannelIDs       []string          `json:"notify_channel_ids,omitempty"`
	RiskCategory           string            `json:"risk_category,omitempty"`
	RiskSubcategory        string            `json:"risk_subcategory,omitempty"`
	ReasonSummary          string            `json:"reason_summary,omitempty"`
	DiscardablePathMatched bool              `json:"discardable_path_matched,omitempty"`
	DiscardablePathReason  string            `json:"discardable_path_reason,omitempty"`
	// ObservationOnly：日常开发操作（清临时文件与构建产物、普通 shell 拼接等）只在工具日志留痕，
	// 不产生告警事件、不要求通知；执行决策不受影响。
	ObservationOnly bool `json:"observation_only,omitempty"`
}

// PolicyContext carries rollout mode and policy-match metadata for one decision.
type PolicyContext struct {
	Mode                  Mode
	ConfirmChannelEnabled bool
	ExplicitAllow         bool
	ExplicitAudit         bool
	ExplicitConfirm       bool
	ExplicitBlock         bool
	GlobalDefault         DecisionAction
	PolicyVersion         string
	TraceID               string
	MatchedRuleID         string
	MatchedPolicyID       string
	MatchedPolicyName     string
	// HighRiskAction 是 agent.high_risk_without_rule 的动作，ConfirmFallback 是
	// agent.confirm_without_channel 的动作；空值按注册表默认值处理。
	HighRiskAction  protection.Action
	ConfirmFallback protection.Action
	// ReleasedRuleID 只在通用例外重算时设置：例外点名的 Skill 隔离/撤销不再作为下限。
	ReleasedRuleID string
}

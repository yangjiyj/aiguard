package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

// ToolCallLog represents a single tool call record.
// EventKind=definition_exposed 仅表示网关观察到客户端提交工具定义，不证明定义已送达模型。
type ToolCallLog struct {
	ID                     string                              `json:"id"`
	RequestID              string                              `json:"request_id"`
	SessionID              string                              `json:"session_id"`
	PromptID               string                              `json:"prompt_id,omitempty"`
	EndpointID             string                              `json:"endpoint_id,omitempty"`
	IntentTaskID           string                              `json:"intent_task_id,omitempty"` // transient locator; server re-resolves before step binding
	MCPServer              string                              `json:"mcp_server,omitempty"`
	IntentTaskSources      []agentintent.IntentTaskSourceClaim `json:"intent_task_sources,omitempty"`
	TenantID               string                              `json:"tenant_id"`
	ApplicationID          string                              `json:"application_id,omitempty"`
	AgentType              string                              `json:"agent_type,omitempty"`
	Model                  string                              `json:"model,omitempty"`
	Protocol               string                              `json:"protocol,omitempty"`
	UserID                 string                              `json:"user_id"`
	ToolName               string                              `json:"tool_name"`
	ToolType               string                              `json:"tool_type"`  // file, network, database, mcp, system
	RiskLevel              string                              `json:"risk_level"` // low, medium, high, critical
	Parameters             map[string]interface{}              `json:"parameters"`
	Result                 string                              `json:"result"`
	Status                 string                              `json:"status"` // success, failed, blocked
	MatchedPolicyID        string                              `json:"matched_policy_id,omitempty"`
	MatchedPolicyName      string                              `json:"matched_policy_name,omitempty"`
	MatchedAction          string                              `json:"matched_action,omitempty"`
	MatchReason            string                              `json:"match_reason,omitempty"`
	RawDecision            string                              `json:"raw_decision,omitempty"`
	EffectiveDecision      string                              `json:"effective_decision,omitempty"`
	Mode                   string                              `json:"mode,omitempty"`
	EffectiveReason        string                              `json:"effective_reason,omitempty"`
	PolicyVersion          string                              `json:"policy_version,omitempty"`
	TraceID                string                              `json:"trace_id,omitempty"`
	Confidence             float64                             `json:"confidence,omitempty"`
	EvidenceJSON           json.RawMessage                     `json:"evidence_json,omitempty"`
	NormalizedTarget       string                              `json:"normalized_target,omitempty"`
	Provenance             string                              `json:"provenance,omitempty"`
	TaintedArguments       json.RawMessage                     `json:"tainted_arguments,omitempty"`
	EventKind              string                              `json:"event_kind"`
	ExecutionObserved      bool                                `json:"execution_observed"`
	ResultObserved         bool                                `json:"result_observed"`
	ToolCallID             string                              `json:"tool_call_id,omitempty"`
	AssetID                string                              `json:"asset_id,omitempty"`
	SkillInvocationID      string                              `json:"skill_invocation_id,omitempty"`
	MCPServerID            string                              `json:"mcp_server_id,omitempty"`
	MCPToolID              string                              `json:"mcp_tool_id,omitempty"`
	DefinitionHash         string                              `json:"definition_hash,omitempty"`
	AttributionMode        string                              `json:"attribution_mode,omitempty"`
	AttributionConfidence  float64                             `json:"attribution_confidence,omitempty"`
	OperationID            string                              `json:"operation_id,omitempty"`
	EventType              string                              `json:"event_type,omitempty"`
	RiskCategory           string                              `json:"risk_category,omitempty"`
	RiskSubcategory        string                              `json:"risk_subcategory,omitempty"`
	ReasonSummary          string                              `json:"reason_summary,omitempty"`
	PublicEventID          string                              `json:"public_event_id,omitempty"`
	TargetSummary          string                              `json:"target_summary,omitempty"`
	ModeDefaultAction      string                              `json:"mode_default_action,omitempty"`
	CustomAction           string                              `json:"custom_action,omitempty"`
	FinalAction            string                              `json:"final_action,omitempty"`
	NotificationRequired   bool                                `json:"notification_required"`
	NotifyChannelIDs       []string                            `json:"notify_channel_ids,omitempty"`
	NotificationStatus     string                              `json:"notification_status,omitempty"`
	DiscardablePathMatched bool                                `json:"discardable_path_matched"`
	DiscardablePathReason  string                              `json:"discardable_path_reason,omitempty"`
	ExecutionForwarded     bool                                `json:"execution_forwarded"`
	CreatedAt              time.Time                           `json:"created_at"`
}

// ToolCallAuditListItem is the bounded list projection. Raw parameters, results,
// targets and evidence remain available only from detail endpoints.
type ToolCallAuditListItem struct {
	ID                string    `json:"id"`
	RequestID         string    `json:"request_id"`
	SessionID         string    `json:"session_id,omitempty"`
	UserID            string    `json:"user_id,omitempty"`
	ApplicationID     string    `json:"application_id,omitempty"`
	AgentType         string    `json:"agent_type,omitempty"`
	Model             string    `json:"model,omitempty"`
	Protocol          string    `json:"protocol,omitempty"`
	ToolName          string    `json:"tool_name"`
	ToolType          string    `json:"tool_type"`
	RiskLevel         string    `json:"risk_level"`
	Status            string    `json:"status"`
	MatchedPolicyID   string    `json:"matched_policy_id,omitempty"`
	MatchedPolicyName string    `json:"matched_policy_name,omitempty"`
	MatchedAction     string    `json:"matched_action,omitempty"`
	MatchReason       string    `json:"match_reason,omitempty"`
	RawDecision       string    `json:"raw_decision,omitempty"`
	EffectiveDecision string    `json:"effective_decision,omitempty"`
	Mode              string    `json:"mode,omitempty"`
	EffectiveReason   string    `json:"effective_reason,omitempty"`
	DispositionStatus string    `json:"disposition_status"`
	DispositionNote   string    `json:"disposition_note,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

type ToolCallAuditPage struct {
	Data       []ToolCallAuditListItem `json:"data"`
	Total      int                     `json:"total"`
	TotalKnown bool                    `json:"total_known"`
	HasMore    bool                    `json:"has_more"`
	Limit      int                     `json:"limit"`
	Offset     int                     `json:"offset"`
}

const legacyToolEventKindSQL = `COALESCE(NULLIF(event_kind, ''), CASE
	WHEN COALESCE(execution_observed, FALSE) AND provenance = 'mcp_gateway' THEN 'execution_forwarded'
	WHEN COALESCE(raw_decision, '') <> '' AND COALESCE(effective_decision, '') <> '' THEN 'invocation_proposed'
	WHEN result = 'request tool passed policy check' THEN 'definition_exposed'
	ELSE 'legacy_unknown'
END)`

const legacyToolEventKindQualifiedSQL = `COALESCE(NULLIF(tcl.event_kind, ''), CASE
	WHEN COALESCE(tcl.execution_observed, FALSE) AND tcl.provenance = 'mcp_gateway' THEN 'execution_forwarded'
	WHEN COALESCE(tcl.raw_decision, '') <> '' AND COALESCE(tcl.effective_decision, '') <> '' THEN 'invocation_proposed'
	WHEN tcl.result = 'request tool passed policy check' THEN 'definition_exposed'
	ELSE 'legacy_unknown'
END)`

// riskOverviewEventKindSQL 只承认看板可解释的生命周期事实。confirmation_replay
// 是独立审批回放审计，不当作调用尝试或未知事件；旧行仅在没有显式 event_kind 时保守派生。
const riskOverviewEventKindSQL = `CASE
	WHEN tcl.event_kind IN ('definition_exposed', 'invocation_proposed', 'execution_forwarded', 'result_observed', 'confirmation_replay') THEN tcl.event_kind
	WHEN COALESCE(tcl.event_kind, '') <> '' THEN 'legacy_unknown'
	WHEN COALESCE(tcl.execution_observed, FALSE) THEN 'execution_forwarded'
	WHEN COALESCE(tcl.raw_decision, '') <> ''
	  OR COALESCE(tcl.effective_decision, '') <> ''
	  OR COALESCE(tcl.mode, '') <> '' THEN 'invocation_proposed'
	WHEN tcl.result = 'request tool passed policy check' THEN 'definition_exposed'
	ELSE 'legacy_unknown'
END`

// riskOverviewNormalizedCTE 是风险概览唯一的事件归一化入口。所有统计先按同一租户、
// 时间窗和可选工具类型过滤，再保守派生旧事件；status 永远不参与执行事实判定。
// attempt_events 按 tool_call_id 去重：拟调用优先于同一调用的执行事件；只有缺少拟调用
// 但真实转发已被观察时，execution_forwarded 才补充证明一次调用尝试。
const riskOverviewNormalizedCTE = `
WITH normalized_events AS (
	SELECT tcl.id,
	       tcl.request_id,
	       tcl.trace_id,
	       tcl.session_id,
	       tcl.tenant_id,
	       tcl.user_id,
	       tcl.tool_name,
	       tcl.tool_type,
	       CASE WHEN ` + legacyShellSyntaxOnlySQL + ` THEN 'low' ELSE COALESCE(NULLIF(tcl.risk_level, ''), 'unknown') END AS risk_level,
	       tcl.matched_policy_id,
	       tcl.matched_policy_name,
	       tcl.execution_observed,
	       tcl.result_observed,
	       tcl.tool_call_id,
	       tcl.created_at,
	       ` + riskOverviewEventKindSQL + ` AS normalized_event_kind,
	       CASE
	         WHEN COALESCE(tcl.tool_call_id, '') <> '' AND COALESCE(tcl.request_id, '') <> ''
	           THEN jsonb_build_array('request', tcl.request_id, 'call', tcl.tool_call_id)::text
	         WHEN COALESCE(tcl.tool_call_id, '') <> '' AND COALESCE(tcl.trace_id, '') <> ''
	           THEN jsonb_build_array('trace', tcl.trace_id, 'call', tcl.tool_call_id)::text
	         ELSE jsonb_build_array('id', tcl.id)::text
	       END AS attempt_key,
	       COALESCE(NULLIF(tcl.raw_decision, ''), 'unknown') AS normalized_raw_decision,
	       COALESCE(NULLIF(tcl.effective_decision, ''), NULLIF(tcl.mode, ''), 'unknown') AS normalized_effective_decision
	FROM tool_call_logs tcl
	WHERE %s
),
attempt_events AS (
	SELECT DISTINCT ON (attempt_key)
	       id, request_id, trace_id, session_id, tenant_id, user_id, tool_name, tool_type,
	       risk_level, matched_policy_id, matched_policy_name, execution_observed,
	       result_observed, tool_call_id, created_at, normalized_event_kind, attempt_key,
	       normalized_raw_decision, normalized_effective_decision
	FROM normalized_events
	WHERE normalized_event_kind = 'invocation_proposed'
	   OR (normalized_event_kind = 'execution_forwarded' AND COALESCE(execution_observed, FALSE))
	ORDER BY attempt_key,
	         CASE normalized_event_kind WHEN 'invocation_proposed' THEN 0 ELSE 1 END,
	         created_at ASC, id ASC
)
`

const toolCallLogSelectColumns = `id, request_id, COALESCE(session_id, '') AS session_id, tenant_id, COALESCE(endpoint_id, '') AS endpoint_id, COALESCE(user_id, '') AS user_id, tool_name, tool_type, risk_level, parameters, COALESCE(result, '') AS result, status,
	COALESCE(matched_policy_id, '') AS matched_policy_id, COALESCE(matched_policy_name, '') AS matched_policy_name, COALESCE(matched_action, '') AS matched_action, COALESCE(match_reason, '') AS match_reason,
	COALESCE(raw_decision, '') AS raw_decision, COALESCE(effective_decision, '') AS effective_decision, COALESCE(mode, '') AS mode, COALESCE(effective_reason, '') AS effective_reason,
	COALESCE(policy_version, '') AS policy_version, COALESCE(trace_id, '') AS trace_id, COALESCE(confidence, 0), COALESCE(evidence_json, '[]'::jsonb)::text,
	COALESCE(normalized_target, '') AS normalized_target, COALESCE(provenance, '') AS provenance, COALESCE(tainted_arguments, '[]'::jsonb)::text,
	` + legacyToolEventKindSQL + `, COALESCE(execution_observed, false), COALESCE(result_observed, false),
	COALESCE(tool_call_id, '') AS tool_call_id, COALESCE(asset_id, '') AS asset_id, COALESCE(skill_invocation_id, '') AS skill_invocation_id, COALESCE(mcp_server_id, '') AS mcp_server_id,
	COALESCE(mcp_tool_id, '') AS mcp_tool_id, COALESCE(definition_hash, '') AS definition_hash, COALESCE(attribution_mode, '') AS attribution_mode, COALESCE(attribution_confidence, 0),
	COALESCE(application_id, '') AS application_id, COALESCE(agent_type, '') AS agent_type, COALESCE(model, '') AS model, COALESCE(protocol, '') AS protocol,
	COALESCE(public_event_id, '') AS public_event_id, created_at`

const toolCallLogSelectColumnsQualified = `tcl.id, tcl.request_id, COALESCE(tcl.session_id, '') AS session_id, tcl.tenant_id, COALESCE(tcl.endpoint_id, '') AS endpoint_id, COALESCE(tcl.user_id, '') AS user_id, tcl.tool_name, tcl.tool_type, tcl.risk_level, tcl.parameters, COALESCE(tcl.result, '') AS result, tcl.status,
	COALESCE(tcl.matched_policy_id, '') AS matched_policy_id, COALESCE(tcl.matched_policy_name, '') AS matched_policy_name, COALESCE(tcl.matched_action, '') AS matched_action, COALESCE(tcl.match_reason, '') AS match_reason,
	COALESCE(tcl.raw_decision, '') AS raw_decision, COALESCE(tcl.effective_decision, '') AS effective_decision, COALESCE(tcl.mode, '') AS mode, COALESCE(tcl.effective_reason, '') AS effective_reason,
	COALESCE(tcl.policy_version, '') AS policy_version, COALESCE(tcl.trace_id, '') AS trace_id, COALESCE(tcl.confidence, 0), COALESCE(tcl.evidence_json, '[]'::jsonb)::text,
	COALESCE(tcl.normalized_target, '') AS normalized_target, COALESCE(tcl.provenance, '') AS provenance, COALESCE(tcl.tainted_arguments, '[]'::jsonb)::text,
	` + legacyToolEventKindQualifiedSQL + `, COALESCE(tcl.execution_observed, false), COALESCE(tcl.result_observed, false),
	COALESCE(tcl.tool_call_id, '') AS tool_call_id, COALESCE(tcl.asset_id, '') AS asset_id, COALESCE(tcl.skill_invocation_id, '') AS skill_invocation_id, COALESCE(tcl.mcp_server_id, '') AS mcp_server_id,
	COALESCE(tcl.mcp_tool_id, '') AS mcp_tool_id, COALESCE(tcl.definition_hash, '') AS definition_hash, COALESCE(tcl.attribution_mode, '') AS attribution_mode, COALESCE(tcl.attribution_confidence, 0),
	COALESCE(tcl.application_id, '') AS application_id, COALESCE(tcl.agent_type, '') AS agent_type, COALESCE(tcl.model, '') AS model, COALESCE(tcl.protocol, '') AS protocol,
	COALESCE(tcl.public_event_id, '') AS public_event_id, tcl.created_at`

type toolCallLogScanner interface {
	Scan(dest ...interface{}) error
}

// legacyShellSyntaxOnlySQL identifies the historical analyzer output that treated
// shell composition syntax alone as critical. Combined evidence remains visible
// as an attention signal; only the syntax-only legacy false positive is normalized.
const legacyShellSyntaxOnlySQL = `(CASE
  WHEN jsonb_typeof(COALESCE(tcl.evidence_json, '[]'::jsonb)) = 'array'
  THEN jsonb_array_length(COALESCE(tcl.evidence_json, '[]'::jsonb)) = 1
       AND tcl.evidence_json @> '[{"rule_id":"command_shell_metacharacter"}]'::jsonb
  ELSE FALSE END)`

// ToolCallStats represents aggregated statistics for tool calls
type ToolCallStats struct {
	ToolType                string `json:"tool_type"`
	Count                   int    `json:"count"`
	LowCount                int    `json:"low_count"`
	MediumCount             int    `json:"medium_count"`
	HighCount               int    `json:"high_count"`
	CriticalCount           int    `json:"critical_count"`
	DefinitionExposedCount  int    `json:"definition_exposed_count"`
	InvocationProposedCount int    `json:"invocation_proposed_count"`
	ExecutionForwardedCount int    `json:"execution_forwarded_count"`
	ResultObservedCount     int    `json:"result_observed_count"`
	ConfirmationReplayCount int    `json:"confirmation_replay_count"`
	UnknownEventCount       int    `json:"unknown_event_count"`
}

// RiskTrendPoint represents a point in the risk trend timeline
type RiskTrendPoint struct {
	Date          string `json:"date"`
	HighCount     int    `json:"high_count"`
	CriticalCount int    `json:"critical_count"`
}

// ToolCallLogRepository handles tool call audit log operations
type ToolCallLogRepository struct {
	db *pgxpool.Pool
}

// NewToolCallLogRepository creates a new tool call log repository
func NewToolCallLogRepository(db *pgxpool.Pool) *ToolCallLogRepository {
	return &ToolCallLogRepository{db: db}
}

func newToolCallLogID() string {
	return "tc_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
}

// Create inserts a new tool call log
func PublicDestructiveEventID(tenantID, operationID, eventType string) string {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(operationID) == "" || strings.TrimSpace(eventType) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{tenantID, operationID, eventType}, "\x1f")))
	return "evt_" + hex.EncodeToString(sum[:16])
}

func buildToolCallLogInsert(log *ToolCallLog) (string, []any, error) {
	if log == nil {
		return "", nil, fmt.Errorf("tool call log is required")
	}
	if log.OperationID != "" && validDestructiveEventType(log.EventType) {
		log.PublicEventID = PublicDestructiveEventID(log.TenantID, log.OperationID, log.EventType)
	}
	evidenceJSON := rawJSONOrDefault(log.EvidenceJSON, "[]")
	taintedArguments := rawJSONOrDefault(log.TaintedArguments, "[]")
	query := `
		INSERT INTO tool_call_logs (
			id, request_id, session_id, tenant_id, user_id, tool_name, tool_type, risk_level,
			parameters, result, status, matched_policy_id, matched_policy_name, matched_action, match_reason,
			raw_decision, effective_decision, mode, effective_reason, policy_version, trace_id, confidence,
			evidence_json, normalized_target, provenance, tainted_arguments,
			event_kind, execution_observed, result_observed, tool_call_id, asset_id, skill_invocation_id,
			mcp_server_id, mcp_tool_id, definition_hash, attribution_mode, attribution_confidence,
			operation_id, event_type, risk_category, risk_subcategory, reason_summary, target_summary,
			mode_default_action, custom_action, final_action, notification_required, notification_status,
			discardable_path_matched, discardable_path_reason, execution_forwarded,
			application_id, agent_type, model, protocol, public_event_id, endpoint_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULLIF($12, ''), NULLIF($13, ''), NULLIF($14, ''), NULLIF($15, ''),
			NULLIF($16, ''), NULLIF($17, ''), NULLIF($18, ''), NULLIF($19, ''), NULLIF($20, ''), NULLIF($21, ''), $22,
			$23::jsonb, NULLIF($24, ''), NULLIF($25, ''), $26::jsonb,
			$27, $28, $29, NULLIF($30, ''), NULLIF($31, ''), NULLIF($32, ''), NULLIF($33, ''), NULLIF($34, ''),
			NULLIF($35, ''), NULLIF($36, ''), CASE WHEN NULLIF($36, '') IS NULL THEN NULL ELSE $37::double precision END,
			NULLIF($38, ''), NULLIF($39, ''), NULLIF($40, ''), NULLIF($41, ''), NULLIF($42, ''), NULLIF($43, ''),
			NULLIF($44, ''), NULLIF($45, ''), NULLIF($46, ''), $47, NULLIF($48, ''), $49, NULLIF($50, ''), $51,
			NULLIF($52, ''), NULLIF($53, ''), NULLIF($54, ''), NULLIF($55, ''), NULLIF($56, ''), NULLIF($57, ''))
		ON CONFLICT (tenant_id, operation_id, event_type)
		WHERE operation_id IS NOT NULL AND btrim(operation_id) <> ''
		DO UPDATE SET
			execution_forwarded = COALESCE(tool_call_logs.execution_forwarded, false) OR COALESCE(EXCLUDED.execution_forwarded, false),
			-- tool_call_logs_execution_fact_check：非 endpoint_hook 行的 execution_observed 必须等于 (event_kind='execution_forwarded')。
			-- DO UPDATE 不改 event_kind，所以合并后的 execution_observed 不能越过已存的 event_kind（正常数据 event_type 与 event_kind 一一对应，这里只是兜底）。
			execution_observed = CASE
				WHEN tool_call_logs.attribution_mode IS NOT DISTINCT FROM 'endpoint_hook'
					THEN COALESCE(tool_call_logs.execution_observed, false) OR COALESCE(EXCLUDED.execution_observed, false)
				ELSE (COALESCE(tool_call_logs.execution_observed, false) OR COALESCE(EXCLUDED.execution_observed, false))
					AND tool_call_logs.event_kind IS NOT DISTINCT FROM 'execution_forwarded'
			END,
			result_observed = COALESCE(tool_call_logs.result_observed, false) OR COALESCE(EXCLUDED.result_observed, false),
			status = CASE
				WHEN COALESCE(tool_call_logs.result_observed, false) THEN tool_call_logs.status
				WHEN COALESCE(EXCLUDED.result_observed, false)
					OR (NOT COALESCE(tool_call_logs.execution_forwarded, false) AND COALESCE(EXCLUDED.execution_forwarded, false))
				THEN EXCLUDED.status
				ELSE tool_call_logs.status END,
			notification_status = CASE
				WHEN tool_call_logs.notification_status IN ('sent', 'dead') THEN tool_call_logs.notification_status
				WHEN tool_call_logs.notification_status = 'pending' AND EXCLUDED.notification_status = 'skipped'
					THEN tool_call_logs.notification_status
				WHEN EXCLUDED.notification_status IS NOT NULL THEN EXCLUDED.notification_status
				ELSE tool_call_logs.notification_status END,
			application_id = COALESCE(NULLIF(tool_call_logs.application_id, ''), EXCLUDED.application_id),
			agent_type = COALESCE(NULLIF(tool_call_logs.agent_type, ''), EXCLUDED.agent_type),
			model = COALESCE(NULLIF(tool_call_logs.model, ''), EXCLUDED.model),
			protocol = COALESCE(NULLIF(tool_call_logs.protocol, ''), EXCLUDED.protocol)
		RETURNING id
	`
	args := []any{
		log.ID, log.RequestID, log.SessionID, log.TenantID, log.UserID, log.ToolName, log.ToolType, log.RiskLevel,
		log.Parameters, log.Result, log.Status, log.MatchedPolicyID, log.MatchedPolicyName, log.MatchedAction, log.MatchReason,
		log.RawDecision, log.EffectiveDecision, log.Mode, log.EffectiveReason, log.PolicyVersion, log.TraceID, log.Confidence,
		evidenceJSON, log.NormalizedTarget, log.Provenance, taintedArguments,
		log.EventKind, log.ExecutionObserved, log.ResultObserved, log.ToolCallID, log.AssetID, log.SkillInvocationID,
		log.MCPServerID, log.MCPToolID, log.DefinitionHash, log.AttributionMode, log.AttributionConfidence,
		log.OperationID, log.EventType, log.RiskCategory, log.RiskSubcategory, log.ReasonSummary, log.TargetSummary,
		log.ModeDefaultAction, log.CustomAction, log.FinalAction, log.NotificationRequired, log.NotificationStatus,
		log.DiscardablePathMatched, log.DiscardablePathReason, log.ExecutionForwarded,
		log.ApplicationID, log.AgentType, log.Model, log.Protocol, log.PublicEventID, log.EndpointID,
	}
	return query, args, nil
}

func buildDestructiveNotificationOutboxInsert(log *ToolCallLog) (string, []any, error) {
	if log == nil || strings.TrimSpace(log.PublicEventID) == "" ||
		strings.TrimSpace(log.OperationID) == "" || !validDestructiveEventType(log.EventType) {
		return "", nil, fmt.Errorf("valid destructive lifecycle event is required")
	}
	query := `
		INSERT INTO outbox_events (
			id, tenant_id, event_type, schema_version, request_id, trace_id,
			payload_json, status, available_at, created_at, updated_at
		)
		SELECT
			'obn_' || md5($1 || chr(31) || $2 || chr(31) || $3 || chr(31) || ch.id),
			$1, 'notify.agent_destructive', 'v1', NULLIF($5, ''), NULLIF($6, ''),
			jsonb_build_object(
				'public_event_id', $4::text,
				'operation_id', $2,
				'event_type', $3,
				'channel_id', ch.id,
				'risk_subcategory', $7::text,
				'reason_summary', $8::text,
				'target_summary', $9::text,
				'final_action', $10::text
			), 'pending', now(), now(), now()
		FROM notify_channels ch
		WHERE ch.tenant_id = $1
		  AND ch.id = ANY($11)
		  AND ch.enabled = true
		ON CONFLICT (id) DO NOTHING
	`
	return query, []any{
		log.TenantID, log.OperationID, log.EventType, log.PublicEventID,
		log.RequestID, log.TraceID, log.RiskSubcategory, log.ReasonSummary,
		log.TargetSummary, log.FinalAction,
		log.NotifyChannelIDs,
	}, nil
}

func (r *ToolCallLogRepository) EnqueueDestructiveNotifications(ctx context.Context, log *ToolCallLog) (int64, error) {
	if log == nil || !log.NotificationRequired || log.DiscardablePathMatched ||
		log.Confidence < 1 || log.FinalAction == "record" {
		return 0, nil
	}
	query, args, err := buildDestructiveNotificationOutboxInsert(log)
	if err != nil {
		return 0, err
	}
	tag, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("enqueue destructive notifications: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *ToolCallLogRepository) SetDestructiveNotificationStatus(ctx context.Context, tenantID, operationID, eventType, status string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(operationID) == "" ||
		!validDestructiveEventType(eventType) {
		return fmt.Errorf("valid destructive lifecycle identity is required")
	}
	switch status {
	case "pending", "sent", "failed", "dead", "skipped":
	default:
		return fmt.Errorf("invalid notification status %q", status)
	}
	_, err := r.db.Exec(ctx, `
		UPDATE tool_call_logs
		SET notification_status=CASE
			WHEN notification_status IN ('sent', 'dead') THEN notification_status
			WHEN notification_status = 'pending' AND $4 = 'skipped' THEN notification_status
			ELSE $4
		END
		WHERE tenant_id=$1 AND operation_id=$2 AND event_type=$3
	`, tenantID, operationID, eventType, status)
	return err
}

func (r *ToolCallLogRepository) RefreshDestructiveNotificationStatus(ctx context.Context, tenantID, operationID, eventType string) (string, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(operationID) == "" ||
		!validDestructiveEventType(eventType) {
		return "", fmt.Errorf("valid destructive lifecycle identity is required")
	}
	var status string
	err := r.db.QueryRow(ctx, `
		WITH aggregate AS (
			SELECT CASE
				WHEN count(*) = 0 THEN 'skipped'
				WHEN bool_or(status = 'dead') THEN 'dead'
				WHEN bool_or(status IN ('pending', 'processing')) THEN 'pending'
				WHEN bool_or(status = 'failed') THEN 'failed'
				WHEN bool_and(status = 'processed') THEN 'sent'
				ELSE 'failed'
			END AS status
			FROM outbox_events
			WHERE tenant_id=$1
			  AND event_type='notify.agent_destructive'
			  AND payload_json->>'operation_id'=$2
			  AND payload_json->>'event_type'=$3
		)
		UPDATE tool_call_logs AS logs
		SET notification_status=CASE
			WHEN logs.notification_status IN ('sent', 'dead') THEN logs.notification_status
			ELSE aggregate.status
		END
		FROM aggregate
		WHERE logs.tenant_id=$1 AND logs.operation_id=$2 AND logs.event_type=$3
		RETURNING logs.notification_status
	`, tenantID, operationID, eventType).Scan(&status)
	if err != nil {
		return "", fmt.Errorf("refresh destructive notification status: %w", err)
	}
	return status, nil
}

// ErrToolLogFactsInvalid 表示这条审计自带的生命周期事实自相矛盾（例如 event_kind=execution_forwarded
// 却声明 execution_observed=false）。这是确定性错误：同样的输入重试一万次结果不变，调用方应丢弃而不是重投。
var ErrToolLogFactsInvalid = errors.New("tool call log lifecycle facts are inconsistent")

// pgCheckViolation 是 PostgreSQL 的 check_violation SQLSTATE。
const pgCheckViolation = "23514"

// ToolCallLogCheckViolation 判断 err（可被 %w 多层包装）是否为 tool_call_logs 上 CHECK 约束违约（SQLSTATE 23514），
// 并返回被违反的约束名。这类错误由数据本身决定，重试不会成功，写入方应丢弃并限频记日志，不能无限重投。
func ToolCallLogCheckViolation(err error) (constraint string, ok bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgCheckViolation {
		return pgErr.ConstraintName, true
	}
	return "", false
}

// IsPermanentToolCallLogError 汇总「重试无意义」的写入错误：约束违约，或事实自相矛盾。
func IsPermanentToolCallLogError(err error) bool {
	if errors.Is(err, ErrToolLogFactsInvalid) {
		return true
	}
	_, ok := ToolCallLogCheckViolation(err)
	return ok
}

func isEndpointHookAttribution(mode string) bool {
	return strings.TrimSpace(mode) == "endpoint_hook"
}

// normalizeExecutionFacts 让待写入的行满足 tool_call_logs_execution_fact_check：
//
//   - endpoint_hook：端侧钩子自己观察到的事实，保持原语义，约束对它豁免；
//   - 其他归因模式（explicit/linked/inferred/none/空）：execution_observed 必须等于 (event_kind='execution_forwarded')。
//     「客户端自己带回来的工具结果」只证明网关看到了一份结果，不是网关观察到执行，所以调用方声称 execution_observed=true
//     而 event_kind 不是 execution_forwarded 时一律降为 false（审计事实宁可少说）。
//     反过来 event_kind=execution_forwarded 却声明 execution_observed=false 是自相矛盾，不替调用方"补成 true"，直接拒绝。
func normalizeExecutionFacts(log *ToolCallLog) error {
	if isEndpointHookAttribution(log.AttributionMode) {
		return nil
	}
	forwarded := log.EventKind == "execution_forwarded"
	if forwarded && !log.ExecutionObserved {
		return fmt.Errorf("%w: event_kind=execution_forwarded requires execution_observed=true (attribution_mode=%q)", ErrToolLogFactsInvalid, log.AttributionMode)
	}
	log.ExecutionObserved = log.ExecutionObserved && forwarded
	return nil
}

func (r *ToolCallLogRepository) Create(ctx context.Context, log *ToolCallLog) error {
	if log.ID == "" {
		log.ID = newToolCallLogID()
	}

	if log.EventKind == "tool_pre" {
		log.EventKind = "invocation_proposed"
	}
	if log.EventKind == "tool_post" {
		log.EventKind = "result_observed"
	}
	if log.EventKind == "" {
		log.EventKind = "legacy_unknown"
	}
	if !validToolEventKind(log.EventKind) {
		return fmt.Errorf("invalid tool event kind %q", log.EventKind)
	}
	if !validAttribution(log.AttributionMode, log.AttributionConfidence) {
		return fmt.Errorf("invalid tool attribution mode/confidence")
	}
	if err := normalizeExecutionFacts(log); err != nil {
		return err
	}
	if log.OperationID != "" || log.EventType != "" {
		if strings.TrimSpace(log.OperationID) == "" || !validDestructiveEventType(log.EventType) {
			return fmt.Errorf("invalid destructive lifecycle tuple")
		}
		query, args, err := buildToolCallLogInsert(log)
		if err != nil {
			return err
		}
		var storedID string
		if err := r.db.QueryRow(ctx, query, args...).Scan(&storedID); err != nil {
			return fmt.Errorf("failed to create destructive tool call log: %w", err)
		}
		log.ID = storedID
		log.PublicEventID = PublicDestructiveEventID(log.TenantID, log.OperationID, log.EventType)
		if log.RequestID != "" && log.TenantID != "" {
			_, _ = r.db.Exec(ctx, `
				UPDATE request_logs
				SET internal_title_request = NULL, agent_type = 'agent-tool-call'
				WHERE request_id = $1
				  AND tenant_id = $2
				  AND COALESCE(agent_type, '') = ''
			`, log.RequestID, log.TenantID)
		}
		if log.CreatedAt.IsZero() {
			log.CreatedAt = time.Now()
		}
		return nil
	}

	evidenceJSON := rawJSONOrDefault(log.EvidenceJSON, "[]")
	taintedArguments := rawJSONOrDefault(log.TaintedArguments, "[]")
	query := `
		INSERT INTO tool_call_logs (
			id, request_id, session_id, tenant_id, user_id, tool_name, tool_type, risk_level,
			parameters, result, status, matched_policy_id, matched_policy_name, matched_action, match_reason,
			raw_decision, effective_decision, mode, effective_reason, policy_version, trace_id, confidence,
			evidence_json, normalized_target, provenance, tainted_arguments,
			event_kind, execution_observed, result_observed, tool_call_id, asset_id, skill_invocation_id,
			mcp_server_id, mcp_tool_id, definition_hash, attribution_mode, attribution_confidence, endpoint_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULLIF($12, ''), NULLIF($13, ''), NULLIF($14, ''), NULLIF($15, ''),
			NULLIF($16, ''), NULLIF($17, ''), NULLIF($18, ''), NULLIF($19, ''), NULLIF($20, ''), NULLIF($21, ''), $22,
			$23::jsonb, NULLIF($24, ''), NULLIF($25, ''), $26::jsonb,
			$27, $28, $29, NULLIF($30, ''), NULLIF($31, ''), NULLIF($32, ''), NULLIF($33, ''), NULLIF($34, ''),
			NULLIF($35, ''), NULLIF($36, ''), CASE WHEN NULLIF($36, '') IS NULL THEN NULL ELSE $37::double precision END, NULLIF($38, ''))
	`
	_, err := r.db.Exec(ctx, query,
		log.ID, log.RequestID, log.SessionID, log.TenantID, log.UserID, log.ToolName, log.ToolType, log.RiskLevel,
		log.Parameters, log.Result, log.Status, log.MatchedPolicyID, log.MatchedPolicyName, log.MatchedAction, log.MatchReason,
		log.RawDecision, log.EffectiveDecision, log.Mode, log.EffectiveReason, log.PolicyVersion, log.TraceID, log.Confidence,
		evidenceJSON, log.NormalizedTarget, log.Provenance, taintedArguments,
		log.EventKind, log.ExecutionObserved, log.ResultObserved, log.ToolCallID, log.AssetID, log.SkillInvocationID,
		log.MCPServerID, log.MCPToolID, log.DefinitionHash, log.AttributionMode, log.AttributionConfidence, log.EndpointID,
	)
	if err != nil {
		return fmt.Errorf("failed to create tool call log: %w", err)
	}
	if log.RequestID != "" && log.TenantID != "" {
		_, _ = r.db.Exec(ctx, `
			UPDATE request_logs
			SET internal_title_request = NULL, agent_type = 'agent-tool-call'
			WHERE request_id = $1
			  AND tenant_id = $2
			  AND COALESCE(agent_type, '') = ''
		`, log.RequestID, log.TenantID)
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	return nil
}

// upsertToolCallMergeSQL 把一次 result 观察并入同租户同 tool_call_id 的最新一行。
//
// 约束 tool_call_logs_execution_fact_check 对非 endpoint_hook 行要求 execution_observed = (event_kind='execution_forwarded')，
// 因此合并必须按「已存行」的归因模式决定语义，而不是按调用方的：
//   - 已存行是 endpoint_hook：端侧钩子事实，保持原语义（event_kind=$5，execution_observed 只增不减）；
//   - 其他行：已是 execution_forwarded 的不降级（网关确实转发过，事实不能丢，也不能改成 result_observed 后还留 exec=true）；
//     其余一律 execution_observed=false。调用方（含 $6）自称的执行事实不会被采信为"网关观察到执行"。
const upsertToolCallMergeSQL = `
		WITH target AS (
			SELECT id FROM tool_call_logs
			WHERE tenant_id=$1 AND tool_call_id=$2
			ORDER BY created_at DESC, id DESC
			LIMIT 1
		)
		UPDATE tool_call_logs AS t
		SET result=CASE WHEN NULLIF($3, '') IS NOT NULL THEN $3 ELSE t.result END,
		    status=CASE WHEN NULLIF($4, '') IS NOT NULL THEN $4 ELSE t.status END,
		    event_kind=CASE
		        WHEN t.attribution_mode IS NOT DISTINCT FROM 'endpoint_hook' THEN $5
		        WHEN t.event_kind IS NOT DISTINCT FROM 'execution_forwarded' THEN t.event_kind
		        ELSE $5
		    END,
		    execution_observed=CASE
		        WHEN t.attribution_mode IS NOT DISTINCT FROM 'endpoint_hook' THEN COALESCE(t.execution_observed, FALSE) OR $6
		        ELSE COALESCE(t.execution_observed, FALSE) AND t.event_kind IS NOT DISTINCT FROM 'execution_forwarded'
		    END,
		    result_observed=COALESCE(t.result_observed, FALSE) OR $7
		FROM target
		WHERE t.id=target.id`

// prepareUpsertCreateFacts 决定"找不到已有行、走 Create"时这一行要落库的生命周期事实。
//
//   - endpoint_hook（含调用方没填归因模式的旧调用方，沿用 endpoint_hook）：端侧钩子自己观察到工具跑完并带回结果，
//     execution_observed=true、result_observed=true，保持原有语义；约束对它豁免。
//   - 其他归因模式（网关 explicit 上报的"客户端自带 tool_result"等）：只记结果被观察到（event_kind=result_observed 时
//     result_observed=true），execution_observed 一律交给 normalizeExecutionFacts 压成与 event_kind 一致。
//     绝不能把"客户端自己带回来的结果"记成"网关观察到执行"——审计事实宁可少说，不能多说。
func prepareUpsertCreateFacts(log *ToolCallLog) error {
	if strings.TrimSpace(log.AttributionMode) == "" {
		log.AttributionMode = "endpoint_hook"
	}
	if isEndpointHookAttribution(log.AttributionMode) {
		log.ExecutionObserved = true
		log.ResultObserved = true
		return nil
	}
	if log.EventKind == "result_observed" {
		log.ResultObserved = true // result_fact_check: event_kind=result_observed 必须 result_observed=true
	}
	return normalizeExecutionFacts(log)
}

// UpsertByToolCallID merges a tool.post observation into the latest record for the
// same tenant and tool_call_id. It records execution/result facts monotonically and
// creates a new result_observed record when no proposal exists yet.
func (r *ToolCallLogRepository) UpsertByToolCallID(ctx context.Context, log *ToolCallLog) (bool, error) {
	if log == nil || strings.TrimSpace(log.TenantID) == "" || strings.TrimSpace(log.ToolCallID) == "" {
		return false, fmt.Errorf("tenant_id and tool_call_id are required")
	}
	if log.EventKind == "tool_pre" {
		log.EventKind = "invocation_proposed"
	}
	if strings.TrimSpace(log.EventKind) == "" || log.EventKind == "tool_post" {
		log.EventKind = "result_observed"
	}
	if !validToolEventKind(log.EventKind) {
		return false, fmt.Errorf("invalid tool event kind %q", log.EventKind)
	}
	cmd, err := r.db.Exec(ctx, upsertToolCallMergeSQL,
		log.TenantID, log.ToolCallID, log.Result, log.Status, log.EventKind,
		log.ExecutionObserved, log.ResultObserved)
	if err != nil {
		return false, fmt.Errorf("upsert tool call log: %w", err)
	}
	if cmd.RowsAffected() > 0 {
		return true, nil
	}
	// Preserve endpoint-hook attribution when the first observed event is a
	// tool.post or when the pre event arrived through this upsert path.
	// The caller's attribution mode is part of the identity contract;
	// overwriting it with "none" makes the subsequent merge impossible.
	if err := prepareUpsertCreateFacts(log); err != nil {
		return false, err
	}
	if err := r.Create(ctx, log); err != nil {
		return false, err
	}
	return false, nil
}

// UpdateEndpointHook updates an endpoint hook record by tool_call_id.
// WHERE 限定 attribution_mode='endpoint_hook'，而 tool_call_logs_execution_fact_check 对 endpoint_hook 行整体豁免，
// 所以这里 execution_observed 的 OR 合并不会违约，保持原样。
func (r *ToolCallLogRepository) UpdateEndpointHook(ctx context.Context, log *ToolCallLog) (bool, error) {
	if log == nil || strings.TrimSpace(log.TenantID) == "" || strings.TrimSpace(log.ToolCallID) == "" {
		return false, fmt.Errorf("tenant_id and tool_call_id are required")
	}
	cmd, err := r.db.Exec(ctx, `UPDATE tool_call_logs SET tool_name=CASE WHEN $3 <> '' THEN $3 ELSE tool_name END, result=CASE WHEN $4 <> '' THEN $4 ELSE result END, status=CASE WHEN $5 <> '' THEN $5 ELSE status END, event_kind=CASE WHEN $6 <> '' THEN $6 ELSE event_kind END, execution_observed=execution_observed OR $7, result_observed=result_observed OR $8 WHERE tenant_id=$1 AND tool_call_id=$2 AND attribution_mode='endpoint_hook'`, log.TenantID, log.ToolCallID, log.ToolName, log.Result, log.Status, log.EventKind, log.ExecutionObserved, log.ResultObserved)
	if err != nil {
		return false, fmt.Errorf("update endpoint hook log: %w", err)
	}
	return cmd.RowsAffected() > 0, nil
}

// ListHighRisk returns tool calls with risk level >= high
func (r *ToolCallLogRepository) ListHighRisk(ctx context.Context, tenantID string, limit, offset int) ([]ToolCallLog, int, error) {
	return r.ListFiltered(ctx, ToolCallFilter{
		TenantID:  tenantID,
		RiskLevel: "high+",
		Limit:     limit,
		Offset:    offset,
	})
}

type ToolCallFilter struct {
	TenantID  string
	RequestID string
	StartDate time.Time
	EndDate   time.Time
	UserID    string
	ClientID  string
	ProjectID string
	SessionID string
	Mode      string
	RiskLevel string
	ToolName  string
	ToolType  string // file/network/database/mcp/system；MCP 审计页按 'mcp' 过滤
	EventKind string
	AgentType string
	PolicyID  string
	// RawDecision/EffectiveDecision：MCP 审计页双决策维度过滤（原始判定 vs 实际动作），
	// 直接匹配对应列，与前端表格展示的 raw_decision/effective_decision 列同源。
	RawDecision       string
	EffectiveDecision string
	// Server：MCP 服务名过滤。tool_call_logs 无独立 server_id 列，约定 tool_name='server__tool'，
	// 按 split_part(tool_name,'__',1) 取前缀比对（与 TopServers 派生同源）。
	Server            string
	Keyword           string
	DispositionStatus string
	AttentionOnly     bool
	Limit             int
	Offset            int
	SkipTotal         bool
}

type AgentRiskOverview struct {
	TotalToolCalls             int            `json:"total_tool_calls"`
	ToolCallAttempts           int            `json:"tool_call_attempts"`
	DefinitionExposedCount     int            `json:"definition_exposed_count"`
	InvocationProposedCount    int            `json:"invocation_proposed_count"`
	ExecutionForwardedCount    int            `json:"execution_forwarded_count"`
	ResultObservedCount        int            `json:"result_observed_count"`
	ConfirmationReplayCount    int            `json:"confirmation_replay_count"`
	UnknownEventCount          int            `json:"unknown_event_count"`
	RawDecisions               map[string]int `json:"raw_decisions"`
	EffectiveDecisions         map[string]int `json:"effective_decisions"`
	HighRiskCalls              int            `json:"high_risk_calls"`
	BlockedCalls               int            `json:"blocked_calls"`
	AuditCalls                 int            `json:"audit_calls"`
	ConfirmCalls               int            `json:"confirm_calls"`
	PendingConfirm             int            `json:"pending_confirm"`
	EffectiveMode              string         `json:"effective_mode"`
	EffectiveModeSource        string         `json:"effective_mode_source"`
	AuditCeiling               *bool          `json:"audit_ceiling"`
	RuntimeModeVerified        bool           `json:"runtime_mode_verified"`
	ConfiguredMode             string         `json:"configured_mode"`
	ConfiguredModeSource       string         `json:"configured_mode_source"`
	ConfiguredAuditCeiling     *bool          `json:"configured_audit_ceiling"`
	ConfirmationPending        int            `json:"confirmation_pending"`
	ConfirmationApproved       int            `json:"confirmation_approved"`
	ConfirmationRejected       int            `json:"confirmation_rejected"`
	ConfirmationExpired        int            `json:"confirmation_expired"`
	ConfirmationExecuted       int            `json:"confirmation_executed"`
	ConfirmationExecuting      int            `json:"confirmation_executing"`
	ConfirmationFailed         int            `json:"confirmation_failed"`
	ConfirmationUnknown        int            `json:"confirmation_unknown"`
	ConfirmationEvidenceFailed int            `json:"confirmation_evidence_failed"`

	ByRiskLevel []RiskLevelCount `json:"by_risk_level"`
	TopTools    []ToolCount      `json:"top_tools"`
	ByPolicy    []PolicyCount    `json:"by_policy"`
	TopUsers    []ObjectCount    `json:"top_users"`
	TopApps     []ObjectCount    `json:"top_apps"`
	TopKeys     []ObjectCount    `json:"top_keys"`
	TopSessions []ObjectCount    `json:"top_sessions"`
	TopAgents   []ObjectCount    `json:"top_agents"`
	// TopServers 是按 MCP server 聚合的 Top 榜（从 tool_name 的 'server__tool' 前缀派生，
	// tool_call_logs 无独立 server_id 列）。仅 MCP 态势（tool_type='mcp'）下有意义，
	// 其余维度也会返回但含义为「tool_name 首段」，前端只在 MCP 态势页展示。
	TopServers []ObjectCount `json:"top_servers"`
}

type RiskLevelCount struct {
	RiskLevel string `json:"risk_level"`
	Count     int    `json:"count"`
}

type ToolCount struct {
	ToolName string `json:"tool_name"`
	Count    int    `json:"count"`
}

type PolicyCount struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Mode       string `json:"mode"`
	Count      int    `json:"count"`
}

type ObjectCount struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func toolCallFilterWhere(filter ToolCallFilter) (string, []interface{}, error) {
	if filter.TenantID == "" {
		return "", nil, fmt.Errorf("tenant id is required")
	}

	where := []string{"tcl.tenant_id = $1"}
	args := []interface{}{filter.TenantID}
	if !filter.StartDate.IsZero() {
		args = append(args, filter.StartDate)
		where = append(where, fmt.Sprintf("tcl.created_at >= $%d", len(args)))
	}
	if !filter.EndDate.IsZero() {
		args = append(args, filter.EndDate)
		where = append(where, fmt.Sprintf("tcl.created_at < $%d", len(args)))
	}
	if filter.RequestID != "" {
		args = append(args, filter.RequestID)
		where = append(where, fmt.Sprintf("tcl.request_id = $%d", len(args)))
	}
	if filter.UserID != "" {
		args = append(args, filter.UserID)
		where = append(where, fmt.Sprintf("tcl.user_id = $%d", len(args)))
	}
	if filter.ClientID != "" {
		args = append(args, filter.ClientID)
		where = append(where, fmt.Sprintf("rl.client_id = $%d", len(args)))
	}
	if filter.ProjectID != "" {
		args = append(args, filter.ProjectID)
		where = append(where, fmt.Sprintf("rl.project_id = $%d", len(args)))
	}
	if filter.SessionID != "" {
		args = append(args, filter.SessionID)
		where = append(where, fmt.Sprintf("tcl.session_id = $%d", len(args)))
	}
	if filter.Mode != "" {
		args = append(args, filter.Mode)
		where = append(where, fmt.Sprintf("COALESCE(NULLIF(tcl.effective_decision, ''), tcl.mode) = $%d", len(args)))
	}
	if filter.RiskLevel == "high+" {
		where = append(where, "tcl.risk_level IN ('high', 'critical')", "NOT "+legacyShellSyntaxOnlySQL)
	} else if filter.RiskLevel != "" {
		args = append(args, filter.RiskLevel)
		where = append(where, fmt.Sprintf("tcl.risk_level = $%d", len(args)))
	}
	if filter.ToolName != "" {
		args = append(args, filter.ToolName)
		where = append(where, fmt.Sprintf("tcl.tool_name = $%d", len(args)))
	}
	if filter.ToolType != "" {
		args = append(args, filter.ToolType)
		where = append(where, fmt.Sprintf("tcl.tool_type = $%d", len(args)))
	}
	if filter.EventKind != "" {
		args = append(args, filter.EventKind)
		where = append(where, fmt.Sprintf("("+legacyToolEventKindQualifiedSQL+") = $%d", len(args)))
	}
	if filter.AgentType != "" {
		args = append(args, filter.AgentType)
		where = append(where, fmt.Sprintf("rl.agent_type = $%d", len(args)))
	}
	if filter.PolicyID != "" {
		args = append(args, filter.PolicyID)
		where = append(where, fmt.Sprintf("tcl.matched_policy_id = $%d", len(args)))
	}
	if filter.RawDecision != "" {
		args = append(args, filter.RawDecision)
		where = append(where, fmt.Sprintf("tcl.raw_decision = $%d", len(args)))
	}
	if filter.EffectiveDecision != "" {
		args = append(args, filter.EffectiveDecision)
		where = append(where, fmt.Sprintf("tcl.effective_decision = $%d", len(args)))
	}
	if filter.Server != "" {
		args = append(args, filter.Server)
		where = append(where, fmt.Sprintf("split_part(tcl.tool_name, '__', 1) = $%d", len(args)))
	}
	if strings.TrimSpace(filter.Keyword) != "" {
		args = append(args, "%"+escapePostgresLikeLiteral(strings.TrimSpace(filter.Keyword))+"%")
		arg := len(args)
		// operation_id / public_event_id / trace_id are the numbers an agent-side
		// block notice shows; they must be searchable from the console.
		where = append(where, fmt.Sprintf(`(
			tcl.tool_name ILIKE $%[1]d ESCAPE E'\\'
			OR COALESCE(tcl.matched_policy_name, '') ILIKE $%[1]d ESCAPE E'\\'
			OR COALESCE(tcl.match_reason, '') ILIKE $%[1]d ESCAPE E'\\'
			OR COALESCE(tcl.request_id, '') ILIKE $%[1]d ESCAPE E'\\'
			OR COALESCE(tcl.session_id, '') ILIKE $%[1]d ESCAPE E'\\'
			OR COALESCE(tcl.user_id, '') ILIKE $%[1]d ESCAPE E'\\'
			OR COALESCE(tcl.operation_id, '') ILIKE $%[1]d ESCAPE E'\\'
			OR COALESCE(tcl.public_event_id, '') ILIKE $%[1]d ESCAPE E'\\'
			OR COALESCE(tcl.trace_id, '') ILIKE $%[1]d ESCAPE E'\\'
		)`, arg))
	}
	if filter.DispositionStatus != "" {
		args = append(args, filter.DispositionStatus)
		where = append(where, fmt.Sprintf("COALESCE(ad.status, 'open') = $%d", len(args)))
	}
	if filter.AttentionOnly {
		where = append(where, "(tcl.tool_type <> 'system' OR LOWER(COALESCE(NULLIF(tcl.matched_action, ''), tcl.mode, '')) <> 'audit' OR LOWER(tcl.status) IN ('blocked', 'denied'))")
	}
	return strings.Join(where, " AND "), args, nil
}

func normalizeToolCallPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// ListAuditPage applies every filter in PostgreSQL before pagination and returns
// only the fields needed by the list UI.
func (r *ToolCallLogRepository) ListAuditPage(ctx context.Context, filter ToolCallFilter) (*ToolCallAuditPage, error) {
	where, args, err := toolCallFilterWhere(filter)
	if err != nil {
		return nil, err
	}
	filter.Limit, filter.Offset = normalizeToolCallPage(filter.Limit, filter.Offset)
	query, listArgs, countQuery, countArgs := buildToolCallAuditPageQuery(where, args, filter)

	page := &ToolCallAuditPage{
		Data:       []ToolCallAuditListItem{},
		TotalKnown: !filter.SkipTotal,
		Limit:      filter.Limit,
		Offset:     filter.Offset,
	}
	if page.TotalKnown {
		if err := r.db.QueryRow(ctx, countQuery, countArgs...).Scan(&page.Total); err != nil {
			return nil, fmt.Errorf("failed to count filtered tool audit rows: %w", err)
		}
	}
	rows, err := r.db.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to list filtered tool audit rows: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item ToolCallAuditListItem
		if err := rows.Scan(
			&item.ID, &item.RequestID, &item.SessionID, &item.UserID,
			&item.ApplicationID, &item.AgentType, &item.Model, &item.Protocol,
			&item.ToolName, &item.ToolType, &item.RiskLevel, &item.Status,
			&item.MatchedPolicyID, &item.MatchedPolicyName, &item.MatchedAction, &item.MatchReason,
			&item.RawDecision, &item.EffectiveDecision, &item.Mode, &item.EffectiveReason,
			&item.DispositionStatus, &item.DispositionNote, &item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan filtered tool audit row: %w", err)
		}
		page.Data = append(page.Data, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Data) > page.Limit {
		page.HasMore = true
		page.Data = page.Data[:page.Limit]
	}
	return page, nil
}

const toolCallAuditListColumns = `
tcl.id,
COALESCE(tcl.request_id, ''),
COALESCE(tcl.session_id, ''),
COALESCE(tcl.user_id, ''),
COALESCE(tcl.application_id, ''),
COALESCE(NULLIF(tcl.agent_type, ''), rl.agent_type, ''),
COALESCE(tcl.model, ''),
COALESCE(tcl.protocol, ''),
tcl.tool_name,
tcl.tool_type,
tcl.risk_level,
tcl.status,
COALESCE(tcl.matched_policy_id, ''),
COALESCE(tcl.matched_policy_name, ''),
COALESCE(tcl.matched_action, ''),
COALESCE(tcl.match_reason, ''),
COALESCE(tcl.raw_decision, ''),
COALESCE(tcl.effective_decision, ''),
COALESCE(tcl.mode, ''),
COALESCE(tcl.effective_reason, ''),
COALESCE(ad.status, 'open'),
LEFT(COALESCE(ad.note, ''), 500),
tcl.created_at`

func buildToolCallAuditPageQuery(where string, args []interface{}, filter ToolCallFilter) (string, []interface{}, string, []interface{}) {
	joins := `
FROM tool_call_logs tcl
LEFT JOIN request_logs rl
  ON rl.request_id = tcl.request_id AND rl.tenant_id = tcl.tenant_id
LEFT JOIN audit_dispositions ad
  ON ad.tenant_id = tcl.tenant_id
 AND ad.subject_type = 'tool_call'
 AND ad.subject_id = tcl.id`
	limit, offset := normalizeToolCallPage(filter.Limit, filter.Offset)
	listArgs := append([]interface{}{}, args...)
	listArgs = append(listArgs, limit+1, offset)
	limitIdx := len(args) + 1
	offsetIdx := len(args) + 2
	query := fmt.Sprintf(`
SELECT %s
%s
WHERE %s
ORDER BY tcl.created_at DESC, tcl.id DESC
LIMIT $%d OFFSET $%d
`, toolCallAuditListColumns, joins, where, limitIdx, offsetIdx)
	countQuery := fmt.Sprintf(`
SELECT COUNT(*)::int
%s
WHERE %s
`, joins, where)
	return query, listArgs, countQuery, append([]interface{}{}, args...)
}

// ListFiltered lists tool calls with tenant isolation plus optional request-owner dimensions.
func (r *ToolCallLogRepository) ListFiltered(ctx context.Context, filter ToolCallFilter) ([]ToolCallLog, int, error) {
	where, args, err := toolCallFilterWhere(filter)
	if err != nil {
		return nil, 0, err
	}

	query, listArgs, countQuery, countArgs := buildToolCallListQuery(where, args, filter)
	total := 0
	if !filter.SkipTotal {
		if err := r.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("failed to count filtered tool calls: %w", err)
		}
	}

	rows, err := r.db.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list filtered tool calls: %w", err)
	}
	defer rows.Close()

	logs := []ToolCallLog{}
	for rows.Next() {
		log, err := scanToolCallLog(rows)
		if err != nil {
			return nil, 0, err
		}
		logs = append(logs, log)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if filter.SkipTotal {
		total = len(logs)
	}
	return logs, total, nil
}

func buildToolCallListQuery(where string, args []interface{}, filter ToolCallFilter) (string, []interface{}, string, []interface{}) {
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)::int
		FROM tool_call_logs tcl
		LEFT JOIN request_logs rl ON rl.request_id = tcl.request_id AND rl.tenant_id = tcl.tenant_id
		WHERE %s
	`, where)

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	listArgs := make([]interface{}, len(args))
	copy(listArgs, args)
	listArgs = append(listArgs, limit, offset)
	limitIdx := len(args) + 1
	offsetIdx := len(args) + 2
	query := fmt.Sprintf(`
		SELECT `+toolCallLogSelectColumnsQualified+`
		FROM tool_call_logs tcl
		LEFT JOIN request_logs rl ON rl.request_id = tcl.request_id AND rl.tenant_id = tcl.tenant_id
		WHERE %s
		ORDER BY tcl.created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, limitIdx, offsetIdx)
	countArgs := append([]interface{}{}, args...)
	return query, listArgs, countQuery, countArgs
}

// GetRiskOverview returns tenant-scoped AgentGuard risk counters and top dimensions.
// toolType 非空时按 tcl.tool_type 过滤（MCP 态势页传 'mcp' 只看 MCP 调用）；
// 空=不过滤，行为与旧签名一致（向后兼容）。
func (r *ToolCallLogRepository) GetRiskOverview(ctx context.Context, tenantID string, startDate, endDate time.Time, toolType string) (*AgentRiskOverview, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	overview := &AgentRiskOverview{
		RawDecisions:       map[string]int{},
		EffectiveDecisions: map[string]int{},
		ByRiskLevel:        []RiskLevelCount{},
		TopTools:           []ToolCount{},
		ByPolicy:           []PolicyCount{},
		TopUsers:           []ObjectCount{},
		TopApps:            []ObjectCount{},
		TopKeys:            []ObjectCount{},
		TopSessions:        []ObjectCount{},
		TopAgents:          []ObjectCount{},
		TopServers:         []ObjectCount{},
	}

	where := "tcl.tenant_id = $1 AND tcl.created_at >= $2 AND tcl.created_at < $3"
	args := []interface{}{tenantID, startDate, endDate}
	if toolType != "" {
		args = append(args, toolType)
		where += fmt.Sprintf(" AND tcl.tool_type = $%d", len(args))
	}
	counterQuery := fmt.Sprintf(riskOverviewNormalizedCTE, where) + `
		SELECT
			(SELECT COUNT(*)::int FROM attempt_events),
			(SELECT COUNT(*)::int FROM normalized_events WHERE normalized_event_kind = 'definition_exposed'),
			(SELECT COUNT(*)::int FROM normalized_events WHERE normalized_event_kind = 'invocation_proposed'),
			(SELECT COUNT(*)::int FROM normalized_events WHERE normalized_event_kind = 'execution_forwarded' AND COALESCE(execution_observed, FALSE)),
			(SELECT COUNT(*)::int FROM normalized_events WHERE normalized_event_kind = 'result_observed' AND COALESCE(result_observed, FALSE)),
			(SELECT COUNT(*)::int FROM normalized_events WHERE normalized_event_kind = 'confirmation_replay'),
			(SELECT COUNT(*)::int FROM normalized_events WHERE normalized_event_kind = 'legacy_unknown'),
			(SELECT COUNT(*)::int FROM attempt_events WHERE risk_level IN ('high', 'critical')),
			(SELECT COUNT(*)::int FROM attempt_events WHERE normalized_raw_decision = 'allow'),
			(SELECT COUNT(*)::int FROM attempt_events WHERE normalized_raw_decision = 'audit'),
			(SELECT COUNT(*)::int FROM attempt_events WHERE normalized_raw_decision = 'confirm'),
			(SELECT COUNT(*)::int FROM attempt_events WHERE normalized_raw_decision = 'block'),
			(SELECT COUNT(*)::int FROM attempt_events WHERE normalized_raw_decision NOT IN ('allow', 'audit', 'confirm', 'block')),
			(SELECT COUNT(*)::int FROM attempt_events WHERE normalized_effective_decision = 'allow'),
			(SELECT COUNT(*)::int FROM attempt_events WHERE normalized_effective_decision = 'audit'),
			(SELECT COUNT(*)::int FROM attempt_events WHERE normalized_effective_decision = 'confirm'),
			(SELECT COUNT(*)::int FROM attempt_events WHERE normalized_effective_decision = 'block'),
			(SELECT COUNT(*)::int FROM attempt_events WHERE normalized_effective_decision NOT IN ('allow', 'audit', 'confirm', 'block'))
	`
	var rawAllow, rawAudit, rawConfirm, rawBlock, rawUnknown int
	var effectiveAllow, effectiveAudit, effectiveConfirm, effectiveBlock, effectiveUnknown int
	if err := r.db.QueryRow(ctx, counterQuery, args...).Scan(
		&overview.ToolCallAttempts,
		&overview.DefinitionExposedCount,
		&overview.InvocationProposedCount,
		&overview.ExecutionForwardedCount,
		&overview.ResultObservedCount,
		&overview.ConfirmationReplayCount,
		&overview.UnknownEventCount,
		&overview.HighRiskCalls,
		&rawAllow, &rawAudit, &rawConfirm, &rawBlock, &rawUnknown,
		&effectiveAllow, &effectiveAudit, &effectiveConfirm, &effectiveBlock, &effectiveUnknown,
	); err != nil {
		return nil, fmt.Errorf("failed to get risk overview counters: %w", err)
	}
	overview.TotalToolCalls = overview.ToolCallAttempts
	overview.RawDecisions = map[string]int{"allow": rawAllow, "audit": rawAudit, "confirm": rawConfirm, "block": rawBlock, "unknown": rawUnknown}
	overview.EffectiveDecisions = map[string]int{"allow": effectiveAllow, "audit": effectiveAudit, "confirm": effectiveConfirm, "block": effectiveBlock, "unknown": effectiveUnknown}
	overview.BlockedCalls = effectiveBlock
	overview.AuditCalls = effectiveAudit
	overview.ConfirmCalls = effectiveConfirm
	if err := r.populateRiskOverviewConfirmationCounts(ctx, overview, tenantID, startDate, endDate, toolType); err != nil {
		return nil, err
	}

	var err error
	if overview.ByRiskLevel, err = r.listRiskLevelCounts(ctx, where, args); err != nil {
		return nil, err
	}
	if overview.TopTools, err = r.listToolCounts(ctx, where, args); err != nil {
		return nil, err
	}
	if overview.ByPolicy, err = r.listPolicyCounts(ctx, where, args); err != nil {
		return nil, err
	}
	factCTE := fmt.Sprintf(riskOverviewNormalizedCTE, where)
	if overview.TopUsers, err = r.listObjectCounts(ctx, factCTE+`
		SELECT ae.user_id AS id, COALESCE(NULLIF(u.username, ''), ae.user_id) AS name, COUNT(*)::int AS count
		FROM attempt_events ae
		LEFT JOIN users u ON u.id = ae.user_id AND u.tenant_id = ae.tenant_id
		WHERE COALESCE(ae.user_id, '') <> '' AND ae.risk_level IN ('high', 'critical')
		GROUP BY ae.user_id, u.username
		ORDER BY count DESC, id ASC
		LIMIT 5
	`, args, "top users"); err != nil {
		return nil, err
	}
	if overview.TopApps, err = r.listObjectCounts(ctx, factCTE+`
		SELECT rl.project_id AS id, COALESCE(NULLIF(p.name, ''), rl.project_id) AS name, COUNT(*)::int AS count
		FROM attempt_events ae
		LEFT JOIN request_logs rl ON rl.request_id = ae.request_id AND rl.tenant_id = ae.tenant_id
		LEFT JOIN projects p ON p.id = rl.project_id AND p.tenant_id = ae.tenant_id
		WHERE COALESCE(rl.project_id, '') <> ''
		GROUP BY rl.project_id, p.name
		ORDER BY count DESC, id ASC
		LIMIT 5
	`, args, "top apps"); err != nil {
		return nil, err
	}
	if overview.TopKeys, err = r.listObjectCounts(ctx, factCTE+`
		SELECT rl.client_id AS id, COALESCE(NULLIF(k.key_prefix, ''), rl.client_id) AS name, COUNT(*)::int AS count
		FROM attempt_events ae
		LEFT JOIN request_logs rl ON rl.request_id = ae.request_id AND rl.tenant_id = ae.tenant_id
		LEFT JOIN internal_keys k ON k.id = rl.client_id AND k.tenant_id = ae.tenant_id
		WHERE COALESCE(rl.client_id, '') <> ''
		GROUP BY rl.client_id, k.key_prefix
		ORDER BY count DESC, id ASC
		LIMIT 5
	`, args, "top keys"); err != nil {
		return nil, err
	}
	if overview.TopSessions, err = r.listObjectCounts(ctx, factCTE+`
		SELECT session_id AS id, session_id AS name, COUNT(*)::int AS count
		FROM attempt_events
		WHERE COALESCE(session_id, '') <> ''
		GROUP BY session_id
		ORDER BY count DESC, id ASC
		LIMIT 5
	`, args, "top sessions"); err != nil {
		return nil, err
	}
	// TopAgents only groups high/critical attempts by the originating agent.
	if overview.TopAgents, err = r.listObjectCounts(ctx, factCTE+`
		SELECT rl.agent_type AS id, rl.agent_type AS name, COUNT(*)::int AS count
		FROM attempt_events ae
		LEFT JOIN request_logs rl ON rl.request_id = ae.request_id AND rl.tenant_id = ae.tenant_id
		WHERE COALESCE(rl.agent_type, '') <> '' AND ae.risk_level IN ('high', 'critical')
		GROUP BY rl.agent_type
		ORDER BY count DESC, id ASC
		LIMIT 5
	`, args, "top agents"); err != nil {
		return nil, err
	}
	for i := range overview.TopAgents {
		overview.TopAgents[i].Name = agentdetect.Label(overview.TopAgents[i].ID)
	}
	// TopServers：MCP 审计约定 tool_name = 'server__tool'（mcp_proxy 建单时 server.Name+'__'+tool），
	// 用 split_part(tool_name,'__',1) 取前缀作 server 名。tool_call_logs 无独立 server_id 列，
	// 故从名字派生；无 '__' 分隔的行整名回退为 server（对非 MCP 维度无害，前端只在 MCP 态势展示）。
	if overview.TopServers, err = r.listObjectCounts(ctx, factCTE+`
		SELECT split_part(tool_name, '__', 1) AS id, split_part(tool_name, '__', 1) AS name, COUNT(*)::int AS count
		FROM attempt_events
		WHERE COALESCE(tool_name, '') <> ''
		GROUP BY split_part(tool_name, '__', 1)
		ORDER BY count DESC, id ASC
		LIMIT 10
	`, args, "top servers"); err != nil {
		return nil, err
	}
	return overview, nil
}

func (r *ToolCallLogRepository) populateRiskOverviewConfirmationCounts(
	ctx context.Context,
	overview *AgentRiskOverview,
	tenantID string,
	startDate, endDate time.Time,
	toolType string,
) error {
	where := "c.tenant_id = $1 AND c.created_at >= $2 AND c.created_at < $3"
	args := []interface{}{tenantID, startDate, endDate}
	if toolType == "mcp" {
		where += " AND COALESCE(c.source, '') = 'mcp'"
	} else if toolType != "" {
		args = append(args, toolType)
		where += fmt.Sprintf(` AND EXISTS (
			SELECT 1
			FROM tool_call_logs scoped_tcl
			WHERE scoped_tcl.tenant_id = c.tenant_id
			  AND COALESCE(c.request_id, '') <> ''
			  AND scoped_tcl.request_id = c.request_id
			  AND COALESCE(c.tool_call_id, '') <> ''
			  AND scoped_tcl.tool_call_id = c.tool_call_id
			  AND scoped_tcl.tool_name = c.tool_name
			  AND scoped_tcl.tool_type = $%d
		)`, len(args))
	}
	query := fmt.Sprintf(`
		WITH scoped_confirmations AS (
			SELECT c.*,
			       CASE
			         WHEN c.status = 'pending' AND c.expires_at <= CURRENT_TIMESTAMP THEN 'expired'
			         ELSE c.status
			       END AS normalized_status
			FROM agentguard_confirmations c
			WHERE %s
		)
		SELECT
			(COUNT(*) FILTER (WHERE c.normalized_status = 'pending'))::int,
			(COUNT(*) FILTER (WHERE c.normalized_status = 'approved'))::int,
			(COUNT(*) FILTER (WHERE c.normalized_status = 'rejected'))::int,
			(COUNT(*) FILTER (WHERE c.normalized_status = 'expired'))::int,
			(COUNT(*) FILTER (
				WHERE c.normalized_status = 'approved'
				  AND c.replay_status = 'executed'
				  AND COALESCE(c.source, '') <> 'mcp'
				  AND COALESCE(c.replay_tool_log_id, '') <> ''
				  AND EXISTS (
					SELECT 1
					FROM tool_call_logs tcl
					WHERE tcl.tenant_id = c.tenant_id
					  AND tcl.id = c.replay_tool_log_id
					  AND (`+riskOverviewEventKindSQL+`) = 'execution_forwarded'
					  AND COALESCE(tcl.execution_observed, FALSE)
					  AND COALESCE(c.tool_call_id, '') <> ''
					  AND tcl.tool_call_id = c.tool_call_id
					  AND tcl.tool_name = c.tool_name
					  AND (COALESCE(c.request_id, '') = '' OR tcl.request_id = c.request_id)
					  AND tcl.created_at >= COALESCE(c.resolved_at, c.created_at)
					  AND (tcl.tool_type <> 'mcp' OR tcl.provenance = 'mcp_gateway')
				  )
			))::int
		FROM scoped_confirmations c
	`, where)
	if err := r.db.QueryRow(ctx, query, args...).Scan(
		&overview.ConfirmationPending,
		&overview.ConfirmationApproved,
		&overview.ConfirmationRejected,
		&overview.ConfirmationExpired,
		&overview.ConfirmationExecuted,
	); err != nil {
		return fmt.Errorf("failed to get confirmation overview counters: %w", err)
	}
	if toolType == "" || toolType == "mcp" {
		var executed, executing, failed, unknown, evidenceFailed int
		err := r.db.QueryRow(ctx, `
			SELECT
				(COUNT(*) FILTER (
					WHERE e.execution_status = 'executed'
					  AND e.evidence_status = 'complete'
					  AND COALESCE(e.audit_request_id, '') <> ''
					  AND COALESCE(e.tool_log_id, '') <> ''
					  AND EXISTS (
						SELECT 1 FROM tool_call_logs tcl
						WHERE tcl.tenant_id = e.tenant_id
						  AND tcl.id = e.tool_log_id
						  AND tcl.request_id = e.audit_request_id
						  AND tcl.tool_type = 'mcp'
						  AND tcl.provenance = 'mcp_gateway'
						  AND (`+riskOverviewEventKindSQL+`) = 'execution_forwarded'
						  AND COALESCE(tcl.execution_observed, FALSE)
						  AND COALESCE(c.tool_call_id, '') <> ''
						  AND tcl.tool_call_id = c.tool_call_id
						  AND tcl.tool_name = c.tool_name
						  AND tcl.created_at >= COALESCE(e.started_at, c.resolved_at, c.created_at)
					  )
				))::int,
				(COUNT(*) FILTER (WHERE e.execution_status = 'executing'))::int,
				(COUNT(*) FILTER (WHERE e.execution_status = 'failed'))::int,
				(COUNT(*) FILTER (WHERE e.execution_status = 'unknown'))::int,
				(COUNT(*) FILTER (WHERE e.evidence_status = 'failed'))::int
			FROM mcp_confirmation_executions e
			JOIN agentguard_confirmations c
			  ON c.id = e.confirmation_id AND c.tenant_id = e.tenant_id
			WHERE e.tenant_id = $1
			  AND c.created_at >= $2 AND c.created_at < $3
			  AND COALESCE(c.source, '') = 'mcp'
			  AND c.status = 'approved'
		`, tenantID, startDate, endDate).Scan(
			&executed, &executing, &failed, &unknown, &evidenceFailed,
		)
		if err != nil {
			return fmt.Errorf("failed to get MCP confirmation execution counters: %w", err)
		}
		overview.ConfirmationExecuted += executed
		overview.ConfirmationExecuting = executing
		overview.ConfirmationFailed = failed
		overview.ConfirmationUnknown = unknown
		overview.ConfirmationEvidenceFailed = evidenceFailed
	}

	overview.PendingConfirm = overview.ConfirmationPending
	return nil
}

func (r *ToolCallLogRepository) listRiskLevelCounts(ctx context.Context, where string, args []interface{}) ([]RiskLevelCount, error) {
	query := fmt.Sprintf(riskOverviewNormalizedCTE, where) + `
		SELECT COALESCE(NULLIF(risk_level, ''), 'unknown') AS risk_level, COUNT(*)::int AS count
		FROM attempt_events
		GROUP BY risk_level
		ORDER BY count DESC, risk_level ASC
	`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list risk level counts: %w", err)
	}
	defer rows.Close()

	items := []RiskLevelCount{}
	for rows.Next() {
		var item RiskLevelCount
		if err := rows.Scan(&item.RiskLevel, &item.Count); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *ToolCallLogRepository) listToolCounts(ctx context.Context, where string, args []interface{}) ([]ToolCount, error) {
	query := fmt.Sprintf(riskOverviewNormalizedCTE, where) + `
		SELECT tool_name, COUNT(*)::int AS count
		FROM attempt_events
		GROUP BY tool_name
		ORDER BY count DESC, tool_name ASC
		LIMIT 10
	`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list tool counts: %w", err)
	}
	defer rows.Close()

	items := []ToolCount{}
	for rows.Next() {
		var item ToolCount
		if err := rows.Scan(&item.ToolName, &item.Count); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *ToolCallLogRepository) listPolicyCounts(ctx context.Context, where string, args []interface{}) ([]PolicyCount, error) {
	query := fmt.Sprintf(riskOverviewNormalizedCTE, where) + `
		SELECT COALESCE(matched_policy_id, '') AS policy_id,
		       COALESCE(matched_policy_name, '') AS policy_name,
		       normalized_effective_decision AS mode,
		       COUNT(*)::int AS count
		FROM attempt_events
		WHERE matched_policy_id IS NOT NULL
		GROUP BY matched_policy_id, matched_policy_name, normalized_effective_decision
		ORDER BY count DESC, policy_id ASC, mode ASC
	`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list policy counts: %w", err)
	}
	defer rows.Close()

	items := []PolicyCount{}
	for rows.Next() {
		var item PolicyCount
		if err := rows.Scan(&item.PolicyID, &item.PolicyName, &item.Mode, &item.Count); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *ToolCallLogRepository) listObjectCounts(ctx context.Context, query string, args []interface{}, label string) ([]ObjectCount, error) {
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list %s: %w", label, err)
	}
	defer rows.Close()

	items := []ObjectCount{}
	for rows.Next() {
		var item ObjectCount
		if err := rows.Scan(&item.ID, &item.Name, &item.Count); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListBySession returns all tool calls in a session (time-ordered)
func (r *ToolCallLogRepository) ListBySession(ctx context.Context, tenantID, sessionID string) ([]ToolCallLog, error) {
	query := `
		SELECT ` + toolCallLogSelectColumns + `
		FROM tool_call_logs
		WHERE tenant_id = $1 AND session_id = $2
		ORDER BY created_at ASC
	`
	rows, err := r.db.Query(ctx, query, tenantID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tool calls by session: %w", err)
	}
	defer rows.Close()

	var logs []ToolCallLog
	for rows.Next() {
		log, err := scanToolCallLog(rows)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

// ListBySessionLimited returns the newest bounded detail rows in timeline order.
func (r *ToolCallLogRepository) ListBySessionLimited(ctx context.Context, tenantID, sessionID string, limit int) ([]ToolCallLog, error) {
	limit, _ = normalizeToolCallPage(limit, 0)
	query := `
		SELECT ` + toolCallLogSelectColumns + `
		FROM (
			SELECT *
			FROM tool_call_logs
			WHERE tenant_id = $1 AND session_id = $2
			ORDER BY created_at DESC, id DESC
			LIMIT $3
		) bounded
		ORDER BY created_at ASC, id ASC
	`
	rows, err := r.db.Query(ctx, query, tenantID, sessionID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list bounded tool calls by session: %w", err)
	}
	defer rows.Close()

	logs := []ToolCallLog{}
	for rows.Next() {
		log, err := scanToolCallLog(rows)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

// ListByUser returns recent tool calls for a user
func (r *ToolCallLogRepository) ListByUser(ctx context.Context, tenantID, userID string, limit, offset int) ([]ToolCallLog, int, error) {
	countQuery := `SELECT COUNT(*) FROM tool_call_logs WHERE tenant_id = $1 AND user_id = $2`
	var total int
	if err := r.db.QueryRow(ctx, countQuery, tenantID, userID).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
		SELECT ` + toolCallLogSelectColumns + `
		FROM tool_call_logs
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := r.db.Query(ctx, query, tenantID, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list tool calls by user: %w", err)
	}
	defer rows.Close()

	var logs []ToolCallLog
	for rows.Next() {
		log, err := scanToolCallLog(rows)
		if err != nil {
			return nil, 0, err
		}
		logs = append(logs, log)
	}
	return logs, total, nil
}

// GetStats returns aggregated statistics by tool type
func (r *ToolCallLogRepository) GetStats(ctx context.Context, tenantID string) ([]ToolCallStats, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	return r.getStats(ctx, "tcl.tenant_id = $1 AND tcl.created_at < CURRENT_TIMESTAMP", []interface{}{tenantID})
}

// GetStatsWindow returns lifecycle and call-fact statistics in the half-open [startDate,endDate) window.
func (r *ToolCallLogRepository) GetStatsWindow(ctx context.Context, tenantID string, startDate, endDate time.Time) ([]ToolCallStats, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	if !endDate.After(startDate) {
		return nil, fmt.Errorf("end date must be after start date")
	}
	return r.getStats(
		ctx,
		"tcl.tenant_id = $1 AND tcl.created_at >= $2 AND tcl.created_at < $3",
		[]interface{}{tenantID, startDate, endDate},
	)
}

func (r *ToolCallLogRepository) getStats(ctx context.Context, where string, args []interface{}) ([]ToolCallStats, error) {
	query := fmt.Sprintf(riskOverviewNormalizedCTE, where) + `
		, lifecycle_stats AS (
			SELECT tool_type,
			       (COUNT(*) FILTER (WHERE normalized_event_kind = 'definition_exposed'))::int AS definition_exposed_count,
			       (COUNT(*) FILTER (WHERE normalized_event_kind = 'invocation_proposed'))::int AS invocation_proposed_count,
			       (COUNT(*) FILTER (WHERE normalized_event_kind = 'execution_forwarded' AND COALESCE(execution_observed, FALSE)))::int AS execution_forwarded_count,
			       (COUNT(*) FILTER (WHERE normalized_event_kind = 'result_observed' AND COALESCE(result_observed, FALSE)))::int AS result_observed_count,
			       (COUNT(*) FILTER (WHERE normalized_event_kind = 'confirmation_replay'))::int AS confirmation_replay_count,
			       (COUNT(*) FILTER (WHERE normalized_event_kind = 'legacy_unknown'))::int AS unknown_event_count
			FROM normalized_events
			GROUP BY tool_type
		), attempt_stats AS (
			SELECT tool_type,
			       COUNT(*)::int AS count,
			       (COUNT(*) FILTER (WHERE risk_level = 'low'))::int AS low_count,
			       (COUNT(*) FILTER (WHERE risk_level = 'medium'))::int AS medium_count,
			       (COUNT(*) FILTER (WHERE risk_level = 'high'))::int AS high_count,
			       (COUNT(*) FILTER (WHERE risk_level = 'critical'))::int AS critical_count
			FROM attempt_events
			GROUP BY tool_type
		)
		SELECT
			l.tool_type,
			COALESCE(a.count, 0), COALESCE(a.low_count, 0), COALESCE(a.medium_count, 0),
			COALESCE(a.high_count, 0), COALESCE(a.critical_count, 0),
			l.definition_exposed_count, l.invocation_proposed_count, l.execution_forwarded_count,
			l.result_observed_count, l.confirmation_replay_count, l.unknown_event_count
		FROM lifecycle_stats l
		LEFT JOIN attempt_stats a ON a.tool_type = l.tool_type
		ORDER BY COALESCE(a.count, 0) DESC, l.tool_type ASC
	`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get tool call stats: %w", err)
	}
	defer rows.Close()

	var stats []ToolCallStats
	for rows.Next() {
		var s ToolCallStats
		if err := rows.Scan(
			&s.ToolType, &s.Count, &s.LowCount, &s.MediumCount, &s.HighCount, &s.CriticalCount,
			&s.DefinitionExposedCount, &s.InvocationProposedCount, &s.ExecutionForwardedCount,
			&s.ResultObservedCount, &s.ConfirmationReplayCount, &s.UnknownEventCount,
		); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, nil
}

// GetRiskTrend returns daily risk trend for the last N days
func (r *ToolCallLogRepository) GetRiskTrend(ctx context.Context, tenantID string, days int) ([]RiskTrendPoint, error) {
	where := "tcl.tenant_id = $1 AND tcl.created_at >= CURRENT_DATE - INTERVAL '1 day' * $2 AND tcl.created_at < CURRENT_TIMESTAMP"
	query := fmt.Sprintf(riskOverviewNormalizedCTE, where) + `
		SELECT
			DATE(created_at) as date,
			COUNT(*) FILTER (WHERE risk_level = 'high') as high_count,
			COUNT(*) FILTER (WHERE risk_level = 'critical') as critical_count
		FROM attempt_events
		GROUP BY DATE(created_at)
		ORDER BY date ASC
	`
	rows, err := r.db.Query(ctx, query, tenantID, days)
	if err != nil {
		return nil, fmt.Errorf("failed to get risk trend: %w", err)
	}
	defer rows.Close()

	var trend []RiskTrendPoint
	for rows.Next() {
		var p RiskTrendPoint
		var date time.Time
		if err := rows.Scan(&date, &p.HighCount, &p.CriticalCount); err != nil {
			return nil, err
		}
		p.Date = date.Format("2006-01-02")
		trend = append(trend, p)
	}
	return trend, nil
}

// DeleteOlderThan deletes logs older than retention days, returning rows deleted.
func (r *ToolCallLogRepository) DeleteOlderThan(ctx context.Context, retentionDays int) (int64, error) {
	query := `DELETE FROM tool_call_logs WHERE created_at < CURRENT_DATE - INTERVAL '1 day' * $1`
	tag, err := r.db.Exec(ctx, query, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old tool call logs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListByRequest returns all tool call logs for a specific request_id
func (r *ToolCallLogRepository) ListByRequest(ctx context.Context, tenantID, requestID string) ([]ToolCallLog, error) {
	query := `
		SELECT ` + toolCallLogSelectColumns + `
		FROM tool_call_logs
		WHERE tenant_id = $1 AND request_id = $2
		ORDER BY created_at ASC
	`
	rows, err := r.db.Query(ctx, query, tenantID, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tool calls by request: %w", err)
	}
	defer rows.Close()

	var logs []ToolCallLog
	for rows.Next() {
		log, err := scanToolCallLog(rows)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

func scanToolCallLog(scanner toolCallLogScanner) (ToolCallLog, error) {
	var log ToolCallLog
	var evidenceJSON string
	var taintedArguments string
	err := scanner.Scan(
		&log.ID, &log.RequestID, &log.SessionID, &log.TenantID, &log.EndpointID, &log.UserID, &log.ToolName, &log.ToolType, &log.RiskLevel,
		&log.Parameters, &log.Result, &log.Status, &log.MatchedPolicyID, &log.MatchedPolicyName, &log.MatchedAction, &log.MatchReason,
		&log.RawDecision, &log.EffectiveDecision, &log.Mode, &log.EffectiveReason, &log.PolicyVersion, &log.TraceID, &log.Confidence,
		&evidenceJSON, &log.NormalizedTarget, &log.Provenance, &taintedArguments,
		&log.EventKind, &log.ExecutionObserved, &log.ResultObserved, &log.ToolCallID, &log.AssetID, &log.SkillInvocationID,
		&log.MCPServerID, &log.MCPToolID, &log.DefinitionHash, &log.AttributionMode, &log.AttributionConfidence,
		&log.ApplicationID, &log.AgentType, &log.Model, &log.Protocol, &log.PublicEventID, &log.CreatedAt,
	)
	if err != nil {
		return ToolCallLog{}, err
	}
	log.EvidenceJSON = json.RawMessage(rawJSONOrDefault(json.RawMessage(evidenceJSON), "[]"))
	log.TaintedArguments = json.RawMessage(rawJSONOrDefault(json.RawMessage(taintedArguments), "[]"))
	return log, nil
}

func validDestructiveEventType(eventType string) bool {
	switch eventType {
	case "tool_destructive_intent", "tool_attempt_blocked", "tool_execution_risk":
		return true
	default:
		return false
	}
}

func validToolEventKind(kind string) bool {
	// Endpoint hook wire events use tool.pre/tool.post; normalize them to
	// the canonical lifecycle vocabulary used by the audit schema.
	if kind == "tool_pre" {
		kind = "invocation_proposed"
	}
	if kind == "tool_post" {
		kind = "result_observed"
	}
	switch kind {
	case "legacy_unknown", "definition_exposed", "invocation_proposed", "execution_forwarded", "result_observed", "confirmation_replay":
		return true
	default:
		return false
	}
}

func validAttribution(mode string, confidence float64) bool {
	if confidence < 0 || confidence > 1 {
		return false
	}
	if mode == "" {
		return confidence == 0
	}
	switch mode {
	case "explicit", "linked", "inferred", "none", "endpoint_hook":
		return true
	default:
		return false
	}
}

func rawJSONOrDefault(raw json.RawMessage, fallback string) string {
	if len(raw) == 0 || !json.Valid(raw) {
		return fallback
	}
	return string(raw)
}
func (r *ToolCallLogRepository) CreateDestructiveLifecycle(ctx context.Context, log *ToolCallLog) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("tool call log repository is unavailable")
	}
	if log == nil {
		return fmt.Errorf("tool call log is required")
	}
	if log.ID == "" {
		log.ID = newToolCallLogID()
	}
	if log.EventKind == "" {
		log.EventKind = "legacy_unknown"
	}
	if !validToolEventKind(log.EventKind) {
		return fmt.Errorf("invalid tool event kind %q", log.EventKind)
	}
	if !validAttribution(log.AttributionMode, log.AttributionConfidence) {
		return fmt.Errorf("invalid tool attribution mode/confidence")
	}
	if strings.TrimSpace(log.OperationID) == "" || !validDestructiveEventType(log.EventType) {
		return fmt.Errorf("invalid destructive lifecycle tuple")
	}
	if err := normalizeExecutionFacts(log); err != nil {
		return err
	}
	log.PublicEventID = PublicDestructiveEventID(log.TenantID, log.OperationID, log.EventType)
	insertQuery, insertArgs, err := buildToolCallLogInsert(log)
	if err != nil {
		return err
	}
	shouldNotify := log.NotificationRequired && !log.DiscardablePathMatched &&
		log.Confidence >= 1 && log.FinalAction != "record"
	var outboxQuery string
	var outboxArgs []any
	if shouldNotify {
		outboxQuery, outboxArgs, err = buildDestructiveNotificationOutboxInsert(log)
		if err != nil {
			return err
		}
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin destructive lifecycle transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var storedID string
	if err := tx.QueryRow(ctx, insertQuery, insertArgs...).Scan(&storedID); err != nil {
		return fmt.Errorf("create destructive lifecycle: %w", err)
	}
	status := "skipped"
	if shouldNotify {
		if _, err := tx.Exec(ctx, outboxQuery, outboxArgs...); err != nil {
			return fmt.Errorf("enqueue destructive notifications: %w", err)
		}
		if err := tx.QueryRow(ctx, `
			SELECT CASE
				WHEN count(*) = 0 THEN 'skipped'
				WHEN bool_or(status = 'dead') THEN 'dead'
				WHEN bool_or(status IN ('pending', 'processing')) THEN 'pending'
				WHEN bool_or(status = 'failed') THEN 'failed'
				WHEN bool_and(status = 'processed') THEN 'sent'
				ELSE 'failed'
			END
			FROM outbox_events
			WHERE tenant_id=$1
			  AND event_type='notify.agent_destructive'
			  AND payload_json->>'operation_id'=$2
			  AND payload_json->>'event_type'=$3
		`, log.TenantID, log.OperationID, log.EventType).Scan(&status); err != nil {
			return fmt.Errorf("aggregate destructive notification status: %w", err)
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE tool_call_logs
		SET notification_status=CASE
			WHEN notification_status IN ('sent', 'dead') THEN notification_status
			WHEN notification_status = 'pending' AND $4 = 'skipped' THEN notification_status
			ELSE $4
		END
		WHERE tenant_id=$1 AND operation_id=$2 AND event_type=$3
	`, log.TenantID, log.OperationID, log.EventType, status)
	if err != nil {
		return fmt.Errorf("set destructive notification status: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("destructive notification status row was not updated")
	}
	if log.RequestID != "" && log.TenantID != "" {
		if _, err := tx.Exec(ctx, `
			UPDATE request_logs
			SET internal_title_request = NULL, agent_type = 'agent-tool-call'
			WHERE request_id = $1
			  AND tenant_id = $2
			  AND COALESCE(agent_type, '') = ''
		`, log.RequestID, log.TenantID); err != nil {
			return fmt.Errorf("update destructive request agent type: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit destructive lifecycle: %w", err)
	}
	log.ID = storedID
	log.NotificationStatus = status
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	return nil
}

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrAgentOperationNotFound     = errors.New("agent operation object not found")
	ErrAgentOperationConflict     = errors.New("agent operation policy version conflict")
	ErrAgentOperationInvalidScope = errors.New("invalid agent operation policy scope")
)

type AgentOperationPolicyMutation struct {
	TenantID, ActorID, Source string
	ScopeType, ScopeRef       string
	Mode, Action, Protocol    string
	DiscardablePaths          []string
	NotifyChannelIDs          []string
	RestrictedFilePatterns    []string
	RestrictedFileAction      string
	// RestrictedFileScopes 是受限文件生效的环节；nil 表示不改（新建时三项全选）。
	RestrictedFileScopes []string
	ExpectedVersion      int64
}

type AgentOperationPolicy struct {
	ScopeType, ScopeRef    string
	Mode, Action, Protocol string
	ModeDefaultAction      string
	CurrentAction          string
	ConfigSource           string
	DiscardablePaths       []string
	NotifyChannelIDs       []string
	RestrictedFilePatterns []string
	RestrictedFileAction   string
	RestrictedFileScopes   []string
	Version                int64
	UpdatedBy              string
	UpdatedAt              time.Time
	// Disabled 为 true 表示这个范围有一条策略但已被停用（enabled=false）。用 Disabled 而不是 Enabled：
	// 零值（false）= 启用，所有不关心这个字段的构造点（桩、默认值）保持原行为。
	Disabled bool
}

type AgentOperationEffectivePolicyInput struct {
	ApplicationID string
	AgentType     string
	Protocol      string
	Mode          string
}

type AgentOperationEffectivePolicy struct {
	Mode, Action, ScopeType, ScopeRef string
	ConfigSource, Protocol            string
	DiscardablePaths                  []string
	NotifyChannelIDs                  []string
	RestrictedFilePatterns            []string
	RestrictedFileAction              string
	RestrictedFileScopes              []string
}

type AgentOperationEvent struct {
	PublicEventID, OperationID, RequestID, TraceID string
	ApplicationID, AgentType, Model, Protocol      string
	ToolName, ToolCallID, TargetSummary            string
	CategoryCode, CategoryLabel                    string
	SubcategoryCode, BasisCode                     string
	Confidence                                     float64
	ModeDefaultAction, CustomAction, CurrentAction string
	StatusCode, StatusLabel                        string
	NotificationCode                               string
	NoiseReduction                                 bool
	CreatedAt                                      time.Time
}

type AgentOperationEventFilter struct {
	ApplicationID string
	AgentType     string
	Action        string
	Status        string
	From          *time.Time
	To            *time.Time
	Limit         int
	Offset        int
}

type AgentOperationChannel struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type AgentOperationRepository struct{ db *pgxpool.Pool }

func NewAgentOperationRepository(db *pgxpool.Pool) *AgentOperationRepository {
	return &AgentOperationRepository{db: db}
}

func agentOperationTenantArg(tenantID string) any {
	if strings.TrimSpace(tenantID) == "" {
		return nil
	}
	return strings.TrimSpace(tenantID)
}

// 受限文件作用范围：工具调用、用户消息提及的文件、正向代理的模型输出（迁移 999 默认三项全选）。
var RestrictedFileScopeValues = []string{"tool_call", "user_mention", "proxy_output"}

// DefaultRestrictedFileScopes 返回默认作用范围（三项全选，等于 2.9.21 的行为）。
func DefaultRestrictedFileScopes() []string {
	return append([]string(nil), RestrictedFileScopeValues...)
}

// NormalizeRestrictedFileScopes 按固定顺序去重，丢掉不认识的取值；nil 保持 nil（表示不改）。
func NormalizeRestrictedFileScopes(scopes []string) []string {
	if scopes == nil {
		return nil
	}
	out := []string{}
	for _, known := range RestrictedFileScopeValues {
		for _, scope := range scopes {
			if strings.TrimSpace(scope) == known {
				out = append(out, known)
				break
			}
		}
	}
	return out
}

func decodeRestrictedFileScopes(raw []byte) []string {
	var scopes []string
	if len(raw) == 0 || json.Unmarshal(raw, &scopes) != nil || scopes == nil {
		return DefaultRestrictedFileScopes()
	}
	return NormalizeRestrictedFileScopes(scopes)
}

func normalizeAgentOperationStringArray(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string(nil), values...)
}

func (r *AgentOperationRepository) SavePolicy(ctx context.Context, mutation AgentOperationPolicyMutation) (*AgentOperationPolicy, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin policy transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	stored, err := saveAgentOperationPolicyTx(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit policy: %w", err)
	}
	return stored, nil
}

func saveAgentOperationPolicyTx(ctx context.Context, tx pgx.Tx, mutation AgentOperationPolicyMutation) (*AgentOperationPolicy, error) {
	mutation.TenantID = strings.TrimSpace(mutation.TenantID)
	mutation.DiscardablePaths = normalizeAgentOperationStringArray(mutation.DiscardablePaths)
	mutation.NotifyChannelIDs = normalizeAgentOperationStringArray(mutation.NotifyChannelIDs)
	mutation.RestrictedFilePatterns = normalizeAgentOperationStringArray(mutation.RestrictedFilePatterns)
	if strings.TrimSpace(mutation.RestrictedFileAction) == "" {
		mutation.RestrictedFileAction = "block"
	}
	if err := validateAgentOperationScope(ctx, tx, mutation); err != nil {
		return nil, err
	}
	if err := validateAgentOperationChannels(ctx, tx, mutation.TenantID, mutation.NotifyChannelIDs); err != nil {
		return nil, err
	}
	tenantArg := agentOperationTenantArg(mutation.TenantID)

	var internalID string
	var current AgentOperationPolicy
	var pathsRaw, channelsRaw, restrictedRaw, scopesRaw []byte
	err := tx.QueryRow(ctx, `
		SELECT id, scope_type, scope_ref, mode, action, protocol,
		       discardable_paths_json, notify_channel_ids_json,
		       restricted_file_patterns_json, restricted_file_action, restricted_file_scopes_json,
		       version, updated_by, updated_at
		FROM agent_destructive_policies
		WHERE tenant_id IS NOT DISTINCT FROM $1 AND scope_type=$2 AND scope_ref=$3 AND enabled=true
		FOR UPDATE
	`, tenantArg, mutation.ScopeType, mutation.ScopeRef).Scan(
		&internalID, &current.ScopeType, &current.ScopeRef, &current.Mode, &current.Action, &current.Protocol,
		&pathsRaw, &channelsRaw, &restrictedRaw, &current.RestrictedFileAction, &scopesRaw,
		&current.Version, &current.UpdatedBy, &current.UpdatedAt,
	)
	var before any = map[string]any{}
	nextVersion := int64(1)
	if err == nil {
		if current.Version != mutation.ExpectedVersion {
			return nil, ErrAgentOperationConflict
		}
		_ = json.Unmarshal(pathsRaw, &current.DiscardablePaths)
		_ = json.Unmarshal(channelsRaw, &current.NotifyChannelIDs)
		_ = json.Unmarshal(restrictedRaw, &current.RestrictedFilePatterns)
		current.RestrictedFileScopes = decodeRestrictedFileScopes(scopesRaw)
		current.decorate()
		before = publicAgentOperationPolicySnapshot(current)
		nextVersion = current.Version + 1
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("load policy for update: %w", err)
	} else if mutation.ExpectedVersion != 1 {
		return nil, ErrAgentOperationConflict
	}

	pathsJSON, _ := json.Marshal(mutation.DiscardablePaths)
	channelsJSON, _ := json.Marshal(mutation.NotifyChannelIDs)
	restrictedJSON, _ := json.Marshal(mutation.RestrictedFilePatterns)
	// 作用范围：变更没带时保留现值（新建时三项全选）。
	scopes := NormalizeRestrictedFileScopes(mutation.RestrictedFileScopes)
	if scopes == nil {
		scopes = current.RestrictedFileScopes
		if internalID == "" || scopes == nil {
			scopes = DefaultRestrictedFileScopes()
		}
	}
	scopesJSON, _ := json.Marshal(scopes)
	if internalID == "" {
		internalID = "adp_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
		_, err = tx.Exec(ctx, `
			INSERT INTO agent_destructive_policies
			(id,tenant_id,scope_type,scope_ref,mode,action,protocol,discardable_paths_json,notify_channel_ids_json,restricted_file_patterns_json,restricted_file_action,restricted_file_scopes_json,version,enabled,created_by,updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11,$13::jsonb,1,true,$12,$12)
		`, internalID, tenantArg, mutation.ScopeType, mutation.ScopeRef, mutation.Mode, mutation.Action,
			mutation.Protocol, pathsJSON, channelsJSON, restrictedJSON, mutation.RestrictedFileAction, mutation.ActorID, scopesJSON)
	} else {
		tag, updateErr := tx.Exec(ctx, `
			UPDATE agent_destructive_policies
			SET mode=$4, action=$5, protocol=$6, discardable_paths_json=$7::jsonb,
			    notify_channel_ids_json=$8::jsonb, restricted_file_patterns_json=$9::jsonb,
			    restricted_file_action=$10, restricted_file_scopes_json=$13::jsonb,
			    version=version+1, updated_by=$11, updated_at=now()
			WHERE tenant_id IS NOT DISTINCT FROM $1 AND scope_type=$2 AND scope_ref=$3 AND version=$12 AND enabled=true
		`, tenantArg, mutation.ScopeType, mutation.ScopeRef, mutation.Mode, mutation.Action,
			mutation.Protocol, pathsJSON, channelsJSON, restrictedJSON, mutation.RestrictedFileAction,
			mutation.ActorID, mutation.ExpectedVersion, scopesJSON)
		if updateErr != nil {
			return nil, fmt.Errorf("update policy: %w", updateErr)
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrAgentOperationConflict
		}
	}
	if err != nil {
		return nil, fmt.Errorf("save policy: %w", err)
	}

	stored := &AgentOperationPolicy{
		ScopeType: mutation.ScopeType, ScopeRef: mutation.ScopeRef, Mode: mutation.Mode,
		Action: mutation.Action, Protocol: mutation.Protocol, DiscardablePaths: mutation.DiscardablePaths,
		NotifyChannelIDs: mutation.NotifyChannelIDs, RestrictedFilePatterns: mutation.RestrictedFilePatterns,
		RestrictedFileAction: mutation.RestrictedFileAction, RestrictedFileScopes: scopes, Version: nextVersion, UpdatedBy: mutation.ActorID,
		UpdatedAt: time.Now().UTC(),
	}
	stored.decorate()
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(publicAgentOperationPolicySnapshot(*stored))
	_, err = tx.Exec(ctx, `
		INSERT INTO agent_destructive_policy_audits
		(id,tenant_id,actor_id,source,scope_type,scope_ref,before_json,after_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)
	`, "adpa_"+strings.ReplaceAll(uuid.NewString(), "-", "")[:24], tenantArg, mutation.ActorID,
		mutation.Source, mutation.ScopeType, mutation.ScopeRef, beforeJSON, afterJSON)
	if err != nil {
		return nil, fmt.Errorf("write policy audit: %w", err)
	}
	return stored, nil
}

func (r *AgentOperationRepository) GetPolicy(ctx context.Context, tenantID, scopeType, scopeRef string) (*AgentOperationPolicy, error) {
	tenantArg := agentOperationTenantArg(tenantID)
	var p AgentOperationPolicy
	var pathsRaw, channelsRaw, restrictedRaw, scopesRaw []byte
	var enabled bool
	// 同一范围可能同时有停用行和启用行（停用后重新保存会新建一行）：启用行优先，其次取最近更新的停用行。
	// 只有完全没有行才是「未配置」；有行但都停用是「已停用」，不能当成默认值展示给管理员。
	err := r.db.QueryRow(ctx, `
		SELECT scope_type, scope_ref, mode, action, protocol, discardable_paths_json,
		       notify_channel_ids_json, restricted_file_patterns_json, restricted_file_action,
		       restricted_file_scopes_json, version, updated_by, updated_at, enabled
		FROM agent_destructive_policies
		WHERE tenant_id IS NOT DISTINCT FROM $1 AND scope_type=$2 AND scope_ref=$3
		ORDER BY enabled DESC, updated_at DESC
		LIMIT 1
	`, tenantArg, scopeType, scopeRef).Scan(&p.ScopeType, &p.ScopeRef, &p.Mode, &p.Action, &p.Protocol,
		&pathsRaw, &channelsRaw, &restrictedRaw, &p.RestrictedFileAction, &scopesRaw, &p.Version, &p.UpdatedBy, &p.UpdatedAt, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentOperationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}
	_ = json.Unmarshal(pathsRaw, &p.DiscardablePaths)
	_ = json.Unmarshal(channelsRaw, &p.NotifyChannelIDs)
	_ = json.Unmarshal(restrictedRaw, &p.RestrictedFilePatterns)
	p.RestrictedFileScopes = decodeRestrictedFileScopes(scopesRaw)
	p.decorate()
	p.Disabled = !enabled
	return &p, nil
}

func (r *AgentOperationRepository) ResolveEffectivePolicy(ctx context.Context, tenantID string, input AgentOperationEffectivePolicyInput) (*AgentOperationEffectivePolicy, error) {
	input.ApplicationID = strings.TrimSpace(input.ApplicationID)
	input.AgentType = strings.TrimSpace(input.AgentType)
	input.Protocol = strings.ToLower(strings.TrimSpace(input.Protocol))
	input.Mode = normalizeAgentOperationMode(input.Mode)

	var effective AgentOperationEffectivePolicy
	var pathsRaw, channelsRaw, restrictedRaw, scopesRaw []byte
	var globalPolicy bool
	err := r.db.QueryRow(ctx, `
		SELECT tenant_id IS NULL, mode, action, scope_type, scope_ref, protocol,
		       discardable_paths_json, notify_channel_ids_json,
		       restricted_file_patterns_json, restricted_file_action, restricted_file_scopes_json
		FROM agent_destructive_policies
		WHERE enabled=true
		  AND (tenant_id=$1 OR tenant_id IS NULL)
		  AND (
		    (tenant_id=$1 AND scope_type='application' AND scope_ref=$2)
		    OR (scope_type='agent' AND (scope_ref=$3 OR scope_ref='*'))
		    OR (scope_type='tenant' AND scope_ref='')
		  )
		  -- 只对确认行按协议过滤：protocol 为空的确认行对所有协议生效，protocol=mcp 的只管 MCP 请求；
		  -- 其余动作的行不看 protocol（与 2.9.21 同口径）。
		  AND (action <> 'confirm' OR protocol = '' OR (protocol='mcp' AND $4='mcp'))
		ORDER BY
		  CASE WHEN tenant_id=$1 THEN 0 ELSE 1 END,
		  CASE scope_type WHEN 'application' THEN 0 WHEN 'agent' THEN 1 ELSE 2 END,
		  CASE WHEN scope_type='agent' AND scope_ref=$3 THEN 0
		       WHEN scope_type='agent' AND scope_ref='*' THEN 1
		       ELSE 0 END
		LIMIT 1
	`, tenantID, input.ApplicationID, input.AgentType, input.Protocol).Scan(
		&globalPolicy, &effective.Mode, &effective.Action, &effective.ScopeType, &effective.ScopeRef, &effective.Protocol,
		&pathsRaw, &channelsRaw, &restrictedRaw, &effective.RestrictedFileAction, &scopesRaw,
	)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("resolve effective operation policy: %w", err)
	}
	if err == nil {
		_ = json.Unmarshal(pathsRaw, &effective.DiscardablePaths)
		_ = json.Unmarshal(channelsRaw, &effective.NotifyChannelIDs)
		_ = json.Unmarshal(restrictedRaw, &effective.RestrictedFilePatterns)
		effective.RestrictedFileScopes = decodeRestrictedFileScopes(scopesRaw)
		if globalPolicy {
			// A global policy never carries a tenant-owned channel reference.
			effective.NotifyChannelIDs = []string{}
		}
		effective.ConfigSource = effective.ScopeType + "_policy"
	} else if input.Mode != "" {
		effective.RestrictedFileScopes = DefaultRestrictedFileScopes()
		effective.Mode = input.Mode
		effective.Action = agentOperationModePreset(input.Mode)
		effective.ConfigSource = "mode_preset"
	} else {
		effective.RestrictedFileScopes = DefaultRestrictedFileScopes()
		effective.Mode = "audit"
		effective.Action = "record"
		effective.ConfigSource = "system_default"
	}
	if effective.Action != "record" && len(effective.NotifyChannelIDs) == 0 {
		rows, err := r.db.Query(ctx, `
			SELECT id FROM notify_channels
			WHERE tenant_id=$1 AND enabled=true
			ORDER BY id
		`, tenantID)
		if err != nil {
			return nil, fmt.Errorf("snapshot operation channels: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var channelID string
			if err := rows.Scan(&channelID); err != nil {
				return nil, fmt.Errorf("scan operation channel snapshot: %w", err)
			}
			effective.NotifyChannelIDs = append(effective.NotifyChannelIDs, channelID)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterate operation channel snapshot: %w", err)
		}
	}
	return &effective, nil
}

func normalizeAgentOperationMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "observe", "audit":
		return "audit"
	case "light":
		return "light"
	case "strict":
		return "strict"
	default:
		return ""
	}
}

func agentOperationModePreset(mode string) string {
	switch mode {
	case "light":
		return "alert_allow"
	case "strict":
		return "block"
	default:
		return "record"
	}
}

func validateAgentOperationScope(ctx context.Context, tx pgx.Tx, m AgentOperationPolicyMutation) error {
	if m.ScopeType == "tenant" {
		return nil
	}
	if m.ScopeType == "application" && m.TenantID == "" {
		return ErrAgentOperationInvalidScope
	}
	if m.ScopeType == "agent" {
		if m.ScopeRef == "*" {
			return nil
		}
		if strings.ContainsAny(m.ScopeRef, "*?") {
			return ErrAgentOperationInvalidScope
		}
	}
	var exists bool
	var err error
	switch m.ScopeType {
	case "application":
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE tenant_id=$1 AND id=$2 AND status='active')`, m.TenantID, m.ScopeRef).Scan(&exists)
	case "agent":
		if m.TenantID == "" {
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_sessions WHERE agent_type=$1 AND status='active')`, m.ScopeRef).Scan(&exists)
		} else {
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_sessions WHERE tenant_id=$1 AND agent_type=$2 AND status='active')`, m.TenantID, m.ScopeRef).Scan(&exists)
		}
	default:
		return ErrAgentOperationInvalidScope
	}
	if err != nil {
		return fmt.Errorf("validate policy scope: %w", err)
	}
	if !exists {
		return ErrAgentOperationNotFound
	}
	return nil
}

func validateAgentOperationChannels(ctx context.Context, tx pgx.Tx, tenantID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if strings.TrimSpace(tenantID) == "" {
		return ErrAgentOperationInvalidScope
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM notify_channels WHERE tenant_id=$1 AND enabled=true AND id=ANY($2)`, tenantID, ids).Scan(&count); err != nil {
		return fmt.Errorf("validate notify channels: %w", err)
	}
	if count != len(ids) {
		return ErrAgentOperationNotFound
	}
	return nil
}

func (p *AgentOperationPolicy) decorate() {
	p.ModeDefaultAction = map[string]string{"audit": "record", "light": "alert_allow", "strict": "block"}[p.Mode]
	p.CurrentAction = p.Action
	p.ConfigSource = p.ScopeType
}

func publicAgentOperationPolicySnapshot(p AgentOperationPolicy) map[string]any {
	return map[string]any{
		"scope_type": p.ScopeType, "scope_ref": p.ScopeRef, "mode": p.Mode,
		"action": p.Action, "protocol": p.Protocol, "discardable_paths": p.DiscardablePaths,
		"notify_channel_ids": p.NotifyChannelIDs, "version": p.Version,
	}
}

func (r *AgentOperationRepository) GetEvent(ctx context.Context, tenantID, publicEventID string) (*AgentOperationEvent, error) {
	var e AgentOperationEvent
	var eventType, riskCategory, riskSubcategory, reasonSummary, notificationStatus string
	var finalAction string
	var executionForwarded, resultObserved bool
	err := r.db.QueryRow(ctx, `
		SELECT public_event_id, operation_id, request_id, trace_id, application_id, agent_type,
		       model, protocol, tool_name, tool_call_id, target_summary, risk_category,
		       risk_subcategory, reason_summary, confidence, mode_default_action,
		       COALESCE(custom_action,''), final_action, COALESCE(notification_status,''),
		       COALESCE(discardable_path_matched,false), COALESCE(execution_forwarded,false),
		       COALESCE(result_observed,false), event_type, created_at
		FROM tool_call_logs WHERE tenant_id=$1 AND public_event_id=$2
	`, tenantID, publicEventID).Scan(
		&e.PublicEventID, &e.OperationID, &e.RequestID, &e.TraceID, &e.ApplicationID, &e.AgentType,
		&e.Model, &e.Protocol, &e.ToolName, &e.ToolCallID, &e.TargetSummary, &riskCategory,
		&riskSubcategory, &reasonSummary, &e.Confidence, &e.ModeDefaultAction, &e.CustomAction,
		&finalAction, &notificationStatus, &e.NoiseReduction, &executionForwarded, &resultObserved,
		&eventType, &e.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentOperationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get operation event: %w", err)
	}
	e.CurrentAction = finalAction
	e.CategoryCode, e.CategoryLabel = "destructive_operation", "\u7834\u574f\u6027\u64cd\u4f5c"
	e.SubcategoryCode = customerSubcategory(riskSubcategory)
	e.BasisCode = "deterministic_detection"
	e.NotificationCode = customerNotificationStatus(notificationStatus)
	e.StatusCode, e.StatusLabel = customerEventStatus(finalAction, executionForwarded, resultObserved)
	_ = eventType
	_ = riskCategory
	_ = reasonSummary
	return &e, nil
}

func (r *AgentOperationRepository) ListEvents(ctx context.Context, tenantID string, filter AgentOperationEventFilter) ([]AgentOperationEvent, int, error) {
	where := []string{"tenant_id=$1", "public_event_id IS NOT NULL"}
	args := []any{tenantID}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if filter.ApplicationID != "" {
		add("application_id=$%d", filter.ApplicationID)
	}
	if filter.AgentType != "" {
		add("agent_type=$%d", filter.AgentType)
	}
	if filter.Action != "" {
		add("final_action=$%d", filter.Action)
	}
	if filter.Status != "" {
		switch filter.Status {
		case "result_observed":
			where = append(where, "COALESCE(result_observed,false)=true")
		case "execution_forwarded":
			where = append(where, "COALESCE(result_observed,false)=false", "COALESCE(execution_forwarded,false)=true")
		case "recorded", "alert_allowed", "awaiting_confirmation", "blocked":
			action := map[string]string{
				"recorded": "record", "alert_allowed": "alert_allow",
				"awaiting_confirmation": "confirm", "blocked": "block",
			}[filter.Status]
			where = append(where, "COALESCE(result_observed,false)=false", "COALESCE(execution_forwarded,false)=false")
			add("final_action=$%d", action)
		default:
			return nil, 0, fmt.Errorf("unsupported event status")
		}
	}
	if filter.From != nil {
		add("created_at >= $%d", *filter.From)
	}
	if filter.To != nil {
		add("created_at <= $%d", *filter.To)
	}
	whereSQL := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, "SELECT count(*) FROM tool_call_logs WHERE "+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count operation events: %w", err)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	listArgs := append(append([]any{}, args...), limit, filter.Offset)
	rows, err := r.db.Query(ctx, `
		SELECT public_event_id
		FROM tool_call_logs
		WHERE `+whereSQL+fmt.Sprintf(" ORDER BY created_at DESC, public_event_id DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2), listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list operation events: %w", err)
	}
	defer rows.Close()
	publicIDs := make([]string, 0, limit)
	for rows.Next() {
		var publicID string
		if err := rows.Scan(&publicID); err != nil {
			return nil, 0, fmt.Errorf("scan operation event id: %w", err)
		}
		publicIDs = append(publicIDs, publicID)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate operation event ids: %w", err)
	}
	events := make([]AgentOperationEvent, 0, len(publicIDs))
	for _, publicID := range publicIDs {
		event, err := r.GetEvent(ctx, tenantID, publicID)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, *event)
	}
	return events, total, nil
}

func (r *AgentOperationRepository) ListChannels(ctx context.Context, tenantID string, ids []string) ([]AgentOperationChannel, error) {
	if len(ids) == 0 {
		return []AgentOperationChannel{}, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT id, type, name, enabled
		FROM notify_channels
		WHERE tenant_id=$1 AND id=ANY($2)
		ORDER BY name, id
	`, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("list operation channels: %w", err)
	}
	defer rows.Close()
	channels := make([]AgentOperationChannel, 0, len(ids))
	for rows.Next() {
		var channel AgentOperationChannel
		if err := rows.Scan(&channel.ID, &channel.Type, &channel.Name, &channel.Enabled); err != nil {
			return nil, fmt.Errorf("scan operation channel: %w", err)
		}
		channels = append(channels, channel)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate operation channels: %w", err)
	}
	return channels, nil
}

func customerEventStatus(action string, forwarded, observed bool) (string, string) {
	if observed {
		return "result_observed", "\u7ed3\u679c\u5df2\u89c2\u5bdf"
	}
	if forwarded {
		return "execution_forwarded", "\u5df2\u8f6c\u53d1\u6267\u884c"
	}
	switch action {
	case "alert_allow":
		return "alert_allowed", "\u5df2\u544a\u8b66\u5e76\u653e\u884c"
	case "confirm":
		return "awaiting_confirmation", "\u7b49\u5f85\u786e\u8ba4"
	case "block":
		return "blocked", "\u5df2\u963b\u65ad"
	default:
		return "recorded", "\u5df2\u8bb0\u5f55"
	}
}

func customerNotificationStatus(status string) string {
	switch status {
	case "pending":
		return "queued"
	case "sent":
		return "delivered"
	case "failed", "dead":
		return "delivery_failed"
	default:
		return "not_required"
	}
}

func customerSubcategory(value string) string {
	switch value {
	case "filesystem_delete":
		return "file_delete"
	case "filesystem_overwrite":
		return "file_overwrite"
	case "database_destructive":
		return "database_change"
	case "infrastructure_destroy":
		return "infrastructure_change"
	default:
		return "other_destructive_operation"
	}
}

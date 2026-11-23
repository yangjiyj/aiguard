package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentguardmatch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentGuardPolicyCenterManagedIDPrefix marks the one per-tenant policy that
// the policy center manages (W5 5.1); CreatePolicyWithVersion keeps such IDs.
const AgentGuardPolicyCenterManagedIDPrefix = "policy-center-ag-"

const (
	AgentGuardModeObserve = "observe"
	AgentGuardModeAudit   = "audit"
	AgentGuardModeStrict  = "strict"

	AgentGuardActionAllow   = "allow"
	AgentGuardActionAudit   = "audit"
	AgentGuardActionConfirm = "confirm"
	AgentGuardActionBlock   = "block"

	AgentGuardFailOpen   = "fail_open"
	AgentGuardFailClosed = "fail_closed"
)

type AgentGuardPolicy struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	Name          string         `json:"name"`
	ScopeType     string         `json:"scope_type"`
	ScopeRef      string         `json:"scope_ref"`
	Mode          string         `json:"mode"`
	DefaultAction string         `json:"default_action"`
	FailPolicy    string         `json:"fail_policy"`
	Priority      int            `json:"priority"`
	Enabled       bool           `json:"enabled"`
	TemplateID    string         `json:"template_id,omitempty"`
	RulesJSON     map[string]any `json:"rules_json"`
	BehaviorJSON  map[string]any `json:"behavior_json"`
	DLPJSON       map[string]any `json:"dlp_json"`
	CreatedBy     string         `json:"created_by,omitempty"`
	UpdatedBy     string         `json:"updated_by,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type AgentGuardPolicyScope struct {
	TenantID  string
	ProjectID string
	UserID    string
	KeyPrefix string
	AgentID   string
	SessionID string
}

type AgentGuardPolicyVersion struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	PolicyID      string         `json:"policy_id"`
	PolicyVersion string         `json:"policy_version"`
	SnapshotJSON  map[string]any `json:"snapshot_json"`
	ConfigHash    string         `json:"config_hash"`
	Active        bool           `json:"active"`
	CreatedBy     string         `json:"created_by"`
	CreatedAt     time.Time      `json:"created_at"`
}

type AgentGuardException struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ScopeType     string    `json:"scope_type"`
	ScopeRef      string    `json:"scope_ref"`
	RuleID        string    `json:"rule_id,omitempty"`
	TargetPattern string    `json:"target_pattern,omitempty"`
	Decision      string    `json:"decision"`
	Reason        string    `json:"reason"`
	ExpiresAt     time.Time `json:"expires_at"`
	Enabled       bool      `json:"enabled"`
	CreatedBy     string    `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type AgentGuardConfirmation struct {
	ID                string         `json:"id"`
	TenantID          string         `json:"tenant_id"`
	RequestID         string         `json:"request_id"`
	TraceID           string         `json:"trace_id"`
	ToolName          string         `json:"tool_name"`
	RawDecision       string         `json:"raw_decision"`
	EffectiveDecision string         `json:"effective_decision"`
	Status            string         `json:"status"`
	TimeoutAction     string         `json:"timeout_action"`
	Reason            string         `json:"reason"`
	EvidenceJSON      map[string]any `json:"evidence_json"`
	ExpiresAt         time.Time      `json:"expires_at"`
	ResolvedBy        string         `json:"resolved_by,omitempty"`
	ResolvedAt        *time.Time     `json:"resolved_at,omitempty"`
	ResolutionNote    string         `json:"resolution_note,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	ToolCallID        string         `json:"tool_call_id,omitempty"`
	ToolCallArguments string         `json:"tool_call_arguments,omitempty"`
	ChoiceIndex       int            `json:"choice_index"`
	ReplayStatus      string         `json:"replay_status,omitempty"`
	ReplayedAt        *time.Time     `json:"replayed_at,omitempty"`
	ReplayToolLogID   string         `json:"replay_tool_log_id,omitempty"`
	// ResolutionApplied 只在本次请求把 pending 原子迁移到 approved/rejected
	// 时为 true。它是服务端幂等控制信号，不暴露给 API 调用方。
	ResolutionApplied bool `json:"-"`
	// Source 标记确认单来源：''=AgentGuard（默认），'mcp'=MCP 安全网关。
	// 审批列表据此按来源过滤，替代 tool_name 含 '__' 的脆弱启发式。
	Source string `json:"source,omitempty"`
	// MCPExecution is a safe status projection. Ciphertext, arguments and the
	// single-use attempt token are never serialized.
	MCPExecution *MCPConfirmationExecution `json:"mcp_execution,omitempty"`
	// W5 5.3: who triggered the call. Recorded at creation so an approver can
	// never approve their own request. Empty on legacy rows.
	RequesterUserID   string `json:"requester_user_id,omitempty"`
	RequesterClientID string `json:"requester_client_id,omitempty"`
	// ArgumentsHash binds a single-use retry (W5 5.2) to the exact canonical
	// arguments. Computed server-side; never trusted from the client.
	ArgumentsHash string `json:"-"`
	// FirstApprovedBy is set when dual approval is required and one approver
	// has already approved; the confirmation stays pending until a second,
	// different approver approves.
	FirstApprovedBy string `json:"first_approved_by,omitempty"`
	// AwaitingSecondApproval is true only on the response to a first approval
	// under dual approval; the row is still pending.
	AwaitingSecondApproval bool `json:"awaiting_second_approval,omitempty"`
	// SelfApproved 只在本次请求由确认单的触发人自己批准（允许本人批准时）为 true，不落库。
	SelfApproved bool `json:"-"`
}

// AgentGuardApprovalPolicy controls who may resolve a confirmation (W5 5.3).
type AgentGuardApprovalPolicy struct {
	// RequireDualApproval needs two distinct approvers before approval takes
	// effect. A single rejection still resolves immediately.
	RequireDualApproval bool
	// AllowSelfApproval 允许触发调用的人批准自己的确认单（系统设置
	// agentguard_allow_self_approval，默认关）。本人批准的审计在批准的同一事务里写（事务审计，
	// 提交后进审计链；来源地址取请求上下文）。
	AllowSelfApproval bool
}

// AgentGuardConfirmationConsumeRequest identifies the retried call. All
// fields must match the approved confirmation (W5 5.2).
type AgentGuardConfirmationConsumeRequest struct {
	TenantID          string
	ToolCallID        string
	ToolName          string
	ArgumentsHash     string
	RequesterUserID   string
	RequesterClientID string
	RequestID         string
}

var (
	ErrAgentGuardConfirmationResolutionConflict    = errors.New("agentguard confirmation already resolved with a different status")
	ErrAgentGuardConfirmationExpired               = errors.New("agentguard confirmation expired")
	ErrAgentGuardConfirmationReplayStateNotUpdated = errors.New("agentguard confirmation replay state was not updated")
	// ErrAgentGuardConfirmationSelfApproval: the approver triggered the call.
	ErrAgentGuardConfirmationSelfApproval = errors.New("agentguard confirmation cannot be approved by its requester")
	// ErrAgentGuardConfirmationSameApprover: dual approval needs a second, different approver.
	ErrAgentGuardConfirmationSameApprover = errors.New("agentguard confirmation second approval must come from a different approver")
)

// AgentGuardConfirmationApprovalWindow bounds how long an approved non-MCP
// confirmation may be consumed by a client retry.
const AgentGuardConfirmationApprovalWindow = 30 * time.Minute

// AgentGuardArgumentsHash canonicalises JSON arguments (sorted keys, no
// insignificant whitespace) before hashing so that a retry which re-serialises
// the same arguments still matches. Non-JSON input is hashed verbatim.
func AgentGuardArgumentsHash(arguments string) string {
	canonical := strings.TrimSpace(arguments)
	if canonical != "" {
		decoder := json.NewDecoder(strings.NewReader(canonical))
		decoder.UseNumber()
		var decoded any
		if decoder.Decode(&decoded) == nil && !decoder.More() {
			if encoded, err := json.Marshal(decoded); err == nil {
				canonical = string(encoded)
			}
		}
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

type AgentGuardPolicyRepository struct {
	db *pgxpool.Pool
}

func NewAgentGuardPolicyRepository(db *pgxpool.Pool) *AgentGuardPolicyRepository {
	return &AgentGuardPolicyRepository{db: db}
}

func ResolveAgentGuardPolicy(policies []*AgentGuardPolicy, scope AgentGuardPolicyScope) *AgentGuardPolicy {
	var matches []*AgentGuardPolicy
	for _, p := range policies {
		if p == nil || !p.Enabled || p.TenantID != scope.TenantID {
			continue
		}
		if agentGuardPolicyMatchesScope(p, scope) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		return nil
	}
	sort.SliceStable(matches, func(i, j int) bool {
		li := agentGuardScopeRank(matches[i].ScopeType)
		lj := agentGuardScopeRank(matches[j].ScopeType)
		if li != lj {
			return li > lj
		}
		if matches[i].Priority != matches[j].Priority {
			return matches[i].Priority > matches[j].Priority
		}
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	return matches[0]
}

func ValidateAgentGuardPolicy(p *AgentGuardPolicy) error {
	if p == nil {
		return errors.New("policy is nil")
	}
	if strings.TrimSpace(p.TenantID) == "" {
		return errors.New("tenant_id is required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("name is required")
	}
	switch p.ScopeType {
	case "tenant":
	case "global_template", "project", "user", "key", "agent", "session":
		if strings.TrimSpace(p.ScopeRef) == "" {
			return errors.New("scope_ref is required for non-tenant policy")
		}
	default:
		return errors.New("unsupported scope_type")
	}
	if p.Mode != AgentGuardModeObserve && p.Mode != AgentGuardModeAudit && p.Mode != AgentGuardModeStrict {
		return errors.New("mode must be observe, audit, or strict")
	}
	if p.DefaultAction != AgentGuardActionAllow && p.DefaultAction != AgentGuardActionAudit &&
		p.DefaultAction != AgentGuardActionConfirm && p.DefaultAction != AgentGuardActionBlock {
		return errors.New("default_action must be allow, audit, confirm, or block")
	}
	if p.FailPolicy != AgentGuardFailOpen && p.FailPolicy != AgentGuardFailClosed {
		return errors.New("fail_policy must be fail_open or fail_closed")
	}
	if err := validateAgentGuardPolicyRules(p.RulesJSON); err != nil {
		return err
	}
	return nil
}

func validateAgentGuardPolicyRules(rulesJSON map[string]any) error {
	if rulesJSON == nil {
		return nil
	}
	rawRules, exists := rulesJSON["rules"]
	if !exists || rawRules == nil {
		return nil
	}
	var rules []map[string]any
	switch value := rawRules.(type) {
	case []map[string]any:
		rules = value
	case []any:
		rules = make([]map[string]any, 0, len(value))
		for index, item := range value {
			rule, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("rules_json.rules[%d] must be an object", index)
			}
			rules = append(rules, rule)
		}
	default:
		return errors.New("rules_json.rules must be an array")
	}

	seenIDs := make(map[string]struct{}, len(rules))
	for index, rule := range rules {
		ruleID, _ := rule["id"].(string)
		ruleID = strings.TrimSpace(ruleID)
		if ruleID == "" {
			return fmt.Errorf("rules_json.rules[%d].id is required", index)
		}
		if _, duplicate := seenIDs[ruleID]; duplicate {
			return fmt.Errorf("rules_json.rules[%d].id %q is duplicated", index, ruleID)
		}
		seenIDs[ruleID] = struct{}{}
		rule["id"] = ruleID

		nameValue, nameExists := rule["name"]
		switch name := nameValue.(type) {
		case nil:
			rule["name"] = ""
		case string:
			rule["name"] = name
		default:
			if nameExists {
				return fmt.Errorf("rules_json.rules[%d].name must be a string or null", index)
			}
		}

		enabledValue, enabledExists := rule["enabled"]
		switch enabled := enabledValue.(type) {
		case nil:
			rule["enabled"] = true
		case bool:
			rule["enabled"] = enabled
		default:
			if enabledExists {
				return fmt.Errorf("rules_json.rules[%d].enabled must be a boolean or null", index)
			}
		}

		pattern, _ := rule["tool_pattern"].(string)
		pattern = strings.TrimSpace(pattern)
		if !agentguardmatch.ValidPattern(pattern) {
			return fmt.Errorf("rules_json.rules[%d].tool_pattern must be a valid non-empty glob", index)
		}
		rule["tool_pattern"] = pattern

		action, _ := rule["action"].(string)
		switch action {
		case AgentGuardActionAllow, AgentGuardActionAudit, AgentGuardActionConfirm, AgentGuardActionBlock:
		default:
			return fmt.Errorf("rules_json.rules[%d].action must be allow, audit, confirm, or block", index)
		}
	}
	return nil
}

func ValidateAgentGuardException(e *AgentGuardException) error {
	if e == nil {
		return errors.New("exception is nil")
	}
	e.RuleID = strings.TrimSpace(e.RuleID)
	if e.RuleID == "" {
		return errors.New("rule_id is required")
	}
	if strings.TrimSpace(e.TenantID) == "" {
		return errors.New("tenant_id is required")
	}
	if strings.TrimSpace(e.ScopeType) == "" {
		return errors.New("scope_type is required")
	}
	if strings.TrimSpace(e.Reason) == "" {
		return errors.New("reason is required")
	}
	if e.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	if !e.ExpiresAt.After(time.Now()) {
		return errors.New("expires_at must be in the future")
	}
	if e.Decision == "" {
		e.Decision = AgentGuardActionAudit
	}
	if e.Decision != AgentGuardActionAllow && e.Decision != AgentGuardActionAudit {
		return errors.New("exception decision must be allow or audit")
	}
	return nil
}

func NewAgentGuardPolicyVersion(policy *AgentGuardPolicy, createdBy string) (*AgentGuardPolicyVersion, error) {
	if policy == nil {
		return nil, errors.New("policy is nil")
	}
	if policy.ID == "" || policy.TenantID == "" {
		return nil, errors.New("policy id and tenant_id are required")
	}
	snapshot := map[string]any{
		"id":             policy.ID,
		"tenant_id":      policy.TenantID,
		"name":           policy.Name,
		"scope_type":     policy.ScopeType,
		"scope_ref":      policy.ScopeRef,
		"mode":           withDefault(policy.Mode, AgentGuardModeAudit),
		"default_action": withDefault(policy.DefaultAction, AgentGuardActionAudit),
		"fail_policy":    withDefault(policy.FailPolicy, AgentGuardFailClosed),
		"priority":       policy.Priority,
		"enabled":        policy.Enabled,
		"template_id":    policy.TemplateID,
		"rules_json":     mapOrEmpty(policy.RulesJSON),
		"behavior_json":  mapOrEmpty(policy.BehaviorJSON),
		"dlp_json":       mapOrEmpty(policy.DLPJSON),
	}
	bytes, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("marshal policy snapshot: %w", err)
	}
	sum := sha256.Sum256(bytes)
	now := time.Now().UTC()
	version := hex.EncodeToString(sum[:8])
	return &AgentGuardPolicyVersion{
		ID:            "agpv_" + uuid.New().String()[:8],
		TenantID:      policy.TenantID,
		PolicyID:      policy.ID,
		PolicyVersion: version,
		SnapshotJSON:  snapshot,
		ConfigHash:    hex.EncodeToString(sum[:]),
		Active:        true,
		CreatedBy:     createdBy,
		CreatedAt:     now,
	}, nil
}

type agentGuardPolicyEncodedJSON struct {
	rules    []byte
	behavior []byte
	dlp      []byte
}

func prepareAgentGuardPolicyForWrite(p *AgentGuardPolicy, create bool) (agentGuardPolicyEncodedJSON, error) {
	if p == nil {
		return agentGuardPolicyEncodedJSON{}, errors.New("policy is nil")
	}
	if create {
		// W5 5.1: keep only the policy center's managed ID (derived from the
		// tenant, see migration 900); any other caller-supplied ID is replaced
		// so clients never choose policy IDs.
		if !strings.HasPrefix(p.ID, AgentGuardPolicyCenterManagedIDPrefix) {
			p.ID = "agp_" + uuid.New().String()[:8]
		}
	} else if strings.TrimSpace(p.ID) == "" {
		return agentGuardPolicyEncodedJSON{}, errors.New("policy id is required")
	}
	if p.Mode == "" {
		p.Mode = AgentGuardModeAudit
	}
	if p.DefaultAction == "" {
		p.DefaultAction = AgentGuardActionAudit
	}
	if p.FailPolicy == "" {
		p.FailPolicy = AgentGuardFailClosed
	}
	if err := ValidateAgentGuardPolicy(p); err != nil {
		return agentGuardPolicyEncodedJSON{}, err
	}
	return encodeAgentGuardPolicyJSON(p)
}

func encodeAgentGuardPolicyJSON(p *AgentGuardPolicy) (agentGuardPolicyEncodedJSON, error) {
	rulesJSON, err := json.Marshal(mapOrEmpty(p.RulesJSON))
	if err != nil {
		return agentGuardPolicyEncodedJSON{}, fmt.Errorf("marshal rules_json: %w", err)
	}
	behaviorJSON, err := json.Marshal(mapOrEmpty(p.BehaviorJSON))
	if err != nil {
		return agentGuardPolicyEncodedJSON{}, fmt.Errorf("marshal behavior_json: %w", err)
	}
	dlpJSON, err := json.Marshal(mapOrEmpty(p.DLPJSON))
	if err != nil {
		return agentGuardPolicyEncodedJSON{}, fmt.Errorf("marshal dlp_json: %w", err)
	}
	return agentGuardPolicyEncodedJSON{rules: rulesJSON, behavior: behaviorJSON, dlp: dlpJSON}, nil
}

func createAgentGuardPolicyTx(ctx context.Context, tx pgx.Tx, p *AgentGuardPolicy, encoded agentGuardPolicyEncodedJSON) error {
	now := time.Now()
	_, err := tx.Exec(ctx, `
		INSERT INTO agentguard_policies (
			id, tenant_id, name, scope_type, scope_ref, mode, default_action, fail_policy,
			priority, enabled, template_id, rules_json, behavior_json, dlp_json,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
	`, p.ID, p.TenantID, p.Name, p.ScopeType, p.ScopeRef, p.Mode, p.DefaultAction, p.FailPolicy,
		p.Priority, p.Enabled, agentGuardNullableString(p.TemplateID), encoded.rules, encoded.behavior, encoded.dlp,
		agentGuardNullableString(p.CreatedBy), agentGuardNullableString(p.UpdatedBy), now, now)
	if err != nil {
		return fmt.Errorf("create agentguard policy: %w", err)
	}
	return nil
}

func updateAgentGuardPolicyTx(ctx context.Context, tx pgx.Tx, p *AgentGuardPolicy, encoded agentGuardPolicyEncodedJSON) (bool, error) {
	result, err := tx.Exec(ctx, `
		UPDATE agentguard_policies
		SET name = $3,
		    scope_type = $4,
		    scope_ref = $5,
		    mode = $6,
		    default_action = $7,
		    fail_policy = $8,
		    priority = $9,
		    enabled = $10,
		    template_id = $11,
		    rules_json = $12,
		    behavior_json = $13,
		    dlp_json = $14,
		    updated_by = $15,
		    updated_at = $16
		WHERE tenant_id = $1 AND id = $2
	`, p.TenantID, p.ID, p.Name, p.ScopeType, p.ScopeRef, p.Mode, p.DefaultAction, p.FailPolicy,
		p.Priority, p.Enabled, agentGuardNullableString(p.TemplateID), encoded.rules, encoded.behavior, encoded.dlp,
		agentGuardNullableString(p.UpdatedBy), time.Now())
	if err != nil {
		return false, fmt.Errorf("update agentguard policy: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

func getAgentGuardPolicyTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (*AgentGuardPolicy, error) {
	row := tx.QueryRow(ctx, `
		SELECT id, tenant_id, name, scope_type, scope_ref, mode, default_action, fail_policy,
		       priority, enabled, COALESCE(template_id, ''), rules_json, behavior_json, dlp_json,
		       COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at
		FROM agentguard_policies
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE
	`, tenantID, id)
	policy, err := scanAgentGuardPolicyRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get agentguard policy in transaction: %w", err)
	}
	return policy, nil
}

func upsertAgentGuardPolicyVersionTx(ctx context.Context, tx pgx.Tx, policy *AgentGuardPolicy, createdBy string) (*AgentGuardPolicyVersion, error) {
	candidate, err := NewAgentGuardPolicyVersion(policy, createdBy)
	if err != nil {
		return nil, err
	}
	snapshotJSON, err := json.Marshal(candidate.SnapshotJSON)
	if err != nil {
		return nil, fmt.Errorf("marshal version snapshot: %w", err)
	}
	_, err = tx.Exec(ctx, `
		UPDATE agentguard_policy_versions
		SET active = FALSE
		WHERE tenant_id = $1 AND policy_id = $2 AND policy_version <> $3
	`, candidate.TenantID, candidate.PolicyID, candidate.PolicyVersion)
	if err != nil {
		return nil, fmt.Errorf("deactivate old agentguard policy versions: %w", err)
	}
	row := tx.QueryRow(ctx, `
		INSERT INTO agentguard_policy_versions (
			id, tenant_id, policy_id, policy_version, snapshot_json, config_hash, active, created_by, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,TRUE,$7,$8)
		ON CONFLICT (policy_id, policy_version)
		DO UPDATE SET
			active = TRUE,
			snapshot_json = EXCLUDED.snapshot_json,
			config_hash = EXCLUDED.config_hash
		WHERE agentguard_policy_versions.tenant_id = EXCLUDED.tenant_id
		RETURNING id, tenant_id, policy_id, policy_version, snapshot_json, config_hash,
		          active, COALESCE(created_by, ''), created_at
	`, candidate.ID, candidate.TenantID, candidate.PolicyID, candidate.PolicyVersion, snapshotJSON,
		candidate.ConfigHash, agentGuardNullableString(candidate.CreatedBy), candidate.CreatedAt)
	version, err := scanAgentGuardPolicyVersionRow(row)
	if err != nil {
		return nil, fmt.Errorf("upsert agentguard policy version: %w", err)
	}
	return version, nil
}

// CreatePolicyWithVersion persists the policy and its active version atomically.
func (r *AgentGuardPolicyRepository) CreatePolicyWithVersion(ctx context.Context, p *AgentGuardPolicy, createdBy string) (*AgentGuardPolicy, *AgentGuardPolicyVersion, error) {
	encoded, err := prepareAgentGuardPolicyForWrite(p, true)
	if err != nil {
		return nil, nil, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin create agentguard policy transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := createAgentGuardPolicyTx(ctx, tx, p, encoded); err != nil {
		return nil, nil, err
	}
	stored, err := getAgentGuardPolicyTx(ctx, tx, p.TenantID, p.ID)
	if err != nil {
		return nil, nil, err
	}
	if stored == nil {
		return nil, nil, errors.New("created AgentGuard policy could not be reloaded")
	}
	version, err := upsertAgentGuardPolicyVersionTx(ctx, tx, stored, createdBy)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit create agentguard policy transaction: %w", err)
	}
	*p = *stored
	return stored, version, nil
}

// UpdatePolicyWithVersion updates a tenant-owned policy and its active version atomically.
func (r *AgentGuardPolicyRepository) UpdatePolicyWithVersion(ctx context.Context, p *AgentGuardPolicy, createdBy string) (*AgentGuardPolicy, *AgentGuardPolicyVersion, bool, error) {
	encoded, err := prepareAgentGuardPolicyForWrite(p, false)
	if err != nil {
		return nil, nil, false, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, nil, false, fmt.Errorf("begin update agentguard policy transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	updated, err := updateAgentGuardPolicyTx(ctx, tx, p, encoded)
	if err != nil {
		return nil, nil, false, err
	}
	if !updated {
		return nil, nil, false, nil
	}
	stored, err := getAgentGuardPolicyTx(ctx, tx, p.TenantID, p.ID)
	if err != nil {
		return nil, nil, false, err
	}
	if stored == nil {
		return nil, nil, false, nil
	}
	version, err := upsertAgentGuardPolicyVersionTx(ctx, tx, stored, createdBy)
	if err != nil {
		return nil, nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, false, fmt.Errorf("commit update agentguard policy transaction: %w", err)
	}
	*p = *stored
	return stored, version, true, nil
}

// CreatePolicy is retained for internal compatibility and now creates the first version atomically.
func (r *AgentGuardPolicyRepository) CreatePolicy(ctx context.Context, p *AgentGuardPolicy) error {
	if p == nil {
		return errors.New("policy is nil")
	}
	_, _, err := r.CreatePolicyWithVersion(ctx, p, p.CreatedBy)
	return err
}

// UpdatePolicy is retained for internal compatibility and now versions the update atomically.
func (r *AgentGuardPolicyRepository) UpdatePolicy(ctx context.Context, p *AgentGuardPolicy) (bool, error) {
	if p == nil {
		return false, errors.New("policy is nil")
	}
	_, _, updated, err := r.UpdatePolicyWithVersion(ctx, p, p.UpdatedBy)
	return updated, err
}

func (r *AgentGuardPolicyRepository) ListPolicies(ctx context.Context, tenantID string) ([]*AgentGuardPolicy, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, name, scope_type, scope_ref, mode, default_action, fail_policy,
		       priority, enabled, COALESCE(template_id, ''), rules_json, behavior_json, dlp_json,
		       COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at
		FROM agentguard_policies
		WHERE tenant_id = $1
		ORDER BY scope_type, priority DESC, created_at DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list agentguard policies: %w", err)
	}
	defer rows.Close()
	return scanAgentGuardPolicyRows(rows)
}

func (r *AgentGuardPolicyRepository) GetPolicy(ctx context.Context, tenantID, id string) (*AgentGuardPolicy, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, name, scope_type, scope_ref, mode, default_action, fail_policy,
		       priority, enabled, COALESCE(template_id, ''), rules_json, behavior_json, dlp_json,
		       COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at
		FROM agentguard_policies
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, id)
	p, err := scanAgentGuardPolicyRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// CreateVersion is retained for internal compatibility and performs idempotent version activation in one transaction.
func (r *AgentGuardPolicyRepository) CreateVersion(ctx context.Context, policy *AgentGuardPolicy, createdBy string) (*AgentGuardPolicyVersion, error) {
	if err := ValidateAgentGuardPolicy(policy); err != nil {
		return nil, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create agentguard policy version transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	stored, err := getAgentGuardPolicyTx(ctx, tx, policy.TenantID, policy.ID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, errors.New("AgentGuard policy not found for version creation")
	}
	if err := ValidateAgentGuardPolicy(stored); err != nil {
		return nil, err
	}
	version, err := upsertAgentGuardPolicyVersionTx(ctx, tx, stored, createdBy)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create agentguard policy version transaction: %w", err)
	}
	return version, nil
}

func (r *AgentGuardPolicyRepository) ListVersions(ctx context.Context, tenantID, policyID string) ([]*AgentGuardPolicyVersion, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, policy_id, policy_version, snapshot_json, config_hash, active, COALESCE(created_by, ''), created_at
		FROM agentguard_policy_versions
		WHERE tenant_id = $1 AND policy_id = $2
		ORDER BY created_at DESC
	`, tenantID, policyID)
	if err != nil {
		return nil, fmt.Errorf("list agentguard policy versions: %w", err)
	}
	defer rows.Close()
	var versions []*AgentGuardPolicyVersion
	for rows.Next() {
		v, err := scanAgentGuardPolicyVersionRow(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

func (r *AgentGuardPolicyRepository) CreateException(ctx context.Context, e *AgentGuardException) error {
	if err := ValidateAgentGuardException(e); err != nil {
		return err
	}
	if e.ID == "" {
		e.ID = "agex_" + uuid.New().String()[:8]
	}
	if !e.Enabled {
		e.Enabled = true
	}
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		INSERT INTO agentguard_exceptions (
			id, tenant_id, scope_type, scope_ref, rule_id, target_pattern, decision,
			reason, expires_at, enabled, created_by, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`, e.ID, e.TenantID, e.ScopeType, e.ScopeRef, agentGuardNullableString(e.RuleID), agentGuardNullableString(e.TargetPattern), e.Decision,
		e.Reason, e.ExpiresAt, e.Enabled, agentGuardNullableString(e.CreatedBy), now, now)
	if err != nil {
		return fmt.Errorf("create agentguard exception: %w", err)
	}
	e.CreatedAt = now
	e.UpdatedAt = now
	return nil
}

func (r *AgentGuardPolicyRepository) DeleteException(ctx context.Context, tenantID, id string) (bool, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" {
		return false, errors.New("tenant_id and exception id are required")
	}
	result, err := r.db.Exec(ctx, `
		UPDATE agentguard_exceptions
		SET enabled = FALSE, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND enabled = TRUE
	`, tenantID, id)
	if err != nil {
		return false, fmt.Errorf("delete agentguard exception: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

func (r *AgentGuardPolicyRepository) ListActiveExceptions(ctx context.Context, tenantID string, now time.Time) ([]*AgentGuardException, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, scope_type, scope_ref, COALESCE(rule_id, ''), COALESCE(target_pattern, ''), decision,
		       reason, expires_at, enabled, COALESCE(created_by, ''), created_at, updated_at
		FROM agentguard_exceptions
		WHERE tenant_id = $1 AND enabled = TRUE AND expires_at > $2
		ORDER BY expires_at ASC
	`, tenantID, now)
	if err != nil {
		return nil, fmt.Errorf("list agentguard exceptions: %w", err)
	}
	defer rows.Close()
	var exceptions []*AgentGuardException
	for rows.Next() {
		e, err := scanAgentGuardExceptionRow(rows)
		if err != nil {
			return nil, err
		}
		exceptions = append(exceptions, e)
	}
	return exceptions, rows.Err()
}

func (r *AgentGuardPolicyRepository) RollbackPolicy(ctx context.Context, tenantID, policyID, versionID, actorID string) (*AgentGuardPolicy, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin rollback agentguard policy transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	row := tx.QueryRow(ctx, `
		SELECT id, tenant_id, policy_id, policy_version, snapshot_json, config_hash, active, COALESCE(created_by, ''), created_at
		FROM agentguard_policy_versions
		WHERE tenant_id = $1 AND policy_id = $2 AND id = $3
	`, tenantID, policyID, versionID)
	version, err := scanAgentGuardPolicyVersionRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get agentguard version for rollback: %w", err)
	}
	policy := policyFromSnapshot(version.SnapshotJSON)
	policy.ID = policyID
	policy.TenantID = tenantID
	policy.UpdatedBy = actorID
	if policy.Mode == "" {
		policy.Mode = AgentGuardModeAudit
	}
	if policy.DefaultAction == "" {
		policy.DefaultAction = AgentGuardActionAudit
	}
	if policy.FailPolicy == "" {
		policy.FailPolicy = AgentGuardFailClosed
	}
	// This is a trusted persisted snapshot, so legacy rules without IDs remain replayable.
	encoded, err := encodeAgentGuardPolicyJSON(policy)
	if err != nil {
		return nil, err
	}
	updated, err := updateAgentGuardPolicyTx(ctx, tx, policy, encoded)
	if err != nil {
		return nil, err
	}
	if !updated {
		return nil, nil
	}
	_, err = tx.Exec(ctx, `
		UPDATE agentguard_policy_versions SET active = FALSE
		WHERE tenant_id = $1 AND policy_id = $2 AND id <> $3
	`, tenantID, policyID, versionID)
	if err != nil {
		return nil, fmt.Errorf("deactivate agentguard policy versions: %w", err)
	}
	result, err := tx.Exec(ctx, `
		UPDATE agentguard_policy_versions SET active = TRUE
		WHERE tenant_id = $1 AND policy_id = $2 AND id = $3
	`, tenantID, policyID, versionID)
	if err != nil {
		return nil, fmt.Errorf("mark rollback version active: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, nil
	}
	stored, err := getAgentGuardPolicyTx(ctx, tx, tenantID, policyID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit rollback agentguard policy transaction: %w", err)
	}
	return stored, nil
}

func (r *AgentGuardPolicyRepository) CreateConfirmation(ctx context.Context, c *AgentGuardConfirmation) error {
	if c == nil {
		return errors.New("confirmation is nil")
	}
	if c.ID == "" {
		c.ID = "agcf_" + uuid.New().String()[:8]
	}
	if c.Status == "" {
		c.Status = "pending"
	}
	if c.TimeoutAction == "" {
		c.TimeoutAction = AgentGuardActionBlock
	}
	if c.ExpiresAt.IsZero() {
		c.ExpiresAt = time.Now().Add(10 * time.Minute)
	}
	evidenceJSON, err := json.Marshal(mapOrEmpty(c.EvidenceJSON))
	if err != nil {
		return fmt.Errorf("marshal confirmation evidence: %w", err)
	}
	now := time.Now()
	// The retry binding hash is always derived here from the persisted
	// arguments; a caller-supplied value is ignored.
	c.ArgumentsHash = AgentGuardArgumentsHash(c.ToolCallArguments)
	_, err = r.db.Exec(ctx, `
		INSERT INTO agentguard_confirmations (
			id, tenant_id, request_id, trace_id, tool_name, raw_decision, effective_decision,
			status, timeout_action, reason, evidence_json, expires_at, created_at,
			tool_call_id, tool_call_arguments, choice_index, source,
			requester_user_id, requester_client_id, arguments_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
			NULLIF($18, ''), NULLIF($19, ''), $20)
	`, c.ID, c.TenantID, c.RequestID, c.TraceID, c.ToolName, c.RawDecision, c.EffectiveDecision,
		c.Status, c.TimeoutAction, c.Reason, evidenceJSON, c.ExpiresAt, now,
		c.ToolCallID, c.ToolCallArguments, c.ChoiceIndex, c.Source,
		c.RequesterUserID, c.RequesterClientID, c.ArgumentsHash)
	if err != nil {
		return fmt.Errorf("create agentguard confirmation: %w", err)
	}
	c.CreatedAt = now
	return nil
}

// ListConfirmations lists legacy AgentGuard/MCP confirmations. T15 uses a dedicated
// queue because its one-use claim semantics differ and is always excluded here.
func (r *AgentGuardPolicyRepository) ListConfirmations(ctx context.Context, tenantID, status, source string) ([]*AgentGuardConfirmation, error) {
	query := `
		SELECT id, tenant_id, COALESCE(request_id, ''), trace_id, tool_name, raw_decision, effective_decision,
		       CASE
		         WHEN status = 'pending' AND expires_at <= CURRENT_TIMESTAMP THEN 'expired'
		         ELSE status
		       END AS effective_status,
		       timeout_action, COALESCE(reason, ''), evidence_json, expires_at,
		       COALESCE(resolved_by, ''), resolved_at, COALESCE(resolution_note, ''), created_at,
		       COALESCE(tool_call_id, ''), COALESCE(tool_call_arguments, ''), COALESCE(choice_index, 0),
		       COALESCE(replay_status, 'pending'), replayed_at, COALESCE(replay_tool_log_id, ''), COALESCE(source, ''),
		       COALESCE(requester_user_id, ''), COALESCE(requester_client_id, ''), COALESCE(first_approved_by, '')
		FROM agentguard_confirmations
		WHERE tenant_id = $1`
	args := []any{tenantID}
	query += ` AND COALESCE(source, '') <> 'agent_authorization'`
	switch status {
	case "pending":
		query += ` AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP`
	case "expired":
		query += ` AND (status = 'expired' OR (status = 'pending' AND expires_at <= CURRENT_TIMESTAMP))`
	case "":
		// 不过滤，但 SELECT 仍把已超时 pending 诚实呈现为 expired。
	default:
		args = append(args, status)
		query += fmt.Sprintf(` AND status = $%d`, len(args))
	}
	if source == "agentguard" {
		query += ` AND COALESCE(source, '') <> 'mcp'`
	} else if source != "" {
		args = append(args, source)
		query += fmt.Sprintf(` AND source = $%d`, len(args))
	}
	query += ` ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list agentguard confirmations: %w", err)
	}
	defer rows.Close()
	var confirmations []*AgentGuardConfirmation
	for rows.Next() {
		c, err := scanAgentGuardConfirmationRow(rows)
		if err != nil {
			return nil, err
		}
		confirmations = append(confirmations, c)
	}
	return confirmations, rows.Err()
}

const agentGuardConfirmationColumns = `id, tenant_id, COALESCE(request_id, ''), trace_id, tool_name, raw_decision, effective_decision,
		       status, timeout_action, COALESCE(reason, ''), evidence_json, expires_at,
		       COALESCE(resolved_by, ''), resolved_at, COALESCE(resolution_note, ''), created_at,
		       COALESCE(tool_call_id, ''), COALESCE(tool_call_arguments, ''), COALESCE(choice_index, 0),
		       COALESCE(replay_status, 'pending'), replayed_at, COALESCE(replay_tool_log_id, ''), COALESCE(source, ''),
		       COALESCE(requester_user_id, ''), COALESCE(requester_client_id, ''), COALESCE(first_approved_by, '')`

// ResolveConfirmation keeps the legacy single-approver behaviour; the
// requester can still never approve their own call (W5 5.3).
func (r *AgentGuardPolicyRepository) ResolveConfirmation(ctx context.Context, tenantID, id, status, actorID, note string) (*AgentGuardConfirmation, error) {
	return r.ResolveConfirmationWithPolicy(ctx, tenantID, id, status, actorID, note, AgentGuardApprovalPolicy{})
}

// ResolveConfirmationWithPolicy resolves a confirmation under a row lock.
//
//   - approved by the recorded requester -> ErrAgentGuardConfirmationSelfApproval
//   - dual approval, first approver       -> row stays pending, first_approved_by set,
//     AwaitingSecondApproval=true, ResolutionApplied=false
//   - dual approval, same approver again  -> ErrAgentGuardConfirmationSameApprover
//   - rejection always resolves immediately (a requester may withdraw).
//
// Expired / already-resolved rows behave exactly as before.
func (r *AgentGuardPolicyRepository) ResolveConfirmationWithPolicy(ctx context.Context, tenantID, id, status, actorID, note string, policy AgentGuardApprovalPolicy) (*AgentGuardConfirmation, error) {
	if status != "approved" && status != "rejected" {
		return nil, errors.New("status must be approved or rejected")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin resolve agentguard confirmation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var expired bool
	row := tx.QueryRow(ctx, `
		SELECT `+agentGuardConfirmationColumns+`, (expires_at <= NOW())
		FROM agentguard_confirmations
		WHERE tenant_id = $1 AND id = $2 AND COALESCE(source, '') <> 'agent_authorization'
		FOR UPDATE
	`, tenantID, id)
	c, err := scanAgentGuardConfirmationRowWith(row, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load agentguard confirmation: %w", err)
	}

	if c.Status == "pending" && expired {
		// 未完成处置的过期单必须先物化为 expired，避免它永远停留在 pending。
		row = tx.QueryRow(ctx, `
			UPDATE agentguard_confirmations
			SET status = 'expired', resolved_at = COALESCE(resolved_at, NOW())
			WHERE tenant_id = $1 AND id = $2 AND COALESCE(source, '') <> 'agent_authorization'
			RETURNING `+agentGuardConfirmationColumns, tenantID, id)
		c, err = scanAgentGuardConfirmationRow(row)
		if err != nil {
			return nil, fmt.Errorf("expire agentguard confirmation: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit expire agentguard confirmation: %w", err)
		}
		return c, ErrAgentGuardConfirmationExpired
	}
	if c.Status != "pending" {
		if c.Status == status {
			return c, nil
		}
		if c.Status == "expired" {
			return c, ErrAgentGuardConfirmationExpired
		}
		return c, ErrAgentGuardConfirmationResolutionConflict
	}

	selfApproved := false
	if status == "approved" {
		if c.RequesterUserID != "" && c.RequesterUserID == actorID {
			if !policy.AllowSelfApproval {
				return c, ErrAgentGuardConfirmationSelfApproval
			}
			selfApproved = true
		}
		if policy.RequireDualApproval {
			if c.FirstApprovedBy == "" {
				row = tx.QueryRow(ctx, `
					UPDATE agentguard_confirmations
					SET first_approved_by = $3, first_approved_at = NOW()
					WHERE tenant_id = $1 AND id = $2 AND COALESCE(source, '') <> 'agent_authorization'
					RETURNING `+agentGuardConfirmationColumns, tenantID, id, actorID)
				c, err = scanAgentGuardConfirmationRow(row)
				if err != nil {
					return nil, fmt.Errorf("record first agentguard approval: %w", err)
				}
				if selfApproved {
					if err := writeSelfApprovalAudit(ctx, tx, tenantID, actorID, c, true); err != nil {
						return nil, err
					}
				}
				if err := commitWithOperationAudit(ctx, tx); err != nil {
					return nil, fmt.Errorf("commit first agentguard approval: %w", err)
				}
				c.AwaitingSecondApproval = true
				c.SelfApproved = selfApproved
				return c, nil
			}
			if c.FirstApprovedBy == actorID {
				return c, ErrAgentGuardConfirmationSameApprover
			}
		}
	}

	row = tx.QueryRow(ctx, `
		UPDATE agentguard_confirmations
		SET status = $3, resolved_by = $4, resolved_at = NOW(), resolution_note = $5
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending' AND COALESCE(source, '') <> 'agent_authorization'
		RETURNING `+agentGuardConfirmationColumns, tenantID, id, status, actorID, note)
	c, err = scanAgentGuardConfirmationRow(row)
	if err != nil {
		return nil, fmt.Errorf("resolve agentguard confirmation: %w", err)
	}
	if selfApproved {
		if err := writeSelfApprovalAudit(ctx, tx, tenantID, actorID, c, false); err != nil {
			return nil, err
		}
	}
	if err := commitWithOperationAudit(ctx, tx); err != nil {
		return nil, fmt.Errorf("commit resolve agentguard confirmation: %w", err)
	}
	c.ResolutionApplied = true
	c.SelfApproved = selfApproved
	return c, nil
}

// writeSelfApprovalAudit 用事务审计写本人批准审计 agentguard_confirmation.self_approved：与批准同一
// 事务写 audit_operations（审计写不进去批准也不生效），提交后由 commitWithOperationAudit 送进审计链。
func writeSelfApprovalAudit(ctx context.Context, tx pgx.Tx, tenantID, actorID string, c *AgentGuardConfirmation, awaitingSecond bool) error {
	if err := writeTransactionalOperationAudit(ctx, tx, tenantID, actorID, "agentguard_confirmation.self_approved",
		"agentguard_confirmation", c.ID, map[string]any{
			"confirmation_id": c.ID, "status": c.Status, "awaiting_second_approval": awaitingSecond,
		}); err != nil {
		return fmt.Errorf("audit agentguard self approval: %w", err)
	}
	return nil
}

// SetConfirmationRequester records the requester on a confirmation created
// through a path that does not carry it in the insert (MCP deduplicated
// create). It never overwrites an existing requester.
func (r *AgentGuardPolicyRepository) SetConfirmationRequester(ctx context.Context, tenantID, id, userID, clientID string) error {
	if strings.TrimSpace(userID) == "" && strings.TrimSpace(clientID) == "" {
		return nil
	}
	_, err := r.db.Exec(ctx, `
		UPDATE agentguard_confirmations
		SET requester_user_id = NULLIF($3, ''), requester_client_id = NULLIF($4, '')
		WHERE tenant_id = $1 AND id = $2 AND COALESCE(source, '') <> 'agent_authorization'
		  AND requester_user_id IS NULL AND requester_client_id IS NULL
	`, tenantID, id, userID, clientID)
	if err != nil {
		return fmt.Errorf("set agentguard confirmation requester: %w", err)
	}
	return nil
}

// ConsumeApprovedConfirmation atomically marks one approved, unconsumed,
// non-MCP confirmation as executed and returns it (W5 5.2). A match requires
// the same tenant, tool name, canonical arguments hash and requester (user and
// API key). A confirmation with the same tool_call_id is preferred; model
// regenerations normally mint a new tool_call_id, so an identical call from
// the same requester is also accepted. Each approval is usable exactly once
// and only within AgentGuardConfirmationApprovalWindow of the approval.
// Returns (nil, nil) when nothing matches.
func (r *AgentGuardPolicyRepository) ConsumeApprovedConfirmation(ctx context.Context, req AgentGuardConfirmationConsumeRequest) (*AgentGuardConfirmation, error) {
	if req.TenantID == "" || req.ToolName == "" || req.ArgumentsHash == "" {
		return nil, nil
	}
	if req.RequesterUserID == "" && req.RequesterClientID == "" {
		// Without a requester identity the approval cannot be bound to a caller.
		return nil, nil
	}
	row := r.db.QueryRow(ctx, `
		UPDATE agentguard_confirmations
		SET replay_status = 'executed', replayed_at = NOW(), consumed_request_id = NULLIF($8, '')
		WHERE id = (
			SELECT id FROM agentguard_confirmations
			WHERE tenant_id = $1 AND tool_name = $2 AND arguments_hash = $3
			  AND COALESCE(source, '') = ''
			  AND status = 'approved' AND replay_status = 'pending'
			  AND resolved_at > NOW() - make_interval(secs => $7)
			  AND COALESCE(requester_user_id, '') = $4
			  AND COALESCE(requester_client_id, '') = $5
			ORDER BY (COALESCE(tool_call_id, '') = $6) DESC, resolved_at DESC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		  AND status = 'approved' AND replay_status = 'pending'
		RETURNING `+agentGuardConfirmationColumns,
		req.TenantID, req.ToolName, req.ArgumentsHash, req.RequesterUserID, req.RequesterClientID,
		req.ToolCallID, AgentGuardConfirmationApprovalWindow.Seconds(), req.RequestID)
	c, err := scanAgentGuardConfirmationRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("consume agentguard confirmation: %w", err)
	}
	return c, nil
}

// MarkConfirmationReplayed 回写批准审计的登记状态与 tool_log_id。pending 表示等待
// 客户端重试，不代表已执行；只有登记失败时写 failed。
func (r *AgentGuardPolicyRepository) MarkConfirmationReplayed(ctx context.Context, tenantID, id, replayStatus, toolLogID string) error {
	result, err := r.db.Exec(ctx, `
		UPDATE agentguard_confirmations
		SET replay_status = CASE WHEN replay_status = 'executed' THEN 'executed' ELSE $3 END,
		    replay_tool_log_id = NULLIF($4, ''), replayed_at = COALESCE(replayed_at, $5)
		WHERE tenant_id = $1 AND id = $2 AND status = 'approved' AND COALESCE(source, '') <> 'agent_authorization'
	`, tenantID, id, replayStatus, toolLogID, time.Now())
	if err != nil {
		return fmt.Errorf("mark agentguard confirmation replayed: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrAgentGuardConfirmationReplayStateNotUpdated
	}
	return nil
}

func agentGuardPolicyMatchesScope(p *AgentGuardPolicy, scope AgentGuardPolicyScope) bool {
	switch p.ScopeType {
	case "global_template":
		return true
	case "tenant":
		return p.ScopeRef == "" || p.ScopeRef == scope.TenantID
	case "project":
		return p.ScopeRef != "" && p.ScopeRef == scope.ProjectID
	case "user":
		return p.ScopeRef != "" && p.ScopeRef == scope.UserID
	case "key":
		return p.ScopeRef != "" && p.ScopeRef == scope.KeyPrefix
	case "agent":
		return p.ScopeRef != "" && p.ScopeRef == scope.AgentID
	case "session":
		return p.ScopeRef != "" && p.ScopeRef == scope.SessionID
	default:
		return false
	}
}

func agentGuardScopeRank(scopeType string) int {
	switch scopeType {
	case "session":
		return 70
	case "key":
		return 60
	case "agent":
		return 50
	case "user":
		return 40
	case "project":
		return 30
	case "tenant":
		return 20
	case "global_template":
		return 10
	default:
		return 0
	}
}

func scanAgentGuardPolicyRows(rows pgx.Rows) ([]*AgentGuardPolicy, error) {
	var policies []*AgentGuardPolicy
	for rows.Next() {
		p, err := scanAgentGuardPolicyRow(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

func scanAgentGuardPolicyRow(row pgx.Row) (*AgentGuardPolicy, error) {
	var p AgentGuardPolicy
	var rulesJSON, behaviorJSON, dlpJSON []byte
	if err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.ScopeType, &p.ScopeRef, &p.Mode, &p.DefaultAction,
		&p.FailPolicy, &p.Priority, &p.Enabled, &p.TemplateID, &rulesJSON, &behaviorJSON, &dlpJSON,
		&p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rulesJSON, &p.RulesJSON)
	_ = json.Unmarshal(behaviorJSON, &p.BehaviorJSON)
	_ = json.Unmarshal(dlpJSON, &p.DLPJSON)
	return &p, nil
}

func scanAgentGuardPolicyVersionRow(row pgx.Row) (*AgentGuardPolicyVersion, error) {
	var v AgentGuardPolicyVersion
	var snapshotJSON []byte
	if err := row.Scan(&v.ID, &v.TenantID, &v.PolicyID, &v.PolicyVersion, &snapshotJSON, &v.ConfigHash,
		&v.Active, &v.CreatedBy, &v.CreatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(snapshotJSON, &v.SnapshotJSON)
	return &v, nil
}

func scanAgentGuardExceptionRow(row pgx.Row) (*AgentGuardException, error) {
	var e AgentGuardException
	if err := row.Scan(&e.ID, &e.TenantID, &e.ScopeType, &e.ScopeRef, &e.RuleID, &e.TargetPattern,
		&e.Decision, &e.Reason, &e.ExpiresAt, &e.Enabled, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, err
	}
	return &e, nil
}

func scanAgentGuardConfirmationRow(row pgx.Row) (*AgentGuardConfirmation, error) {
	return scanAgentGuardConfirmationRowWith(row)
}

// scanAgentGuardConfirmationRowWith scans agentGuardConfirmationColumns
// followed by any extra trailing columns.
func scanAgentGuardConfirmationRowWith(row pgx.Row, extra ...any) (*AgentGuardConfirmation, error) {
	var c AgentGuardConfirmation
	var evidenceJSON []byte
	dest := []any{&c.ID, &c.TenantID, &c.RequestID, &c.TraceID, &c.ToolName, &c.RawDecision,
		&c.EffectiveDecision, &c.Status, &c.TimeoutAction, &c.Reason, &evidenceJSON, &c.ExpiresAt,
		&c.ResolvedBy, &c.ResolvedAt, &c.ResolutionNote, &c.CreatedAt,
		&c.ToolCallID, &c.ToolCallArguments, &c.ChoiceIndex,
		&c.ReplayStatus, &c.ReplayedAt, &c.ReplayToolLogID, &c.Source,
		&c.RequesterUserID, &c.RequesterClientID, &c.FirstApprovedBy}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(evidenceJSON, &c.EvidenceJSON)
	return &c, nil
}

func policyFromSnapshot(snapshot map[string]any) *AgentGuardPolicy {
	return &AgentGuardPolicy{
		Name:          stringFromSnapshot(snapshot, "name"),
		ScopeType:     stringFromSnapshot(snapshot, "scope_type"),
		ScopeRef:      stringFromSnapshot(snapshot, "scope_ref"),
		Mode:          stringFromSnapshot(snapshot, "mode"),
		DefaultAction: stringFromSnapshot(snapshot, "default_action"),
		FailPolicy:    stringFromSnapshot(snapshot, "fail_policy"),
		Priority:      intFromSnapshot(snapshot, "priority"),
		Enabled:       boolFromSnapshot(snapshot, "enabled"),
		TemplateID:    stringFromSnapshot(snapshot, "template_id"),
		RulesJSON:     mapFromSnapshot(snapshot, "rules_json"),
		BehaviorJSON:  mapFromSnapshot(snapshot, "behavior_json"),
		DLPJSON:       mapFromSnapshot(snapshot, "dlp_json"),
	}
}

func stringFromSnapshot(snapshot map[string]any, key string) string {
	value, _ := snapshot[key].(string)
	return value
}

func intFromSnapshot(snapshot map[string]any, key string) int {
	switch value := snapshot[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func boolFromSnapshot(snapshot map[string]any, key string) bool {
	value, ok := snapshot[key].(bool)
	return ok && value
}

func mapFromSnapshot(snapshot map[string]any, key string) map[string]any {
	value, ok := snapshot[key].(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return value
}

func mapOrEmpty(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func withDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func agentGuardNullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

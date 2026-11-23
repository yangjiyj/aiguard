package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
)

const (
	policyCenterAgentBehaviorDestructive = "destructive_operation"
	policyCenterAgentBehaviorSystem      = "system_command"
	policyCenterAgentBehaviorFile        = "sensitive_resource"
	policyCenterAgentBehaviorNetwork     = "network_egress"
	policyCenterAgentBehaviorDatabase    = "database_change"
	policyCenterAgentBehaviorMCP         = "external_tool"

	policyCenterAgentBehaviorRecord     = "record"
	policyCenterAgentBehaviorAlertAllow = "alert_allow"
	policyCenterAgentBehaviorBlock      = "block"

	// policyCenterAgentGuardPolicyPrefix names the one tenant policy that carries
	// every policy-center AgentGuard category (W5 5.1). agentguard_policies.id is
	// a global primary key, so the ID is derived from the tenant; migration 900
	// computes the same value and merges the pre-fix per-category duplicates.
	policyCenterAgentGuardPolicyPrefix = repository.AgentGuardPolicyCenterManagedIDPrefix

	// policyCenterRuleActionKey keeps the console choice (record / alert_allow /
	// block) on a managed rule; "action" holds the enforced AgentGuard action.
	policyCenterRuleActionKey = "policy_center_action"
)

// policyCenterAgentGuardPolicyIDFor must stay byte-identical to migration 900:
// 'policy-center-ag-' || left(encode(sha256(convert_to(tenant_id,'UTF8')),'hex'),16).
func policyCenterAgentGuardPolicyIDFor(tenantID string) string {
	sum := sha256.Sum256([]byte(tenantID))
	return policyCenterAgentGuardPolicyPrefix + hex.EncodeToString(sum[:])[:16]
}

type policyCenterAgentBehaviorDefinition struct {
	Key         string
	Label       string
	Description string
	ToolPattern string
	Source      string
}

var policyCenterAgentBehaviorDefinitions = []policyCenterAgentBehaviorDefinition{
	{Key: policyCenterAgentBehaviorDestructive, Label: "删除与破坏", Description: "管理 Agent 准备调用删除或破坏性工具时的处理动作", Source: policyCenterAgentBehaviorDestructive},
	{Key: policyCenterAgentBehaviorSystem, Label: "系统命令", Description: "管理 Agent 调用系统命令工具时的处理动作", ToolPattern: "system.*", Source: "agentguard"},
	{Key: policyCenterAgentBehaviorFile, Label: "敏感资源访问", Description: "管理 Agent 读取敏感文件和资源时的处理动作", ToolPattern: "file.*", Source: "agentguard"},
	{Key: policyCenterAgentBehaviorNetwork, Label: "网络外联", Description: "管理 Agent 调用网络工具或向外部发送数据时的处理动作", ToolPattern: "network.*", Source: "agentguard"},
	{Key: policyCenterAgentBehaviorDatabase, Label: "数据库变更", Description: "管理 Agent 执行数据库写入或结构变更时的处理动作", ToolPattern: "database.*", Source: "agentguard"},
	{Key: policyCenterAgentBehaviorMCP, Label: "外部工具（MCP）", Description: "管理 Agent 调用外部 MCP 工具时的处理动作", Source: "mcp"},
}

type policyCenterAgentBehaviorUpdateRequest struct {
	Action  string `json:"action"`
	Version string `json:"version"`
	// 仅 sensitive_resource 支持：受限文件模式、命中动作与作用范围（tool_call、user_mention、
	// proxy_output 多选，可以一项不选）。
	RestrictedFilePatterns *[]string `json:"restricted_file_patterns,omitempty"`
	RestrictedFileAction   string    `json:"restricted_file_action,omitempty"`
	RestrictedFileScopes   *[]string `json:"restricted_file_scopes,omitempty"`
	// network_egress only: sensitive-read -> egress sequence window in seconds, 0 = off (W5 5.5).
	SensitiveReadEgressWindowSeconds *int `json:"sensitive_read_egress_window_seconds,omitempty"`
}

type policyCenterAgentBehaviorState struct {
	Definition           policyCenterAgentBehaviorDefinition
	Configured           bool
	ConfiguredAction     string
	RawConfiguredAction  string
	CurrentAction        string
	Health               string
	HealthMessage        string
	HasAdvancedOverrides bool
	Version              string

	destructivePolicy    *repository.AgentOperationPolicy
	restrictedReadFailed bool
	agentGuardPolicy     *repository.AgentGuardPolicy
	agentPoliciesVersion string
	mcpPolicy            *repository.MCPPolicy
	mcpPolicies          []*repository.MCPPolicy
}

func GetPolicyCenterAgentBehaviors(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		states, err := loadPolicyCenterAgentBehaviors(r, deps, user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "agent behavior status is unavailable")
			return
		}
		items := make([]map[string]any, 0, len(states))
		for _, state := range states {
			items = append(items, state.customerProjection())
		}
		writeJSON(w, map[string]any{"items": items})
	}
}

func PutPolicyCenterAgentBehavior(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		// SoD 归 security_write：系统管理员与安全员可改（roles.CanManageSecurityPolicy），其余仍拒绝。
		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only security policy managers can update agent behaviors")
			return
		}
		definition, ok := policyCenterAgentBehaviorDefinitionByKey(chi.URLParam(r, "key"))
		if !ok {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent behavior not found")
			return
		}
		request, err := decodePolicyCenterAgentBehaviorUpdateRequest(w, r)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		if !policyCenterActionAllowed(definition, request.Action) {
			writeError(w, "invalid_request", "action "+request.Action+" is not available for "+definition.Key)
			return
		}
		states, err := loadPolicyCenterAgentBehaviors(r, deps, user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "agent behavior status is unavailable")
			return
		}
		state := policyCenterAgentBehaviorStateByKey(states, definition.Key)
		if state == nil || state.Health == "error" {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "agent behavior status is unavailable")
			return
		}
		if request.Version != state.Version {
			writeErrorWithStatus(w, http.StatusConflict, "version_conflict", "agent behavior changed; reload before saving")
			return
		}

		// 受限文件字段只挂在 sensitive_resource（敏感资源访问）上。
		carriesRestrictedFields := request.carriesRestrictedFields()
		if carriesRestrictedFields && definition.Key != policyCenterAgentBehaviorFile {
			writeErrorWithStatus(w, http.StatusBadRequest, "restricted_file_fields_not_supported",
				"restricted_file_patterns/restricted_file_action/restricted_file_scopes 仅支持敏感资源访问（sensitive_resource）")
			return
		}
		if carriesRestrictedFields {
			if request.RestrictedFilePatterns != nil {
				if err := filerestrict.Validate(*request.RestrictedFilePatterns); err != nil {
					writeError(w, "invalid_request", err.Error())
					return
				}
			}
			if request.RestrictedFileAction != "" {
				if _, err := filerestrict.ValidateAction(request.RestrictedFileAction); err != nil {
					writeError(w, "invalid_request", err.Error())
					return
				}
			}
			if request.RestrictedFileScopes != nil {
				if err := validatePolicyCenterRestrictedFileScopes(*request.RestrictedFileScopes); err != nil {
					writeError(w, "invalid_request", err.Error())
					return
				}
			}
		}

		if request.Action != state.ConfiguredAction && policyCenterRestrictedFieldsChanged(state, request) {
			writeErrorWithStatus(w, http.StatusBadRequest, "combined_update_not_supported", "save the baseline action and restricted file configuration separately")
			return
		}

		if request.SensitiveReadEgressWindowSeconds != nil {
			if definition.Key != policyCenterAgentBehaviorNetwork {
				writeErrorWithStatus(w, http.StatusBadRequest, "sequence_window_not_supported",
					"sensitive_read_egress_window_seconds is only supported on network_egress")
				return
			}
			if err := validatePolicyCenterSequenceWindow(*request.SensitiveReadEgressWindowSeconds); err != nil {
				writeError(w, "invalid_request", err.Error())
				return
			}
		}

		if deps.PolicyCenterBehaviorRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "agent behavior conditional storage is unavailable")
			return
		}
		mutation, err := preparePolicyCenterAgentBehaviorMutation(user, state, request)
		if err == nil {
			err = deps.PolicyCenterBehaviorRepo.Save(r.Context(), mutation)
		}
		if err != nil {
			writePolicyCenterAgentBehaviorSaveError(w, err)
			return
		}
		auditDetails := map[string]any{
			"behavior_key":      definition.Key,
			"configured_action": request.Action,
			"version":           request.Version,
		}
		if request.RestrictedFileScopes != nil {
			auditDetails["restricted_file_scopes"] = *request.RestrictedFileScopes
		}
		logAudit(r, deps, "policy_center.agent_behavior.update", auditDetails, "policy_center_agent_behavior", definition.Key)

		freshStates, err := loadPolicyCenterAgentBehaviors(r, deps, user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "agent behavior status is unavailable")
			return
		}
		fresh := policyCenterAgentBehaviorStateByKey(freshStates, definition.Key)
		if fresh == nil || fresh.Health == "error" {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "agent behavior status is unavailable")
			return
		}
		writeJSON(w, fresh.customerProjection())
	}
}

func loadPolicyCenterAgentBehaviors(r *http.Request, deps *Dependencies, tenantID string) ([]policyCenterAgentBehaviorState, error) {
	if deps == nil {
		return nil, errors.New("dependencies unavailable")
	}
	// 执行模式只按 resolveSecurityExecutionMode 判定（显式模式优先，部署变量只作初值，读库失败按记录）。
	auditOnly := securityAuditOnlyEnabled(r.Context(), deps)

	agentPolicies, agentErr := listPolicyCenterAgentGuardPolicies(r, deps, tenantID)
	mcpPolicies, mcpErr := listPolicyCenterMCPPolicies(r, deps, tenantID)

	var destructivePolicy *repository.AgentOperationPolicy
	var destructiveErr error
	if deps.AgentOperationRepo == nil {
		destructiveErr = errors.New("destructive policy repository unavailable")
	} else {
		destructivePolicy, destructiveErr = deps.AgentOperationRepo.GetPolicy(r.Context(), tenantID, "tenant", "")
		if errors.Is(destructiveErr, repository.ErrAgentOperationNotFound) {
			destructiveErr = nil
		}
		// GetPolicy 现在也会返回已停用的行；策略中心的保存路径只认启用行，读写口径保持一致：停用按未配置处理。
		if destructiveErr == nil && destructivePolicy != nil && destructivePolicy.Disabled {
			destructivePolicy = nil
		}
	}

	states := make([]policyCenterAgentBehaviorState, 0, len(policyCenterAgentBehaviorDefinitions))
	for _, definition := range policyCenterAgentBehaviorDefinitions {
		state := policyCenterAgentBehaviorState{
			Definition:       definition,
			ConfiguredAction: policyCenterAgentBehaviorRecord,
			Health:           "ok",
			Version:          policyCenterAgentBehaviorVersion(definition.Key, "missing"),
		}
		switch definition.Source {
		case policyCenterAgentBehaviorDestructive:
			state.destructivePolicy = destructivePolicy
			if destructiveErr != nil {
				state.setError("删除与破坏策略暂时无法读取")
			} else if destructivePolicy != nil {
				state.Configured = true
				state.ConfiguredAction = normalizePolicyCenterAgentAction(destructivePolicy.Action)
				state.Version = policyCenterAgentBehaviorVersion(definition.Key, destructivePolicy)
				if !policyCenterActionAllowed(definition, state.ConfiguredAction) {
					state.RawConfiguredAction = strings.TrimSpace(destructivePolicy.Action)
					state.HasAdvancedOverrides = true
					state.setError("删除与破坏策略包含暂不支持的高级动作")
				}
			}
		case "agentguard":
			state.agentGuardPolicy, state.HasAdvancedOverrides = findPolicyCenterAgentGuardPolicy(agentPolicies, definition)
			state.agentPoliciesVersion = repository.PolicyCenterAgentGuardPoliciesVersion(agentPolicies)
			state.Version = policyCenterAgentBehaviorVersion(definition.Key, []any{state.agentPoliciesVersion, state.agentGuardPolicy})
			if agentErr != nil {
				state.setError("AgentGuard 策略暂时无法读取")
			} else if state.agentGuardPolicy != nil && !policyCenterMergedPolicyLacksCategory(state.agentGuardPolicy, definition) {
				state.Configured = true
				state.ConfiguredAction = policyCenterAgentGuardRuleAction(state.agentGuardPolicy, definition)
				if !isPolicyCenterAgentAction(state.ConfiguredAction) {
					state.RawConfiguredAction = state.ConfiguredAction
					state.HasAdvancedOverrides = true
					state.setError("AgentGuard 策略包含暂不支持的高级动作")
				}
			}
			if agentErr == nil && state.agentGuardPolicy != nil && !isPolicyCenterAgentAction(normalizePolicyCenterAgentAction(state.agentGuardPolicy.DefaultAction)) {
				if state.RawConfiguredAction == "" {
					state.RawConfiguredAction = strings.TrimSpace(state.agentGuardPolicy.DefaultAction)
				}
				state.HasAdvancedOverrides = true
				state.setError("AgentGuard 策略包含暂不支持的高级动作")
			}
			if definition.Key == policyCenterAgentBehaviorFile {
				state.destructivePolicy = destructivePolicy
				state.Version = policyCenterAgentBehaviorVersion(definition.Key, []any{state.agentPoliciesVersion, state.agentGuardPolicy, destructivePolicy})
				state.restrictedReadFailed = destructiveErr != nil
				if destructiveErr != nil {
					state.setError("删除与破坏策略暂时无法读取")
				}
			}
		case "mcp":
			state.mcpPolicy = findPolicyCenterMCPPolicy(mcpPolicies)
			state.mcpPolicies = mcpPolicies
			state.Version = policyCenterAgentBehaviorVersion(definition.Key, []any{repository.PolicyCenterMCPPoliciesVersion(mcpPolicies), state.mcpPolicy})
			if mcpErr != nil {
				state.setError("MCP 策略暂时无法读取")
			} else if state.mcpPolicy != nil {
				state.Configured = true
				state.ConfiguredAction = normalizePolicyCenterMCPAction(state.mcpPolicy.DefaultAction)
				state.HasAdvancedOverrides = len(mcpPolicies) > 1
				if !isPolicyCenterAgentAction(state.ConfiguredAction) {
					state.RawConfiguredAction = strings.TrimSpace(state.mcpPolicy.DefaultAction)
					state.HasAdvancedOverrides = true
					state.setError("MCP 策略包含暂不支持的高级动作")
				}
			}
		}
		if state.Health == "ok" && auditOnly {
			state.CurrentAction = policyCenterAgentBehaviorRecord
		} else {
			state.CurrentAction = state.ConfiguredAction
			// An MCP policy's own mode caps its action at runtime (observe records,
			// audit alerts); report what the gateway will actually do.
			if definition.Source == "mcp" && state.mcpPolicy != nil {
				state.CurrentAction = policyCenterMCPEffectiveAction(state.ConfiguredAction, state.mcpPolicy.Mode)
			}
		}
		if state.Health == "error" || (state.HasAdvancedOverrides && !auditOnly) {
			state.CurrentAction = "unknown"
		}
		states = append(states, state)
	}
	return states, nil
}

func listPolicyCenterAgentGuardPolicies(r *http.Request, deps *Dependencies, tenantID string) ([]*repository.AgentGuardPolicy, error) {
	repo := deps.AgentGuardBehaviorRepo
	if repo == nil {
		repo = deps.AgentGuardPolicyRepo
	}
	if repo == nil {
		return nil, errors.New("AgentGuard policy repository unavailable")
	}
	return repo.ListPolicies(r.Context(), tenantID)
}

func listPolicyCenterMCPPolicies(r *http.Request, deps *Dependencies, tenantID string) ([]*repository.MCPPolicy, error) {
	if deps.MCPPolicyRepo == nil {
		return nil, errors.New("MCP policy repository unavailable")
	}
	return deps.MCPPolicyRepo.ListByTenant(r.Context(), tenantID, "")
}

func (state *policyCenterAgentBehaviorState) setError(message string) {
	state.Health = "error"
	state.HealthMessage = message
}

func (state policyCenterAgentBehaviorState) customerProjection() map[string]any {
	item := map[string]any{
		"key":                    state.Definition.Key,
		"label":                  state.Definition.Label,
		"description":            state.Definition.Description,
		"configured":             state.Configured,
		"configured_action":      state.ConfiguredAction,
		"current_action":         state.CurrentAction,
		"health":                 state.Health,
		"allowed_actions":        policyCenterAllowedActions(state.Definition),
		"has_advanced_overrides": state.HasAdvancedOverrides,
		"version":                state.Version,
		"evaluation_stage":       "invocation_proposed",
	}
	if state.Definition.ToolPattern != "" {
		item["match_scope"] = "tool_category"
		item["match_pattern"] = state.Definition.ToolPattern
	} else if state.Definition.Source == policyCenterAgentBehaviorDestructive {
		item["match_scope"] = "destructive_arguments"
	} else {
		item["match_scope"] = "mcp_gateway"
	}
	if state.HealthMessage != "" {
		item["health_message"] = state.HealthMessage
	}
	if state.RawConfiguredAction != "" {
		item["raw_configured_action"] = state.RawConfiguredAction
	}
	if state.Definition.Key == policyCenterAgentBehaviorNetwork {
		item[agentGuardSequenceWindowKey] = policyCenterSequenceWindowSeconds(state.agentGuardPolicy)
	}
	if state.Definition.Key == policyCenterAgentBehaviorFile && !state.restrictedReadFailed {
		patterns := []string{}
		action := "block"
		if state.destructivePolicy != nil {
			patterns = state.destructivePolicy.RestrictedFilePatterns
			if state.destructivePolicy.RestrictedFileAction != "" {
				action = state.destructivePolicy.RestrictedFileAction
			}
		}
		if patterns == nil {
			patterns = []string{}
		}
		scopes := repository.DefaultRestrictedFileScopes()
		if state.destructivePolicy != nil && state.destructivePolicy.RestrictedFileScopes != nil {
			scopes = state.destructivePolicy.RestrictedFileScopes
		}
		item["restricted_file_patterns"] = patterns
		item["restricted_file_action"] = action
		item["restricted_file_scopes"] = scopes
	}
	return item
}

func decodePolicyCenterAgentBehaviorUpdateRequest(w http.ResponseWriter, r *http.Request) (policyCenterAgentBehaviorUpdateRequest, error) {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	var request policyCenterAgentBehaviorUpdateRequest
	if err := decoder.Decode(&request); err != nil {
		return request, errors.New("invalid JSON format")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return request, errors.New("request body must contain one JSON object")
	}
	request.Action = strings.TrimSpace(request.Action)
	request.Version = strings.TrimSpace(request.Version)
	if !isPolicyCenterAgentAction(request.Action) && request.Action != policyCenterAgentBehaviorConfirm {
		return request, errors.New("action must be record, alert_allow, confirm, or block")
	}
	if request.Version == "" || len(request.Version) > 128 {
		return request, errors.New("version is required")
	}
	return request, nil
}

func policyCenterAgentBehaviorDefinitionByKey(key string) (policyCenterAgentBehaviorDefinition, bool) {
	key = strings.TrimSpace(key)
	for _, definition := range policyCenterAgentBehaviorDefinitions {
		if definition.Key == key {
			return definition, true
		}
	}
	return policyCenterAgentBehaviorDefinition{}, false
}

func policyCenterAgentBehaviorStateByKey(states []policyCenterAgentBehaviorState, key string) *policyCenterAgentBehaviorState {
	for index := range states {
		if states[index].Definition.Key == key {
			return &states[index]
		}
	}
	return nil
}

func isPolicyCenterAgentAction(action string) bool {
	return action == policyCenterAgentBehaviorRecord || action == policyCenterAgentBehaviorAlertAllow || action == policyCenterAgentBehaviorBlock
}

// policyCenterAgentBehaviorConfirm 只有“删除与破坏”卡片能选（2.9.22：非 MCP 协议也能确认，
// 有确认通道走确认票据，没有时按 agent.confirm_without_channel）。
const policyCenterAgentBehaviorConfirm = "confirm"

// policyCenterAllowedActions 是一张卡片能选的动作。
func policyCenterAllowedActions(definition policyCenterAgentBehaviorDefinition) []string {
	if definition.Key == policyCenterAgentBehaviorDestructive {
		return []string{policyCenterAgentBehaviorRecord, policyCenterAgentBehaviorAlertAllow, policyCenterAgentBehaviorConfirm, policyCenterAgentBehaviorBlock}
	}
	return []string{policyCenterAgentBehaviorRecord, policyCenterAgentBehaviorAlertAllow, policyCenterAgentBehaviorBlock}
}

func policyCenterActionAllowed(definition policyCenterAgentBehaviorDefinition, action string) bool {
	for _, allowed := range policyCenterAllowedActions(definition) {
		if allowed == action {
			return true
		}
	}
	return false
}

func normalizePolicyCenterAgentAction(action string) string {
	switch strings.TrimSpace(action) {
	case "record", "allow":
		return policyCenterAgentBehaviorRecord
	case "alert_allow", "audit":
		return policyCenterAgentBehaviorAlertAllow
	case "block":
		return policyCenterAgentBehaviorBlock
	default:
		return strings.TrimSpace(action)
	}
}

func normalizePolicyCenterMCPAction(action string) string {
	return normalizePolicyCenterAgentAction(action)
}

func policyCenterAgentGuardAction(action string) string {
	switch action {
	case policyCenterAgentBehaviorRecord, policyCenterAgentBehaviorAlertAllow:
		// W5 5.7 (D4): "仅记录" means record-and-forward (audit), never an
		// explicit allow that would suppress the analyzer's audit trail.
		return repository.AgentGuardActionAudit
	default:
		return repository.AgentGuardActionBlock
	}
}

func policyCenterAgentGuardMode(action string) string {
	if action == policyCenterAgentBehaviorBlock {
		return repository.AgentGuardModeStrict
	}
	return repository.AgentGuardModeAudit
}

func findPolicyCenterAgentGuardPolicy(policies []*repository.AgentGuardPolicy, definition policyCenterAgentBehaviorDefinition) (*repository.AgentGuardPolicy, bool) {
	managedID := "policy-center-" + definition.Key
	// W5 5.1: every AgentGuard category lives in one merged managed policy so
	// the gateway (which resolves a single tenant policy) sees all of them.
	for _, policy := range policies {
		if policy == nil || policy.TenantID == "" || policy.ScopeType != "tenant" || policy.ScopeRef != "" {
			continue
		}
		if policy.ID == policyCenterAgentGuardPolicyIDFor(policy.TenantID) {
			return policy, policyCenterAgentGuardHasAdvancedRules(policy, managedID)
		}
	}
	for _, policy := range policies {
		if policy == nil || policy.TenantID == "" || policy.ScopeType != "tenant" || policy.ScopeRef != "" {
			continue
		}
		if policy.ID == managedID {
			return policy, policyCenterAgentGuardHasAdvancedRules(policy, managedID)
		}
	}
	for _, policy := range policies {
		if policy == nil || policy.ScopeType != "tenant" || policy.ScopeRef != "" {
			continue
		}
		for _, rule := range policyCenterAgentGuardRules(policy) {
			if stringValue(rule["tool_pattern"]) == definition.ToolPattern {
				return policy, true
			}
		}
	}
	return nil, false
}

func policyCenterAgentGuardRules(policy *repository.AgentGuardPolicy) []map[string]any {
	if policy == nil || policy.RulesJSON == nil {
		return nil
	}
	raw := policy.RulesJSON["rules"]
	switch rules := raw.(type) {
	case []map[string]any:
		return rules
	case []any:
		out := make([]map[string]any, 0, len(rules))
		for _, value := range rules {
			if rule, ok := value.(map[string]any); ok {
				out = append(out, rule)
			}
		}
		return out
	default:
		return nil
	}
}

func policyCenterAgentGuardHasAdvancedRules(policy *repository.AgentGuardPolicy, managedID string) bool {
	for _, rule := range policyCenterAgentGuardRules(policy) {
		id := stringValue(rule["id"])
		// Sibling categories' managed rules share the merged policy; they are
		// not advanced overrides of this category.
		if id != managedID && !policyCenterIsManagedRuleID(id) {
			return true
		}
	}
	return false
}

func policyCenterIsManagedRuleID(id string) bool {
	for _, definition := range policyCenterAgentBehaviorDefinitions {
		if definition.Source == "agentguard" && id == "policy-center-"+definition.Key {
			return true
		}
	}
	return false
}

// policyCenterMergedPolicyLacksCategory reports that the merged managed policy
// exists but this category has never been saved into it: the category is still
// unconfigured (record), not "whatever the merged policy's default is".
func policyCenterMergedPolicyLacksCategory(policy *repository.AgentGuardPolicy, definition policyCenterAgentBehaviorDefinition) bool {
	if policy == nil || policy.ID != policyCenterAgentGuardPolicyIDFor(policy.TenantID) {
		return false
	}
	for _, rule := range policyCenterAgentGuardRules(policy) {
		if stringValue(rule["id"]) == "policy-center-"+definition.Key {
			return false
		}
	}
	return true
}

func policyCenterAgentGuardRuleAction(policy *repository.AgentGuardPolicy, definition policyCenterAgentBehaviorDefinition) string {
	for _, rule := range policyCenterAgentGuardRules(policy) {
		if stringValue(rule["id"]) == "policy-center-"+definition.Key {
			rawAction := normalizePolicyCenterAgentAction(stringValue(rule["action"]))
			if !isPolicyCenterAgentAction(rawAction) {
				return rawAction
			}
			// record and alert_allow both enforce as audit (D4); the console
			// choice is kept on the rule so it reads back as saved.
			if selected := stringValue(rule[policyCenterRuleActionKey]); isPolicyCenterAgentAction(selected) && stringValue(rule["action"]) == policyCenterAgentGuardAction(selected) {
				return selected
			}
			return rawAction
		}
	}
	for _, rule := range policyCenterAgentGuardRules(policy) {
		if stringValue(rule["tool_pattern"]) == definition.ToolPattern {
			return normalizePolicyCenterAgentAction(stringValue(rule["action"]))
		}
	}
	return normalizePolicyCenterAgentAction(policy.DefaultAction)
}

// policyCenterMCPEffectiveAction maps an MCP policy's configured action and
// mode to what the gateway enforces (agentguard applyMode semantics).
func policyCenterMCPEffectiveAction(configured, mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case repository.AgentGuardModeStrict:
		return configured
	case "observe":
		return policyCenterAgentBehaviorRecord
	default:
		if configured == policyCenterAgentBehaviorBlock {
			return policyCenterAgentBehaviorAlertAllow
		}
		return configured
	}
}

func findPolicyCenterMCPPolicy(policies []*repository.MCPPolicy) *repository.MCPPolicy {
	var fallback *repository.MCPPolicy
	for _, policy := range policies {
		if policy == nil || policy.ScopeType != "tenant" || policy.ScopeRef != "" ||
			policy.ServerID != "" || (policy.ToolPattern != "" && policy.ToolPattern != "*") {
			continue
		}
		if policy.Note == "policy-center:external_tool" {
			return policy
		}
		if fallback == nil {
			fallback = policy
		}
	}
	return fallback
}

func (request policyCenterAgentBehaviorUpdateRequest) carriesRestrictedFields() bool {
	return request.RestrictedFilePatterns != nil || request.RestrictedFileAction != "" || request.RestrictedFileScopes != nil
}

// validatePolicyCenterRestrictedFileScopes 校验受限文件作用范围：只认三个取值，不许重复；可以为空。
func validatePolicyCenterRestrictedFileScopes(scopes []string) error {
	seen := map[string]bool{}
	for _, scope := range scopes {
		if !slices.Contains(repository.RestrictedFileScopeValues, scope) {
			return errors.New("restricted_file_scopes must be tool_call, user_mention, or proxy_output")
		}
		if seen[scope] {
			return errors.New("restricted_file_scopes must not repeat")
		}
		seen[scope] = true
	}
	return nil
}

func policyCenterRestrictedFieldsChanged(state *policyCenterAgentBehaviorState, request policyCenterAgentBehaviorUpdateRequest) bool {
	var patterns []string
	action := "block"
	scopes := repository.DefaultRestrictedFileScopes()
	if state.destructivePolicy != nil {
		patterns = state.destructivePolicy.RestrictedFilePatterns
		if state.destructivePolicy.RestrictedFileAction != "" {
			action = state.destructivePolicy.RestrictedFileAction
		}
		if state.destructivePolicy.RestrictedFileScopes != nil {
			scopes = state.destructivePolicy.RestrictedFileScopes
		}
	}
	return (request.RestrictedFilePatterns != nil && !slices.Equal(*request.RestrictedFilePatterns, patterns)) ||
		(request.RestrictedFileAction != "" && request.RestrictedFileAction != action) ||
		(request.RestrictedFileScopes != nil && !slices.Equal(repository.NormalizeRestrictedFileScopes(*request.RestrictedFileScopes), scopes))
}

func preparePolicyCenterAgentBehaviorMutation(user *repository.User, state *policyCenterAgentBehaviorState, request policyCenterAgentBehaviorUpdateRequest) (repository.PolicyCenterAgentBehaviorMutation, error) {
	mutation := repository.PolicyCenterAgentBehaviorMutation{TenantID: user.TenantID, ActorID: user.ID}
	if state.Definition.Source == "agentguard" {
		change := &repository.PolicyCenterAgentGuardChange{
			ID:                      policyCenterAgentGuardPolicyIDFor(user.TenantID),
			Expected:                repository.PolicyCenterExpectedState{ExpectedAbsent: state.agentGuardPolicy == nil},
			ExpectedPoliciesVersion: state.agentPoliciesVersion,
		}
		if state.agentGuardPolicy != nil {
			change.ID = state.agentGuardPolicy.ID
			change.Expected.ExpectedVersion = repository.PolicyCenterSnapshotVersion(state.agentGuardPolicy)
		}
		carriesRestrictedFields := request.carriesRestrictedFields()
		if !carriesRestrictedFields || request.Action != state.ConfiguredAction {
			candidate, err := preparePolicyCenterAgentGuardBehavior(user, state, request.Action, request.SensitiveReadEgressWindowSeconds)
			if err != nil {
				return mutation, err
			}
			change.Policy = candidate
		}
		mutation.AgentGuard = change
	}
	if state.Definition.Source == "mcp" {
		candidate := preparePolicyCenterMCPBehavior(user, state, request.Action)
		change := &repository.PolicyCenterMCPChange{
			ID: candidate.ID, Policy: candidate,
			Expected:                repository.PolicyCenterExpectedState{ExpectedAbsent: state.mcpPolicy == nil},
			ExpectedPoliciesVersion: repository.PolicyCenterMCPPoliciesVersion(state.mcpPolicies),
		}
		if state.mcpPolicy != nil {
			change.Expected.ExpectedVersion = repository.PolicyCenterSnapshotVersion(state.mcpPolicy)
		}
		mutation.MCP = change
	}
	if state.Definition.Key == policyCenterAgentBehaviorFile || state.Definition.Key == policyCenterAgentBehaviorDestructive {
		change := &repository.PolicyCenterOperationChange{
			ScopeType: "tenant", ScopeRef: "",
			Expected: repository.PolicyCenterExpectedState{ExpectedAbsent: state.destructivePolicy == nil},
		}
		if state.destructivePolicy != nil {
			change.Expected.ExpectedVersion = repository.PolicyCenterSnapshotVersion(state.destructivePolicy)
			change.ExpectedStorageVersion = state.destructivePolicy.Version
		}
		if state.Definition.Key == policyCenterAgentBehaviorDestructive {
			candidate := preparePolicyCenterOperationMutation(user, state, request.Action)
			change.Mutation = &candidate
		} else if request.carriesRestrictedFields() &&
			(request.Action == state.ConfiguredAction || policyCenterRestrictedFieldsChanged(state, request)) {
			candidate := preparePolicyCenterRestrictedFilesMutation(user, state, request)
			change.Mutation = &candidate
		}
		mutation.Operation = change
	}
	return mutation, nil
}

func preparePolicyCenterOperationMutation(user *repository.User, state *policyCenterAgentBehaviorState, action string) repository.AgentOperationPolicyMutation {
	mutation := repository.AgentOperationPolicyMutation{
		TenantID: user.TenantID, ActorID: user.ID, Source: "policy_center",
		ScopeType: "tenant", ScopeRef: "", Mode: "audit", Action: action,
		ExpectedVersion: 1,
	}
	if state.destructivePolicy != nil {
		mutation.Mode = state.destructivePolicy.Mode
		mutation.Protocol = state.destructivePolicy.Protocol
		mutation.DiscardablePaths = append([]string(nil), state.destructivePolicy.DiscardablePaths...)
		mutation.NotifyChannelIDs = append([]string(nil), state.destructivePolicy.NotifyChannelIDs...)
		mutation.RestrictedFilePatterns = append([]string(nil), state.destructivePolicy.RestrictedFilePatterns...)
		mutation.RestrictedFileAction = state.destructivePolicy.RestrictedFileAction
		if state.destructivePolicy.RestrictedFileScopes != nil {
			mutation.RestrictedFileScopes = append([]string{}, state.destructivePolicy.RestrictedFileScopes...)
		}
		mutation.ExpectedVersion = state.destructivePolicy.Version
	}
	// 卡片选“确认”对所有协议生效（protocol 为空），不沿用旧行只管 MCP 的 protocol=mcp。
	if action == policyCenterAgentBehaviorConfirm {
		mutation.Protocol = ""
	}
	return mutation
}

func preparePolicyCenterRestrictedFilesMutation(user *repository.User, state *policyCenterAgentBehaviorState, request policyCenterAgentBehaviorUpdateRequest) repository.AgentOperationPolicyMutation {
	action := "record"
	if state.destructivePolicy != nil {
		action = state.destructivePolicy.Action
	}
	mutation := preparePolicyCenterOperationMutation(user, state, action)
	if request.RestrictedFilePatterns != nil {
		mutation.RestrictedFilePatterns = append([]string(nil), (*request.RestrictedFilePatterns)...)
	}
	if request.RestrictedFileAction != "" {
		mutation.RestrictedFileAction = request.RestrictedFileAction
	}
	if request.RestrictedFileScopes != nil {
		mutation.RestrictedFileScopes = append([]string{}, (*request.RestrictedFileScopes)...)
	}
	return mutation
}

func preparePolicyCenterAgentGuardBehavior(user *repository.User, state *policyCenterAgentBehaviorState, action string, sequenceWindowSeconds *int) (*repository.AgentGuardPolicy, error) {
	candidate, err := clonePolicyCenterAgentGuardPolicy(state.agentGuardPolicy)
	if err != nil {
		return nil, err
	}
	managedID := "policy-center-" + state.Definition.Key
	// W5 5.1: a category without a policy is written into the single merged
	// managed policy (fixed ID) instead of a new policy per category; the
	// gateway resolves exactly one tenant policy.
	createMerged := candidate == nil
	if createMerged {
		candidate = &repository.AgentGuardPolicy{
			ID:        policyCenterAgentGuardPolicyIDFor(user.TenantID),
			TenantID:  user.TenantID,
			Name:      "策略中心托管规则",
			ScopeType: "tenant",
			// Rules carry the enforcement (RuleMode strict at the gateway); the
			// policy default must never turn one category's block into a
			// tenant-wide default.
			Mode:          repository.AgentGuardModeAudit,
			DefaultAction: repository.AgentGuardActionAudit,
			FailPolicy:    repository.AgentGuardFailClosed,
			Enabled:       true,
			RulesJSON:     map[string]any{},
			CreatedBy:     user.ID,
			UpdatedBy:     user.ID,
		}
	} else {
		candidate.Enabled = true
		candidate.UpdatedBy = user.ID
	}
	if candidate.RulesJSON == nil {
		candidate.RulesJSON = map[string]any{}
	}
	rules := policyCenterAgentGuardRules(candidate)
	if rules == nil {
		rules = []map[string]any{}
	}
	managedAction := policyCenterAgentGuardAction(action)
	found := false
	for _, rule := range rules {
		if stringValue(rule["id"]) == managedID {
			rule["tool_pattern"] = state.Definition.ToolPattern
			rule["action"] = managedAction
			rule[policyCenterRuleActionKey] = action
			rule["enabled"] = true
			found = true
			break
		}
	}
	if !found {
		rules = append(rules, map[string]any{
			"id": managedID, "name": state.Definition.Label, "tool_pattern": state.Definition.ToolPattern,
			"action": managedAction, policyCenterRuleActionKey: action, "enabled": true,
		})
	}
	candidate.RulesJSON["rules"] = rules
	applyPolicyCenterSequenceWindow(candidate, sequenceWindowSeconds)
	return candidate, nil
}

func preparePolicyCenterMCPBehavior(user *repository.User, state *policyCenterAgentBehaviorState, action string) *repository.MCPPolicy {
	candidate := &repository.MCPPolicy{
		ID:       "policy-center-mcp-" + strings.TrimPrefix(policyCenterAgentGuardPolicyIDFor(user.TenantID), policyCenterAgentGuardPolicyPrefix),
		TenantID: user.TenantID, ScopeType: "tenant", ScopeRef: "", ServerID: "", ToolPattern: "*",
		Mode: repository.AgentGuardModeAudit, DefaultAction: policyCenterAgentGuardAction(action),
		Priority: 0, Enabled: true, Note: "policy-center:external_tool", CreatedBy: user.ID,
	}
	if state.mcpPolicy != nil {
		*candidate = *state.mcpPolicy
		candidate.DefaultAction = policyCenterAgentGuardAction(action)
		candidate.Enabled = true
	}
	// The policy center has no MCP mode control: "阻断" must run in strict mode
	// or the gateway would only record it.
	candidate.Mode = policyCenterAgentGuardMode(action)
	return candidate
}

func clonePolicyCenterAgentGuardPolicy(policy *repository.AgentGuardPolicy) (*repository.AgentGuardPolicy, error) {
	if policy == nil {
		return nil, nil
	}
	clone := *policy
	for source, target := range map[*map[string]any]*map[string]any{
		&policy.RulesJSON:    &clone.RulesJSON,
		&policy.BehaviorJSON: &clone.BehaviorJSON,
		&policy.DLPJSON:      &clone.DLPJSON,
	} {
		if *source == nil {
			*target = nil
			continue
		}
		raw, err := json.Marshal(*source)
		if err != nil {
			return nil, err
		}
		*target = nil
		if err := json.Unmarshal(raw, target); err != nil {
			return nil, err
		}
	}
	return &clone, nil
}

func policyCenterAgentBehaviorVersion(key string, value any) string {
	raw, _ := json.Marshal([]any{key, value})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:12])
}

func stringValue(value any) string {
	typed, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(typed)
}

func writePolicyCenterAgentBehaviorSaveError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrAgentOperationConflict), errors.Is(err, repository.ErrPolicyCenterBehaviorConflict):
		writeErrorWithStatus(w, http.StatusConflict, "version_conflict", "agent behavior changed; reload before saving")
	case errors.Is(err, repository.ErrAgentOperationNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent behavior source not found")
	default:
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "agent behavior could not be saved")
	}
}

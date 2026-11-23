package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentguardmatch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AgentGuardPolicyTemplate struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Description    string           `json:"description"`
	RecommendedFor []string         `json:"recommended_for"`
	Policy         AgentGuardPolicy `json:"policy"`
}

type AgentGuardGovernanceStats struct {
	GeneratedAt        time.Time                            `json:"generated_at"`
	TotalHits          int                                  `json:"total_hits"`
	ReviewedCount      int                                  `json:"reviewed_count"`
	BlockedCount       int                                  `json:"blocked_count"`
	FalsePositiveCount int                                  `json:"false_positive_count"`
	AcceptedRiskCount  int                                  `json:"accepted_risk_count"`
	FalsePositiveRate  float64                              `json:"false_positive_rate"`
	ByRule             []AgentGuardStatsGroup               `json:"by_rule"`
	ByTool             []AgentGuardStatsGroup               `json:"by_tool"`
	ByApp              []AgentGuardStatsGroup               `json:"by_app"`
	Recommendations    []AgentGuardGovernanceRecommendation `json:"recommendations"`
}

type AgentGuardStatsGroup struct {
	Dimension          string  `json:"dimension"`
	Key                string  `json:"key"`
	Name               string  `json:"name"`
	HitCount           int     `json:"hit_count"`
	ReviewedCount      int     `json:"reviewed_count"`
	BlockedCount       int     `json:"blocked_count"`
	FalsePositiveCount int     `json:"false_positive_count"`
	AcceptedRiskCount  int     `json:"accepted_risk_count"`
	FalsePositiveRate  float64 `json:"false_positive_rate"`
}

type AgentGuardGovernanceRecommendation struct {
	Type            string `json:"type"`
	Severity        string `json:"severity"`
	Problem         string `json:"problem"`
	Impact          string `json:"impact"`
	RelatedObject   string `json:"related_object"`
	SuggestedAction string `json:"suggested_action"`
}

type AgentGuardExceptionSuggestion struct {
	SourceToolCallID string               `json:"source_tool_call_id"`
	SourceSummary    string               `json:"source_summary"`
	Exception        *AgentGuardException `json:"exception"`
	Explanation      string               `json:"explanation"`
}

type AgentGuardPolicySimulationRequest struct {
	PolicyID string            `json:"policy_id"`
	Policy   *AgentGuardPolicy `json:"policy"`
	Days     int               `json:"days"`
	Limit    int               `json:"limit"`
}

type AgentGuardPolicySimulationResult struct {
	GeneratedAt        time.Time                    `json:"generated_at"`
	PolicyID           string                       `json:"policy_id,omitempty"`
	PolicyName         string                       `json:"policy_name,omitempty"`
	TotalEvaluated     int                          `json:"total_evaluated"`
	WouldAllowCount    int                          `json:"would_allow_count"`
	WouldAuditCount    int                          `json:"would_audit_count"`
	WouldConfirmCount  int                          `json:"would_confirm_count"`
	WouldBlockCount    int                          `json:"would_block_count"`
	ChangedActionCount int                          `json:"changed_action_count"`
	Samples            []AgentGuardSimulationSample `json:"samples"`
}

type AgentGuardSimulationSample struct {
	ToolCallID       string `json:"tool_call_id"`
	ToolName         string `json:"tool_name"`
	ToolType         string `json:"tool_type"`
	CurrentDecision  string `json:"current_decision"`
	WouldDecision    string `json:"would_decision"`
	Reason           string `json:"reason"`
	NormalizedTarget string `json:"normalized_target,omitempty"`
	CreatedAt        string `json:"created_at"`
}

type AgentGuardBehaviorBaseline struct {
	GeneratedAt time.Time                   `json:"generated_at"`
	Profiles    []AgentGuardActorProfile    `json:"profiles"`
	Anomalies   []AgentGuardBehaviorAnomaly `json:"anomalies"`
}

type AgentGuardActorProfile struct {
	ActorID             string              `json:"actor_id"`
	ActorLabel          string              `json:"actor_label"`
	TotalCalls          int                 `json:"total_calls"`
	HighRiskCalls       int                 `json:"high_risk_calls"`
	BlockedCalls        int                 `json:"blocked_calls"`
	DistinctToolCount   int                 `json:"distinct_tool_count"`
	DistinctTargetCount int                 `json:"distinct_target_count"`
	CommonTools         []AgentGuardTopItem `json:"common_tools"`
	CommonTargets       []AgentGuardTopItem `json:"common_targets"`
	FirstSeen           time.Time           `json:"first_seen"`
	LastSeen            time.Time           `json:"last_seen"`
}

type AgentGuardTopItem struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type AgentGuardBehaviorAnomaly struct {
	ActorID         string `json:"actor_id"`
	Type            string `json:"type"`
	Severity        string `json:"severity"`
	Problem         string `json:"problem"`
	Evidence        string `json:"evidence"`
	SuggestedAction string `json:"suggested_action"`
}

type AgentGuardRollout struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	PolicyID       string     `json:"policy_id"`
	ScopeType      string     `json:"scope_type"`
	ScopeRef       string     `json:"scope_ref"`
	RolloutMode    string     `json:"rollout_mode"`
	TrafficPercent int        `json:"traffic_percent"`
	Status         string     `json:"status"`
	CreatedBy      string     `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	SimulationOnly bool       `json:"simulation_only"`
}

func AgentGuardPolicyTemplates() []AgentGuardPolicyTemplate {
	return []AgentGuardPolicyTemplate{
		{
			ID:          "loose",
			Name:        "低干预观察模板",
			Description: "适合 POC 初期收集样本，尽量降低误报，只对高风险保持阻断。",
			RecommendedFor: []string{
				"首次接入智能体工具调用",
				"需要先建立客户良性样本集",
			},
			Policy: AgentGuardPolicy{
				TemplateID:    "loose",
				Name:          "AgentGuard 低干预观察模板",
				ScopeType:     "tenant",
				Mode:          AgentGuardModeObserve,
				DefaultAction: AgentGuardActionAudit,
				FailPolicy:    AgentGuardFailOpen,
				Priority:      10,
				Enabled:       true,
				RulesJSON: map[string]any{"rules": []map[string]any{
					{"id": "audit-network-egress", "name": "记录网络外联", "tool_pattern": "network.*", "action": AgentGuardActionAudit, "enabled": true},
					{"id": "audit-system-command", "name": "记录系统命令", "tool_pattern": "system.*", "action": AgentGuardActionAudit, "enabled": true},
				}},
				BehaviorJSON: map[string]any{"file_read_burst_10s": 200, "network_egress_burst_10s": 200, "command_execute_burst_10s": 100},
				DLPJSON:      map[string]any{"high_confidence_secret_egress": "audit"},
			},
		},
		{
			ID:          "standard",
			Name:        "标准治理模板",
			Description: "适合生产 POC 默认启用：先审计、可确认、可通过例外治理误报，高风险始终不可绕过。",
			RecommendedFor: []string{
				"生产 POC 默认策略",
				"需要控制误报同时保留审计证据",
			},
			Policy: AgentGuardPolicy{
				TemplateID:    "standard",
				Name:          "AgentGuard 标准治理模板",
				ScopeType:     "tenant",
				Mode:          AgentGuardModeAudit,
				DefaultAction: AgentGuardActionAudit,
				FailPolicy:    AgentGuardFailClosed,
				Priority:      100,
				Enabled:       true,
				RulesJSON: map[string]any{"rules": []map[string]any{
					{"id": "audit-network-egress", "name": "网络外联审计", "tool_pattern": "network.*", "action": AgentGuardActionAudit, "enabled": true},
					{"id": "confirm-system-command", "name": "系统命令确认", "tool_pattern": "system.*", "action": AgentGuardActionConfirm, "enabled": true},
					{"id": "audit-file-read", "name": "文件读取审计", "tool_pattern": "file.*", "action": AgentGuardActionAudit, "enabled": true},
					{"id": "confirm-database-write", "name": "数据库写操作确认", "tool_pattern": "database.*", "action": AgentGuardActionConfirm, "enabled": true},
				}},
				BehaviorJSON: map[string]any{"file_read_burst_10s": 100, "network_egress_burst_10s": 100, "command_execute_burst_10s": 50},
				DLPJSON:      map[string]any{"high_confidence_secret_egress": "block"},
			},
		},
		{
			ID:          "strict",
			Name:        "强制防护模板",
			Description: "适合已完成灰度和误报收敛的关键业务，对高风险工具调用执行强制阻断或确认。",
			RecommendedFor: []string{
				"核心生产应用",
				"已完成样本回放和策略模拟",
			},
			Policy: AgentGuardPolicy{
				TemplateID:    "strict",
				Name:          "AgentGuard 强制防护模板",
				ScopeType:     "tenant",
				Mode:          AgentGuardModeStrict,
				DefaultAction: AgentGuardActionAudit,
				FailPolicy:    AgentGuardFailClosed,
				Priority:      200,
				Enabled:       true,
				RulesJSON: map[string]any{"rules": []map[string]any{
					{"id": "block-untrusted-egress", "name": "不可信来源外联阻断", "tool_pattern": "network.*", "action": AgentGuardActionBlock, "enabled": true},
					{"id": "confirm-system-command", "name": "系统命令确认", "tool_pattern": "system.*", "action": AgentGuardActionConfirm, "enabled": true},
					{"id": "audit-file-read", "name": "文件读取审计", "tool_pattern": "file.*", "action": AgentGuardActionAudit, "enabled": true},
					{"id": "confirm-database-write", "name": "数据库写操作确认", "tool_pattern": "database.*", "action": AgentGuardActionConfirm, "enabled": true},
				}},
				BehaviorJSON: map[string]any{"file_read_burst_10s": 50, "network_egress_burst_10s": 50, "command_execute_burst_10s": 20},
				DLPJSON:      map[string]any{"high_confidence_secret_egress": "block"},
			},
		},
	}
}

func BuildAgentGuardGovernanceStats(logs []ToolCallLog, dispositions []AuditDisposition, now time.Time) AgentGuardGovernanceStats {
	statusByToolCall := map[string]string{}
	for _, disposition := range dispositions {
		if disposition.SubjectType == "tool_call" {
			statusByToolCall[disposition.SubjectID] = disposition.Status
		}
	}

	stats := AgentGuardGovernanceStats{GeneratedAt: now}
	byRule := map[string]*AgentGuardStatsGroup{}
	byTool := map[string]*AgentGuardStatsGroup{}
	byApp := map[string]*AgentGuardStatsGroup{}
	for _, log := range logs {
		stats.TotalHits++
		if log.EffectiveDecision == AgentGuardActionBlock || log.Status == AgentGuardActionBlock {
			stats.BlockedCount++
		}
		status := statusByToolCall[log.ID]
		if status == "false_positive" {
			stats.FalsePositiveCount++
			stats.ReviewedCount++
		} else if status == "accepted" {
			stats.AcceptedRiskCount++
			stats.ReviewedCount++
		} else if status == "resolved" {
			stats.ReviewedCount++
		}

		mergeAgentGuardStatsGroup(groupFor(byRule, "rule", agentGuardRuleKey(log), agentGuardRuleKey(log)), log, status)
		mergeAgentGuardStatsGroup(groupFor(byTool, "tool", safeGroupKey(log.ToolName), toolDisplayName(log)), log, status)
		appKey := safeGroupKey(log.SessionID)
		if appKey == "未归属" {
			appKey = "未归属应用"
		}
		mergeAgentGuardStatsGroup(groupFor(byApp, "app", appKey, appKey), log, status)
	}
	stats.FalsePositiveRate = ratio(stats.FalsePositiveCount, stats.ReviewedCount)
	stats.ByRule = sortedAgentGuardGroups(byRule)
	stats.ByTool = sortedAgentGuardGroups(byTool)
	stats.ByApp = sortedAgentGuardGroups(byApp)
	stats.Recommendations = buildAgentGuardGovernanceRecommendations(stats)
	return stats
}

func SuggestAgentGuardExceptionFromToolCall(log ToolCallLog, reason string, now time.Time) (*AgentGuardExceptionSuggestion, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, errors.New("reason is required")
	}
	target := strings.TrimSpace(log.NormalizedTarget)
	if target == "" {
		target = strings.TrimSpace(firstStringArg(log.Parameters, "url", "uri", "endpoint", "host", "target", "path", "file_path", "filepath", "file", "destination"))
	}
	if target == "" {
		target = strings.TrimSpace(log.ToolName)
	}
	exception := &AgentGuardException{
		TenantID:      log.TenantID,
		ScopeType:     "tenant",
		ScopeRef:      "",
		RuleID:        agentGuardRuleKey(log),
		TargetPattern: target,
		Decision:      AgentGuardActionAudit,
		Reason:        reason,
		ExpiresAt:     now.Add(7 * 24 * time.Hour),
		Enabled:       true,
	}
	return &AgentGuardExceptionSuggestion{
		SourceToolCallID: log.ID,
		SourceSummary:    fmt.Sprintf("%s / %s / %s", log.ToolName, log.EffectiveDecision, agentGuardRuleKey(log)),
		Exception:        exception,
		Explanation:      "建议先将误报降级为审计，并设置 7 天过期时间；高风险不允许生成放行例外。",
	}, nil
}

// SimulateAgentGuardPolicyOnLogs 把历史工具调用日志投影到候选策略下的决策分布。
// auditOnly 传入全局记录模式（resolveSimulationAuditOnly）：为 true 时执行上限恒为 audit，任何策略模式
// （含 strict）都只投影为审计——与网关 clampModeToCeiling 语义一致，避免
// 治理看板把「运行时只审计」的流量误报成「会阻断」。auditOnly=false 时保留策略内在的
// what-if 投影（若启用强制则会阻断的假设）。
func SimulateAgentGuardPolicyOnLogs(policy *AgentGuardPolicy, logs []ToolCallLog, sampleLimit int, auditOnly bool) AgentGuardPolicySimulationResult {
	now := time.Now().UTC()
	result := AgentGuardPolicySimulationResult{GeneratedAt: now}
	if policy != nil {
		result.PolicyID = policy.ID
		result.PolicyName = policy.Name
	}
	if sampleLimit <= 0 {
		sampleLimit = 20
	}
	for _, log := range logs {
		result.TotalEvaluated++
		decision, reason := simulateAgentGuardDecision(policy, log, auditOnly)
		switch decision {
		case AgentGuardActionAllow:
			result.WouldAllowCount++
		case AgentGuardActionConfirm:
			result.WouldConfirmCount++
		case AgentGuardActionBlock:
			result.WouldBlockCount++
		default:
			result.WouldAuditCount++
		}
		current := log.EffectiveDecision
		if current == "" {
			current = log.Status
		}
		if decision != current {
			result.ChangedActionCount++
		}
		if (decision == AgentGuardActionBlock || decision == AgentGuardActionConfirm || decision != current) && len(result.Samples) < sampleLimit {
			result.Samples = append(result.Samples, AgentGuardSimulationSample{
				ToolCallID:       log.ID,
				ToolName:         log.ToolName,
				ToolType:         log.ToolType,
				CurrentDecision:  current,
				WouldDecision:    decision,
				Reason:           reason,
				NormalizedTarget: log.NormalizedTarget,
				CreatedAt:        log.CreatedAt.Format(time.RFC3339),
			})
		}
	}
	return result
}

func BuildAgentGuardBehaviorBaseline(logs []ToolCallLog, now time.Time) AgentGuardBehaviorBaseline {
	type mutableProfile struct {
		profile AgentGuardActorProfile
		tools   map[string]int
		targets map[string]int
		recent  int
		reads   int
	}
	profiles := map[string]*mutableProfile{}
	for _, log := range logs {
		actorID := strings.TrimSpace(log.UserID)
		if actorID == "" {
			actorID = strings.TrimSpace(log.SessionID)
		}
		if actorID == "" {
			actorID = "unknown"
		}
		p := profiles[actorID]
		if p == nil {
			p = &mutableProfile{
				profile: AgentGuardActorProfile{ActorID: actorID, ActorLabel: actorID, FirstSeen: log.CreatedAt, LastSeen: log.CreatedAt},
				tools:   map[string]int{},
				targets: map[string]int{},
			}
			profiles[actorID] = p
		}
		p.profile.TotalCalls++
		if log.RiskLevel == "high" || log.RiskLevel == "critical" {
			p.profile.HighRiskCalls++
		}
		if log.EffectiveDecision == AgentGuardActionBlock || log.Status == AgentGuardActionBlock {
			p.profile.BlockedCalls++
		}
		if log.CreatedAt.Before(p.profile.FirstSeen) {
			p.profile.FirstSeen = log.CreatedAt
		}
		if log.CreatedAt.After(p.profile.LastSeen) {
			p.profile.LastSeen = log.CreatedAt
		}
		p.tools[safeGroupKey(log.ToolName)]++
		target := strings.TrimSpace(log.NormalizedTarget)
		if target == "" {
			target = safeGroupKey(firstStringArg(log.Parameters, "url", "path", "target", "file"))
		}
		if target != "" && target != "未归属" {
			p.targets[target]++
		}
		if now.Sub(log.CreatedAt) <= time.Hour {
			p.recent++
		}
		if log.ToolType == "file" && strings.Contains(strings.ToLower(log.ToolName), "read") && now.Sub(log.CreatedAt) <= 10*time.Minute {
			p.reads++
		}
	}
	baseline := AgentGuardBehaviorBaseline{GeneratedAt: now}
	for _, p := range profiles {
		p.profile.DistinctToolCount = len(p.tools)
		p.profile.DistinctTargetCount = len(p.targets)
		p.profile.CommonTools = topAgentGuardItems(p.tools, 5)
		p.profile.CommonTargets = topAgentGuardItems(p.targets, 5)
		baseline.Profiles = append(baseline.Profiles, p.profile)
		riskRate := ratio(p.profile.HighRiskCalls, p.profile.TotalCalls)
		if p.reads >= 5 {
			baseline.Anomalies = append(baseline.Anomalies, AgentGuardBehaviorAnomaly{
				ActorID:         p.profile.ActorID,
				Type:            "burst_file_read",
				Severity:        "high",
				Problem:         "短时间文件读取次数异常",
				Evidence:        fmt.Sprintf("10 分钟内读取文件 %d 次", p.reads),
				SuggestedAction: "复核该智能体任务目标，必要时为文件读取配置更小范围的策略。",
			})
		}
		if p.profile.TotalCalls >= 5 && riskRate >= 0.8 {
			baseline.Anomalies = append(baseline.Anomalies, AgentGuardBehaviorAnomaly{
				ActorID:         p.profile.ActorID,
				Type:            "high_risk_actor",
				Severity:        "medium",
				Problem:         "该智能体近期高风险工具调用占比过高",
				Evidence:        fmt.Sprintf("高风险 %d 次 / 总调用 %d 次", p.profile.HighRiskCalls, p.profile.TotalCalls),
				SuggestedAction: "先在审计模式下观察任务来源，再按应用或智能体收紧策略。",
			})
		}
	}
	sort.SliceStable(baseline.Profiles, func(i, j int) bool {
		return baseline.Profiles[i].TotalCalls > baseline.Profiles[j].TotalCalls
	})
	return baseline
}

func ValidateAgentGuardRollout(r *AgentGuardRollout) error {
	if r == nil {
		return errors.New("rollout is nil")
	}
	if strings.TrimSpace(r.TenantID) == "" {
		return errors.New("tenant_id is required")
	}
	if strings.TrimSpace(r.PolicyID) == "" {
		return errors.New("policy_id is required")
	}
	if strings.TrimSpace(r.ScopeType) == "" {
		return errors.New("scope_type is required")
	}
	if r.ScopeType != "tenant" && strings.TrimSpace(r.ScopeRef) == "" {
		return errors.New("scope_ref is required for scoped rollout")
	}
	if r.RolloutMode == "" {
		r.RolloutMode = AgentGuardModeAudit
	}
	if r.RolloutMode != AgentGuardModeObserve && r.RolloutMode != AgentGuardModeAudit && r.RolloutMode != AgentGuardModeStrict {
		return errors.New("rollout_mode must be observe, audit, or strict")
	}
	if r.TrafficPercent < 1 || r.TrafficPercent > 100 {
		return errors.New("traffic_percent must be between 1 and 100")
	}
	if r.Status == "" {
		r.Status = "active"
	}
	if r.Status != "active" && r.Status != "paused" && r.Status != "completed" {
		return errors.New("status must be active, paused, or completed")
	}
	if r.ExpiresAt.IsZero() || !r.ExpiresAt.After(time.Now()) {
		return errors.New("expires_at must be in the future")
	}
	return nil
}

func (r *AgentGuardPolicyRepository) GetFalsePositiveStats(ctx context.Context, tenantID string, days int) (*AgentGuardGovernanceStats, error) {
	logs, err := r.listAgentGuardRecentToolLogs(ctx, tenantID, days, 5000)
	if err != nil {
		return nil, err
	}
	dispositions, err := r.listAgentGuardToolDispositions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	stats := BuildAgentGuardGovernanceStats(logs, dispositions, time.Now().UTC())
	return &stats, nil
}

func (r *AgentGuardPolicyRepository) SuggestException(ctx context.Context, tenantID, toolCallID, reason, actorID string, now time.Time) (*AgentGuardExceptionSuggestion, error) {
	log, err := r.getAgentGuardToolCallByID(ctx, tenantID, toolCallID)
	if err != nil {
		return nil, err
	}
	if log == nil {
		return nil, pgx.ErrNoRows
	}
	suggestion, err := SuggestAgentGuardExceptionFromToolCall(*log, reason, now)
	if err != nil {
		return nil, err
	}
	suggestion.Exception.TenantID = tenantID
	suggestion.Exception.CreatedBy = actorID
	return suggestion, nil
}

func (r *AgentGuardPolicyRepository) SimulatePolicy(ctx context.Context, tenantID string, req AgentGuardPolicySimulationRequest) (*AgentGuardPolicySimulationResult, error) {
	policy := req.Policy
	if policy == nil && req.PolicyID != "" {
		var err error
		policy, err = r.GetPolicy(ctx, tenantID, req.PolicyID)
		if err != nil {
			return nil, err
		}
	}
	if policy == nil {
		return nil, errors.New("policy or policy_id is required")
	}
	policy.TenantID = tenantID
	logs, err := r.listAgentGuardRecentToolLogs(ctx, tenantID, req.Days, req.Limit)
	if err != nil {
		return nil, err
	}
	var modeValues map[string]string
	modeReadOK := true
	if r.db != nil {
		var modeErr error
		modeValues, modeErr = loadExecutionModeValues(ctx, r.db)
		modeReadOK = modeErr == nil
	}
	auditOnly := resolveSimulationAuditOnly(modeValues, modeReadOK)
	result := SimulateAgentGuardPolicyOnLogs(policy, logs, 20, auditOnly)
	return &result, nil
}

func (r *AgentGuardPolicyRepository) GetBehaviorBaseline(ctx context.Context, tenantID string, days int) (*AgentGuardBehaviorBaseline, error) {
	logs, err := r.listAgentGuardRecentToolLogs(ctx, tenantID, days, 5000)
	if err != nil {
		return nil, err
	}
	baseline := BuildAgentGuardBehaviorBaseline(logs, time.Now().UTC())
	return &baseline, nil
}

func (r *AgentGuardPolicyRepository) CreateRollout(ctx context.Context, rollout *AgentGuardRollout) error {
	if err := ValidateAgentGuardRollout(rollout); err != nil {
		return err
	}
	if rollout.ID == "" {
		rollout.ID = "agro_" + uuid.New().String()[:8]
	}
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		INSERT INTO agentguard_rollouts (
			id, tenant_id, policy_id, scope_type, scope_ref, rollout_mode, traffic_percent,
			status, created_by, created_at, updated_at, expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	`, rollout.ID, rollout.TenantID, rollout.PolicyID, rollout.ScopeType, rollout.ScopeRef, rollout.RolloutMode,
		rollout.TrafficPercent, rollout.Status, agentGuardNullableString(rollout.CreatedBy), now, now, rollout.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create agentguard rollout: %w", err)
	}
	rollout.CreatedAt = now
	rollout.UpdatedAt = now
	rollout.SimulationOnly = true
	return nil
}

func (r *AgentGuardPolicyRepository) ListRollouts(ctx context.Context, tenantID, status string) ([]*AgentGuardRollout, error) {
	query := `
		SELECT id, tenant_id, policy_id, scope_type, scope_ref, rollout_mode, traffic_percent, status,
		       COALESCE(created_by, ''), created_at, updated_at, expires_at, completed_at
		FROM agentguard_rollouts
		WHERE tenant_id = $1`
	args := []any{tenantID}
	if status != "" {
		args = append(args, status)
		query += fmt.Sprintf(" AND status = $%d", len(args))
	}
	query += " ORDER BY created_at DESC"
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list agentguard rollouts: %w", err)
	}
	defer rows.Close()
	var out []*AgentGuardRollout
	for rows.Next() {
		var item AgentGuardRollout
		if err := rows.Scan(&item.ID, &item.TenantID, &item.PolicyID, &item.ScopeType, &item.ScopeRef,
			&item.RolloutMode, &item.TrafficPercent, &item.Status, &item.CreatedBy, &item.CreatedAt,
			&item.UpdatedAt, &item.ExpiresAt, &item.CompletedAt); err != nil {
			return nil, err
		}
		item.SimulationOnly = true
		out = append(out, &item)
	}
	return out, rows.Err()
}

func (r *AgentGuardPolicyRepository) listAgentGuardRecentToolLogs(ctx context.Context, tenantID string, days, limit int) ([]ToolCallLog, error) {
	if days <= 0 {
		days = 7
	}
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	rows, err := r.db.Query(ctx, `
		SELECT `+toolCallLogSelectColumns+`
		FROM tool_call_logs
		WHERE tenant_id = $1
		  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 day' * $2
		  AND (raw_decision IS NOT NULL OR effective_decision IS NOT NULL OR COALESCE(matched_policy_name, '') ILIKE '%AgentGuard%')
		ORDER BY created_at DESC
		LIMIT $3
	`, tenantID, days, limit)
	if err != nil {
		return nil, fmt.Errorf("list agentguard recent tool logs: %w", err)
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
	return logs, rows.Err()
}

func (r *AgentGuardPolicyRepository) getAgentGuardToolCallByID(ctx context.Context, tenantID, toolCallID string) (*ToolCallLog, error) {
	row := r.db.QueryRow(ctx, `
		SELECT `+toolCallLogSelectColumns+`
		FROM tool_call_logs
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, toolCallID)
	log, err := scanToolCallLog(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get agentguard tool call: %w", err)
	}
	return &log, nil
}

func (r *AgentGuardPolicyRepository) listAgentGuardToolDispositions(ctx context.Context, tenantID string) ([]AuditDisposition, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, subject_type, subject_id, status,
		       COALESCE(note, ''), COALESCE(operator_id, ''), COALESCE(operator_name, ''),
		       created_at, updated_at
		FROM audit_dispositions
		WHERE tenant_id = $1 AND subject_type = 'tool_call'
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list agentguard tool dispositions: %w", err)
	}
	defer rows.Close()
	var out []AuditDisposition
	for rows.Next() {
		var item AuditDisposition
		if err := rows.Scan(&item.ID, &item.TenantID, &item.SubjectType, &item.SubjectID, &item.Status,
			&item.Note, &item.OperatorID, &item.OperatorName, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func groupFor(groups map[string]*AgentGuardStatsGroup, dimension, key, name string) *AgentGuardStatsGroup {
	key = safeGroupKey(key)
	group := groups[key]
	if group == nil {
		group = &AgentGuardStatsGroup{Dimension: dimension, Key: key, Name: name}
		groups[key] = group
	}
	return group
}

func mergeAgentGuardStatsGroup(group *AgentGuardStatsGroup, log ToolCallLog, status string) {
	group.HitCount++
	if log.EffectiveDecision == AgentGuardActionBlock || log.Status == AgentGuardActionBlock {
		group.BlockedCount++
	}
	switch status {
	case "false_positive":
		group.FalsePositiveCount++
		group.ReviewedCount++
	case "accepted":
		group.AcceptedRiskCount++
		group.ReviewedCount++
	case "resolved":
		group.ReviewedCount++
	}
	group.FalsePositiveRate = ratio(group.FalsePositiveCount, group.ReviewedCount)
}

func sortedAgentGuardGroups(groups map[string]*AgentGuardStatsGroup) []AgentGuardStatsGroup {
	out := make([]AgentGuardStatsGroup, 0, len(groups))
	for _, group := range groups {
		out = append(out, *group)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].FalsePositiveRate != out[j].FalsePositiveRate {
			return out[i].FalsePositiveRate > out[j].FalsePositiveRate
		}
		return out[i].HitCount > out[j].HitCount
	})
	return out
}

func buildAgentGuardGovernanceRecommendations(stats AgentGuardGovernanceStats) []AgentGuardGovernanceRecommendation {
	var out []AgentGuardGovernanceRecommendation
	for _, group := range stats.ByRule {
		if group.FalsePositiveCount > 0 && group.FalsePositiveRate >= 0.4 {
			out = append(out, AgentGuardGovernanceRecommendation{
				Type:            "false_positive_rule",
				Severity:        "medium",
				Problem:         fmt.Sprintf("规则 %s 的误报占比较高", group.Name),
				Impact:          fmt.Sprintf("已确认误报 %d 次 / 已复核 %d 次", group.FalsePositiveCount, group.ReviewedCount),
				RelatedObject:   group.Key,
				SuggestedAction: "复核命中样本；对确认安全的业务目标创建有过期时间的例外，或先降级为审计。",
			})
		}
	}
	return out
}

func agentGuardRuleKey(log ToolCallLog) string {
	type evidence struct {
		RuleID string `json:"rule_id"`
	}
	var items []evidence
	if len(log.EvidenceJSON) > 0 && json.Unmarshal(log.EvidenceJSON, &items) == nil {
		for _, item := range items {
			if strings.TrimSpace(item.RuleID) != "" {
				return item.RuleID
			}
		}
	}
	for _, value := range []string{log.MatchedPolicyID, log.EffectiveReason, log.MatchReason, log.RawDecision} {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "agentguard_rule_unknown"
}

func toolDisplayName(log ToolCallLog) string {
	if strings.TrimSpace(log.ToolName) != "" {
		return log.ToolName
	}
	if strings.TrimSpace(log.ToolType) != "" {
		return log.ToolType
	}
	return "未识别工具"
}

func safeGroupKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "未归属"
	}
	return value
}

func ratio(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func firstStringArg(args map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := args[key]
		if !ok {
			continue
		}
		if s, ok := value.(string); ok {
			return s
		}
	}
	return ""
}

func simulateAgentGuardDecision(policy *AgentGuardPolicy, log ToolCallLog, auditOnly bool) (string, string) {
	// 计算生效模式：audit_only 是执行“上限”（observe<audit<strict，数值越小越宽松），把策略
	// 模式钳制到不高于 audit——与网关 agentguard clampModeToCeiling 语义一致。缺省（policy==nil）
	// 按 strict 解释（缺省策略最严格），audit_only 可将其钳制为审计。
	policyMode := AgentGuardModeStrict
	if policy != nil {
		policyMode = policy.Mode
	}
	effectiveMode := clampAgentGuardSimulationMode(policyMode, auditOnly)

	if policy == nil {
		return AgentGuardActionAudit, "missing_policy"
	}
	action := policy.DefaultAction
	if action == "" {
		action = AgentGuardActionAudit
	}
	reason := "default_action"
	rules := normalizeAgentGuardRuleMaps(policy.RulesJSON)
	sharedRules := make([]agentguardmatch.Rule, 0, len(rules))
	for _, rule := range rules {
		ruleID := stringFromRule(rule, "id")
		if strings.TrimSpace(ruleID) == "" {
			ruleID = stringFromRule(rule, "name")
		}
		sharedRules = append(sharedRules, agentguardmatch.Rule{
			ID:      ruleID,
			Pattern: stringFromRule(rule, "tool_pattern"),
			Action:  stringFromRule(rule, "action"),
			Enabled: boolFromRule(rule, "enabled", true),
		})
	}
	matched := agentguardmatch.Evaluate(sharedRules, log.ToolName, log.ToolType)
	if matched.Matched {
		action = matched.Action
		reason = matched.RuleID
	}
	return applyAgentGuardSimulationMode(action, effectiveMode), reason
}

// agentGuardModeEnforcementRank 按执行强度给模式排序：observe(0) < audit(1) < strict(2)。
// 数值越小越宽松（越不阻断）。用于把 audit_only 作为对 strict 的“上限”钳制，与网关
// agentguard modeEnforcementRank 保持一致。
func agentGuardModeEnforcementRank(mode string) int {
	switch mode {
	case AgentGuardModeObserve:
		return 0
	case AgentGuardModeStrict:
		return 2
	default: // audit 及未知值按 audit 处理
		return 1
	}
}

// clampAgentGuardSimulationMode 返回策略模式与执行上限中“更宽松”（执行强度更低）者。
// auditOnly=true 对应全局记录模式（见 resolveSimulationAuditOnly），执行上限为 audit：strict 被钳到 audit，
// observe 仍保持 observe（更宽松）。auditOnly=false 不钳制，保留策略自身 what-if 投影。
// 与网关 clampModeToCeiling 语义一致。
func clampAgentGuardSimulationMode(policyMode string, auditOnly bool) string {
	if !auditOnly {
		return policyMode
	}
	if agentGuardModeEnforcementRank(AgentGuardModeAudit) < agentGuardModeEnforcementRank(policyMode) {
		return AgentGuardModeAudit
	}
	return policyMode
}

// resolveSimulationAuditOnly 与数据面同口径：两个键交给 executionmode.FromValues（控制台显式模式优先；
// 没有显式模式时部署变量 SECURITY_AUDIT_ONLY=true 作初值，D7；其次旧键；都没有按记录）。
// 读库失败按记录模式（readOK=false），不在读不到配置时模拟成会真拦。
func resolveSimulationAuditOnly(values map[string]string, readOK bool) bool {
	if !readOK {
		return true
	}
	auditOnly, _ := executionmode.FromValues(values, executionmode.DeploymentRecordInitialValue())
	return auditOnly
}

func normalizeAgentGuardRuleMaps(raw map[string]any) []map[string]any {
	if raw == nil {
		return nil
	}
	value, ok := raw["rules"]
	if !ok {
		return nil
	}
	switch rules := value.(type) {
	case []map[string]any:
		return rules
	case []any:
		out := make([]map[string]any, 0, len(rules))
		for _, item := range rules {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func stringFromRule(rule map[string]any, key string) string {
	value, _ := rule[key].(string)
	return value
}

func boolFromRule(rule map[string]any, key string, fallback bool) bool {
	value, ok := rule[key].(bool)
	if !ok {
		return fallback
	}
	return value
}

func applyAgentGuardSimulationMode(action, mode string) string {
	switch mode {
	case AgentGuardModeObserve, AgentGuardModeAudit:
		if action == AgentGuardActionBlock || action == AgentGuardActionConfirm {
			return AgentGuardActionAudit
		}
		return action
	case AgentGuardModeStrict:
		if action == AgentGuardActionAllow || action == AgentGuardActionAudit || action == AgentGuardActionConfirm || action == AgentGuardActionBlock {
			return action
		}
	}
	return AgentGuardActionAudit
}

func topAgentGuardItems(counts map[string]int, limit int) []AgentGuardTopItem {
	items := make([]AgentGuardTopItem, 0, len(counts))
	for key, count := range counts {
		items = append(items, AgentGuardTopItem{Key: key, Count: count})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Key < items[j].Key
	})
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

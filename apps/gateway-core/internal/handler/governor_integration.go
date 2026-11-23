package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/errclass"
	"github.com/yangjiyj/aiguard/packages/shared-go/ratelog"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GovernorDecider is the interface exposed to the handler layer.
// It matches *governor.Decider but is defined here as an interface so
// the handler package does not need to import the governor package in tests.
type GovernorDecider interface {
	Decide(ctx context.Context, ref governor.ScopeRef) governor.Decision
}

type governorNonRealtimeDecider interface {
	DecideNonRealtime(ctx context.Context, ref governor.ScopeRef) governor.Decision
}

// SetGovernor injects a governor.Decider (or nil to disable) into the handler.
// When gov is nil the governor check is skipped and all requests are passed through.
func (h *ChatCompletionsHandler) SetGovernor(gov GovernorDecider) {
	h.governor = gov
}

// SetDB injects the database pool used by recordGovernorEvent to write alert_inbox rows.
// Call this once during server startup. If nil, alert_inbox writes are skipped (log-only).
func (h *ChatCompletionsHandler) SetDB(db *pgxpool.Pool) {
	h.db = db
}

// applyGovernorDecision calls governor.Decide and writes the HTTP response for
// blocking actions. Returns true if the request was terminated, false to continue.
// Fix 1: ScopeRef uses stable key and team identities from the envelope.
// Fix 2: ActionDowngradeMod re-queries models.downgrade_to when decision.DowngradeTo is empty.
// Fix 3: ActionAlert (including soft-mode alerts) writes to alert_inbox.
func (h *ChatCompletionsHandler) applyGovernorDecision(
	ctx context.Context,
	w http.ResponseWriter,
	envelope *modelrouter.RequestEnvelope,
	requestID string,
) bool {
	return applyGovernorDecision(ctx, w, envelope, requestID, h.governor, h.quotaAdmission != nil, true, h.db)
}

func applyGovernorDecision(
	ctx context.Context,
	w http.ResponseWriter,
	envelope *modelrouter.RequestEnvelope,
	requestID string,
	decider GovernorDecider,
	nonRealtime bool,
	allowDowngrade bool,
	db *pgxpool.Pool,
) bool {
	if decider == nil {
		return false
	}

	// ClientID is the stable internal_keys.id used by key-scope governance.
	ref := governor.ScopeRef{
		UserModelAccessEnforced: auth.UserModelAccessEnforced(ctx),
		TenantID:                envelope.TenantID,
		TeamID:                  envelope.TeamID,
		ProjectID:               envelope.ProjectID,
		UserID:                  trustedActorUserID(envelope),
		KeyID:                   envelope.ClientID,
		ModelID:                 envelope.ModelID,
		ModelName:               envelope.Model,
	}

	var decision governor.Decision
	if policyDecider, ok := decider.(governorNonRealtimeDecider); nonRealtime && ok {
		decision = policyDecider.DecideNonRealtime(ctx, ref)
	} else {
		decision = decider.Decide(ctx, ref)
	}
	configuredAction := decision.Action
	quotaAction := decision.TriggeredMetric != "" &&
		(configuredAction == governor.ActionPauseKey || configuredAction == governor.ActionDowngradeMod)
	unsupportedEndpointAction := configuredAction == governor.ActionPauseKey ||
		(configuredAction == governor.ActionDowngradeMod && !allowDowngrade)
	if quotaAction || unsupportedEndpointAction {
		decision.Action = governor.ActionRateLimit
		decision.AlertOnly = false
		decision.DowngradeTo = ""
		decision.Reason = "unsupported configured action " + string(configuredAction) + " was safely rate-limited"
	}

	// Emit event for non-none decisions (Fix 3: also fires for soft-mode AlertOnly)
	if decision.Action != governor.ActionNone {
		recordGovernorEvent(ctx, db, decision, envelope, string(decision.Action))
	}

	switch decision.Action {
	case governor.ActionRateLimit:
		if decision.BudgetCutoff {
			// 断流开启且额度状态无法确认：fail-closed，统一 503 中文，不让请求绕过预算。
			markBudgetOutcome(envelope, billingOutcomeBudgetUnavailable)
			writeErrorResponseWithStatus(w, "billing_unavailable", governor.BillingUnavailableCutoffMessage, requestID, http.StatusServiceUnavailable)
			return true
		}
		w.Header().Set("Retry-After", "60")
		writeErrorResponse(w, "rate_limited", "quota exceeded: "+decision.TriggeredMetric, requestID)
		return true

	case governor.ActionDowngradeMod:
		downgradeTo := decision.DowngradeTo
		if downgradeTo == "" && db != nil {
			var destination *string
			err := db.QueryRow(ctx,
				`SELECT downgrade_to FROM models WHERE id = $1`,
				envelope.ModelID,
			).Scan(&destination)
			if err != nil || destination == nil || *destination == "" {
				recordGovernorEvent(ctx, db, decision, envelope, "governor.downgrade_fallback_alert")
				return false
			}
			downgradeTo = *destination
		}
		if downgradeTo == "" {
			return false
		}
		originalModel := envelope.ModelID
		envelope.ModelID = downgradeTo
		envelope.Model = downgradeTo
		w.Header().Set("X-UAG-Downgraded", "true")
		w.Header().Set("X-UAG-Original-Model", originalModel)
		w.Header().Set("X-UAG-Triggered-Scope", decision.TriggeredScope)
		recordGovernorEvent(ctx, db, decision, envelope, "governor.model_downgraded")
		return false

	case governor.ActionAlert:
		// Alert-only (incl. soft mode): recordGovernorEvent already fired above.
		// Never blocks the request.
		return false
	}

	return false
}

// recordGovernorEvent writes a governor event to both the log and alert_inbox table.
// Fix 3: alert_inbox INSERT added so soft-mode and hard-mode alerts are persisted.
func (h *ChatCompletionsHandler) recordGovernorEvent(
	ctx context.Context,
	d governor.Decision,
	env *modelrouter.RequestEnvelope,
	eventType string,
) {
	recordGovernorEvent(ctx, h.db, d, env, eventType)
}

func recordGovernorEvent(
	ctx context.Context,
	db *pgxpool.Pool,
	d governor.Decision,
	env *modelrouter.RequestEnvelope,
	eventType string,
) {
	log.Printf("[governor.event] type=%s action=%s scope=%s metric=%s downgrade_to=%s project=%s user=%s key=%s team=%s estimated=%d actual=%d",
		eventType, d.Action, d.TriggeredScope, d.TriggeredMetric, d.DowngradeTo,
		env.ProjectID, env.UserID, env.KeyPrefix, env.TeamID, d.Estimated, d.Actual)

	if db == nil {
		return
	}
	// 预留超出每个请求结算都可能触发一次：按（租户、主体、模型、类型、天）合并成一条，见 quota_overrun_alert.go。
	if isQuotaOverrunEvent(eventType) {
		recordQuotaOverrunAlert(ctx, db, d, env, eventType)
		return
	}

	bodyJSON, _ := json.Marshal(map[string]any{
		"triggered_scope":  d.TriggeredScope,
		"triggered_metric": d.TriggeredMetric,
		"key_prefix":       env.KeyPrefix,
		"project_id":       env.ProjectID,
		"tenant_id":        env.TenantID,
		"team_id":          env.TeamID,
		"downgrade_to":     d.DowngradeTo,
		"reason":           d.Reason,
		"alert_only":       d.AlertOnly,
	})

	severity := "high"
	if d.AlertOnly {
		severity = "warning"
	}

	alertID := newAuditID("alert_")
	title := governorAlertTitle(eventType, d.Reason)
	_, err := db.Exec(ctx, `
		INSERT INTO alert_inbox (id, tenant_id, severity, type, title, body_json, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT DO NOTHING
	`, alertID, env.TenantID, severity, eventType, title, bodyJSON, time.Now())
	if err != nil {
		// 这里是请求路径上的一次性写入，没有重试循环；库不可用时每个触发配额动作的请求都会失败一次。
		// 只记错误类别（pgx 连接错误文本会带用户名与库名），并限频；[governor.event] 行已在上面无条件记录，事件本身不丢。
		governorAlertInsertFailureLog.Printf(errclass.Classify(err),
			"[recordGovernorEvent] alert_inbox insert failed: %s", errclass.Summary(err))
	}
}

// governorAlertInsertFailureLog 限频：首条必打，之后每 20 条一条，累计次数在 total=。
var governorAlertInsertFailureLog = ratelog.New(20)

// governorAlertTitle 是访问与额度治理事件写进消息中心的标题。标题会原样进入消息导出和
// 外部通知，必须是中文；与 web-console alertInboxDisplay.ts 的 governanceCopy 同口径。
func governorAlertTitle(eventType, reason string) string {
	reason = strings.ToLower(strings.TrimSpace(reason))
	switch {
	case reason == "model not allowed for team":
		return "模型未对该团队开放"
	case strings.HasPrefix(reason, "fail-open"):
		if strings.Contains(reason, "timeout") || strings.Contains(reason, "deadline") {
			return "额度检查超时，已放行请求"
		}
		return "额度检查异常，已放行请求"
	case eventType == "quota.admission.reservation_overrun":
		return "额度预占超出（Token）"
	case eventType == "quota.admission.cost_reservation_overrun":
		return "额度预占超出（费用）"
	case eventType == "quota.admission.runtime_fault":
		return "额度观测故障"
	default:
		return "访问与额度治理通知"
	}
}

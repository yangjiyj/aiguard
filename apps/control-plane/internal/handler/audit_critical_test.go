package handler

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/opsalert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type recordingChainWriter struct {
	mu     sync.Mutex
	events []string
	err    error
}

func (w *recordingChainWriter) Append(_ context.Context, _, eventType, eventID string, _ map[string]any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	w.events = append(w.events, eventID)
	return nil
}

func (w *recordingChainWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.events)
}

type recordingOpsAlerts struct {
	mu     sync.Mutex
	events []opsalert.Event
}

func (r *recordingOpsAlerts) Emit(_ context.Context, ev opsalert.Event) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return true, nil
}

func auditRequest() *httptest.ResponseRecorder { return httptest.NewRecorder() }

// 关键事件（改价格/预算/断流/资费/钱包/执行模式）在 logAudit 返回时已同步写入审计链。
func TestLogAuditWritesCriticalEventsSynchronously(t *testing.T) {
	for _, action := range []string{"price.update", "billing.tariff.publish", "billing.tariff.create", "billing.adjustment", "quota_policy.update"} {
		writer := &recordingChainWriter{}
		deps := &Dependencies{SystemRepo: &capturingSystemRepo{}, AuditAppender: audit_chain.NewAppender(writer, false)}
		req := httptest.NewRequest("POST", "/x", nil)
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u", TenantID: "t"}))
		logAudit(req, deps, action, map[string]interface{}{"k": "v"}, "x", "y")
		if writer.count() != 1 {
			t.Fatalf("%s: critical audit must be in the chain when logAudit returns, got %d", action, writer.count())
		}
	}
	if !isCriticalAudit("update_system_settings", map[string]interface{}{"new_configured_mode": "protect"}) {
		t.Fatal("execution mode change must be critical")
	}
	if isCriticalAudit("update_system_settings", map[string]interface{}{"log_retention_days": "90"}) || isCriticalAudit("create_user", nil) {
		t.Fatal("ordinary operations must stay asynchronous")
	}
}

// 关键事件写入审计链失败时产生“关键审计写入失败”告警，而不是静默丢失。
func TestLogAuditCriticalFailureRaisesAlert(t *testing.T) {
	writer := &recordingChainWriter{err: errors.New("db down")}
	alerts := &recordingOpsAlerts{}
	deps := &Dependencies{SystemRepo: &capturingSystemRepo{}, AuditAppender: audit_chain.NewAppender(writer, false), OpsAlerts: alerts}
	req := httptest.NewRequest("POST", "/x", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u", TenantID: "t"}))
	logAudit(req, deps, "billing.credit", map[string]interface{}{}, "wallet", "w")
	if len(alerts.events) != 1 || alerts.events[0].Type != opsalert.TypeAuditWriteFailed || alerts.events[0].ScopeLabel != "钱包调账" {
		t.Fatalf("alerts=%+v", alerts.events)
	}
}

// 币种切换与作废其他币种价格是关键审计：必须同步写审计链，不能走可丢失的异步队列。
func TestCurrencySwitchAuditActionsAreCritical(t *testing.T) {
	for _, action := range []string{"billing.currency.switch", "billing.price.retire_other_currencies"} {
		if !isCriticalAudit(action, nil) {
			t.Errorf("%s 必须是关键审计", action)
		}
	}
	if auditActionLabel("billing.currency.switch") != "切换系统币种" {
		t.Errorf("告警标题应为切换系统币种：%q", auditActionLabel("billing.currency.switch"))
	}
	if auditActionLabel("billing.price.retire_other_currencies") != "修改价格" {
		t.Errorf("作废其他币种价格归入修改价格：%q", auditActionLabel("billing.price.retire_other_currencies"))
	}
}

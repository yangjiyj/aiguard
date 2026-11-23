package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/opsalert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeChainVerifier struct {
	result *repository.VerifyResult
	err    error
	calls  int
}

func (f *fakeChainVerifier) Verify(context.Context, int64, int64) (*repository.VerifyResult, error) {
	f.calls++
	return f.result, f.err
}

// 定时校验失败产生“审计链完整性校验失败”高危告警，结果供审计日志页展示（中文原因）。
func TestAuditChainHealthVerifyFailureRaisesAlertAndRecordsStatus(t *testing.T) {
	alerts := &recordingOpsAlerts{}
	status := NewAuditIntegrityStatus(false)
	at := time.Date(2026, 10, 11, 3, 0, 0, 0, time.UTC)
	h := &AuditChainHealth{Verifier: &fakeChainVerifier{result: &repository.VerifyResult{OK: false, FirstBreakAtSeq: 42, Detail: "signature invalid"}}, Status: status, Alerts: alerts, Now: func() time.Time { return at }}
	h.VerifyOnce(context.Background())
	if len(alerts.events) != 1 || alerts.events[0].Type != opsalert.TypeAuditVerifyFailed {
		t.Fatalf("alerts=%+v", alerts.events)
	}
	if kind, _ := opsalert.KindOf(opsalert.TypeAuditVerifyFailed); kind.Severity != "critical" {
		t.Fatalf("verify failure must be high severity: %+v", kind)
	}
	rec := httptest.NewRecorder()
	GetAuditChainIntegrity(&Dependencies{AuditIntegrity: status})(rec, httptest.NewRequest("GET", "/admin/v1/audit-chain/integrity", nil))
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["verified"] != true || got["ok"] != false || got["first_break_at_seq"] != float64(42) || got["detail"] != "签名校验失败" || got["last_verified_at"] != "2026-10-11T03:00:00Z" {
		t.Fatalf("integrity=%v", got)
	}
}

func TestAuditChainHealthPassAndNotYetVerified(t *testing.T) {
	status := NewAuditIntegrityStatus(true)
	if snap := status.snapshot(); snap["verified"] != false || snap["hmac_default_key"] != true {
		t.Fatalf("snapshot=%v", snap)
	}
	alerts := &recordingOpsAlerts{}
	h := &AuditChainHealth{Verifier: &fakeChainVerifier{result: &repository.VerifyResult{OK: true}}, Status: status, Alerts: alerts}
	h.VerifyOnce(context.Background())
	h.ReportDefaultKey(context.Background())
	if snap := status.snapshot(); snap["ok"] != true {
		t.Fatalf("snapshot=%v", snap)
	}
	if len(alerts.events) != 1 || alerts.events[0].Type != opsalert.TypeAuditHMACDefaultKey {
		t.Fatalf("default key must raise exactly one alert, got %+v", alerts.events)
	}
	// 校验本身跑不起来：记为失败但不误报篡改。
	failing := &AuditChainHealth{Verifier: &fakeChainVerifier{err: errors.New("db")}, Status: status, Alerts: alerts}
	failing.VerifyOnce(context.Background())
	if snap := status.snapshot(); snap["ok"] != false || snap["detail"] != "校验未能完成" || len(alerts.events) != 1 {
		t.Fatalf("snapshot=%v alerts=%d", snap, len(alerts.events))
	}
}

// 正向代理用量未知：按站点聚合成告警（P1 记录用量未知 fact 时调用）。
func TestReportProxyUsageUnknownEmitsPerHostAlert(t *testing.T) {
	alerts := &recordingOpsAlerts{}
	ReportProxyUsageUnknown(context.Background(), &Dependencies{OpsAlerts: alerts}, "t1", "chat.example.cn", "req-1")
	ReportProxyUsageUnknown(context.Background(), nil, "t1", "x", "")
	if len(alerts.events) != 1 || alerts.events[0].Type != opsalert.TypeProxyUsageUnknown || alerts.events[0].ScopeKey != "host:chat.example.cn" || alerts.events[0].ScopeLabel != "站点 chat.example.cn" {
		t.Fatalf("alerts=%+v", alerts.events)
	}
}

func TestAuditChainHealthReportsDroppedRecords(t *testing.T) {
	alerts := &recordingOpsAlerts{}
	h := &AuditChainHealth{Alerts: alerts, Dropped: func() map[string]int64 { return map[string]int64{"t1": 7, "t2": 0} }}
	h.ReportDropped(context.Background())
	if len(alerts.events) != 1 || alerts.events[0].Type != opsalert.TypeAuditRecordDropped || alerts.events[0].Count != 7 || alerts.events[0].TenantID != "t1" {
		t.Fatalf("alerts=%+v", alerts.events)
	}
}

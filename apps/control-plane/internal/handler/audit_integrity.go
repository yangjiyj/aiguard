package handler

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/opsalert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// OpsAlertEmitter 由 *opsalert.Emitter 实现。
type OpsAlertEmitter interface {
	Emit(ctx context.Context, ev opsalert.Event) (bool, error)
}

// AuditIntegrityStatus 是审计链的健康状况：签名密钥是否为开发默认值、最近一次完整性校验的结论。
type AuditIntegrityStatus struct {
	mu            sync.RWMutex
	defaultKey    bool
	lastVerified  time.Time
	lastOK        bool
	lastBreakSeq  int64
	lastDetail    string
	lastErr       string
	verifiedCount bool
}

func NewAuditIntegrityStatus(defaultKey bool) *AuditIntegrityStatus {
	return &AuditIntegrityStatus{defaultKey: defaultKey}
}

func (s *AuditIntegrityStatus) record(at time.Time, result *repository.VerifyResult, err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastVerified, s.verifiedCount = at, true
	s.lastErr, s.lastDetail, s.lastBreakSeq = "", "", 0
	if err != nil {
		s.lastOK, s.lastErr = false, "校验未能完成"
		return
	}
	s.lastOK = result != nil && result.OK
	if result != nil && !result.OK {
		s.lastBreakSeq = result.FirstBreakAtSeq
		s.lastDetail = verifyDetailLabel(result.Detail)
	}
}

// verifyDetailLabel 把校验失败原因转成中文，界面不露英文。
func verifyDetailLabel(detail string) string {
	switch detail {
	case "prev_hash mismatch":
		return "前后记录链接不一致"
	case "payload_hash mismatch":
		return "记录内容与摘要不一致"
	case "chain_hash mismatch":
		return "链式摘要不一致"
	case "signature invalid":
		return "签名校验失败"
	case "":
		return ""
	default:
		return "记录无法读取"
	}
}

func (s *AuditIntegrityStatus) snapshot() map[string]any {
	out := map[string]any{"hmac_default_key": false, "verified": false}
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out["hmac_default_key"] = s.defaultKey
	if !s.verifiedCount {
		return out
	}
	out["verified"] = true
	out["last_verified_at"] = s.lastVerified.UTC().Format(time.RFC3339)
	out["ok"] = s.lastOK
	if s.lastBreakSeq > 0 {
		out["first_break_at_seq"] = s.lastBreakSeq
	}
	if s.lastDetail != "" {
		out["detail"] = s.lastDetail
	}
	if s.lastErr != "" {
		out["detail"] = s.lastErr
	}
	return out
}

// GetAuditChainIntegrity handles GET /admin/v1/audit-chain/integrity：
// 返回签名密钥状态与最近一次完整性校验结果（只读，不触发校验）。
func GetAuditChainIntegrity(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var status *AuditIntegrityStatus
		if deps != nil {
			status = deps.AuditIntegrity
		}
		writeJSON(w, status.snapshot())
	}
}

type auditChainVerifier interface {
	Verify(ctx context.Context, fromSeq, toSeq int64) (*repository.VerifyResult, error)
}

// AuditChainHealth 承担审计链的后台守护：每天完整校验一次、上报丢失的审计记录、开发默认密钥告警。
type AuditChainHealth struct {
	Verifier auditChainVerifier
	Status   *AuditIntegrityStatus
	Alerts   OpsAlertEmitter
	Dropped  func() map[string]int64
	TenantID string
	Now      func() time.Time
	verifyMu sync.Mutex
}

func (h *AuditChainHealth) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UTC()
}

func (h *AuditChainHealth) tenant() string {
	if h.TenantID != "" {
		return h.TenantID
	}
	return "tenant_default"
}

// VerifyOnce 完整校验一次审计链（与 POST /admin/v1/audit-chain/verify 同一实现）；失败时产生高危告警。
func (h *AuditChainHealth) VerifyOnce(ctx context.Context) {
	if h == nil || h.Verifier == nil {
		return
	}
	h.verifyMu.Lock()
	defer h.verifyMu.Unlock()
	result, err := h.Verifier.Verify(ctx, 0, 0)
	at := h.now()
	h.Status.record(at, result, err)
	if err != nil {
		log.Printf("[audit_chain.verify] verify failed to run: %v", err)
		return
	}
	if result != nil && !result.OK {
		log.Printf("[audit_chain.verify] integrity broken at seq=%d (%s)", result.FirstBreakAtSeq, result.Detail)
		h.emit(ctx, opsalert.Event{
			TenantID: h.tenant(), Type: opsalert.TypeAuditVerifyFailed, ScopeKey: "chain",
			ScopeLabel: verifyDetailLabel(result.Detail),
			Detail:     map[string]any{"first_break_at_seq": result.FirstBreakAtSeq, "verified_at": at.Format(time.RFC3339)},
		})
	}
}

// ReportDropped 把审计链队列丢失的非关键记录汇总成“审计记录丢失”告警。
func (h *AuditChainHealth) ReportDropped(ctx context.Context) {
	if h == nil || h.Dropped == nil {
		return
	}
	for tenantID, count := range h.Dropped() {
		if count <= 0 {
			continue
		}
		if tenantID == "" {
			tenantID = h.tenant()
		}
		h.emit(ctx, opsalert.Event{TenantID: tenantID, Type: opsalert.TypeAuditRecordDropped, ScopeKey: "queue", Count: int(count),
			ScopeLabel: "本次丢失 " + strconv.FormatInt(count, 10) + " 条", Detail: map[string]any{"dropped": count}})
	}
}

// ReportDefaultKey 在使用开发默认签名密钥时写一条高危告警。
func (h *AuditChainHealth) ReportDefaultKey(ctx context.Context) {
	if h == nil || h.Status == nil || !h.Status.defaultKey {
		return
	}
	h.emit(ctx, opsalert.Event{TenantID: h.tenant(), Type: opsalert.TypeAuditHMACDefaultKey, ScopeKey: "control-plane"})
}

func (h *AuditChainHealth) emit(ctx context.Context, ev opsalert.Event) {
	if h.Alerts == nil {
		return
	}
	if _, err := h.Alerts.Emit(ctx, ev); err != nil {
		log.Printf("[audit_chain] alert %s failed: %v", ev.Type, err)
	}
}

// Run 启动守护：启动时报告默认密钥并校验一次，之后每分钟上报丢失、每 24 小时校验一次。
func (h *AuditChainHealth) Run(ctx context.Context, verifyEvery, dropEvery time.Duration) {
	if h == nil {
		return
	}
	h.ReportDefaultKey(ctx)
	h.VerifyOnce(ctx)
	verifyTicker := time.NewTicker(verifyEvery)
	dropTicker := time.NewTicker(dropEvery)
	defer verifyTicker.Stop()
	defer dropTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-verifyTicker.C:
			h.VerifyOnce(ctx)
		case <-dropTicker.C:
			h.ReportDropped(ctx)
		}
	}
}

// ReportProxyUsageUnknown 是“正向代理用量未知”告警的接入点：记录用量未知 fact 的一方调用，
// 同租户同站点的事件聚合到同一个告警组，首次出现时走告警渠道外发。deps 或告警组件未配置时不做任何事。
func ReportProxyUsageUnknown(ctx context.Context, deps *Dependencies, tenantID, host, requestID string) {
	if deps == nil || deps.OpsAlerts == nil {
		return
	}
	detail := map[string]any{"host": host}
	if requestID != "" {
		detail["sample_request_id"] = requestID
	}
	label := "站点 " + host
	if host == "" {
		label = "站点 未知"
	}
	if _, err := deps.OpsAlerts.Emit(ctx, opsalert.Event{TenantID: tenantID, Type: opsalert.TypeProxyUsageUnknown,
		ScopeKey: "host:" + host, ScopeLabel: label, Detail: detail}); err != nil {
		log.Printf("[billing_ops_alert] proxy usage unknown alert failed: %v", err)
	}
}

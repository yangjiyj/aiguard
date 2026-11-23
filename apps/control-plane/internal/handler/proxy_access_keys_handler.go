package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// ListProxyAccessKeys handles GET /admin/v1/proxy-access-keys
// 正向代理访问密钥列表（只返回前缀，绝不回显明文/哈希）。
func ListProxyAccessKeys(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.ProxyAccessKeyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "proxy access keys not configured")
			return
		}

		keys, err := deps.ProxyAccessKeyRepo.ListByTenant(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
	}
}

// CreateProxyAccessKey handles POST /admin/v1/proxy-access-keys
// Body: {model_ids, rpm_limit, daily_cap}
// 签发一把访问密钥：服务端铸造明文，仅在本次响应里回显一次（full_key），库里只存哈希。
func CreateProxyAccessKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.ProxyAccessKeyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "proxy access keys not configured")
			return
		}

		var req struct {
			ModelIDs         []string `json:"model_ids"`
			RPMLimit         int      `json:"rpm_limit"`
			DailyCap         int      `json:"daily_cap"`
			ExpiresInSeconds *int     `json:"expires_in_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON")
			return
		}

		// 把相对 TTL 解析为绝对过期时刻；非法值（≤0 或超上限）直接 400 拒绝，绝不静默纠正。
		expiresAt, err := resolveIssueExpiry(req.ExpiresInSeconds, time.Now())
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		rawKey := generateSecureKey()
		k := &repository.ProxyAccessKey{
			TenantID:  user.TenantID,
			ModelIDs:  req.ModelIDs,
			RPMLimit:  req.RPMLimit,
			DailyCap:  req.DailyCap,
			ExpiresAt: expiresAt,
		}
		if err := deps.ProxyAccessKeyRepo.Create(r.Context(), k, rawKey); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "proxy_access_key.create", map[string]interface{}{
			"key_id": k.ID, "prefix": k.ProxyKeyPrefix, "model_ids": k.ModelIDs,
			"expires_at": k.ExpiresAt,
		}, "proxy_access_key", k.ID)

		// 明文仅此一次回显，前端必须提示用户立刻保存。
		resp := map[string]interface{}{
			"id":               k.ID,
			"tenant_id":        k.TenantID,
			"proxy_key_prefix": k.ProxyKeyPrefix,
			"model_ids":        k.ModelIDs,
			"rpm_limit":        k.RPMLimit,
			"daily_cap":        k.DailyCap,
			"status":           k.Status,
			"created_at":       k.CreatedAt,
			"expires_at":       k.ExpiresAt,
			"full_key":         rawKey,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

// UpdateProxyAccessKey handles PUT /admin/v1/proxy-access-keys/{id}
// Body: {model_ids, rpm_limit, daily_cap, status}
// 管理动作：调整模型白名单/限额/状态（含吊销 status=revoked）。
func UpdateProxyAccessKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.ProxyAccessKeyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "proxy access keys not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		var req struct {
			ModelIDs []string `json:"model_ids"`
			RPMLimit int      `json:"rpm_limit"`
			DailyCap int      `json:"daily_cap"`
			Status   string   `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON")
			return
		}
		if req.Status == "" {
			req.Status = "active"
		}

		if err := deps.ProxyAccessKeyRepo.Update(r.Context(), user.TenantID, id, req.ModelIDs, req.RPMLimit, req.DailyCap, req.Status); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "proxy_access_key.update", map[string]interface{}{
			"key_id": id, "status": req.Status, "rpm_limit": req.RPMLimit, "daily_cap": req.DailyCap,
		}, "proxy_access_key", id)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}
}

// DeleteProxyAccessKey handles DELETE /admin/v1/proxy-access-keys/{id}
func DeleteProxyAccessKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.ProxyAccessKeyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "proxy access keys not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		if err := deps.ProxyAccessKeyRepo.Delete(r.Context(), user.TenantID, id); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "proxy_access_key.delete", map[string]interface{}{"key_id": id}, "proxy_access_key", id)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}
}

const (
	defaultRotationGrace = 24 * time.Hour
	maxRotationGrace     = 30 * 24 * time.Hour
	// maxIssueTTL：签发时可设的最长有效期上限（10 年），防把毫秒/纳秒当秒之类单位笔误
	// 造出近乎永不过期的 key。
	maxIssueTTL = 10 * 365 * 24 * time.Hour
)

// resolveRotationGrace 解析请求里的 grace_seconds 为旧 key 的灰度时长。
// nil（未传）回退默认 24h；0 立即吊销（无窗口，安全事件应急）；
// 负数拒绝；超过 30d 拒绝（reject-not-coerce，绝不静默截断为安全默认值）。
func resolveRotationGrace(graceSeconds *int) (time.Duration, error) {
	if graceSeconds == nil {
		return defaultRotationGrace, nil
	}
	s := *graceSeconds
	if s < 0 {
		return 0, fmt.Errorf("grace_seconds 不能为负: %d", s)
	}
	d := time.Duration(s) * time.Second
	if d > maxRotationGrace {
		return 0, fmt.Errorf("grace_seconds 超过上限 %d 秒: %d", int(maxRotationGrace/time.Second), s)
	}
	return d, nil
}

// computeOldKeyExpiry 计算轮换后旧 key 的过期时刻：now+grace，
// 但绝不晚于旧 key 原有过期时刻（避免轮换反而延长了本应更早作废的 key）。
func computeOldKeyExpiry(now time.Time, grace time.Duration, existing *time.Time) time.Time {
	exp := now.Add(grace)
	if existing != nil && existing.Before(exp) {
		return *existing
	}
	return exp
}

// resolveIssueExpiry 把签发请求里的相对 TTL expires_in_seconds 解析为绝对过期时刻。
// 用相对秒数（而非客户端传绝对时间戳）规避客户端时钟/时区漂移，服务端用权威 now() 计算。
// nil（未传）→ nil（永不过期，向后兼容默认）；>0 → now+ttl；
// ≤0 → 拒绝（签发即过期=出生即死，无意义）；>maxIssueTTL → 拒绝。
// 先在整数秒维度比上限再乘 time.Second：超大 int 乘 1e9 会溢出 int64 回绕成过去时刻，
// 造成静默 fail-open（永不过期）。reject-not-coerce，与 3.1/3.2/3.3 一致。
func resolveIssueExpiry(expiresInSeconds *int, now time.Time) (*time.Time, error) {
	if expiresInSeconds == nil {
		return nil, nil
	}
	s := *expiresInSeconds
	if s <= 0 {
		return nil, fmt.Errorf("expires_in_seconds 必须为正: %d", s)
	}
	maxSec := int(maxIssueTTL / time.Second)
	if s > maxSec {
		return nil, fmt.Errorf("expires_in_seconds 超过上限 %d 秒: %d", maxSec, s)
	}
	exp := now.Add(time.Duration(s) * time.Second)
	return &exp, nil
}

// RotateProxyAccessKey handles POST /admin/v1/proxy-access-keys/{id}/rotate
// 轮换 = 复用 Create 发一把新 active key（继承旧 key 的 scope），并把旧 key 的
// expires_at 设为 now+grace 进入双 key 灰度窗口。gateway-core verifier 按
// proxy_key_hash + status='active' + (expires_at IS NULL OR > now()) 查表，
// 窗口内两行均命中——在用客户端无感切换；窗口后旧行查表即过期，无需清理任务。
func RotateProxyAccessKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.ProxyAccessKeyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "proxy access keys not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		var req struct {
			GraceSeconds *int `json:"grace_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, "invalid_request", "invalid JSON")
			return
		}

		grace, err := resolveRotationGrace(req.GraceSeconds)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		old, err := deps.ProxyAccessKeyRepo.Get(r.Context(), id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "proxy access key not found")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if old == nil || old.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "proxy access key not found")
			return
		}

		// 发新 key：整体继承旧 key 的授权 scope（轮换=换密钥不换授权）。
		rawKey := generateSecureKey()
		nk := &repository.ProxyAccessKey{
			TenantID:  old.TenantID,
			ModelIDs:  old.ModelIDs,
			RPMLimit:  old.RPMLimit,
			DailyCap:  old.DailyCap,
			ExpiresAt: old.ExpiresAt,
		}
		if err := deps.ProxyAccessKeyRepo.Create(r.Context(), nk, rawKey); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		// 旧 key 进入灰度：now+grace，但绝不延长其原有过期时刻。
		oldExp := computeOldKeyExpiry(time.Now(), grace, old.ExpiresAt)
		if err := deps.ProxyAccessKeyRepo.SetExpiry(r.Context(), old.ID, &oldExp); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "proxy_access_key.rotate", map[string]interface{}{
			"key_id": nk.ID, "old_key_id": old.ID,
			"grace_seconds": int(grace / time.Second), "old_expires_at": oldExp,
		}, "proxy_access_key", nk.ID)

		resp := map[string]interface{}{
			"id":               nk.ID,
			"tenant_id":        nk.TenantID,
			"proxy_key_prefix": nk.ProxyKeyPrefix,
			"model_ids":        nk.ModelIDs,
			"rpm_limit":        nk.RPMLimit,
			"daily_cap":        nk.DailyCap,
			"status":           nk.Status,
			"created_at":       nk.CreatedAt,
			"full_key":         rawKey,
			"old_key_id":       old.ID,
			"old_expires_at":   oldExp,
			"grace_seconds":    int(grace / time.Second),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}
}

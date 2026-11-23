package handler

import (
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"net/http"
	"strings"
)

// Identity management is tenant-wide audit attribution, restricted to tenant administrators.
// It never grants a caller permissions or changes the authenticated principal.
func AgentIdentityManagement(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedContentEvidenceUser(w, r)
		if !ok {
			return
		}
		if !canMutateAuditDisposition(user) {
			writeErrorWithStatus(w, 403, "forbidden", "需要租户管理员权限")
			return
		}
		if deps.UsageDailyRepo == nil {
			writeErrorWithStatus(w, 503, "unavailable", "身份管理暂不可用")
			return
		}
		repo := repository.NewAgentIdentityRepository(deps.UsageDailyRepo.DB())
		var result interface{}
		var err error
		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Get("view") == "rules" {
				result, err = repo.Rules(r.Context(), user.TenantID)
			} else {
				offset := parseIntParam(r.URL.Query().Get("offset"), 0)
				if offset < 0 || offset > 100000 {
					writeErrorWithStatus(w, 400, "invalid_offset", "分页位置无效")
					return
				}
				keyword := strings.TrimSpace(r.URL.Query().Get("keyword"))
				if len(keyword) > 512 {
					writeErrorWithStatus(w, 400, "invalid_keyword", "搜索条件过长")
					return
				}
				var items []repository.AgentIdentityRecord
				var more bool
				items, more, err = repo.Pending(r.Context(), user.TenantID, keyword, offset)
				result = map[string]interface{}{"items": items, "has_more": more}
			}
		case http.MethodPost:
			var body struct {
				RequestID string `json:"request_id"`
				AgentType string `json:"agent_type"`
				Scope     string `json:"scope"`
				Note      string `json:"note"`
				Dedicated bool   `json:"dedicated_key"`
				RevokeID  string `json:"revoke_id"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			dec.DisallowUnknownFields()
			if dec.Decode(&body) != nil {
				writeErrorWithStatus(w, 400, "invalid_request", "请求格式错误")
				return
			}
			if body.RevokeID != "" {
				err = repo.Revoke(r.Context(), user.TenantID, user.ID, body.RevokeID)
				if err == nil {
					logAudit(r, deps, "agent_identity.revoke", map[string]interface{}{"rule_id": body.RevokeID}, "agent_identity", body.RevokeID)
				}
				result = map[string]bool{"revoked": err == nil}
			} else {
				var id string
				id, err = repo.Confirm(r.Context(), user.TenantID, user.ID, body.RequestID, body.AgentType, body.Scope, body.Note, body.Dedicated)
				if err == nil {
					logAudit(r, deps, "agent_identity.confirm", map[string]interface{}{"request_id": body.RequestID, "agent_type": body.AgentType, "scope": body.Scope}, "agent_identity", id)
				}
				result = map[string]string{"id": id}
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			writeErrorWithStatus(w, 404, "not_found", "记录不存在、已处理或不属于当前租户")
			return
		}
		if errors.Is(err, repository.ErrIdentityScope) {
			writeErrorWithStatus(w, 400, "invalid_scope", "请选择已知客户端、填写确认依据；持续登记需要稳定调用方和特征，或明确声明专用 Key")
			return
		}
		if errors.Is(err, repository.ErrIdentityConflict) {
			writeErrorWithStatus(w, 409, "conflict", "适用范围已有登记，请先查看并撤销冲突规则")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, 500, "internal_error", "身份处理失败，请稍后重试")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

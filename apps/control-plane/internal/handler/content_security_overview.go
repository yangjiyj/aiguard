package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// GetContentSecurityOverview 返回安全运营总览所需的全部统计（一次请求替代逐维度多次计数）。
//
// 口径与 /admin/v1/audit/content?alert_only=true 完全一致：窗口内「确实产生过可处置告警」
// 的会话串数、产生告警的主体数，以及各维度（严重级别 / 风险分类）上含有该类告警的会话串数。
// 因此本接口可以直接作为内容审计页的头部汇总使用，数字与下钻后的明细页对得上。
//
// 刻意不返回人工作业状态（audit_dispositions / alert_groups.status）：那部分只有内容留证页与
// 工具审计页能写，本页既不展示也无法闭环，返回了只会把「告警总数」换个名字。
//
// 权限与内容证据读取保持一致：仅能读全租户内容证据的角色可调用，避免通过汇总绕过行级范围。
func GetContentSecurityOverview(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, authOK := authenticatedContentEvidenceUser(w, r)
		if !authOK {
			return
		}
		if user.DepartmentAssignmentMode == "emergency" {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "content evidence not found")
			return
		}
		if !canReadFullTenantContentEvidence(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "content evidence is not available for this role")
			return
		}

		enabled, err := deps.SystemRepo.GetBool(r.Context(), "content_audit_enabled")
		if err != nil || !enabled {
			writeError(w, "feature_disabled", "内容审计功能未启用")
			return
		}

		scope, windowStart, windowEnd, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid UTC window")
			return
		}

		overview, err := deps.ContentLogRepo.GetContentSecurityOverview(r.Context(), repository.ContentSessionListFilter{
			IncludeDevTraffic: r.URL.Query().Get("include_dev") == "true",
			TenantID:          user.TenantID,
			EnvironmentScope:  scope,
			StartTime:         windowStart,
			EndTime:           windowEnd,
		})
		if err != nil {
			log.Printf("content security overview failed: request_id=%q tenant=%q err=%v",
				r.Header.Get("X-Request-ID"), user.TenantID, err)
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to aggregate security overview")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data":  overview,
			"total": overview.Total,
			"type":  "security_overview",
		})
	}
}

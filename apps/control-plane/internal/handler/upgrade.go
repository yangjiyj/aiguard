package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/buildinfo"
)

// GetVersionInfo returns current version information
func GetVersionInfo(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		// 规则集版本取真实内容指纹。版本接口为兼容保持 200，但编译失败必须通过
		// runtime.status=unavailable 明示，不能把空版本伪装成正常运行态。
		rulesetVersion := ""
		runtimeStatus := unavailableRuleRuntimeStatus()
		if pack, err := compileTenantRulePack(r.Context(), deps, user.TenantID); err == nil {
			rulesetVersion = pack.Version
			conv := evaluateRulePackConvergence(user.TenantID, pack.Version)
			runtimeStatus = ruleRuntimeStatusFromPack(pack, conv)
		}
		current := buildinfo.Current()
		info := map[string]interface{}{
			"version":         current.Version,
			"ruleset_version": rulesetVersion,
			"runtime":         runtimeStatus,
			"edition":         "enterprise",
		}
		if current.Commit != "" {
			info["commit"] = current.Commit
		}
		if current.BuiltAt != "" {
			info["built_at"] = current.BuiltAt
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	}
}

// GetProductInfo returns the configured product identity and underlying engine build.
func GetProductInfo(_ *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.GetUser(r.Context()) == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		engine := buildinfo.Current()
		profile := strings.TrimSpace(os.Getenv("PRODUCT_PROFILE"))
		if profile == "" {
			profile = "gateway"
		}
		name := "JJDGuard"
		version := engine.Version
		if profile == "agent-platform" {
			name = "JJDGuard Agent Platform"
			version = "1.0.0"
			if custom := strings.TrimSpace(os.Getenv("PRODUCT_NAME")); custom != "" {
				name = custom
			}
			if custom := strings.TrimSpace(os.Getenv("PRODUCT_VERSION")); custom != "" {
				version = custom
			}
		}
		writeJSON(w, map[string]string{
			"product_profile": profile,
			"product_name":    name,
			"product_version": version,
			"engine_version":  engine.Version,
			"engine_commit":   engine.Commit,
		})
	}
}

// CheckUpgrade checks for latest available version
func CheckUpgrade(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		// Placeholder - would call upgrade server in production
		result := map[string]interface{}{
			"has_upgrade":    false,
			"latest_version": buildinfo.Current().Version,
			"release_notes":  "",
			"compatibility":  "compatible",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// UploadUpgradePackage handles offline upgrade package upload
func UploadUpgradePackage(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		// Placeholder - would handle multipart file upload
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "upload endpoint ready (placeholder)"})
	}
}

// ExecuteUpgrade executes an upgrade
func ExecuteUpgrade(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		// Placeholder
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "upgrade executed (placeholder)"})
	}
}

// RollbackUpgrade rolls back to previous version
func RollbackUpgrade(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		// Placeholder
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "rollback endpoint ready (placeholder)"})
	}
}

// GetUpgradeHistory returns upgrade history list
func GetUpgradeHistory(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		// Placeholder - would query upgrade_history table
		result := map[string]interface{}{
			"data":  []interface{}{},
			"total": 0,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// SyncRuleSet 触发一次「权威规则集版本重算 + 各节点收敛核对」，并如实回报。
//
// 方案A 为拉取制：control-plane 无法把规则推给引擎，只能告知管理员
//
//	(1) 当前权威规则集版本（与引擎实际拉取同一内容指纹，源自 3.7 ContentVersion）；
//	(2) 各节点据 3.7 拉取台账推导的收敛情况（哪些节点尚未拉到该版本）。
//
// 用 POST：它触发一次实时重算+核对（动作），而非返回缓存的 GET 读。
func SyncRuleSet(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		// 重算本租户权威规则集版本（与引擎拉取共用同一编译路径，杜绝版本漂移）。
		pack, err := compileTenantRulePack(r.Context(), deps, user.TenantID)
		if err != nil {
			logRulePackSecurityEvent(r, user.TenantID, runtimeCompileUnavailableCode)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ruleset_version": "",
				"checked_at":      time.Now().UTC().Format(time.RFC3339),
				"runtime":         unavailableRuleRuntimeStatus(),
			})
			return
		}
		conv := evaluateRulePackConvergence(user.TenantID, pack.Version)
		runtimeStatus := ruleRuntimeStatusFromPack(pack, conv)
		writeAgentGuardJSON(w, map[string]interface{}{
			"ruleset_version":       pack.Version,
			"checked_at":            time.Now().UTC().Format(time.RFC3339),
			"node_count":            conv.NodeCount,
			"converged_count":       conv.ConvergedCount,
			"fresh_count":           conv.FreshCount,
			"fresh_converged_count": conv.FreshConvergedCount,
			"stale_count":           conv.StaleCount,
			"all_converged":         conv.AllConverged,
			"stale_nodes":           conv.StaleNodes,
			"runtime":               runtimeStatus,
		})
	}
}

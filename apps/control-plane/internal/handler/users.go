package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

// ListUsers - returns all users across all tenants (platform_admin only)
func ListUsers(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if user.Role != "platform_admin" && user.Role != "tenant_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		tenant := ""
		if user.Role == "tenant_admin" {
			tenant = user.TenantID
		}
		limit, offset := 0, 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 || value > 500 {
				writeError(w, "invalid_limit", "分页大小需在 1 到 500 之间")
				return
			}
			limit = value
		}
		if raw := r.URL.Query().Get("offset"); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 0 || value > 1000000 {
				writeError(w, "invalid_offset", "分页位置不合法")
				return
			}
			offset = value
		}
		var users []*repository.UserWithStats
		var total int
		var err error
		if scoped, ok := userStore(deps).(interface {
			ListScopedWithStats(context.Context, string, int, int) ([]*repository.UserWithStats, int, error)
		}); ok {
			users, total, err = scoped.ListScopedWithStats(r.Context(), tenant, limit, offset)
		} else if tenant == "" {
			users, err = userStore(deps).ListAllWithStats(r.Context())
			total = len(users)
		} else {
			writeErrorWithStatus(w, 503, "user_list_unavailable", "当前用户列表不支持租户作用域查询")
			return
		}
		if err != nil {
			writeError(w, "internal_error", "failed to list users")
			return
		}

		duplicates := map[string][]string{}
		if deps.UserAccountMergeRepo != nil {
			tenants := map[string]bool{}
			for _, candidate := range users {
				tenants[candidate.TenantID] = true
			}
			for tenant := range tenants {
				peers, duplicateErr := deps.UserAccountMergeRepo.PossibleDuplicates(r.Context(), tenant)
				if duplicateErr != nil {
					writeError(w, "internal_error", "failed to inspect duplicate identities")
					return
				}
				for id, ids := range peers {
					duplicates[id] = ids
				}
			}
		}
		data := make([]types.UserInfo, len(users))
		for i, u := range users {
			data[i] = types.UserInfo{
				ID:                         u.ID,
				PossibleDuplicateUserIDs:   duplicates[u.ID],
				TenantID:                   u.TenantID,
				Username:                   u.Username,
				Email:                      u.Email,
				Phone:                      u.Phone,
				Role:                       u.Role,
				Status:                     u.Status,
				PasswordChangeRequired:     u.MustChangePassword,
				DepartmentID:               u.DepartmentID,
				DepartmentName:             u.DepartmentName,
				DepartmentAssignmentMode:   u.DepartmentAssignmentMode,
				DepartmentAssignmentSource: u.DepartmentAssignmentSource,
				DepartmentAssignmentRuleID: u.DepartmentAssignmentRuleID,
				DepartmentResolvedAt:       u.DepartmentResolvedAt,
				TeamsCSV:                   u.TeamsCSV,
				TeamsJSON:                  u.TeamsJSON,
				ProjectsCount:              u.ProjectsCount,
				GrantsCount:                u.GrantsCount,
				LastLoginAt:                u.LastLoginAt,
			}
		}

		resp := types.UserListResponse{Data: data, Total: total}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// validUserPlatformRoles 是 users.role（全局平台角色）的权威取值域。
// 仅用于校验写入入参（创建 / 更新用户），绝不影响读取既有数据——
// 历史遗留的非法角色（如 operator）仍可正常列出与查看详情。
var validUserPlatformRoles = map[string]bool{
	"platform_connector": true,
	"platform_admin":     true,
	"security_officer":   true, // W4
	"auditor":            true, // W4
	"tenant_admin":       true,
	"dept_manager":       true, // 部门主管（只读、只看本部门）；建号后须再加进对应部门(team_members)
	"developer":          true,
	"viewer":             true,
	"chat_user":          true,
}

// isValidUserPlatformRole 判定角色是否属于权威平台角色域。
func isValidUserPlatformRole(role string) bool {
	return validUserPlatformRoles[role]
}

func CreateUser(deps *Dependencies) http.HandlerFunc {
	return createManagedUser(deps)
}

// UpdateUser - updates an existing user's fields
func UpdateUser(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		userID := chi.URLParam(r, "id")
		var req types.UpdateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.Status != "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "status_endpoint_required", "status must be changed through the lifecycle endpoint")
			return
		}

		existing, err := userStore(deps).GetByID(r.Context(), userID)
		if err != nil {
			writeError(w, "internal_error", "failed to get user")
			return
		}
		if existing == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		if existing.TenantID == repository.SystemTenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}

		targetRole := req.Role
		if targetRole != "" && !isValidUserPlatformRole(targetRole) {
			writeError(w, "invalid_role", "invalid platform role")
			return
		}
		// C1：任意角色变化都需走事务化路径同步 permission_grants/audit/outbox。
		// emergencyRoleTransition 涵盖 emergency 边界（进出 platform_admin 或现有 emergency
		// 用户离开 emergency），需 KC subject 编排；tenantRoleTransition 是纯租户内角色
		// 变化（如 viewer -> tenant_admin），DB 单事务即可。
		roleChanged := targetRole != "" && targetRole != existing.Role
		emergencyRoleTransition := roleChanged &&
			(targetRole == "platform_admin" || existing.DepartmentAssignmentMode == "emergency")
		tenantRoleTransition := roleChanged && !emergencyRoleTransition
		if emergencyRoleTransition && targetRole != "platform_admin" && req.DepartmentID == nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "department_required", "department is required when leaving emergency access")
			return
		}
		if emergencyRoleTransition && targetRole == "platform_admin" && req.DepartmentID != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "emergency_department_forbidden", "emergency administrators cannot have a department")
			return
		}
		// 角色事务化路径会自行写 users.role，这里清空 req.Role 避免后续 userStore.Update
		// 重复写入或破坏事务一致性（username/email/phone 仍走 userStore.Update）。
		if emergencyRoleTransition || tenantRoleTransition {
			req.Role = ""
		}

		var department *repository.Team
		if req.DepartmentID != nil {
			departmentID := strings.TrimSpace(*req.DepartmentID)
			if departmentID == "" {
				writeErrorWithStatus(w, http.StatusBadRequest, "department_required", "department is required")
				return
			}
			var ok bool
			department, ok = createUserDepartment(w, r, deps, existing.TenantID, departmentID)
			if !ok {
				return
			}
			if deps.IdentityBindingService == nil {
				writeError(w, "internal_error", "identity binding service is unavailable")
				return
			}
		}

		// Update only provided fields
		updateProfile := req.Role != ""
		if req.Username != "" {
			existing.Username = req.Username
			updateProfile = true
		}
		if req.Email != "" {
			existing.Email = req.Email
			updateProfile = true
		}
		if req.Phone != "" {
			existing.Phone = req.Phone
			updateProfile = true
		}
		if req.Role != "" {
			// M3：只校验写入入参；不带 role 时保持既有值（含历史遗留非法角色）不受影响。
			if !isValidUserPlatformRole(req.Role) {
				writeError(w, "invalid_role", "非法的平台角色，只允许 platform_admin、security_officer、auditor、tenant_admin、dept_manager、developer、viewer、chat_user 之一")
				return
			}
			existing.Role = req.Role
		}
		if emergencyRoleTransition {
			if !applyManagedUserRoleTransition(w, r, deps, user, existing, targetRole, department) {
				return
			}
		} else if tenantRoleTransition {
			if !applyManagedUserTenantRoleTransition(w, r, deps, user, existing, targetRole) {
				return
			}
		}
		if updateProfile {
			if err := userStore(deps).Update(r.Context(), existing); err != nil {
				if errors.Is(err, repository.ErrUserReconciliationRequired) {
					writeErrorWithStatus(w, http.StatusConflict, "identity_reconciliation_required", "密码同步未完成，账号已暂停登录，请联系管理员修复。")
					return
				}
				writeError(w, "internal_error", "failed to update user")
				return
			}
		}

		if department != nil && !emergencyRoleTransition && !tenantRoleTransition {
			if err := deps.IdentityBindingService.AssignManually(
				r.Context(), existing.TenantID, existing.ID, department.ID, user.ID,
			); err != nil {
				writeIdentityBindingMutationError(w, err)
				return
			}
			existing.DepartmentID = department.ID
			existing.DepartmentName = department.Name
			existing.DepartmentAssignmentMode = "manual"
			existing.DepartmentAssignmentSource = "admin"
		}

		resp := types.UserInfo{
			ID:                         existing.ID,
			Username:                   existing.Username,
			Email:                      existing.Email,
			Phone:                      existing.Phone,
			Role:                       existing.Role,
			Status:                     existing.Status,
			PasswordChangeRequired:     existing.MustChangePassword,
			TenantID:                   existing.TenantID,
			DepartmentID:               existing.DepartmentID,
			DepartmentName:             existing.DepartmentName,
			DepartmentAssignmentMode:   existing.DepartmentAssignmentMode,
			DepartmentAssignmentSource: existing.DepartmentAssignmentSource,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// DeleteUser - deletes an unreferenced user
func DeleteUser(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		userID := chi.URLParam(r, "id")

		// Cannot delete yourself
		if userID == user.ID {
			writeError(w, "invalid_request", "cannot delete yourself")
			return
		}

		existing, err := deps.UserRepo.GetByID(r.Context(), userID)
		if err != nil {
			writeError(w, "internal_error", "failed to get user")
			return
		}
		if existing == nil {
			writeError(w, "not_found", "user not found")
			return
		}

		if blockers, err := deps.UserRepo.ListDeleteBlockers(r.Context(), existing.ID); err != nil {
			writeError(w, "internal_error", "failed to inspect user references")
			return
		} else if len(blockers) > 0 {
			writeErrorWithStatusAndDetails(w, http.StatusConflict, "user_has_references", formatUserDeleteBlockers(blockers), map[string]interface{}{
				"blockers": blockers,
			})
			return
		}

		// 顺序（High-1）：解析 subject -> 在 Keycloak 禁用 -> 删 users 行 -> 吊销会话 -> 删除 Keycloak 用户。
		//  - subject 必须在删库前解析：user_identity_links 随 users 行级联删除，删完就查不到了。
		//  - 禁用失败就中止（502），库里什么都不动：否则 Keycloak 里是仍可登录的用户而本地行已没，
		//    它凭 Keycloak 登录 Chat 门户会被 JIT 重新建成新的 chat_user。
		//  - 最后一步删 Keycloak 用户失败时账号已禁用、无法登录，进持久化重试队列由 worker 继续清理。
		identityPlan := planLocalIdentityDeletion(r, deps, existing)
		// 先在持久化队列预登记清理（High-A）：入队失败就中止删除，保证 Keycloak 清理始终有可追踪的终点。
		if err := preEnqueueLocalIdentityCleanup(r, deps, existing, identityPlan); err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_cleanup_enqueue_failed",
				"无法登记身份服务清理任务，已取消删除，请稍后重试；账号未做任何改动")
			return
		}
		if err := disableLocalIdentityBeforeDelete(r, deps, identityPlan); err != nil {
			writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_disable_failed",
				"无法先在身份服务中禁用该账号，已取消删除，请稍后重试；账号未做任何改动")
			return
		}
		if _, err := deps.UserRepo.Delete(r.Context(), existing.ID); err != nil {
			// 库删除失败而 Keycloak 已被禁用：尽力恢复启用，避免把一个仍然存在的账号锁死。
			if identityPlan.subject != "" {
				_ = deps.LocalIdentityClient.SetEnabled(r.Context(), identityPlan.subject, true)
			}
			writeError(w, "internal_error", "failed to delete user")
			return
		}
		if deps.SessionRepo != nil {
			_ = deps.SessionRepo.DeleteByUser(r.Context(), existing.ID)
		}
		finishLocalIdentityDeletion(r, deps, existing, identityPlan)
		// 账号删除后只剩审计能追溯「谁删了谁」，所以记下租户、用户名、角色；不记 Keycloak subject。
		logAudit(r, deps, "user.delete", map[string]interface{}{
			"tenant_id": existing.TenantID, "username": existing.Username, "role": existing.Role,
		}, "user", existing.ID)

		w.WriteHeader(http.StatusNoContent)
	}
}

func formatUserDeleteBlockers(blockers []repository.UserDeleteBlocker) string {
	var b strings.Builder
	b.WriteString("无法删除用户：该用户仍有以下数据引用，请先处理。")
	for i, blocker := range blockers {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%d. %s %d 个", i+1, blocker.Label, blocker.Count))
		if blocker.Samples != "" {
			b.WriteString("（示例：")
			b.WriteString(blocker.Samples)
			b.WriteString("）")
		}
		b.WriteString("：到「")
		b.WriteString(blocker.Entry)
		b.WriteString("」，")
		b.WriteString(blocker.Action)
		b.WriteString("。")
	}
	b.WriteString("\n处理完上述资源后可重试删除。")
	return b.String()
}

func ResetPassword(deps *Dependencies) http.HandlerFunc {
	return resetManagedUserPassword(deps)
}

// ChangeCurrentPassword allows the current user to rotate their own password.
func ChangeCurrentPassword(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		var req types.ChangePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.CurrentPassword == "" || req.NewPassword == "" {
			writeError(w, "invalid_request", "current_password and new_password are required")
			return
		}
		if req.CurrentPassword == req.NewPassword { // pragma: allowlist secret
			writeError(w, "invalid_request", "new password must be different from current password")
			return
		}

		currentUser, err := deps.UserRepo.GetByID(r.Context(), user.ID)
		if err != nil || currentUser == nil {
			writeError(w, "internal_error", "failed to load current user")
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(currentUser.PasswordHash), []byte(req.CurrentPassword)); err != nil {
			writeErrorWithStatus(w, http.StatusForbidden, "invalid_password", "current password is incorrect")
			return
		}

		// W3 3.3：复杂度（长度/字符类别/不含用户名）+ 不与最近 N 次相同，参数来自系统设置。
		policy := LoadConsoleLoginPolicy(r.Context(), deps.SystemRepo)
		if err := ValidatePasswordComplexity(policy, currentUser.Username, req.NewPassword); err != nil {
			writePasswordPolicyError(w, err)
			return
		}
		var history PasswordHistoryStore
		if deps.ConsoleSecurity != nil {
			history = deps.ConsoleSecurity
		}
		if err := checkPasswordNotReused(r.Context(), history, policy, currentUser.ID, currentUser.PasswordHash, req.NewPassword); err != nil {
			writePasswordPolicyError(w, err)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, "internal_error", "failed to hash password")
			return
		}

		if !updateCurrentPasswordWithIdentity(w, r, deps, currentUser, req.NewPassword, string(hashedPassword)) {
			return
		}
		if deps.ConsoleSecurity != nil {
			if err := deps.ConsoleSecurity.Record(r.Context(), user.ID, currentUser.PasswordHash, policy.PasswordHistoryCount); err != nil {
				logConsoleSecurityError("record password history", err)
			}
			if err := deps.ConsoleSecurity.MarkPasswordChanged(r.Context(), user.ID); err != nil {
				logConsoleSecurityError("mark password changed", err)
			}
		}
		personalAudience := currentUser.Role == "chat_user" || r.Context().Value(personalLoginContextKey{}) == true
		if deps.SessionRepo != nil {
			if revokeErr := deps.SessionRepo.DeleteByUser(r.Context(), user.ID); revokeErr != nil && personalAudience {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "password_updated_session_revoke_failed",
					"密码已修改，但旧会话撤销未完成。请稍后使用新密码重新登录或联系管理员")
				return
			}
		}

		logAudit(r, deps, "change_password", map[string]interface{}{
			"user_id": user.ID,
		}, "user", user.ID)

		if personalAudience {
			if deps.ChatLoginTickets != nil {
				if revokeErr := deps.ChatLoginTickets.RevokeByUser(r.Context(), currentUser.TenantID, currentUser.ID); revokeErr != nil {
					writeErrorWithStatus(w, http.StatusServiceUnavailable, "chat_login_unavailable",
						"密码已修改，旧登录交接撤销未完成，请使用新密码重新登录或联系管理员")
					return
				}
			}
			// Password verification belongs to this already authenticated POST.
			// Every prior session (including the current token) has been revoked;
			// issue a fresh one-use proof here instead of reusing that token.
			updatedUser, readErr := deps.UserRepo.GetByID(r.Context(), user.ID)
			if readErr != nil || updatedUser == nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "chat_login_unavailable",
					"密码已修改，Chat 登录交接未完成，请使用新密码重新登录")
				return
			}
			if updatedUser.PasswordHash != string(hashedPassword) {
				writeErrorWithStatus(w, 409, "password_change_conflict", "password changed concurrently; sign in again")
				return
			}
			ticket, issued := issueChatLoginTicket(w, r, deps, updatedUser)
			if !issued {
				return
			}
			writeJSON(w, map[string]any{
				"message": "password updated successfully",
				"user": types.UserInfo{ID: updatedUser.ID, Username: updatedUser.Username,
					Role: updatedUser.Role, TenantID: updatedUser.TenantID},
				"chat_ticket": ticket, "expires_in": chatLoginTicketTTLSeconds,
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "password updated successfully"})
	}
}

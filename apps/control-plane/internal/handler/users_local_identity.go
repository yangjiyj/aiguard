package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

const localIdentityUnavailableMessage = "本地身份服务尚未就绪，请联系系统管理员检查身份运行配置并重新执行身份初始化"

func createManagedUser(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := auth.GetUser(r.Context())
		if actor == nil || actor.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		var req types.CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		req.DepartmentID = strings.TrimSpace(req.DepartmentID)
		if req.Username == "" || req.Password == "" {
			writeError(w, "invalid_request", "username and password are required")
			return
		}

		role := strings.TrimSpace(req.Role)
		if role == "" {
			role = "chat_user"
		} else if !isValidUserPlatformRole(role) {
			writeError(w, "invalid_role", "非法的平台角色，只允许 platform_admin、security_officer、auditor、tenant_admin、dept_manager、developer、viewer、chat_user 之一")
			return
		}
		emergency := role == "platform_admin"
		service := role == "platform_connector"
		if service && (req.DepartmentID != "" || (req.TenantID != "" && req.TenantID != actor.TenantID)) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "service identity must use creator tenant without human department")
			return
		}

		targetTenant, ok := createUserTargetTenant(w, r, deps, actor, req.TenantID)
		if !ok {
			return
		}

		var department *repository.Team
		if !emergency && !service {
			if req.DepartmentID == "" {
				writeErrorWithStatus(w, http.StatusBadRequest, "department_required", "department_id is required")
				return
			}
			department, ok = createUserDepartment(w, r, deps, targetTenant, req.DepartmentID)
			if !ok {
				return
			}
		}

		var provisioner localidentity.Provisioner
		if deps != nil {
			provisioner = deps.LocalIdentityProvisioner
			if service {
				provisioner = deps.NativeServiceProvisioner
			}
		}
		if provisioner == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_unavailable", localIdentityUnavailableMessage)
			return
		}
		if !enforceMaxUsersForActiveUser(w, r, deps) {
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, "internal_error", "failed to hash password")
			return
		}

		userID := uuid.NewString()
		provision := localidentity.ProvisionInput{
			ID: userID, TenantID: targetTenant, Username: req.Username,
			Email: req.Email, Phone: req.Phone, PasswordHash: string(hashedPassword),
			Role: role, ActorID: actor.ID, AssignmentSource: "local",
		}
		if emergency || service {
			provision.Status = "active"
			provision.AssignmentMode = "emergency"
			if service {
				provision.AssignmentMode = "service"
			}
			if err := provisioner.Provision(r.Context(), provision); err != nil {
				writeError(w, "internal_error", "failed to create emergency administrator")
				return
			}
			writeCreatedUser(w, provision)
			return
		}

		if standalone, ok := deps.LocalIdentityProvisioner.(interface{ Standalone() bool }); ok && standalone.Standalone() {
			if err := ValidatePasswordComplexity(LoadConsoleLoginPolicy(r.Context(), deps.SystemRepo), req.Username, req.Password); err != nil {
				writePasswordPolicyError(w, err)
				return
			}
			provision.Status = "active"
			provision.DepartmentID = department.ID
			provision.DepartmentName = department.Name
			provision.AssignmentMode = "manual"
			provision.ExternalSubject = userID
			if err := deps.LocalIdentityProvisioner.Provision(r.Context(), provision); err != nil {
				writeErrorWithStatus(w, 503, "local_identity_sync_failed", "failed to create standalone local account")
				return
			}
			linkUserToTeamDefaultApp(r.Context(), deps, targetTenant, department.ID, userID)
			writeCreatedUser(w, provision)
			return
		}
		if deps.LocalIdentityClient == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_unavailable", localIdentityUnavailableMessage)
			return
		}
		externalSubject, err := deps.LocalIdentityClient.CreateUser(r.Context(), localidentity.CreateUserInput{
			Username: req.Username, Email: req.Email, Password: req.Password,
		})
		if err != nil {
			// I7a：用户名冲突(ErrConflict)单独返 409 username_conflict，
			// 其他 KC 错误按 writeLocalIdentityError 映射稳定语义。
			writeLocalIdentityError(w, err, "local_identity_sync_failed", "failed to create local login identity")
			return
		}

		provision.Status = "provisioning"
		provision.DepartmentID = department.ID
		provision.DepartmentName = department.Name
		provision.AssignmentMode = "manual"
		provision.ExternalSubject = externalSubject
		if err := deps.LocalIdentityProvisioner.Provision(r.Context(), provision); err != nil {
			if deleteErr := deps.LocalIdentityClient.DeleteUser(r.Context(), externalSubject); deleteErr != nil {
				if markErr := markLocalIdentityReconciliation(r, deps, provision, "database_provision_failed_identity_delete_failed"); markErr != nil {
					writeReconciliationPersistenceError(w)
					return
				}
			}
			writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "failed to provision local user")
			return
		}

		if err := deps.LocalIdentityClient.SetEnabled(r.Context(), externalSubject, true); err != nil {
			if compensateErr := compensateLocalUserProvision(r, deps, provision, externalSubject, "identity_enable_failed"); compensateErr != nil {
				writeReconciliationPersistenceError(w)
				return
			}
			writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "failed to enable local login identity")
			return
		}
		if err := deps.LocalIdentityProvisioner.Activate(r.Context(), targetTenant, userID); err != nil {
			if compensateErr := compensateLocalUserProvision(r, deps, provision, externalSubject, "database_activate_failed"); compensateErr != nil {
				writeReconciliationPersistenceError(w)
				return
			}
			writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "failed to activate local user")
			return
		}
		if deps.UserIdentityLinkLookup != nil {
			issuer := strings.TrimSpace(deps.IdentityRuntimeConfig.IssuerURL)
			if issuer != "" {
				if err := deps.UserIdentityLinkLookup.BindLoginSources(r.Context(), targetTenant, userID, issuer, externalSubject); err != nil {
					if compensateErr := compensateLocalUserProvision(r, deps, provision, externalSubject, "login_source_bind_failed"); compensateErr != nil {
						writeReconciliationPersistenceError(w)
						return
					}
					writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "failed to bind Chat login identity")
					return
				}
			}
		}

		// 部门是 JJDGuard 的授权边界。新建本地账号成功后，立即绑定该部门
		// 最早创建的默认应用；Chat 首次登录据此签发员工 key，并继承部门模型策略。
		// 该步骤幂等且 best-effort，不把后续授权投影抖动升级为账号创建失败。
		linkUserToTeamDefaultApp(r.Context(), deps, targetTenant, department.ID, userID)

		provision.Status = "active"
		writeCreatedUser(w, provision)
	}
}

func createUserTargetTenant(
	w http.ResponseWriter,
	r *http.Request,
	deps *Dependencies,
	actor *repository.User,
	requestedTenant string,
) (string, bool) {
	targetTenant := actor.TenantID
	requestedTenant = strings.TrimSpace(requestedTenant)
	if requestedTenant == "" || requestedTenant == actor.TenantID {
		return targetTenant, true
	}
	if deps == nil || deps.TenantRepo == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "target unit not found")
		return "", false
	}
	tenant, err := deps.TenantRepo.GetByID(r.Context(), requestedTenant)
	if err != nil || tenant == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "target unit not found")
		return "", false
	}
	return requestedTenant, true
}

func createUserDepartment(
	w http.ResponseWriter,
	r *http.Request,
	deps *Dependencies,
	tenantID, departmentID string,
) (*repository.Team, bool) {
	var store DepartmentStore
	if deps != nil {
		store = deps.DepartmentStore
		if store == nil && deps.TeamRepo != nil {
			store = deps.TeamRepo
		}
	}
	if store == nil {
		writeError(w, "internal_error", "department repository is unavailable")
		return nil, false
	}
	department, err := store.GetByID(r.Context(), departmentID)
	if err != nil {
		writeError(w, "internal_error", "failed to validate department")
		return nil, false
	}
	if department == nil || department.TenantID != tenantID {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "department not found")
		return nil, false
	}
	return department, true
}

func compensateLocalUserProvision(
	r *http.Request,
	deps *Dependencies,
	provision localidentity.ProvisionInput,
	externalSubject, reason string,
) error {
	compensationFailed := false
	if err := deps.LocalIdentityClient.SetEnabled(r.Context(), externalSubject, false); err != nil {
		compensationFailed = true
	}
	if err := deps.LocalIdentityClient.DeleteUser(r.Context(), externalSubject); err != nil {
		compensationFailed = true
	}
	if err := deps.LocalIdentityProvisioner.DeleteProvisioned(r.Context(), provision.TenantID, provision.ID); err != nil {
		compensationFailed = true
	}
	if compensationFailed {
		return markLocalIdentityReconciliation(r, deps, provision, reason+"_compensation_failed")
	}
	return nil
}

func markLocalIdentityReconciliation(
	r *http.Request,
	deps *Dependencies,
	provision localidentity.ProvisionInput,
	reason string,
) error {
	operation := localIdentityReconciliationOperation(reason)
	if operation == "" || strings.TrimSpace(provision.ExternalSubject) == "" {
		return localidentity.ErrInvalidInput
	}
	fingerprint := sha256.Sum256([]byte(provision.TenantID + "|" + provision.ExternalSubject))
	return deps.LocalIdentityProvisioner.MarkReconciliationRequired(r.Context(), localidentity.ReconciliationInput{
		ID:       "local-identity-reconcile-" + uuid.NewString(),
		TenantID: provision.TenantID, UserID: provision.ID, ActorID: provision.ActorID,
		Reason: reason, SubjectFingerprint: hex.EncodeToString(fingerprint[:]),
		Operation: operation, Stage: reason, Provider: "keycloak", Source: "local",
	})
}

func markLocalIdentityReconciliationWithoutSubject(
	r *http.Request,
	deps *Dependencies,
	provision localidentity.ProvisionInput,
	reason string,
) error {
	operation := localIdentityReconciliationOperation(reason)
	if operation == "" || strings.TrimSpace(provision.ExternalSubject) != "" {
		return localidentity.ErrInvalidInput
	}
	return deps.LocalIdentityProvisioner.MarkReconciliationRequired(r.Context(), localidentity.ReconciliationInput{
		ID:       "local-identity-reconcile-" + uuid.NewString(),
		TenantID: provision.TenantID, UserID: provision.ID, ActorID: provision.ActorID,
		Reason: reason, Operation: operation, Stage: reason, Provider: "local", Source: "local",
	})
}

func localIdentityReconciliationOperation(reason string) string {
	switch reason {
	case "database_provision_failed_identity_delete_failed",
		"identity_enable_failed_compensation_failed",
		"database_activate_failed_compensation_failed":
		return "provision"
	case "session_revoke_failed_identity_disabled",
		"database_status_update_failed_identity_disabled",
		"database_status_update_failed_identity_absent",
		"session_revoke_and_database_status_update_failed_identity_absent",
		"database_status_update_failed_identity_compensation_failed":
		return "status_transition"
	case "password_admin_reset_identity_disable_failed",
		"password_admin_reset_identity_reset_failed",
		"password_admin_reset_identity_enable_failed",
		"password_admin_reset_identity_activate_failed",
		"password_self_change_identity_disable_failed",
		"password_self_change_identity_reset_failed",
		"password_self_change_identity_enable_failed",
		"password_self_change_identity_activate_failed",
		"password_runtime_updated_database_failed",
		"password_reset_session_revoke_failed":
		return "password_reset"
	case "role_transition_runtime_enable_failed",
		"role_transition_session_revoke_failed_identity_disabled",
		"role_transition_database_failed_identity_disabled",
		"emergency_demotion_session_revoke_failed_identity_delete_failed",
		"emergency_demotion_database_failed_identity_delete_failed":
		return "role_transition"
	case "delete_user_keycloak_cleanup_failed",
		"delete_user_subject_resolve_failed":
		return "deletion"
	default:
		return ""
	}
}

func writeReconciliationPersistenceError(w http.ResponseWriter) {
	writeErrorWithStatus(w, http.StatusServiceUnavailable, "reconciliation_persistence_failed", "failed to persist identity reconciliation marker")
}

func writeCreatedUser(w http.ResponseWriter, provision localidentity.ProvisionInput) {
	writeJSON(w, types.UserInfo{
		ID: provision.ID, TenantID: provision.TenantID,
		Username: provision.Username, Email: provision.Email, Phone: provision.Phone,
		Role: provision.Role, Status: provision.Status,
		DepartmentID: provision.DepartmentID, DepartmentName: provision.DepartmentName,
		DepartmentAssignmentMode:   provision.AssignmentMode,
		DepartmentAssignmentSource: provision.AssignmentSource,
	})
}

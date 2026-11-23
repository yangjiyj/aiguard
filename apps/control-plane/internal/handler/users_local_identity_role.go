package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

type platformRoleTransitioner interface {
	TransitionPlatformRole(
		ctx context.Context,
		tenantID, userID, role, departmentID, actorID string,
	) error
}

type emergencyIdentityDemoter interface {
	BindEmergencyIdentityAndTransition(
		ctx context.Context,
		in localidentity.EmergencyDemotionInput,
	) error
}

func applyManagedUserRoleTransition(
	w http.ResponseWriter,
	r *http.Request,
	deps *Dependencies,
	actor, existing *repository.User,
	targetRole string,
	department *repository.Team,
) bool {
	transitioner, ok := deps.IdentityBindingService.(platformRoleTransitioner)
	if !ok || deps.LocalIdentityClient == nil || deps.LocalIdentityProvisioner == nil || deps.SessionRepo == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_unavailable", "local identity role transition is unavailable")
		return false
	}

	promoting := targetRole == "platform_admin"
	subject, err := deps.LocalIdentityProvisioner.ExternalSubject(
		r.Context(), existing.TenantID, existing.ID,
	)
	createdIdentity := false
	generatedPasswordHash := ""
	if err != nil && (promoting || !errors.Is(err, localidentity.ErrNotFound)) {
		writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "local login identity is unavailable")
		return false
	}
	if errors.Is(err, localidentity.ErrNotFound) {
		if _, ok := deps.LocalIdentityProvisioner.(emergencyIdentityDemoter); !ok {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_unavailable", "emergency identity demotion is unavailable")
			return false
		}
		password, passwordHash, err := generateTemporaryLocalIdentityPassword()
		if err != nil {
			writeError(w, "internal_error", "failed to generate temporary local identity credential")
			return false
		}
		subject, err = deps.LocalIdentityClient.CreateUser(r.Context(), localidentity.CreateUserInput{
			Username: existing.Username, Email: existing.Email,
			Password: password, Temporary: true,
		})
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "failed to create local login identity")
			return false
		}
		createdIdentity = true
		generatedPasswordHash = passwordHash
	}

	if promoting {
		if err := deps.LocalIdentityClient.SetEnabled(r.Context(), subject, false); err != nil {
			writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "failed to disable local login identity")
			return false
		}
	}

	if err := deps.SessionRepo.DeleteByUser(r.Context(), existing.ID); err != nil {
		if promoting {
			if markErr := markLocalIdentityReconciliation(r, deps, localidentity.ProvisionInput{
				ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID, ExternalSubject: subject,
			}, "role_transition_session_revoke_failed_identity_disabled"); markErr != nil {
				writeReconciliationPersistenceError(w)
				return false
			}
		} else if createdIdentity {
			if markErr := compensateCreatedEmergencyIdentity(
				r, deps, actor, existing, subject, "emergency_demotion_session_revoke_failed"); markErr != nil {
				writeReconciliationPersistenceError(w)
				return false
			}
		}
		writeErrorWithStatus(w, http.StatusBadGateway, "session_revoke_failed", "failed to revoke active sessions")
		return false
	}

	departmentID := ""
	if department != nil {
		departmentID = department.ID
	}
	if createdIdentity {
		demoter := deps.LocalIdentityProvisioner.(emergencyIdentityDemoter)
		err = demoter.BindEmergencyIdentityAndTransition(r.Context(), localidentity.EmergencyDemotionInput{
			TenantID: existing.TenantID, UserID: existing.ID, ExternalSubject: subject,
			PasswordHash: generatedPasswordHash, Role: targetRole,
			DepartmentID: departmentID, ActorID: actor.ID,
		})
	} else {
		err = transitioner.TransitionPlatformRole(
			r.Context(), existing.TenantID, existing.ID, targetRole, departmentID, actor.ID,
		)
	}
	if err != nil {
		if promoting {
			if markErr := markLocalIdentityReconciliation(r, deps, localidentity.ProvisionInput{
				ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID, ExternalSubject: subject,
			}, "role_transition_database_failed_identity_disabled"); markErr != nil {
				writeReconciliationPersistenceError(w)
				return false
			}
		} else if createdIdentity {
			if markErr := compensateCreatedEmergencyIdentity(
				r, deps, actor, existing, subject, "emergency_demotion_database_failed"); markErr != nil {
				writeReconciliationPersistenceError(w)
				return false
			}
		}
		writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "failed to persist local identity role transition")
		return false
	}

	if deps.PermissionChecker != nil {
		deps.PermissionChecker.InvalidateUserCache(existing.ID)
	}
	existing.Role = targetRole
	if promoting {
		existing.DepartmentID = ""
		existing.DepartmentName = ""
		existing.DepartmentAssignmentMode = "emergency"
		existing.DepartmentAssignmentSource = "admin"
		return true
	}

	existing.DepartmentID = department.ID
	existing.DepartmentName = department.Name
	existing.DepartmentAssignmentMode = "manual"
	existing.DepartmentAssignmentSource = "admin"
	if createdIdentity {
		existing.MustChangePassword = true
	}
	if existing.Status != "active" {
		return true
	}
	if err := deps.LocalIdentityClient.SetEnabled(r.Context(), subject, true); err != nil {
		if markErr := markLocalIdentityReconciliation(r, deps, localidentity.ProvisionInput{
			ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID, ExternalSubject: subject,
		}, "role_transition_runtime_enable_failed"); markErr != nil {
			writeReconciliationPersistenceError(w)
			return false
		}
		writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "failed to enable local login identity")
		return false
	}
	return true
}

func generateTemporaryLocalIdentityPassword() (string, string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}
	password := base64.RawURLEncoding.EncodeToString(secret)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return password, string(hash), nil
}

func compensateCreatedEmergencyIdentity(
	r *http.Request,
	deps *Dependencies,
	actor, existing *repository.User,
	subject, reason string,
) error {
	if err := deps.LocalIdentityClient.DeleteUser(r.Context(), subject); err == nil {
		return nil
	}
	return markLocalIdentityReconciliation(r, deps, localidentity.ProvisionInput{
		ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID, ExternalSubject: subject,
	}, reason+"_identity_delete_failed")
}

// tenantRoleTransitioner 是 platformRoleTransitioner 的对称接口，
// 用于非 emergency 边界的纯租户内角色变化（viewer -> tenant_admin 等）。
// 这类变化不编排 Keycloak subject 状态，但仍需事务化同步 permission_grants。
type tenantRoleTransitioner interface {
	TransitionTenantRole(
		ctx context.Context,
		tenantID, userID, role, actorID string,
	) error
}

// applyManagedUserTenantRoleTransition 处理非 emergency 边界的纯租户内角色变化。
// 与 applyManagedUserRoleTransition 的区别：
//   - 不编排 Keycloak subject（subject 启用状态不变）
//   - 不生成临时密码、不调 emergencyIdentityDemoter
//   - 仅在 DB 单事务内同步 users.role + permission_grants + audit + outbox，
//     并在 commit 后失效 permission cache
//
// 失败时返回 false 并写入 HTTP 响应；事务已保证 DB 一致性，无需补偿。
func applyManagedUserTenantRoleTransition(
	w http.ResponseWriter,
	r *http.Request,
	deps *Dependencies,
	actor, existing *repository.User,
	targetRole string,
) bool {
	transitioner, ok := deps.IdentityBindingService.(tenantRoleTransitioner)
	if !ok {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_unavailable", "tenant role transition is unavailable")
		return false
	}
	// M-1：角色一变，旧会话不得继续带着新角色的权限（不用重新登录、不用重新过 TOTP）。与 emergency 路径对齐：
	// 先吊销会话再改角色，吊销失败则不改（fail-closed）。中间件还会拒绝「会话角色与当前角色不一致」的会话，
	// 覆盖吊销与改角色之间新签发的会话，以及所有绕过本路径的角色写入。
	if deps.SessionRepo != nil {
		if err := deps.SessionRepo.DeleteByUser(r.Context(), existing.ID); err != nil {
			writeErrorWithStatus(w, http.StatusBadGateway, "session_revoke_failed", "failed to revoke active sessions")
			return false
		}
	}
	if err := transitioner.TransitionTenantRole(
		r.Context(), existing.TenantID, existing.ID, targetRole, actor.ID,
	); err != nil {
		writeIdentityBindingMutationError(w, err)
		return false
	}
	if deps.PermissionChecker != nil {
		deps.PermissionChecker.InvalidateUserCache(existing.ID)
	}
	// 再吊销一次：关闭「先删会话」与「角色提交」之间用户恰好登录所产生的窗口（尽力而为，失败只记日志；
	// 即使没删成，中间件的角色一致性校验也会拒绝这类会话）。
	if deps.SessionRepo != nil {
		if err := deps.SessionRepo.DeleteByUser(r.Context(), existing.ID); err != nil {
			log.Printf("post-transition session revoke failed (user=%s): %v", existing.ID, err)
		}
	}
	existing.Role = targetRole
	return true
}

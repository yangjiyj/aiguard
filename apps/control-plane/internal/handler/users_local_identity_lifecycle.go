package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

type localIdentityStatusTransitioner interface {
	TransitionStatus(context.Context, localidentity.StatusTransitionInput) error
}

func applyManagedUserStatus(
	w http.ResponseWriter,
	r *http.Request,
	deps *Dependencies,
	actor, existing *repository.User,
	status string,
) bool {
	if existing.Status == status {
		return true
	}
	if existing.Status == "reconciliation_required" && status != existing.Status {
		writeErrorWithStatus(w, 409, "identity_reconciliation_required", "account synchronization is incomplete; complete an administrative password reset before enabling sign-in")
		return false
	}

	if status == "active" && !enforceMaxUsersForActiveUser(w, r, deps) {
		return false
	}
	isEmergency := existing.DepartmentAssignmentMode == "emergency"
	isLocal := existing.DepartmentAssignmentSource == "local"
	if !isEmergency && !isLocal {
		// 本地账号被管理员调整过部门后，部门分配来源会变成 admin；只有既不是本地来源、
		// 也没有本地身份链接的账号（目录/SSO 同步来的）才由外部身份源管状态。
		linked, linkErr := hasLocalIdentityLink(r.Context(), deps, existing)
		if linkErr != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_unavailable", "local credential ownership unavailable")
			return false
		}
		isLocal = linked
	}
	if !isEmergency && !isLocal {
		writeErrorWithStatus(w, http.StatusConflict, "identity_managed_externally", "user status is managed by an external identity source")
		return false
	}
	statusTransitioner, ok := deps.LocalIdentityProvisioner.(localIdentityStatusTransitioner)
	if !ok {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_unavailable", "local identity status transition is unavailable")
		return false
	}

	standalone, ownerErr := standaloneLocalCredential(r.Context(), deps, existing)
	if ownerErr != nil {
		writeErrorWithStatus(w, 503, "local_identity_unavailable", "local credential ownership unavailable")
		return false
	}
	subject := ""
	if isLocal && !isEmergency && !standalone {
		if deps.LocalIdentityClient == nil || deps.LocalIdentityProvisioner == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_unavailable", localIdentityUnavailableMessage)
			return false
		}
		var err error
		subject, err = deps.LocalIdentityProvisioner.ExternalSubject(r.Context(), existing.TenantID, existing.ID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "local login identity is unavailable")
			return false
		}
		if err := deps.LocalIdentityClient.SetEnabled(r.Context(), subject, status == "active"); err != nil {
			writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "failed to update local login identity")
			return false
		}
	}

	var sessionRevokeErr error
	if status == "disabled" && deps.SessionRepo != nil {
		sessionRevokeErr = deps.SessionRepo.DeleteByUser(r.Context(), existing.ID)
	}

	oldStatus := existing.Status
	if err := statusTransitioner.TransitionStatus(r.Context(), localidentity.StatusTransitionInput{
		TenantID: existing.TenantID, UserID: existing.ID, Status: status, ActorID: actor.ID,
	}); err != nil {
		if errors.Is(err, localidentity.ErrReconciliationRequired) {
			if subject != "" && deps.LocalIdentityClient != nil {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
				_ = deps.LocalIdentityClient.SetEnabled(cleanupCtx, subject, false)
				cancel()
			}
			writeErrorWithStatus(w, 409, "identity_reconciliation_required", "account synchronization incomplete; an ordinary status change cannot enable sign-in")
			return false
		}
		if status == "disabled" {
			if isEmergency {
				existing.Status = "disabled"
				_ = userStore(deps).Update(r.Context(), existing)
				reason := "database_status_update_failed_identity_absent"
				if sessionRevokeErr != nil {
					reason = "session_revoke_and_database_status_update_failed_identity_absent"
				}
				if markErr := markLocalIdentityReconciliationWithoutSubject(r, deps, localidentity.ProvisionInput{
					ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID,
				}, reason); markErr != nil {
					writeReconciliationPersistenceError(w)
					return false
				}
			} else if subject != "" {
				if markErr := markLocalIdentityReconciliation(r, deps, localidentity.ProvisionInput{
					ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID, ExternalSubject: subject,
				}, "database_status_update_failed_identity_disabled"); markErr != nil {
					writeReconciliationPersistenceError(w)
					return false
				}
			}
		} else if subject != "" {
			if compensateErr := deps.LocalIdentityClient.SetEnabled(r.Context(), subject, oldStatus == "active"); compensateErr != nil {
				if markErr := markLocalIdentityReconciliation(r, deps, localidentity.ProvisionInput{
					ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID, ExternalSubject: subject,
				}, "database_status_update_failed_identity_compensation_failed"); markErr != nil {
					writeReconciliationPersistenceError(w)
					return false
				}
			}
		}
		writeError(w, "internal_error", "failed to update user status")
		return false
	}
	existing.Status = status
	if sessionRevokeErr != nil {
		var markErr error
		provision := localidentity.ProvisionInput{
			ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID, ExternalSubject: subject,
		}
		if subject == "" {
			markErr = markLocalIdentityReconciliationWithoutSubject(
				r, deps, provision, "session_revoke_failed_identity_disabled",
			)
		} else {
			markErr = markLocalIdentityReconciliation(
				r, deps, provision, "session_revoke_failed_identity_disabled",
			)
		}
		if markErr != nil {
			writeReconciliationPersistenceError(w)
			return false
		}
		writeErrorWithStatus(w, http.StatusBadGateway, "session_revoke_failed", "failed to revoke active sessions")
		return false
	}
	return true
}

func resetManagedUserPassword(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := auth.GetUser(r.Context())
		if actor == nil || actor.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		userID := chi.URLParam(r, "id")
		var req types.ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.Password == "" {
			writeError(w, "invalid_request", "password is required")
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
		if deps.LocalIdentityProvisioner == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_unavailable", localIdentityUnavailableMessage)
			return
		}
		if deps.UserIdentityLinkLookup != nil {
			managedExternally, lookupErr := deps.UserIdentityLinkLookup.HasExternalCredentialOwner(
				r.Context(), existing.TenantID, existing.ID,
			)
			if lookupErr != nil {
				writeError(w, "internal_error", "failed to resolve password ownership")
				return
			}
			if managedExternally {
				writeErrorWithStatus(w, http.StatusConflict, "password_managed_externally", "该用户使用 LDAP/AD 域凭据登录，请前往对应目录修改密码")
				return
			}
			if owner, ok := deps.UserIdentityLinkLookup.(localPasswordOwnership); ok && existing.Role == "chat_user" && existing.DepartmentAssignmentMode != "emergency" {
				local, _, ownerErr := owner.LocalPasswordOwnership(r.Context(), existing.TenantID, existing.ID)
				if ownerErr != nil {
					writeErrorWithStatus(w, 503, "password_sync_unavailable", "password ownership unavailable; password unchanged")
					return
				}
				if !local {
					writeErrorWithStatus(w, 409, "password_managed_externally", "use the enterprise identity provider to change this password")
					return
				}
			}
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, "internal_error", "failed to hash password")
			return
		}

		var operation *repository.UserPasswordOperation
		lockPassword := func() bool {
			if deps.UserRepo == nil || operation != nil {
				return true
			}
			var lockErr error
			operation, lockErr = deps.UserRepo.LockPasswordOperation(r.Context(), existing.TenantID, existing.ID)
			if lockErr != nil {
				writeErrorWithStatus(w, 503, "password_sync_unavailable", "password update serialization unavailable; password unchanged")
				return false
			}
			return true
		}
		defer func() {
			if operation != nil {
				operation.Close()
			}
		}()
		isEmergency := existing.DepartmentAssignmentMode == "emergency"
		subject := ""
		standalone, ownerErr := standaloneLocalCredential(r.Context(), deps, existing)
		if ownerErr != nil {
			writeErrorWithStatus(w, 503, "local_identity_unavailable", "local credential ownership unavailable")
			return
		}
		if !isEmergency && !standalone {
			subject, err = deps.LocalIdentityProvisioner.ExternalSubject(r.Context(), existing.TenantID, existing.ID)
			if errors.Is(err, localidentity.ErrNotFound) {
				// 目录/CSV/API 同步只是账号来源，不代表密码归目录托管。只要没有
				// LDAP/AD 凭据归属，JJDGuard 就接管本地密码。运行态身份缺失时先
				// 持久化本地 hash；账号下次经账号登录进入 Chat 时由控制面绑定。
				subject = ""
			} else if err != nil {
				writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "local login identity is unavailable")
				return
			}
			if subject != "" {
				if deps.LocalIdentityClient == nil {
					writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_identity_unavailable", localIdentityUnavailableMessage)
					return
				}
				if deps.UserRepo == nil {
					writeErrorWithStatus(w, 503, "password_sync_unavailable", "native password storage unavailable; password unchanged")
					return
				}
				if !lockPassword() {
					return
				}
				currentHash, currentStatus, stateErr := operation.CurrentPasswordState(r.Context())
				if stateErr != nil {
					writeErrorWithStatus(w, 503, "password_sync_unavailable", "current account credentials unavailable; password unchanged")
					return
				}
				target := *existing
				target.PasswordHash = currentHash
				target.Status = currentStatus
				finalStatus := "active"
				if currentStatus == "disabled" {
					finalStatus = "disabled"
				}
				if !synchronizeNativePassword(w, r, deps, &target, subject, req.Password, string(hash), operation, finalStatus, "password_admin_reset") {
					return
				}
				operation.Close()
			}
		}
		if subject == "" && !lockPassword() {
			return
		}
		var passwordWriteErr error
		if subject != "" {
			// The shared native protocol already persisted and fenced the hash.
		} else if operation != nil {
			var updated bool
			updated, passwordWriteErr = operation.UpdatePassword(r.Context(), string(hash), false)
			if passwordWriteErr == nil && !updated {
				passwordWriteErr = localidentity.ErrNotFound
			}
			operation.Close()
		} else {
			passwordWriteErr = deps.LocalIdentityProvisioner.UpdatePasswordHash(r.Context(), existing.TenantID, existing.ID, string(hash), false)
		}
		if passwordWriteErr != nil {
			if subject != "" {
				if markErr := markLocalIdentityReconciliation(r, deps, localidentity.ProvisionInput{
					ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID, ExternalSubject: subject,
				}, "password_runtime_updated_database_failed"); markErr != nil {
					writeReconciliationPersistenceError(w)
					return
				}
			}
			writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_sync_failed", "failed to persist password reset")
			return
		}
		if subject == "" {
			log.Print("component=user_password stage=local_takeover status=hash_updated runtime_identity=absent")
		}
		if deps.SessionRepo != nil {
			if err := deps.SessionRepo.DeleteByUser(r.Context(), existing.ID); err != nil {
				if subject != "" {
					if markErr := markLocalIdentityReconciliation(r, deps, localidentity.ProvisionInput{
						ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID, ExternalSubject: subject,
					}, "password_reset_session_revoke_failed"); markErr != nil {
						writeReconciliationPersistenceError(w)
						return
					}
				} else {
					if markErr := markLocalIdentityReconciliationWithoutSubject(
						r, deps, localidentity.ProvisionInput{
							ID: existing.ID, TenantID: existing.TenantID, ActorID: actor.ID,
						}, "password_reset_session_revoke_failed",
					); markErr != nil {
						writeReconciliationPersistenceError(w)
						return
					}
				}
				writeErrorWithStatus(w, http.StatusBadGateway, "session_revoke_failed", "failed to revoke active sessions")
				return
			}
		}
		writeJSON(w, map[string]string{"message": "password reset successful"})
	}
}

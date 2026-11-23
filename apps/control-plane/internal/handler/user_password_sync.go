package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"net/http"
	"time"
)

type localPasswordOwnership interface {
	LocalPasswordOwnership(context.Context, string, string) (bool, string, error)
}

// Ownership remains per account when enterprise SSO is configured later.
func standaloneLocalCredential(ctx context.Context, deps *Dependencies, user *repository.User) (bool, error) {
	if deps == nil {
		return false, nil
	}
	reader, ok := deps.UserIdentityLinkLookup.(localPasswordOwnership)
	if !ok {
		return false, nil
	}
	local, nativeSubject, err := reader.LocalPasswordOwnership(ctx, user.TenantID, user.ID)
	return local && nativeSubject == "", err
}

// hasLocalIdentityLink 判断账号是否由本地身份体系托管（存在 source_type='local' 的身份链接）。
//
// 部门分配来源（department_assignment_source）只记录“部门是谁分配的”：本地账号被管理员挪过部门后
// 来源就变成 admin，但账号仍是本地账号。是否本地托管必须看身份链接，不能看这个字段（见
// TestResetPasswordUsesIdentityLinkInsteadOfDepartmentAssignmentSource）。
func hasLocalIdentityLink(ctx context.Context, deps *Dependencies, user *repository.User) (bool, error) {
	if deps == nil {
		return false, nil
	}
	reader, ok := deps.UserIdentityLinkLookup.(localPasswordOwnership)
	if !ok {
		return false, nil
	}
	local, _, err := reader.LocalPasswordOwnership(ctx, user.TenantID, user.ID)
	return local, err
}

// Keep native IdP and CP credentials identical. Remote failures are ambiguous:
// pause the account before any IdP write and never issue a success ticket while
// the identity is being reconciled. True directory/SSO credentials stay external.
func updateCurrentPasswordWithIdentity(w http.ResponseWriter, r *http.Request, deps *Dependencies, user *repository.User, password, hash string) bool {
	subject := ""
	if deps.UserIdentityLinkLookup != nil {
		external, err := deps.UserIdentityLinkLookup.HasExternalCredentialOwner(r.Context(), user.TenantID, user.ID)
		if err != nil {
			writeErrorWithStatus(w, 503, "password_sync_unavailable", "password ownership could not be verified; password unchanged")
			return false
		}
		if external {
			writeErrorWithStatus(w, 409, "password_managed_externally", "password is managed by the enterprise directory")
			return false
		}
		if reader, ok := deps.UserIdentityLinkLookup.(localPasswordOwnership); ok {
			local, currentSubject, err := reader.LocalPasswordOwnership(r.Context(), user.TenantID, user.ID)
			if err != nil {
				writeErrorWithStatus(w, 503, "password_sync_unavailable", "password ownership could not be verified; password unchanged")
				return false
			}
			if !local && user.Role == "chat_user" {
				writeErrorWithStatus(w, 409, "password_managed_externally", "use the enterprise identity provider to change this password")
				return false
			}
			subject = currentSubject
		}
	}
	operation, lockErr := deps.UserRepo.LockPasswordOperation(r.Context(), user.TenantID, user.ID)
	if lockErr != nil {
		writeErrorWithStatus(w, 503, "password_sync_unavailable", "password update serialization unavailable; password unchanged")
		return false
	}
	defer operation.Close()
	if subject == "" {
		updated, err := operation.UpdatePassword(r.Context(), hash, false, user.PasswordHash)
		if err != nil {
			writeError(w, "internal_error", "failed to update password")
			return false
		}
		if !updated {
			writeErrorWithStatus(w, 409, "password_change_conflict", "account credentials changed; sign in again")
			return false
		}
		return true
	}
	return synchronizeNativePassword(w, r, deps, user, subject, password, hash, operation, "active", "password_self_change")
}

// Every native password writer uses this same fail-closed remote/DB protocol.
func synchronizeNativePassword(w http.ResponseWriter, r *http.Request, deps *Dependencies, user *repository.User, subject, password, hash string, operation *repository.UserPasswordOperation, finalStatus, stagePrefix string) bool {
	if deps.LocalIdentityClient == nil || deps.LocalIdentityProvisioner == nil {
		writeErrorWithStatus(w, 503, "password_sync_unavailable", "local identity password service unavailable; password unchanged")
		return false
	}
	staged, err := operation.PrepareNative(r.Context(), user.PasswordHash, user.Status)
	if err != nil {
		writeErrorWithStatus(w, 503, "password_sync_unavailable", "password update could not be prepared; password unchanged")
		return false
	}
	if !staged {
		writeErrorWithStatus(w, 409, "password_change_conflict", "account credentials changed; sign in again")
		return false
	}
	failed := func(reason string, updated bool) bool {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		cleanupRequest := r.Clone(cleanupCtx)
		_ = deps.LocalIdentityClient.SetEnabled(cleanupCtx, subject, false)
		operation.Close()
		actorID := user.ID
		if actor := auth.GetUser(r.Context()); actor != nil {
			actorID = actor.ID
		}
		markerErr := markLocalIdentityReconciliation(cleanupRequest, deps, localidentity.ProvisionInput{ID: user.ID, TenantID: user.TenantID, ActorID: actorID, ExternalSubject: subject}, reason)
		logAudit(cleanupRequest, deps, "password_sync_failed", map[string]interface{}{"user_id": user.ID, "stage": reason, "password_updated": updated, "account_paused": true, "reconciliation_recorded": markerErr == nil}, "user", user.ID)
		code := "password_identity_sync_failed"
		if updated {
			code = "password_updated_identity_sync_failed"
		}
		writeErrorWithStatusAndDetails(w, 503, code, "password synchronization incomplete; account sign-in paused; contact the administrator", map[string]bool{"password_updated": updated, "account_paused": true})
		return false
	}
	if err := deps.LocalIdentityClient.SetEnabled(r.Context(), subject, false); err != nil {
		return failed(stagePrefix+"_identity_disable_failed", false)
	}
	if err := deps.LocalIdentityClient.ResetPassword(r.Context(), subject, password, false); err != nil {
		return failed(stagePrefix+"_identity_reset_failed", false)
	}
	updated, writeErr := operation.UpdatePassword(r.Context(), hash, false, user.PasswordHash)
	if writeErr != nil || !updated {
		return failed("password_runtime_updated_database_failed", false)
	}
	if err := deps.LocalIdentityClient.SetEnabled(r.Context(), subject, finalStatus == "active"); err != nil {
		return failed(stagePrefix+"_identity_enable_failed", true)
	}
	completed, err := operation.CompleteNative(r.Context(), hash, finalStatus)
	if err != nil || !completed {
		return failed(stagePrefix+"_identity_activate_failed", true)
	}
	return true
}

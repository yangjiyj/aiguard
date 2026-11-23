package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

const (
	identityStatusTimeout  = 2 * time.Second
	identityRestoreTimeout = 10 * time.Second
)

func identityTestConfig(src *repository.IdentitySource, clientSecret string) identity.TestConfig {
	return identity.TestConfig{
		IssuerURL: src.IssuerURL, ClientID: src.ClientID,
		ClientSecret: clientSecret, Scopes: src.Scopes,
		SignatureMode: src.SignatureMode,
		Claims: identity.ClaimConfig{
			SubjectClaim: src.SubjectClaim, UsernameClaim: src.UsernameClaim,
			NameClaim: src.NameClaim, EmailClaim: src.EmailClaim,
			DeptCodeClaim: src.DeptCodeClaim, DeptNameClaim: src.DeptNameClaim,
			GroupsClaim: src.GroupsClaim,
		},
	}
}

func identityClaimMappings(src *repository.IdentitySource) []identityruntime.ClaimMapping {
	type mapping struct {
		name, claim, attribute string
	}
	candidates := []mapping{
		{"subject", src.SubjectClaim, "external_subject"},
		{"username", src.UsernameClaim, "username"},
		{"name", src.NameClaim, "name"},
		{"email", src.EmailClaim, "email"},
		{"phone", src.PhoneClaim, "phone_number"},
		{"department", src.DeptCodeClaim, "department"},
		{"department_name", src.DeptNameClaim, "department_name"},
		{"groups", src.GroupsClaim, "groups"},
	}
	out := make([]identityruntime.ClaimMapping, 0, len(candidates))
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.claim) == "" {
			continue
		}
		out = append(out, identityruntime.ClaimMapping{
			Name: candidate.name, Claim: strings.TrimSpace(candidate.claim),
			UserAttribute: candidate.attribute,
		})
	}
	return out
}

func desiredIdentitySource(
	ctx context.Context,
	deps *Dependencies,
	src *repository.IdentitySource,
) (identityruntime.DesiredIdentitySource, error) {
	if deps.OIDCTester == nil {
		return identityruntime.DesiredIdentitySource{}, identityruntime.ErrRuntimeUnavailable
	}
	clientSecret, err := secrets.DecryptProviderSecret(src.ClientSecretEnc)
	if err != nil || strings.TrimSpace(clientSecret) == "" {
		return identityruntime.DesiredIdentitySource{}, identityruntime.ErrInvalidDesiredSource
	}
	discovery, err := deps.OIDCTester.ResolveDiscovery(ctx, identityTestConfig(src, clientSecret))
	if err != nil || discovery == nil {
		return identityruntime.DesiredIdentitySource{}, identityruntime.ErrInvalidDesiredSource
	}
	desired := identityruntime.DesiredIdentitySource{
		Realm: identityruntime.RealmName, Alias: sourceAlias(src),
		DisplayName: src.DisplayName,
		Endpoints: identityruntime.DiscoveryEndpoints{
			Issuer: discovery.Issuer, Authorization: discovery.AuthorizationEndpoint,
			Token: discovery.TokenEndpoint, JWKS: discovery.JWKSURI,
			UserInfo: discovery.UserInfoEndpoint, EndSession: discovery.EndSessionEndpoint,
		},
		ClientID: src.ClientID, ClientSecret: clientSecret,
		Scopes: strings.Fields(src.Scopes), ClaimMappings: identityClaimMappings(src),
		// 选项一律读取库里已存的值：重新发布/修复绝不回到默认值。
		SignatureMode: identityruntime.NormalizeSignatureMode(src.SignatureMode), SkipProfileReview: src.SkipProfileReview,
	}
	// 9.5：http 端点只在部署显式登记的私网内才可写入运行态（token 端点会携带 client_secret）。
	desired.AllowPrivateHTTP = identity.HTTPEndpointsExplicitlyAllowed(
		desired.Endpoints.Issuer, desired.Endpoints.Authorization, desired.Endpoints.Token,
		desired.Endpoints.JWKS, desired.Endpoints.UserInfo, desired.Endpoints.EndSession,
	)
	digest, err := identityruntime.ComputeDesiredDigest(desired)
	if err != nil {
		return identityruntime.DesiredIdentitySource{}, err
	}
	desired.Digest = digest
	return desired, nil
}

func identityRuntimeErrorCode(err error) string {
	switch {
	case errors.Is(err, identityruntime.ErrManageRealmRequired):
		return "identity_manage_realm_required"
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, identityruntime.ErrRuntimeUnavailable):
		return "identity_runtime_unavailable"
	case errors.Is(err, identityruntime.ErrRuntimeUnauthorized):
		return "identity_runtime_unauthorized"
	case errors.Is(err, identityruntime.ErrPublishConflict),
		errors.Is(err, repository.ErrIdentitySourceChanged):
		return "identity_publish_conflict"
	case errors.Is(err, identityruntime.ErrRollbackFailed):
		return "identity_rollback_failed"
	case errors.Is(err, identityruntime.ErrRuntimeDrifted):
		return "identity_runtime_drifted"
	default:
		return "identity_publish_failed"
	}
}

// 启用「首次登录不弹资料页」需要 realm 级写权限，而默认部署只授予最小权限。
const identityManageRealmRequiredMessage = "启用「首次登录不弹资料页」需要给身份运行服务账号授予 manage-realm 权限，请联系平台运维人员，详见升级文档（identity-nonstandard-oidc）；当前登录配置未切换"

func writeIdentityRuntimeError(w http.ResponseWriter, err error) {
	switch identityRuntimeErrorCode(err) {
	case "identity_runtime_unavailable":
		writeErrorWithStatus(w, http.StatusServiceUnavailable,
			"identity_runtime_unavailable", "身份服务暂不可用，本地管理员登录不受影响")
	case "identity_manage_realm_required":
		writeErrorWithStatus(w, http.StatusBadGateway,
			"identity_manage_realm_required", identityManageRealmRequiredMessage)
	case "identity_runtime_unauthorized":
		writeErrorWithStatus(w, http.StatusServiceUnavailable,
			"identity_runtime_unauthorized", "身份服务授权异常，请联系平台运维人员")
	case "identity_publish_conflict":
		writeErrorWithStatus(w, http.StatusConflict,
			"identity_publish_conflict", "配置已发生变化，请刷新后重试")
	case "identity_rollback_failed":
		writeErrorWithStatus(w, http.StatusInternalServerError,
			"identity_rollback_failed", "身份配置恢复失败，请暂停操作并联系平台运维人员")
	case "identity_runtime_drifted":
		writeErrorWithStatus(w, http.StatusConflict,
			"identity_runtime_drifted", "当前运行配置与已发布配置不一致，请执行修复")
	default:
		writeErrorWithStatus(w, http.StatusBadGateway,
			"identity_publish_failed", "身份配置发布失败，原有登录配置未切换")
	}
}

func restoreIdentityRuntime(ctx context.Context, runtime IdentityRuntime, snapshot identityruntime.RuntimeSnapshot) error {
	restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), identityRestoreTimeout)
	defer cancel()
	return runtime.Restore(restoreCtx, snapshot)
}

func recordIdentityPublicationFailure(
	ctx context.Context,
	deps *Dependencies,
	src *repository.IdentitySource,
	actorID, action string,
	err error,
) {
	code := identityRuntimeErrorCode(err)
	failureCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	ctx = failureCtx
	_ = deps.IdentitySourceRepo.MarkPublicationError(ctx, src.TenantID, src.ID, code, "")
	_ = deps.IdentitySourceRepo.RecordPublicationEvent(ctx, repository.PublicationEvent{
		TenantID: src.TenantID, SourceID: src.ID, SourceVersion: src.Version,
		Action: action, ActorUserID: actorID, Result: "failed", ErrorCode: code,
	})
}

func publishIdentitySource(
	ctx context.Context,
	deps *Dependencies,
	src *repository.IdentitySource,
	actorID, action string,
) error {
	if deps.IdentityRuntime == nil {
		return identityruntime.ErrRuntimeUnavailable
	}
	desired, err := desiredIdentitySource(ctx, deps, src)
	if err != nil {
		return err
	}
	if err := deps.IdentitySourceRepo.MarkPublishing(ctx, src.TenantID, src.ID, src.Version); err != nil {
		return err
	}
	_ = deps.IdentitySourceRepo.RecordPublicationEvent(ctx, repository.PublicationEvent{
		TenantID: src.TenantID, SourceID: src.ID, SourceVersion: src.Version,
		Action: action, ActorUserID: actorID, Result: "started",
		ConfigDigest: desired.Digest,
	})

	publication, err := deps.IdentityRuntime.Publish(ctx, desired)
	if err != nil {
		recordIdentityPublicationFailure(ctx, deps, src, actorID, action, err)
		return err
	}
	if publication.Digest != desired.Digest {
		if !publication.AlreadyCurrent {
			if restoreErr := restoreIdentityRuntime(ctx, deps.IdentityRuntime, publication.Previous); restoreErr != nil {
				recordIdentityPublicationFailure(ctx, deps, src, actorID, action, identityruntime.ErrRollbackFailed)
				return identityruntime.ErrRollbackFailed
			}
		}
		recordIdentityPublicationFailure(ctx, deps, src, actorID, action, identityruntime.ErrPublishVerification)
		return identityruntime.ErrPublishVerification
	}
	if err := deps.IdentitySourceRepo.CommitPublication(ctx, repository.PublicationCommit{
		TenantID: src.TenantID, SourceID: src.ID, ExpectedVersion: src.Version,
		RuntimeAlias: sourceAlias(src), ConfigDigest: publication.Digest,
		PublishedBy: actorID,
	}); err != nil {
		if !publication.AlreadyCurrent {
			if restoreErr := restoreIdentityRuntime(ctx, deps.IdentityRuntime, publication.Previous); restoreErr != nil {
				recordIdentityPublicationFailure(ctx, deps, src, actorID, action, identityruntime.ErrRollbackFailed)
				return identityruntime.ErrRollbackFailed
			}
		}
		recordIdentityPublicationFailure(ctx, deps, src, actorID, action, err)
		return err
	}
	return nil
}

// ActivateIdentitySource publishes a tested source before atomically making it active.
func ActivateIdentitySource(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		alias, ok := sourceAliasFromRequest(r)
		if !ok {
			writeInvalidSourceAlias(w)
			return
		}
		tested, err := deps.IdentitySourceRepo.GetTestedByAlias(r.Context(), user.TenantID, alias)
		if err != nil {
			writeError(w, "internal_error", "获取已测试配置失败")
			return
		}
		if tested == nil {
			draft, draftErr := deps.IdentitySourceRepo.GetDraftByAlias(r.Context(), user.TenantID, alias)
			if draftErr != nil {
				writeError(w, "internal_error", "获取配置草稿失败")
				return
			}
			if draft != nil {
				writeError(w, "invalid_state", "请先完成测试连接")
				return
			}
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "没有可启用的配置")
			return
		}
		if err := publishIdentitySource(r.Context(), deps, tested, user.ID, "publish"); err != nil {
			writeIdentityRuntimeError(w, err)
			return
		}
		logAudit(r, deps, "identity.source.activated", map[string]any{
			"display_name": tested.DisplayName, "source_version": tested.Version,
		}, "identity_source", tested.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true, "message": "身份源已启用",
		})
	}
}

// ReconcileIdentitySource reapplies the current tenant's active configuration.
func ReconcileIdentitySource(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		alias, ok := sourceAliasFromRequest(r)
		if !ok {
			writeInvalidSourceAlias(w)
			return
		}
		active, err := deps.IdentitySourceRepo.GetActiveByAlias(r.Context(), user.TenantID, alias)
		if err != nil {
			writeError(w, "internal_error", "获取当前配置失败")
			return
		}
		if active == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "没有可修复的已启用配置")
			return
		}
		if err := publishIdentitySource(r.Context(), deps, active, user.ID, "reconcile"); err != nil {
			writeIdentityRuntimeError(w, err)
			return
		}
		logAudit(r, deps, "identity.source.reconciled", map[string]any{
			"display_name": active.DisplayName, "source_version": active.Version,
		}, "identity_source", active.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true, "message": "身份配置已按当前设置修复",
		})
	}
}

// DisableIdentitySource disables runtime SSO only when a real local admin remains.
func DisableIdentitySource(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		var req disableReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "请求格式错误")
			return
		}
		if !req.Confirm {
			writeError(w, "confirmation_required", "请确认停用操作")
			return
		}
		alias, ok := sourceAliasFromRequest(r)
		if !ok {
			writeInvalidSourceAlias(w)
			return
		}
		active, err := deps.IdentitySourceRepo.GetActiveByAlias(r.Context(), user.TenantID, alias)
		if err != nil {
			writeError(w, "internal_error", "获取当前配置失败")
			return
		}
		if active == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "没有已启用的身份源")
			return
		}
		if deps.UserRepo == nil {
			writeError(w, "internal_error", "无法确认本地管理员状态")
			return
		}
		emergencyAdmin, err := deps.UserRepo.HasEmergencyAdmin(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "无法确认本地管理员状态")
			return
		}
		if !emergencyAdmin {
			writeErrorWithStatus(w, http.StatusConflict,
				"emergency_admin_required", "停用前请先保留一个可使用密码登录的本地管理员")
			return
		}
		if deps.IdentityRuntime == nil {
			writeIdentityRuntimeError(w, identityruntime.ErrRuntimeUnavailable)
			return
		}
		snapshot, err := deps.IdentityRuntime.Disable(r.Context(), identityruntime.DesiredIdentitySource{
			Realm: identityruntime.RealmName, Alias: alias,
		})
		if err != nil {
			recordIdentityPublicationFailure(r.Context(), deps, active, user.ID, "disable", err)
			writeIdentityRuntimeError(w, err)
			return
		}
		if err := deps.IdentitySourceRepo.Disable(r.Context(), user.TenantID, active.ID); err != nil {
			if restoreErr := restoreIdentityRuntime(r.Context(), deps.IdentityRuntime, snapshot); restoreErr != nil {
				recordIdentityPublicationFailure(r.Context(), deps, active, user.ID, "disable", identityruntime.ErrRollbackFailed)
				writeIdentityRuntimeError(w, identityruntime.ErrRollbackFailed)
				return
			}
			recordIdentityPublicationFailure(r.Context(), deps, active, user.ID, "disable", err)
			writeError(w, "internal_error", "停用未提交，原有登录配置已恢复")
			return
		}
		_ = deps.IdentitySourceRepo.RecordPublicationEvent(r.Context(), repository.PublicationEvent{
			TenantID: active.TenantID, SourceID: active.ID, SourceVersion: active.Version,
			Action: "disable", ActorUserID: user.ID, Result: "succeeded",
			ConfigDigest: active.ConfigDigest,
		})
		logAudit(r, deps, "identity.source.disabled", map[string]any{
			"display_name": active.DisplayName, "source_version": active.Version,
		}, "identity_source", active.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true, "message": "身份源已停用",
		})
	}
}

// GetIdentityStatus merges database publication truth with a bounded runtime check.
func GetIdentityStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		alias, ok := sourceAliasFromRequest(r)
		if !ok {
			writeInvalidSourceAlias(w)
			return
		}
		active, err := deps.IdentitySourceRepo.GetActiveByAlias(r.Context(), user.TenantID, alias)
		if err != nil {
			writeError(w, "internal_error", "获取身份配置状态失败")
			return
		}
		draft, err := deps.IdentitySourceRepo.GetPendingByAlias(r.Context(), user.TenantID, alias)
		if err != nil {
			writeError(w, "internal_error", "获取身份配置状态失败")
			return
		}
		if deps.UserRepo == nil {
			writeError(w, "internal_error", "无法确认本地管理员状态")
			return
		}
		emergencyAdmin, err := deps.UserRepo.HasEmergencyAdmin(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "无法确认本地管理员状态")
			return
		}
		status := identityStatusDTO{
			HasDraft: draft != nil, CallbackURL: callbackURLForAlias(deps, alias),
			EmergencyAdmin: emergencyAdmin, PublishStatus: "not_published",
			RuntimeAvailable: deps.IdentityRuntime != nil,
		}
		if active != nil {
			status.HasActive = true
			status.ActiveDisplayName = active.DisplayName
			status.PublishStatus = active.PublishStatus
			status.AppliedVersion = active.AppliedVersion
			if status.PublishStatus == "" {
				status.PublishStatus = "active"
			}
			if active.LastTestedAt != nil {
				status.LastTestedAt = active.LastTestedAt.Format(time.RFC3339)
			}
			if deps.IdentityRuntime == nil {
				status.RuntimeAvailable = false
				status.RuntimeMessage = "身份服务暂不可用，本地管理员登录不受影响"
			} else {
				checkCtx, cancel := context.WithTimeout(r.Context(), identityStatusTimeout)
				runtimeStatus, runtimeErr := deps.IdentityRuntime.Status(checkCtx, identityruntime.DesiredIdentitySource{
					Realm: identityruntime.RealmName, Alias: alias,
					Digest: active.ConfigDigest,
				})
				cancel()
				if errors.Is(runtimeErr, identityruntime.ErrInvalidDesiredSource) {
					status.PublishStatus = "drifted"
					status.Drift = true
					status.RuntimeMessage = "当前配置尚未完整发布，可按当前配置修复"
					_ = deps.IdentitySourceRepo.MarkRuntimeStatus(
						r.Context(), user.TenantID, active.ID, "drifted",
					)
				} else if runtimeErr != nil {
					status.RuntimeAvailable = false
					status.RuntimeMessage = "身份服务暂不可用，本地管理员登录不受影响"
				} else if runtimeStatus.Drifted {
					status.PublishStatus = "drifted"
					status.Drift = true
					status.RuntimeMessage = "运行配置与当前设置不一致，可按当前配置修复"
					if fields := observeAdoptableDrift(r.Context(), deps, alias, active); len(fields) > 0 {
						status.DriftFields = fields
						status.AdoptRecommended = true
						status.RuntimeMessage = adoptRecommendedMessage
					}
					_ = deps.IdentitySourceRepo.MarkRuntimeStatus(
						r.Context(), user.TenantID, active.ID, "drifted",
					)
				} else {
					status.PublishStatus = "active"
					_ = deps.IdentitySourceRepo.MarkRuntimeStatus(
						r.Context(), user.TenantID, active.ID, "active",
					)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	}
}

const adoptRecommendedMessage = "身份服务中的登录配置与平台保存的配置不一致，当前登录不受影响。如这些差异是现场有意调整，请先「采纳现场运行态」，再「按当前配置修复」。"

// observeAdoptableDrift 只读观测运行态，返回与平台保存值不同的可采纳字段；失败或不支持时返回 nil。
func observeAdoptableDrift(ctx context.Context, deps *Dependencies, alias string, active *repository.IdentitySource) []string {
	observer, ok := deps.IdentityRuntime.(identityRuntimeObserver)
	if !ok || active == nil {
		return nil
	}
	observeCtx, cancel := context.WithTimeout(ctx, identityStatusTimeout)
	defer cancel()
	observed, err := observer.Observe(observeCtx, identityruntime.DesiredIdentitySource{
		Realm: identityruntime.RealmName, Alias: alias,
	})
	if err != nil {
		log.Printf("identity status observe failed reason=%s", observeFailureCode(err))
		return nil
	}
	return diffObservedSettings(observed, active)
}

// observeFailureCode 把观测错误映射为短码，避免日志带出凭据、URL 或响应体。
func observeFailureCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, identityruntime.ErrRuntimeUnavailable):
		return "runtime_unavailable"
	case errors.Is(err, identityruntime.ErrRuntimeUnauthorized):
		return "unauthorized"
	case errors.Is(err, identityruntime.ErrRuntimeNotFound):
		return "not_found"
	case errors.Is(err, identityruntime.ErrRuntimeRejected):
		return "rejected"
	case errors.Is(err, identityruntime.ErrRuntimeResponseTooLarge):
		return "response_too_large"
	default:
		return "other"
	}
}

func diffObservedSettings(observed identityruntime.ObservedSettings, active *repository.IdentitySource) []string {
	if !observed.Exists {
		return nil
	}
	var fields []string
	if identityruntime.NormalizeSignatureMode(observed.SignatureMode) != identityruntime.NormalizeSignatureMode(active.SignatureMode) {
		fields = append(fields, "signature_mode")
	}
	if observed.UsernameClaim != "" && observed.UsernameClaim != active.UsernameClaim {
		fields = append(fields, "username_claim")
	}
	if observed.SkipProfileReview != active.SkipProfileReview {
		fields = append(fields, "skip_profile_review")
	}
	return fields
}

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

type identitySourceDTO struct {
	ID              string `json:"id"`
	DisplayName     string `json:"display_name"`
	Protocol        string `json:"protocol"`
	IssuerURL       string `json:"issuer_url"`
	ClientID        string `json:"client_id"`
	ClientSecretSet bool   `json:"client_secret_set"`
	Scopes          string `json:"scopes"`
	SubjectClaim    string `json:"subject_claim"`
	UsernameClaim   string `json:"username_claim"`
	NameClaim       string `json:"name_claim"`
	EmailClaim      string `json:"email_claim"`
	PhoneClaim      string `json:"phone_claim"`
	DeptCodeClaim   string `json:"dept_code_claim"`
	DeptNameClaim   string `json:"dept_name_claim"`
	GroupsClaim     string `json:"groups_claim"`
	// SignatureMode：id_token 验签方式 jwks（默认）/ none；SkipProfileReview：首次登录不弹资料页。
	SignatureMode     string                 `json:"signature_mode"`
	SkipProfileReview bool                   `json:"skip_profile_review"`
	Status            string                 `json:"status"`
	IsDefault         bool                   `json:"is_default"`
	Version           int                    `json:"version"`
	PublishedBy       string                 `json:"published_by,omitempty"`
	PublishedAt       string                 `json:"published_at,omitempty"`
	LastTestedAt      string                 `json:"last_tested_at,omitempty"`
	LastTestResult    *repository.TestResult `json:"last_test_result,omitempty"`
	CallbackURL       string                 `json:"callback_url"`
	// SourceAlias：9.2 身份源稳定标识；其余身份源接口以 ?source=<alias> 指定目标。
	SourceAlias string `json:"source_alias"`
}

type identityStatusDTO struct {
	HasActive         bool   `json:"has_active"`
	HasDraft          bool   `json:"has_draft"`
	ActiveDisplayName string `json:"active_display_name,omitempty"`
	LastTestedAt      string `json:"last_tested_at,omitempty"`
	EmergencyAdmin    bool   `json:"emergency_admin_available"`
	CallbackURL       string `json:"callback_url"`
	PublishStatus     string `json:"publish_status"`
	AppliedVersion    int    `json:"applied_version,omitempty"`
	Drift             bool   `json:"drift"`
	RuntimeAvailable  bool   `json:"runtime_available"`
	RuntimeMessage    string `json:"runtime_message,omitempty"`
	// DriftFields 为运行态与平台保存值不同的可采纳字段：signature_mode / username_claim / skip_profile_review。
	DriftFields      []string `json:"drift_fields,omitempty"`
	AdoptRecommended bool     `json:"adopt_recommended,omitempty"`
}

type identityDeptMappingDTO struct {
	ID              string `json:"id"`
	MatchValue      string `json:"match_value"`
	MappedTeamID    string `json:"mapped_team_id,omitempty"`
	MappedProjectID string `json:"mapped_project_id,omitempty"`
	Priority        int    `json:"priority"`
	Enabled         bool   `json:"enabled"`
}

func toIdentitySourceDTO(src *repository.IdentitySource, callbackURL string) identitySourceDTO {
	dto := identitySourceDTO{
		ID:                src.ID,
		DisplayName:       src.DisplayName,
		Protocol:          src.Protocol,
		IssuerURL:         src.IssuerURL,
		ClientID:          src.ClientID,
		ClientSecretSet:   src.ClientSecretEnc != "",
		Scopes:            src.Scopes,
		SubjectClaim:      src.SubjectClaim,
		UsernameClaim:     src.UsernameClaim,
		NameClaim:         src.NameClaim,
		EmailClaim:        src.EmailClaim,
		PhoneClaim:        src.PhoneClaim,
		DeptCodeClaim:     src.DeptCodeClaim,
		DeptNameClaim:     src.DeptNameClaim,
		GroupsClaim:       src.GroupsClaim,
		SignatureMode:     identityruntime.NormalizeSignatureMode(src.SignatureMode),
		SkipProfileReview: src.SkipProfileReview,
		Status:            src.Status,
		IsDefault:         src.IsDefault,
		Version:           src.Version,
		CallbackURL:       callbackURL,
		SourceAlias:       sourceAlias(src),
	}
	if src.PublishedBy != "" {
		dto.PublishedBy = src.PublishedBy
	}
	if src.PublishedAt != nil {
		dto.PublishedAt = src.PublishedAt.Format(time.RFC3339)
	}
	if src.LastTestedAt != nil {
		dto.LastTestedAt = src.LastTestedAt.Format(time.RFC3339)
	}
	if src.LastTestResult != nil {
		dto.LastTestResult = src.LastTestResult
	}
	return dto
}

func isIdentityAdmin(user *repository.User) bool {
	return user.Role == "platform_admin" || user.Role == "tenant_admin" || user.Role == "tenant_owner" || user.Role == "admin"
}

// GetIdentitySources GET /admin/v1/identity/sources
func GetIdentitySources(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		sources, err := deps.IdentitySourceRepo.GetAll(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "获取身份源配置失败")
			return
		}
		out := make([]identitySourceDTO, 0, len(sources))
		for _, s := range sources {
			out = append(out, toIdentitySourceDTO(s, callbackURLForAlias(deps, sourceAlias(s))))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
	}
}

type saveDraftReq struct {
	DisplayName   string `json:"display_name"`
	IssuerURL     string `json:"issuer_url"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	Scopes        string `json:"scopes"`
	SubjectClaim  string `json:"subject_claim"`
	UsernameClaim string `json:"username_claim"`
	NameClaim     string `json:"name_claim"`
	EmailClaim    string `json:"email_claim"`
	PhoneClaim    string `json:"phone_claim"`
	DeptCodeClaim string `json:"dept_code_claim"`
	DeptNameClaim string `json:"dept_name_claim"`
	GroupsClaim   string `json:"groups_claim"`
	// 两项可选：缺省时保持已有草稿的值（新建则取默认 jwks / false）。
	SignatureMode     string `json:"signature_mode"`
	SkipProfileReview *bool  `json:"skip_profile_review"`
}

func (req saveDraftReq) validate() string {
	if strings.TrimSpace(req.DisplayName) == "" {
		return "显示名称不能为空"
	}
	if len(req.DisplayName) > 128 {
		return "显示名称不能超过 128 个字符"
	}
	if strings.TrimSpace(req.IssuerURL) == "" {
		return "Issuer 地址不能为空"
	}
	if len(req.IssuerURL) > 512 {
		return "Issuer 地址不能超过 512 个字符"
	}
	if strings.TrimSpace(req.ClientID) == "" {
		return "Client ID 不能为空"
	}
	if len(req.ClientID) > 128 {
		return "Client ID 不能超过 128 个字符"
	}
	if _, msg := normalizeIdentityScopes(req.Scopes); msg != "" {
		return msg
	}
	switch strings.TrimSpace(req.SignatureMode) {
	case "", identityruntime.SignatureModeJWKS, identityruntime.SignatureModeNone:
	default:
		return "id_token 验签方式只能选择「按 IdP 公钥验签」或「不校验签名」"
	}
	if claim := strings.TrimSpace(req.UsernameClaim); claim != "" && !identityruntime.ValidClaimToken(claim) {
		return "用户名取值无效，请选择 preferred_username、邮箱或 sub"
	}
	return ""
}

// W9 9.8：scopes 在保存时就校验，而不是拖到发布时才以笼统错误失败。
const (
	defaultIdentityScopes  = "openid profile email"
	maxIdentityScopesBytes = 256 // 与 identity_sources.scopes varchar(256) 一致
)

// normalizeIdentityScopes：空 → 默认值；按空白切分去重（保序）；每个 token 须符合
// RFC 6749 §3.3 scope-token（%x21 / %x23-5B / %x5D-7E）；必须含 openid；总长 ≤ 256。
func normalizeIdentityScopes(raw string) (string, string) {
	// strings.Fields 会把 U+00A0 等 Unicode 空白当分隔符，先整体拒绝非 ASCII
	// 与除空格/制表符外的控制字符，确保切分只发生在 ASCII 空白上。
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c > 0x7E || (c < 0x20 && c != '\t') || c == 0x7F {
			return "", "Scopes 含非法字符，只允许以空格分隔的标准 scope 名称"
		}
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return defaultIdentityScopes, ""
	}
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	hasOpenID := false
	for _, token := range fields {
		for _, c := range []byte(token) {
			if c < 0x21 || c == 0x22 || c == 0x5C || c > 0x7E {
				return "", "Scopes 含非法字符，只允许以空格分隔的标准 scope 名称"
			}
		}
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
		if token == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		return "", "Scopes 必须包含 openid"
	}
	joined := strings.Join(out, " ")
	if len(joined) > maxIdentityScopesBytes {
		return "", "Scopes 不能超过 256 个字符"
	}
	return joined, ""
}

// SaveIdentityDraft PUT /admin/v1/identity/sources/draft
func SaveIdentityDraft(deps *Dependencies) http.HandlerFunc {
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
		var req saveDraftReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "请求格式错误")
			return
		}
		if msg := req.validate(); msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}

		// 9.2：?source=new 新建一个身份源（alias 由服务端派生）；?source=<alias> 编辑已有身份源；
		// 缺省编辑默认身份源。
		alias := ""
		existing := (*repository.IdentitySource)(nil)
		if strings.TrimSpace(r.URL.Query().Get("source")) == "new" {
			var aliasErr error
			if alias, aliasErr = newSourceAlias(); aliasErr != nil {
				writeError(w, "internal_error", "创建身份源失败")
				return
			}
		} else {
			var ok bool
			if alias, ok = sourceAliasFromRequest(r); !ok {
				writeInvalidSourceAlias(w)
				return
			}
			var err error
			existing, err = deps.IdentitySourceRepo.GetPendingByAlias(r.Context(), user.TenantID, alias)
			if err != nil {
				writeError(w, "internal_error", "获取草稿失败")
				return
			}
			if existing == nil && alias != repository.DefaultRuntimeAlias {
				known, err := deps.IdentitySourceRepo.ListAliases(r.Context(), user.TenantID)
				if err != nil {
					writeError(w, "internal_error", "获取草稿失败")
					return
				}
				if !containsString(known, alias) {
					writeErrorWithStatus(w, http.StatusNotFound, "not_found", "身份源不存在")
					return
				}
			}
		}

		secretEnc := ""
		if req.ClientSecret != "" {
			enc, _, err := secrets.EncryptProviderSecret(req.ClientSecret)
			if err != nil {
				writeError(w, "internal_error", "密钥加密失败")
				return
			}
			secretEnc = enc
		} else if existing != nil {
			secretEnc = existing.ClientSecretEnc
		}

		scopes, _ := normalizeIdentityScopes(req.Scopes)
		src := &repository.IdentitySource{
			TenantID:        user.TenantID,
			DisplayName:     strings.TrimSpace(req.DisplayName),
			Protocol:        "oidc",
			IssuerURL:       strings.TrimSpace(req.IssuerURL),
			ClientID:        strings.TrimSpace(req.ClientID),
			ClientSecretEnc: secretEnc,
			Scopes:          scopes,
			SubjectClaim:    req.SubjectClaim,
			UsernameClaim:   req.UsernameClaim,
			NameClaim:       req.NameClaim,
			EmailClaim:      req.EmailClaim,
			PhoneClaim:      req.PhoneClaim,
			DeptCodeClaim:   req.DeptCodeClaim,
			DeptNameClaim:   req.DeptNameClaim,
			GroupsClaim:     req.GroupsClaim,
			Status:          "draft",
			RuntimeAlias:    alias,
			SignatureMode:   strings.TrimSpace(req.SignatureMode),
		}
		if existing != nil {
			src.ID = existing.ID
			src.Version = existing.Version
			if src.SignatureMode == "" {
				src.SignatureMode = existing.SignatureMode
			}
			src.SkipProfileReview = existing.SkipProfileReview
		}
		if req.SkipProfileReview != nil {
			src.SkipProfileReview = *req.SkipProfileReview
		}

		// 不校验签名只有 token 端点是 https 时才成立；token 端点来自 discovery，保存阶段只能按身份源地址预判。
		if identityruntime.NormalizeSignatureMode(src.SignatureMode) == identityruntime.SignatureModeNone &&
			!strings.HasPrefix(strings.ToLower(src.IssuerURL), "https://") {
			writeErrorWithStatus(w, http.StatusBadRequest, "signature_none_requires_https",
				"选择「不校验签名」时，token 端点必须是 https（当前身份源地址不是 https）")
			return
		}

		if err := deps.IdentitySourceRepo.UpsertDraft(r.Context(), src); err != nil {
			if errors.Is(err, repository.ErrIdentitySourceChanged) {
				writeErrorWithStatus(w, http.StatusConflict, "version_conflict", "配置已发生变化，请刷新后重试")
				return
			}
			writeError(w, "internal_error", "保存草稿失败")
			return
		}

		logAudit(r, deps, "identity.source.draft_saved", map[string]any{
			"display_name": src.DisplayName,
			"issuer_url":   src.IssuerURL,
		}, "identity_source", src.ID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toIdentitySourceDTO(src, callbackURLForAlias(deps, alias)))
	}
}

// TestIdentityConnection POST /admin/v1/identity/sources/test
func TestIdentityConnection(deps *Dependencies) http.HandlerFunc {
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
		draft, err := deps.IdentitySourceRepo.GetDraftByAlias(r.Context(), user.TenantID, alias)
		if err != nil {
			writeError(w, "internal_error", "获取草稿失败")
			return
		}
		if draft == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "请先保存配置草稿")
			return
		}

		clientSecret, err := secrets.DecryptProviderSecret(draft.ClientSecretEnc)
		if err != nil {
			writeError(w, "internal_error", "解密密钥失败")
			return
		}

		cfg := identity.TestConfig{
			IssuerURL:     draft.IssuerURL,
			ClientID:      draft.ClientID,
			ClientSecret:  clientSecret,
			Scopes:        draft.Scopes,
			SignatureMode: draft.SignatureMode,
			Claims: identity.ClaimConfig{
				SubjectClaim:  draft.SubjectClaim,
				UsernameClaim: draft.UsernameClaim,
				NameClaim:     draft.NameClaim,
				EmailClaim:    draft.EmailClaim,
				DeptCodeClaim: draft.DeptCodeClaim,
				DeptNameClaim: draft.DeptNameClaim,
				GroupsClaim:   draft.GroupsClaim,
			},
		}

		result := deps.OIDCTester.TestConnection(r.Context(), cfg)
		if prober, ok := deps.OIDCTester.(interface {
			ProbeAuthenticationEndpoints(context.Context, identity.TestConfig, *identity.TestConnectionResult, string)
		}); ok {
			prober.ProbeAuthenticationEndpoints(r.Context(), cfg, result, callbackURLForAlias(deps, alias))
		}

		testResult := &repository.TestResult{
			Success:  result.Success,
			Stages:   make([]repository.TestStage, len(result.Stages)),
			TestedAt: time.Now().Format(time.RFC3339),
		}
		if result.Error != "" {
			testResult.Error = result.Error
		}
		testResult.Hints = result.Hints
		for i, s := range result.Stages {
			testResult.Stages[i] = repository.TestStage{
				Name: s.Name, Status: s.Status, Message: s.Message,
			}
		}

		if err := deps.IdentitySourceRepo.UpdateTestResult(r.Context(), user.TenantID, draft.ID, draft.Version, testResult); err != nil {
			if errors.Is(err, repository.ErrIdentitySourceChanged) {
				writeErrorWithStatus(w, http.StatusConflict, "version_conflict", "配置已修改，请重新测试")
				return
			}
			writeError(w, "internal_error", "保存测试结果失败")
			return
		}

		logAudit(r, deps, "identity.source.tested", map[string]any{
			"success": result.Success,
			"issuer":  draft.IssuerURL,
		}, "identity_source", draft.ID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": result.Success,
			"stages":  result.Stages,
			"error":   result.Error,
			"hints":   result.Hints,
		})
	}
}

// Runtime-backed activate, disable, reconcile and status handlers live in identity_publication_handler.go.

type disableReq struct {
	Confirm bool `json:"confirm"`
}

// markDeptMappingsDeprecated signals clients that the legacy
// /admin/v1/identity/dept-mappings surface is replaced by the unified
// /admin/v1/identity/department-mappings API. The legacy surface reads and
// writes the same identity_department_mappings table for one release.
func markDeptMappingsDeprecated(w http.ResponseWriter) {
	w.Header().Set("Deprecation", "true")
	w.Header().Set("Link", `</admin/v1/identity/department-mappings>; rel="successor-version"`)
}

// ListIdentityDeptMappings GET /admin/v1/identity/dept-mappings (legacy)
//
// Compatibility reader: resolves from the new identity_department_mappings
// table and projects target_department_id back into mapped_team_id so that
// existing clients keep working for one release.
func ListIdentityDeptMappings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		sourceID := r.URL.Query().Get("source_id")
		if sourceID == "" {
			active, _ := deps.IdentitySourceRepo.GetActive(r.Context(), user.TenantID)
			if active != nil {
				sourceID = active.ID
			}
		}
		markDeptMappingsDeprecated(w)
		// Legacy mappings were all OIDC; read from the unified table so the
		// old client surface keeps working without a dual-write.
		mappings, err := deps.IdentityDepartmentMappingRepo.List(r.Context(), user.TenantID, "oidc", sourceID)
		if err != nil {
			writeError(w, "internal_error", "获取部门映射失败")
			return
		}
		out := make([]identityDeptMappingDTO, 0, len(mappings))
		for _, m := range mappings {
			out = append(out, identityDeptMappingDTO{
				ID: m.ID, MatchValue: m.MatchValue,
				MappedTeamID: m.TargetDepartmentID,
				Priority:     m.Priority, Enabled: m.Enabled,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
	}
}

type deptMappingReq struct {
	MatchValue      string `json:"match_value"`
	MappedTeamID    string `json:"mapped_team_id"`
	MappedProjectID string `json:"mapped_project_id"`
	Priority        int    `json:"priority"`
	Enabled         *bool  `json:"enabled"`
}

func validateIdentityMappingTargets(ctx context.Context, deps *Dependencies, tenantID, teamID, projectID string) (string, error) {
	if teamID != "" {
		if deps.TeamRepo == nil {
			return "", fmt.Errorf("team repository unavailable")
		}
		team, err := deps.TeamRepo.GetByID(ctx, teamID)
		if err != nil {
			return "", err
		}
		if team == nil || team.TenantID != tenantID {
			return "所选部门不属于当前租户", nil
		}
	}
	if projectID != "" {
		if deps.ProjectRepo == nil {
			return "", fmt.Errorf("project repository unavailable")
		}
		project, err := deps.ProjectRepo.GetByID(ctx, tenantID, projectID)
		if err != nil {
			return "", err
		}
		if project == nil {
			return "所选应用不属于当前租户", nil
		}
	}
	return "", nil
}

// CreateIdentityDeptMapping POST /admin/v1/identity/dept-mappings (legacy)
//
// Compatibility writer: persists into identity_department_mappings only (no
// dual-write to the legacy identity_dept_mappings table). source_kind is fixed
// to oidc and match_type to department to mirror the legacy semantics; the
// legacy mapped_team_id is stored as target_department_id.
func CreateIdentityDeptMapping(deps *Dependencies) http.HandlerFunc {
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

		var req deptMappingReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "请求格式错误")
			return
		}
		if strings.TrimSpace(req.MatchValue) == "" {
			writeError(w, "invalid_request", "匹配值不能为空")
			return
		}

		sourceID := r.URL.Query().Get("source_id")
		if sourceID == "" {
			active, _ := deps.IdentitySourceRepo.GetActive(r.Context(), user.TenantID)
			if active != nil {
				sourceID = active.ID
			}
		}
		if sourceID == "" {
			writeError(w, "invalid_request", "请先启用身份源")
			return
		}
		source, err := deps.IdentitySourceRepo.GetByID(r.Context(), user.TenantID, sourceID)
		if err != nil {
			writeError(w, "internal_error", "校验身份源失败")
			return
		}
		if source == nil {
			writeError(w, "invalid_request", "身份源不属于当前租户")
			return
		}
		if msg, err := validateIdentityMappingTargets(r.Context(), deps, user.TenantID, req.MappedTeamID, req.MappedProjectID); err != nil {
			writeError(w, "internal_error", "校验映射目标失败")
			return
		} else if msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}

		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}

		m := &repository.IdentityDepartmentMapping{
			TenantID:           user.TenantID,
			SourceKind:         "oidc",
			SourceID:           sourceID,
			MatchType:          "department",
			MatchValue:         strings.TrimSpace(req.MatchValue),
			TargetDepartmentID: req.MappedTeamID,
			Priority:           req.Priority,
			Enabled:            enabled,
		}
		if err := deps.IdentityDepartmentMappingRepo.Upsert(r.Context(), m); err != nil {
			if errors.Is(err, repository.ErrIdentityDepartmentMappingConflict) {
				writeErrorWithStatus(w, http.StatusConflict, "conflict", "相同的映射已存在")
				return
			}
			writeError(w, "internal_error", "创建部门映射失败")
			return
		}

		logAudit(r, deps, "identity.dept_mapping.created", map[string]any{
			"match_value":     m.MatchValue,
			"legacy_endpoint": true,
		}, "identity_department_mapping", m.ID)

		markDeptMappingsDeprecated(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(identityDeptMappingDTO{
			ID: m.ID, MatchValue: m.MatchValue,
			MappedTeamID: m.TargetDepartmentID,
			Priority:     m.Priority, Enabled: m.Enabled,
		})
	}
}

// UpdateIdentityDeptMapping PATCH /admin/v1/identity/dept-mappings/{id} (legacy)
//
// Compatibility writer: updates the unified identity_department_mappings row.
// The legacy mapped_project_id field is no longer persisted (it was never
// honored by the runtime resolver).
func UpdateIdentityDeptMapping(deps *Dependencies) http.HandlerFunc {
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

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "缺少映射 ID")
			return
		}

		var req deptMappingReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "请求格式错误")
			return
		}
		if strings.TrimSpace(req.MatchValue) == "" {
			writeError(w, "invalid_request", "匹配值不能为空")
			return
		}
		if msg, err := validateIdentityMappingTargets(r.Context(), deps, user.TenantID, req.MappedTeamID, req.MappedProjectID); err != nil {
			writeError(w, "internal_error", "校验映射目标失败")
			return
		} else if msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}

		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}

		// Carry source_kind/source_id/match_type over from the existing row:
		// the legacy request body does not carry them and they form the key.
		existing, err := deps.IdentityDepartmentMappingRepo.Get(r.Context(), user.TenantID, id)
		if err != nil {
			writeError(w, "internal_error", "更新部门映射失败")
			return
		}
		if existing == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "部门映射不存在")
			return
		}
		m := &repository.IdentityDepartmentMapping{
			ID:                 id,
			TenantID:           user.TenantID,
			SourceKind:         existing.SourceKind,
			SourceID:           existing.SourceID,
			MatchType:          existing.MatchType,
			MatchValue:         strings.TrimSpace(req.MatchValue),
			TargetDepartmentID: req.MappedTeamID,
			Priority:           req.Priority,
			Enabled:            enabled,
		}
		if err := deps.IdentityDepartmentMappingRepo.Upsert(r.Context(), m); err != nil {
			if errors.Is(err, repository.ErrIdentityDepartmentMappingNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "部门映射不存在")
				return
			}
			if errors.Is(err, repository.ErrIdentityDepartmentMappingConflict) {
				writeErrorWithStatus(w, http.StatusConflict, "conflict", "相同的映射已存在")
				return
			}
			writeError(w, "internal_error", "更新部门映射失败")
			return
		}

		logAudit(r, deps, "identity.dept_mapping.updated", map[string]any{
			"match_value":     m.MatchValue,
			"legacy_endpoint": true,
		}, "identity_department_mapping", m.ID)

		markDeptMappingsDeprecated(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(identityDeptMappingDTO{
			ID: m.ID, MatchValue: m.MatchValue,
			MappedTeamID: m.TargetDepartmentID,
			Priority:     m.Priority, Enabled: m.Enabled,
		})
	}
}

// DeleteIdentityDeptMapping DELETE /admin/v1/identity/dept-mappings/{id} (legacy)
//
// Compatibility writer: deletes from identity_department_mappings.
func DeleteIdentityDeptMapping(deps *Dependencies) http.HandlerFunc {
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

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "缺少映射 ID")
			return
		}

		if err := deps.IdentityDepartmentMappingRepo.Delete(r.Context(), user.TenantID, id); err != nil {
			if errors.Is(err, repository.ErrIdentityDepartmentMappingNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "部门映射不存在")
				return
			}
			writeError(w, "internal_error", "删除部门映射失败")
			return
		}

		logAudit(r, deps, "identity.dept_mapping.deleted", map[string]any{
			"legacy_endpoint": true,
		}, "identity_department_mapping", id)

		markDeptMappingsDeprecated(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

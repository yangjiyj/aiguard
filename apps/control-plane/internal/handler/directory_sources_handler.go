package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

type directorySourceDTO struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"`
	DisplayName       string `json:"display_name"`
	BindPasswordSet   bool   `json:"bind_password_set"`
	CACertSet         bool   `json:"ca_cert_set"`
	StableIDAttribute string `json:"stable_id_attribute"`
	UsernameAttribute string `json:"username_attribute"`
	EmailAttribute    string `json:"email_attribute"`
	NameAttribute     string `json:"name_attribute"`
	Status            string `json:"status"`
	Version           int    `json:"version"`
}

func toDirectorySourceDTO(source *repository.DirectorySource) directorySourceDTO {
	return directorySourceDTO{ID: source.ID, Kind: string(source.Kind), DisplayName: source.DisplayName,
		BindPasswordSet: source.BindPasswordEnc != "", CACertSet: source.CACertPEM != "",
		StableIDAttribute: source.StableIDAttribute, UsernameAttribute: source.UsernameAttribute,
		EmailAttribute: source.EmailAttribute, NameAttribute: source.NameAttribute, Status: source.Status, Version: source.Version}

}

// directoryAuditDetail records only stable source metadata; connection settings stay out of audit and outbox payloads.
func directoryAuditDetail(source *repository.DirectorySource, fields map[string]any) map[string]any {
	detail := make(map[string]any, len(fields)+3)
	for key, value := range fields {
		detail[key] = value
	}
	if source == nil {
		return detail
	}
	detail["source_id"] = source.ID
	detail["config_version"] = source.Version
	return detail
}

type saveDirectoryDraftRequest struct {
	Kind              *repository.DirectoryKind `json:"kind"`
	DisplayName       *string                   `json:"display_name"`
	ConnectionURL     *string                   `json:"connection_url"`
	BindDN            *string                   `json:"bind_dn"`
	BindPassword      *string                   `json:"bind_password"`
	CACertPEM         *string                   `json:"ca_cert_pem"`
	BaseDN            *string                   `json:"base_dn"`
	UsersDN           *string                   `json:"users_dn"`
	UserFilter        *string                   `json:"user_filter"`
	StableIDAttribute *string                   `json:"stable_id_attribute"`
	UsernameAttribute *string                   `json:"username_attribute"`
	EmailAttribute    *string                   `json:"email_attribute"`
	NameAttribute     *string                   `json:"name_attribute"`
	Version           *int                      `json:"version"`
}

func applyDirectoryDraftString(target *string, value *string) {
	if value != nil {
		*target = strings.TrimSpace(*value)
	}
}

// merge applies only explicitly supplied fields. Existing raw directory settings are
// read server-side under the authenticated tenant, never accepted from a client identifier.
func (input saveDirectoryDraftRequest) merge(existing *repository.DirectorySource, tenantID string) *repository.DirectorySource {
	source := &repository.DirectorySource{TenantID: tenantID}
	if existing != nil {
		copy := *existing
		source = &copy
	}
	source.TenantID = tenantID
	if input.Kind != nil {
		source.Kind = *input.Kind
	}
	applyDirectoryDraftString(&source.DisplayName, input.DisplayName)
	applyDirectoryDraftString(&source.ConnectionURL, input.ConnectionURL)
	applyDirectoryDraftString(&source.BindDN, input.BindDN)
	if input.CACertPEM != nil && strings.TrimSpace(*input.CACertPEM) != "" {
		source.CACertPEM = strings.TrimSpace(*input.CACertPEM)
	}
	applyDirectoryDraftString(&source.BaseDN, input.BaseDN)
	applyDirectoryDraftString(&source.UsersDN, input.UsersDN)
	applyDirectoryDraftString(&source.UserFilter, input.UserFilter)
	applyDirectoryDraftString(&source.StableIDAttribute, input.StableIDAttribute)
	applyDirectoryDraftString(&source.UsernameAttribute, input.UsernameAttribute)
	applyDirectoryDraftString(&source.EmailAttribute, input.EmailAttribute)
	applyDirectoryDraftString(&source.NameAttribute, input.NameAttribute)
	if input.Version != nil {
		source.Version = *input.Version
	}
	return source
}

func (input saveDirectoryDraftRequest) validate(ctx context.Context, policy directoryldap.TargetPolicy, source *repository.DirectorySource) error {
	if source.Kind != repository.DirectoryKindActiveDirectory && source.Kind != repository.DirectoryKindLDAP {
		return errors.New("目录类型必须为 AD 或 LDAP")
	}
	if strings.TrimSpace(source.DisplayName) == "" || strings.TrimSpace(source.BindDN) == "" || strings.TrimSpace(source.BaseDN) == "" || strings.TrimSpace(source.UsersDN) == "" {
		return errors.New("目录名称、绑定 DN、Base DN 和用户范围不能为空")
	}
	if _, err := directoryldap.ValidateConfigWithPolicy(ctx, directoryldap.Config{ConnectionURL: source.ConnectionURL}, policy); err != nil {
		switch {
		case errors.Is(err, directoryldap.ErrInsecureTransport):
			return errors.New("目录连接地址必须是 ldaps:// 或 ldap://（StartTLS）地址")
		case errors.Is(err, directoryldap.ErrTargetNotAllowed):
			return errors.New("目录连接地址未被当前部署批准")
		case errors.Is(err, directoryldap.ErrInvalidTarget):
			return errors.New("目录连接地址无效或无法通过安全校验")
		default:
			return errors.New("目录连接地址无法通过安全校验")
		}
	}
	if err := directoryldap.ValidateUserFilter(source.UserFilter); err != nil {
		return errors.New("directory user filter is invalid")
	}
	return nil
}
func validateDirectoryDraftTarget(ctx context.Context, policy directoryldap.TargetPolicy, draft *repository.DirectorySource) error {
	if draft == nil {
		return directoryldap.ErrTargetNotAllowed
	}
	_, err := directoryldap.ValidateConfigWithPolicy(ctx, directoryldap.Config{ConnectionURL: draft.ConnectionURL}, policy)
	return err
}

func validateDirectoryDraftSyncPreflight(ctx context.Context, policy directoryldap.TargetPolicy, draft *repository.DirectorySource) error {
	if err := validateDirectoryDraftTarget(ctx, policy, draft); err != nil {
		return err
	}
	return directoryldap.ValidateUserFilter(draft.UserFilter)
}

func GetDirectoryDraft(deps *Dependencies) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		user := auth.GetUser(request.Context())
		if user == nil {
			writeUnauthorized(writer, "no user")
			return
		}
		if deps.DirectorySourceRepo == nil {
			writeError(writer, "service_unavailable", "目录同步服务未配置")
			return
		}
		source, err := deps.DirectorySourceRepo.GetDraft(request.Context(), user.TenantID)
		if err != nil {
			writeError(writer, "internal_error", "获取目录草稿失败")
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if source == nil {
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": nil})
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": toDirectorySourceDTO(source)})
	}
}

func SaveDirectoryDraft(deps *Dependencies) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		user := auth.GetUser(request.Context())
		if user == nil {
			writeUnauthorized(writer, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(writer, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		if deps.DirectorySourceRepo == nil {
			writeError(writer, "service_unavailable", "目录同步服务未配置")
			return
		}
		var input saveDirectoryDraftRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			writeError(writer, "invalid_request", "请求格式错误")
			return
		}
		existing, err := deps.DirectorySourceRepo.GetDraft(request.Context(), user.TenantID)
		if err != nil {
			writeError(writer, "internal_error", "获取已有目录草稿失败")
			return
		}
		source := input.merge(existing, user.TenantID)
		if err := input.validate(request.Context(), DirectoryTargetPolicyFor(request.Context(), deps), source); err != nil {
			writeError(writer, "invalid_request", err.Error())
			return
		}
		if input.BindPassword != nil && *input.BindPassword != "" {
			source.BindPasswordEnc, _, err = secrets.EncryptProviderSecret(*input.BindPassword)
			if err != nil {
				writeError(writer, "internal_error", "绑定密码加密失败")
				return
			}
		} else if existing == nil {
			writeError(writer, "invalid_request", "首次保存必须提供绑定密码")
			return
		}
		if err := deps.DirectorySourceRepo.UpsertDraft(request.Context(), source); err != nil {
			if errors.Is(err, repository.ErrDirectorySourceChanged) {
				writeErrorWithStatus(writer, http.StatusConflict, "version_conflict", "目录草稿已发生变化，请刷新后重试")
				return
			}
			if errors.Is(err, repository.ErrDirectorySourceActivating) {
				writeErrorWithStatus(writer, http.StatusConflict, "directory_activation_in_progress", "目录源正在激活")
				return
			}
			writeError(writer, "internal_error", "保存目录草稿失败")
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": toDirectorySourceDTO(source)})
	}
}
func TestDirectoryConnection(deps *Dependencies) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		user := auth.GetUser(request.Context())
		if user == nil {
			writeUnauthorized(writer, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(writer, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		if deps.DirectorySourceRepo == nil || deps.DirectoryTester == nil {
			writeError(writer, "service_unavailable", "目录同步服务未配置")
			return
		}
		draft, err := deps.DirectorySourceRepo.GetDraft(request.Context(), user.TenantID)
		if err != nil {
			writeError(writer, "internal_error", "获取目录草稿失败")
			return
		}
		if draft == nil {
			writeErrorWithStatus(writer, http.StatusNotFound, "not_found", "请先保存配置草稿")
			return
		}
		if err := validateDirectoryDraftTarget(request.Context(), DirectoryTargetPolicyFor(request.Context(), deps), draft); err != nil {
			writeError(writer, "invalid_request", "目录连接地址不符合当前安全策略")
			return
		}

		password, err := secrets.DecryptProviderSecret(draft.BindPasswordEnc)
		if err != nil {
			writeError(writer, "internal_error", "解密绑定密码失败")
			return
		}
		result, testErr := deps.DirectoryTester.TestConnection(request.Context(), directoryldap.TestRequest{
			ConnectionURL: draft.ConnectionURL, BindDN: draft.BindDN, BindPassword: password, CACertPEM: draft.CACertPEM,
		})
		testResult := &repository.TestResult{Success: testErr == nil, TestedAt: time.Now().Format(time.RFC3339)}
		if result.Connected {
			testResult.Stages = append(testResult.Stages, repository.TestStage{Name: "ldaps", Status: "passed", Message: "已建立加密连接"})
		}
		if result.Bound {
			testResult.Stages = append(testResult.Stages, repository.TestStage{Name: "bind", Status: "passed", Message: "绑定账号验证通过"})
		}
		if result.RootDSE {
			testResult.Stages = append(testResult.Stages, repository.TestStage{Name: "root_dse", Status: "passed", Message: "目录能力读取通过"})
		}
		if testErr != nil {
			testResult.Error = "目录连接、凭据或证书校验未通过"
		}
		if err := deps.DirectorySourceRepo.UpdateTestResult(request.Context(), user.TenantID, draft.ID, draft.Version, testResult); err != nil {
			if errors.Is(err, repository.ErrDirectorySourceChanged) {
				writeErrorWithStatus(writer, http.StatusConflict, "version_conflict", "配置已修改，请重新测试")
				return
			}
			writeError(writer, "internal_error", "保存测试结果失败")
			return
		}
		logAudit(request, deps, "directory.source.tested", directoryAuditDetail(draft, map[string]any{"success": testResult.Success}), "directory_source", draft.ID)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": testResult.Success, "stages": testResult.Stages, "error": testResult.Error})
	}
}

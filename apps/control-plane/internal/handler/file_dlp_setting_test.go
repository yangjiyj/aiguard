package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 文件 DLP 全局开关：非布尔值必须被系统设置校验拒绝。
func TestFileContentDLPSettingRejectsNonBoolean(t *testing.T) {
	err := validateSemanticSettingValues(context.Background(), map[string]string{
		"file_content_dlp_enabled": "yes",
	})
	if err == nil {
		t.Fatal("file_content_dlp_enabled 非布尔值必须被拒绝")
	}
}

// 配置缺失且环境变量未设置时，文件 DLP 必须默认关闭。
func TestFileContentDLPSettingDefaultsOff(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "")
	if got := fileContentDLPEnabled(context.Background(), &Dependencies{
		SystemRepo: &capturingSystemRepo{settings: map[string]string{}},
	}); got {
		t.Fatal("配置缺失时文件 DLP 必须默认关闭")
	}
}

// 数据库存 true 时动态值必须为开。
func TestFileContentDLPSettingOnFromDatabase(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "")
	if got := fileContentDLPEnabled(context.Background(), &Dependencies{
		SystemRepo: &capturingSystemRepo{settings: map[string]string{"file_content_dlp_enabled": "true"}},
	}); !got {
		t.Fatal("数据库 file_content_dlp_enabled=true 时应开启")
	}
}

// 仓储不可用或查询失败时，回落到环境变量后备，后备默认关闭；后备 true 时开启。
func TestFileContentDLPSettingFallsBackToEnvWhenRepoFails(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "")
	if got := fileContentDLPEnabled(context.Background(), &Dependencies{
		SystemRepo: &failingFileDLPSystemRepo{},
	}); got {
		t.Fatal("仓储失败且环境变量未设置时必须默认关闭")
	}

	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	if got := fileContentDLPEnabled(context.Background(), &Dependencies{
		SystemRepo: &failingFileDLPSystemRepo{},
	}); !got {
		t.Fatal("仓储失败但环境变量=true 时应通过后备开启")
	}
}

// 仓储本身为 nil（控制平面未装配）时也必须安全回落，默认关闭。
func TestFileContentDLPSettingNilRepoDefaultsOff(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "")
	if got := fileContentDLPEnabled(context.Background(), &Dependencies{}); got {
		t.Fatal("SystemRepo 缺失时必须默认关闭")
	}
}

func TestSecurityAuditOnlyEnvironmentCannotBeDisabledBySystemSetting(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	deps := &Dependencies{
		SystemRepo: &capturingSystemRepo{settings: map[string]string{
			securityAuditOnlySettingKey: "false",
		}},
	}

	if !securityAuditOnlyEnabled(context.Background(), deps) {
		t.Fatal("SECURITY_AUDIT_ONLY=true 必须优先于数据库 false，避免审计模式中断业务")
	}
}

// failingFileDLPSystemRepo 让 GetBool 报错，模拟控制平面仓储不可用。
type failingFileDLPSystemRepo struct{}

func (r *failingFileDLPSystemRepo) Get(context.Context, string) (*repository.SystemSetting, error) {
	return nil, errFileDLPRepoUnavailable
}
func (r *failingFileDLPSystemRepo) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	return nil, errFileDLPRepoUnavailable
}
func (r *failingFileDLPSystemRepo) Set(context.Context, string, string) error {
	return errFileDLPRepoUnavailable
}
func (r *failingFileDLPSystemRepo) SetMultiple(context.Context, map[string]string) error {
	return errFileDLPRepoUnavailable
}
func (r *failingFileDLPSystemRepo) CreateAuditOperation(context.Context, *repository.AuditOperation) error {
	return errFileDLPRepoUnavailable
}
func (r *failingFileDLPSystemRepo) ListAuditOperations(context.Context, int, int, string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, errFileDLPRepoUnavailable
}
func (r *failingFileDLPSystemRepo) GetBool(context.Context, string) (bool, error) {
	return false, errFileDLPRepoUnavailable
}

// engine 投影缺省时必须下发 JSON boolean false（loader 侧 _BOOL_KEYS 已认该键）。
func TestSemanticEngineProjectionEmitsFileDLPDefaultOff(t *testing.T) {
	deps := semanticTestDeps(map[string]string{})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config", nil)
	w := httptest.NewRecorder()
	GetInternalSemanticConfig(deps).ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := decodeSemanticPayload(t, w)
	if got["file_content_dlp_enabled"] != false {
		t.Fatalf("engine file_content_dlp_enabled=%#v, want false", got["file_content_dlp_enabled"])
	}
}

func TestSemanticEngineProjectionUsesEnvFallbackWhenSettingMissing(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	deps := semanticTestDeps(map[string]string{})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config", nil)
	w := httptest.NewRecorder()
	GetInternalSemanticConfig(deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := decodeSemanticPayload(t, w)
	if got["file_content_dlp_enabled"] != true {
		t.Fatalf("engine missing DB setting must use env fallback, got %#v", got["file_content_dlp_enabled"])
	}
}

// 数据库开则 engine 投影回显 true。
func TestSemanticEngineProjectionEmitsFileDLPOnFromDB(t *testing.T) {
	deps := semanticTestDeps(map[string]string{"file_content_dlp_enabled": "true"})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config", nil)
	w := httptest.NewRecorder()
	GetInternalSemanticConfig(deps).ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := decodeSemanticPayload(t, w)
	if got["file_content_dlp_enabled"] != true {
		t.Fatalf("engine file_content_dlp_enabled=%#v, want true", got["file_content_dlp_enabled"])
	}
}

// gateway 投影也必须包含该全局开关。
func TestSemanticGatewayProjectionEmitsFileDLP(t *testing.T) {
	deps := semanticTestDeps(map[string]string{"file_content_dlp_enabled": "true"})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config/gateway", nil)
	w := httptest.NewRecorder()
	GetInternalSemanticGatewayConfig(deps).ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := decodeSemanticPayload(t, w)
	if got["file_content_dlp_enabled"] != true {
		t.Fatalf("gateway file_content_dlp_enabled=%#v, want true", got["file_content_dlp_enabled"])
	}
}

func (r *failingFileDLPSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}

package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 执行模式判定只有一处：显式模式 > 部署变量初值 > 旧键 > 安全默认（记录）。
// 控制面每个读者（上传拦截、MCP 契约、集成接口、控制台视图、下发投影）都必须与它一致。
func TestResolveSecurityExecutionModePrecedence(t *testing.T) {
	cases := []struct {
		name         string
		env          string
		settings     map[string]string
		wantAudit    bool
		wantSource   string
		viewSource   string
		integrateSrc string
	}{
		{"显式防护压过部署变量", "true", map[string]string{"security_execution_mode": "protect", "security_audit_only": "true"}, false, executionmode.SourceAdminSettings, "admin_settings", "system_settings"},
		{"显式记录压过旧键", "false", map[string]string{"security_execution_mode": "record", "security_audit_only": "false"}, true, executionmode.SourceAdminSettings, "admin_settings", "system_settings"},
		{"部署变量是没有显式模式时的初值", "true", map[string]string{"security_audit_only": "false"}, true, executionmode.SourceDeployment, "deployment", "deployment"},
		{"非法显式值不算显式", "false", map[string]string{"security_execution_mode": "block", "security_audit_only": "false"}, false, executionmode.SourceLegacy, "system_setting", "system_settings"},
		{"旧键记录", "", map[string]string{"security_audit_only": "true"}, true, executionmode.SourceLegacy, "system_setting", "system_settings"},
		{"旧键防护", "false", map[string]string{"security_audit_only": " FALSE "}, false, executionmode.SourceLegacy, "system_setting", "system_settings"},
		{"旧键非法值按安全默认", "", map[string]string{"security_audit_only": "0"}, true, executionmode.SourceSafeDefault, "safe_default", "safe_default"},
		{"旧键空值按安全默认", "", map[string]string{"security_audit_only": " "}, true, executionmode.SourceSafeDefault, "safe_default", "safe_default"},
		{"什么都没有", "", map[string]string{}, true, executionmode.SourceSafeDefault, "safe_default", "safe_default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", tc.env)
			ctx := context.Background()
			deps := semanticTestDeps(tc.settings)
			audit, source := resolveSecurityExecutionMode(ctx, deps)
			if audit != tc.wantAudit || source != tc.wantSource {
				t.Fatalf("resolve=(%v,%q) want (%v,%q)", audit, source, tc.wantAudit, tc.wantSource)
			}
			if got := securityAuditOnlyEnabled(ctx, deps); got != tc.wantAudit {
				t.Fatalf("securityAuditOnlyEnabled=%v", got)
			}
			if got := mcpAuditOnlyCeiling(ctx, deps); got != tc.wantAudit {
				t.Fatalf("mcpAuditOnlyCeiling=%v", got)
			}
			if got := integrationAuditOnlySourceLabel(source); got != tc.integrateSrc {
				t.Fatalf("integration source=%q want %q", got, tc.integrateSrc)
			}
			configs, err := buildSemanticComponentConfigs(ctx, deps)
			if err != nil {
				t.Fatal(err)
			}
			if configs.Engine["security_audit_only"] != tc.wantAudit || configs.Gateway["security_audit_only"] != tc.wantAudit {
				t.Fatalf("projection engine=%v gateway=%v", configs.Engine["security_audit_only"], configs.Gateway["security_audit_only"])
			}
			settings, _ := deps.SystemRepo.GetAll(ctx)
			view := securityExecutionModeForSettings(ctx, deps, settings)
			wantMode := securityExecutionModeProtect
			if tc.wantAudit {
				wantMode = securityExecutionModeRecord
			}
			if view.EffectiveMode != wantMode || view.ConfiguredMode != wantMode || view.Source != tc.viewSource {
				t.Fatalf("view=%+v want mode %q source %q", view, wantMode, tc.viewSource)
			}
		})
	}
}

type failingModeSystemRepo struct{ capturingSystemRepo }

func (r *failingModeSystemRepo) Get(context.Context, string) (*repository.SystemSetting, error) {
	return nil, errors.New("db down")
}

func (r *failingModeSystemRepo) GetByKeys(context.Context, []string) ([]*repository.SystemSetting, error) {
	return nil, errors.New("db down")
}

// 读库失败不能当成“没有显式模式”再去看旧键：那样旧键 false 会让控制面单独判成防护。
func TestResolveSecurityExecutionModeReadFailureIsRecord(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	deps := &Dependencies{SystemRepo: &failingModeSystemRepo{capturingSystemRepo{settings: map[string]string{"security_audit_only": "false"}}}}
	audit, source := resolveSecurityExecutionMode(context.Background(), deps)
	if !audit || source != executionmode.SourceSafeDefault {
		t.Fatalf("read failure must resolve to record/safe_default, got (%v,%q)", audit, source)
	}
}

// 复审第四轮：resolveSecurityExecutionMode 只是 executionmode 的薄包装，两个键一次查询读出。
type byKeysModeSystemRepo struct {
	capturingSystemRepo
	calls int
	keys  []string
	err   error
}

func (r *byKeysModeSystemRepo) GetByKeys(_ context.Context, keys []string) ([]*repository.SystemSetting, error) {
	r.calls++
	r.keys = append([]string(nil), keys...)
	if r.err != nil {
		return nil, r.err
	}
	var out []*repository.SystemSetting
	for _, key := range keys {
		if value, ok := r.settings[key]; ok {
			out = append(out, &repository.SystemSetting{Key: key, Value: value})
		}
	}
	return out, nil
}

func (r *byKeysModeSystemRepo) Get(context.Context, string) (*repository.SystemSetting, error) {
	return nil, errors.New("must read both keys in one query")
}

func TestResolveSecurityExecutionModeReadsBothKeysInOneQuery(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	repo := &byKeysModeSystemRepo{capturingSystemRepo: capturingSystemRepo{settings: map[string]string{"security_execution_mode": "protect", "security_audit_only": "true"}}}
	audit, source := resolveSecurityExecutionMode(context.Background(), &Dependencies{SystemRepo: repo})
	if audit || source != executionmode.SourceAdminSettings || repo.calls != 1 || len(repo.keys) != 2 {
		t.Fatalf("got (%v,%q) calls=%d keys=%v", audit, source, repo.calls, repo.keys)
	}
	repo.err = errors.New("db down")
	if audit, source := resolveSecurityExecutionMode(context.Background(), &Dependencies{SystemRepo: repo}); !audit || source != executionmode.SourceSafeDefault {
		t.Fatalf("查询失败按安全默认：(%v,%q)", audit, source)
	}
}

// 合流前次要项：SystemRepo 接口直接声明 GetByKeys，执行模式判定不再做类型断言兜底。
func TestSystemRepoDeclaresGetByKeys(t *testing.T) {
	var repo SystemRepo = &capturingSystemRepo{settings: map[string]string{"security_execution_mode": "protect", "other": "x"}}
	settings, err := repo.GetByKeys(context.Background(), executionmode.Keys())
	if err != nil || len(settings) != 1 || settings[0].Key != "security_execution_mode" {
		t.Fatalf("settings=%v err=%v", settings, err)
	}
}

package handler

import (
	"context"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
)

// resolveSecurityExecutionMode 读库判定当前执行模式，判定规则见 executionmode.FromValues。
//
// 两个键一次查询读出；查询失败返回 (true, SourceSafeDefault)：控制面绝不在读不到配置时单独判成
// 防护而拦截。deps 或仓储为空时按没有配置处理（部署初值或安全默认）。
func resolveSecurityExecutionMode(ctx context.Context, deps *Dependencies) (auditOnly bool, source string) {
	values, ok := readExecutionModeSettings(ctx, deps)
	if !ok {
		return true, executionmode.SourceSafeDefault
	}
	return executionmode.FromValues(values, executionmode.DeploymentRecordInitialValue())
}

func readExecutionModeSettings(ctx context.Context, deps *Dependencies) (map[string]string, bool) {
	values := map[string]string{}
	if deps == nil || deps.SystemRepo == nil {
		return values, true
	}
	settings, err := deps.SystemRepo.GetByKeys(ctx, executionmode.Keys())
	if err != nil {
		return nil, false
	}
	for _, setting := range settings {
		if setting != nil {
			values[setting.Key] = setting.Value
		}
	}
	return values, true
}

// executionModeViewSource 是控制台 /system/settings 视图里的来源标签；旧键沿用 system_setting。
func executionModeViewSource(source string) string {
	if source == executionmode.SourceLegacy {
		return "system_setting"
	}
	return source
}

// integrationAuditOnlySourceLabel 是集成接口 audit_only_source 的对外标签（契约不变）：
// 库里的显式模式和旧键都报 system_settings。
func integrationAuditOnlySourceLabel(source string) string {
	switch source {
	case executionmode.SourceAdminSettings, executionmode.SourceLegacy:
		return "system_settings"
	default:
		return source
	}
}

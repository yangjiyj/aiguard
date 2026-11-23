package handler

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
)

// fileContentDLPSettingKey 是文件内容 DLP 全局开关在 system_settings 中的唯一动态真源键。
const fileContentDLPSettingKey = "file_content_dlp_enabled"

const securityAuditOnlySettingKey = executionmode.LegacySettingKey

// errFileDLPRepoUnavailable 表示控制平面仓储不可用，读取回落到环境变量后备。
var errFileDLPRepoUnavailable = errors.New("file dlp system repo unavailable")

// fileContentDLPEnabled 解析文件内容 DLP 全局开关的当前动态值。
// 数据库配置优先；缺失或仓储不可用时回落到 SECURITY_FILE_CONTENT_DLP_ENABLED 环境变量；
// 环境变量未设置或非法时默认关闭。该函数只供控制平面内部读取，签名投影构建见 semantic_effective_config.go。
func fileContentDLPEnabled(ctx context.Context, deps *Dependencies) bool {
	if deps != nil && deps.SystemRepo != nil {
		if setting, err := deps.SystemRepo.Get(ctx, fileContentDLPSettingKey); err == nil && setting != nil {
			value := strings.TrimSpace(setting.Value)
			return strings.EqualFold(value, "true") || value == "1"
		}
	}
	return fileContentDLPEnvFallback()
}

// securityAuditOnlyEnabled 报告控制面判定的执行模式是否为记录模式，规则见 resolveSecurityExecutionMode。
func securityAuditOnlyEnabled(ctx context.Context, deps *Dependencies) bool {
	auditOnly, _ := resolveSecurityExecutionMode(ctx, deps)
	return auditOnly
}

// fileContentDLPEnvFallback 解析环境变量后备值，默认关闭。
func fileContentDLPEnvFallback() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SECURITY_FILE_CONTENT_DLP_ENABLED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

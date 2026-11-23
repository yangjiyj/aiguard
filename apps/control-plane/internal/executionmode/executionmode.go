// Package executionmode 判定安全执行模式：记录（record，检测只留痕不拦截）或防护（protect）。
//
// 这是叶子包（只依赖标准库），控制面各处——设置接口、签名投影、上传拦截、MCP 契约、集成接口、
// 模式巡检、端侧与仿真的只审计判定——都用 FromValues 得出同一个结论，不要各自解析两个键或读部署变量。
//
// 优先级：显式模式（security_execution_mode=record/protect）> 部署变量 SECURITY_AUDIT_ONLY=true 作初值
// > 旧键 security_audit_only=true/false > 安全默认记录模式。
package executionmode

import (
	"os"
	"strings"
)

// 两个设置键。
const (
	// SettingKey 是控制台写入的显式执行模式，取值 Record / Protect。
	SettingKey = "security_execution_mode"
	// LegacySettingKey 是旧键，取值 "true"（记录）/ "false"（防护）。
	LegacySettingKey = "security_audit_only"
)

// 显式模式的取值。
const (
	Record  = "record"
	Protect = "protect"
)

// 判定来源。
const (
	// SourceAdminSettings：库里有显式执行模式。
	SourceAdminSettings = "admin_settings"
	// SourceDeployment：库里没有显式模式，部署变量 SECURITY_AUDIT_ONLY=true 作初值（设计 D7）。
	SourceDeployment = "deployment"
	// SourceLegacy：只有旧键 security_audit_only=true/false。
	SourceLegacy = "legacy"
	// SourceSafeDefault：以上都没有、取值非法或读不到配置，按记录模式（不拦截）。
	SourceSafeDefault = "safe_default"
)

// deploymentEnv 是部署变量名；只由 DeploymentRecordInitialValue 读取。
const deploymentEnv = "SECURITY_AUDIT_ONLY"

// Keys 返回判定要读的两个设置键（副本），供调用方一次查询读出。
func Keys() []string {
	return []string{SettingKey, LegacySettingKey}
}

// FromValues 是判定的纯函数：values 是 system_settings 的键值（只看 Keys() 两个键，可为 nil），
// deploymentRecord 一般传 DeploymentRecordInitialValue()，只想看库里配置时传 false。
// auditOnly 为 true 表示记录模式。旧键只认 true/false（不分大小写、可带空白），其他取值按安全默认。
// 读不到配置（查库失败）时调用方不要调它，直接按 (true, SourceSafeDefault) 处理。
func FromValues(values map[string]string, deploymentRecord bool) (auditOnly bool, source string) {
	switch values[SettingKey] {
	case Record:
		return true, SourceAdminSettings
	case Protect:
		return false, SourceAdminSettings
	}
	if deploymentRecord {
		return true, SourceDeployment
	}
	if legacy, ok := values[LegacySettingKey]; ok {
		switch strings.ToLower(strings.TrimSpace(legacy)) {
		case "true":
			return true, SourceLegacy
		case "false":
			return false, SourceLegacy
		}
	}
	return true, SourceSafeDefault
}

// DeploymentRecordInitialValue 报告部署变量 SECURITY_AUDIT_ONLY 是否要求记录模式（1/true/yes/on）。
// 设计 D7：它只在库里没有显式执行模式时作初值，不锁定控制台。
func DeploymentRecordInitialValue() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(deploymentEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ModeName 把判定结果换成模式名 Record / Protect。
func ModeName(auditOnly bool) string {
	if auditOnly {
		return Record
	}
	return Protect
}

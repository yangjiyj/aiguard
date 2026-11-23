package handler

import (
	"context"
	"strconv"
	"strings"
)

// ConsoleLoginPolicy 控制台登录安全参数（等保三级）。全部来自 system_settings，
// 缺失或非法值回退到默认值（迁移 880 写入同样的默认值）。
type ConsoleLoginPolicy struct {
	LockoutThreshold     int
	LockoutMinutes       int
	PasswordMinLength    int
	PasswordMinClasses   int
	PasswordHistoryCount int
	PasswordMaxAgeDays   int
	SessionIdleMinutes   int
	SessionAbsoluteHours int
	SessionMaxConcurrent int
	AdminTOTPRequired    bool
	AdminIPAllowlist     []string
}

const (
	settingLockoutThreshold     = "console_login_lockout_threshold"
	settingLockoutMinutes       = "console_login_lockout_minutes"
	settingPasswordMinLength    = "console_password_min_length"
	settingPasswordMinClasses   = "console_password_min_classes"
	settingPasswordHistoryCount = "console_password_history_count"
	settingPasswordMaxAgeDays   = "console_password_max_age_days"
	settingSessionIdleMinutes   = "console_session_idle_minutes"
	settingSessionAbsoluteHours = "console_session_absolute_hours"
	settingSessionMaxConcurrent = "console_session_max_concurrent"
	settingAdminTOTPRequired    = "console_admin_totp_required"
	settingAdminIPAllowlist     = "console_admin_ip_allowlist"
)

func DefaultConsoleLoginPolicy() ConsoleLoginPolicy {
	return ConsoleLoginPolicy{
		LockoutThreshold: 5, LockoutMinutes: 30,
		PasswordMinLength: 12, PasswordMinClasses: 3, PasswordHistoryCount: 5, PasswordMaxAgeDays: 90,
		SessionIdleMinutes: 30, SessionAbsoluteHours: 12, SessionMaxConcurrent: 3,
	}
}

// consoleIntSettingBounds 同时用于读取回退与写入校验。0 表示“关闭”仅对允许关闭的项开放。
var consoleIntSettingBounds = map[string][2]int{
	settingLockoutThreshold:     {1, 100},
	settingLockoutMinutes:       {1, 1440},
	settingPasswordMinLength:    {8, 128},
	settingPasswordMinClasses:   {1, 4},
	settingPasswordHistoryCount: {0, 24},
	settingPasswordMaxAgeDays:   {0, 3650},
	settingSessionIdleMinutes:   {5, 1440},
	settingSessionAbsoluteHours: {1, 168},
	settingSessionMaxConcurrent: {0, 100},
}

func LoadConsoleLoginPolicy(ctx context.Context, repo SystemRepo) ConsoleLoginPolicy {
	p := DefaultConsoleLoginPolicy()
	if repo == nil {
		return p
	}
	settings, err := repo.GetAll(ctx)
	if err != nil {
		return p
	}
	values := make(map[string]string, len(settings))
	for _, s := range settings {
		values[s.Key] = s.Value
	}
	readInt := func(key string, dst *int) {
		raw, ok := values[key]
		if !ok {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		b := consoleIntSettingBounds[key]
		if err == nil && n >= b[0] && n <= b[1] {
			*dst = n
		}
	}
	readInt(settingLockoutThreshold, &p.LockoutThreshold)
	readInt(settingLockoutMinutes, &p.LockoutMinutes)
	readInt(settingPasswordMinLength, &p.PasswordMinLength)
	readInt(settingPasswordMinClasses, &p.PasswordMinClasses)
	readInt(settingPasswordHistoryCount, &p.PasswordHistoryCount)
	readInt(settingPasswordMaxAgeDays, &p.PasswordMaxAgeDays)
	readInt(settingSessionIdleMinutes, &p.SessionIdleMinutes)
	readInt(settingSessionAbsoluteHours, &p.SessionAbsoluteHours)
	readInt(settingSessionMaxConcurrent, &p.SessionMaxConcurrent)
	if v, ok := values[settingAdminTOTPRequired]; ok {
		p.AdminTOTPRequired = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	if v, ok := values[settingAdminIPAllowlist]; ok {
		p.AdminIPAllowlist = splitCIDRList(v)
	}
	return p
}

func splitCIDRList(raw string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == ';' }) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

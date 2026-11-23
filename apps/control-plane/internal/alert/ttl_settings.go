package alert

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 告警组 TTL 自动关闭的系统设置键。库里有合法值时优先于环境变量
// ALERT_TTL_ENABLED / ALERT_GROUP_TTL_DAYS；都没有时与历史行为一致：不关闭任何组。
const (
	AlertTTLEnabledSettingKey   = "alert_ttl_enabled"
	AlertGroupTTLDaysSettingKey = "alert_group_ttl_days"

	AlertTTLDefaultDays = 14
	AlertTTLMinDays     = 1
	AlertTTLMaxDays     = 365
)

// AlertTTLConfig 是一次 tick 实际采用的 TTL 配置。EnabledSource 取 db / env / default，便于日志排查。
type AlertTTLConfig struct {
	Enabled       bool
	TTLDays       int
	EnabledSource string
}

// ParseAlertTTLDays 校验天数：整数 1~365。系统设置接口与定时任务共用这一份口径。
func ParseAlertTTLDays(raw string) (int, error) {
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || days < AlertTTLMinDays || days > AlertTTLMaxDays {
		return 0, fmt.Errorf("alert_group_ttl_days must be an integer between %d and %d", AlertTTLMinDays, AlertTTLMaxDays)
	}
	return days, nil
}

func parseTTLBool(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// ResolveAlertTTLConfig 合成 TTL 配置：开关与天数各自"库优先、环境变量兜底、最后默认"。
// 库里的空串或非法值视为未设置（回落到下一级），而不是当成关闭——但两级都没有时一定是关闭。
func ResolveAlertTTLConfig(dbEnabled, dbDays *string, envEnabled, envDays string) AlertTTLConfig {
	cfg := AlertTTLConfig{TTLDays: AlertTTLDefaultDays, EnabledSource: "default"}
	if dbEnabled != nil {
		if v, ok := parseTTLBool(*dbEnabled); ok {
			cfg.Enabled, cfg.EnabledSource = v, "db"
		}
	}
	if cfg.EnabledSource == "default" {
		// env 沿用历史口径：只有 "true"（不区分大小写）才开启。
		if strings.TrimSpace(envEnabled) != "" {
			cfg.Enabled, cfg.EnabledSource = strings.EqualFold(strings.TrimSpace(envEnabled), "true"), "env"
		}
	}
	if dbDays != nil {
		if d, err := ParseAlertTTLDays(*dbDays); err == nil {
			cfg.TTLDays = d
			return cfg
		}
	}
	if d, err := ParseAlertTTLDays(envDays); err == nil {
		cfg.TTLDays = d
	}
	return cfg
}

// AlertTTLSettingsReader 是定时任务读取系统设置的最小接口（*repository.SystemRepository 满足）。
type AlertTTLSettingsReader interface {
	Get(ctx context.Context, key string) (*repository.SystemSetting, error)
}

// AlertTTLCloser 是 AutoCloseStale 的最小接口（*repository.AlertGroupRepository 满足）。
// 关闭条件（stage='input'、非 canary、无高价值 finding，及 runtime_fault 静默分支）全部在仓储层，这里不改。
type AlertTTLCloser interface {
	AutoCloseStale(ctx context.Context, now time.Time, ttl, faultTTL time.Duration, batchLimit int) (int64, error)
}

// LoadAlertTTLConfig 每次 tick 读库；库读失败返回错误，调用方据此跳过（fail-closed），
// 不回落到环境变量——否则库抖动期间一个旧的 env=true 会绕过管理员在界面上关掉的开关。
func LoadAlertTTLConfig(ctx context.Context, settings AlertTTLSettingsReader, getenv func(string) string) (AlertTTLConfig, error) {
	var dbEnabled, dbDays *string
	if settings != nil {
		for key, dst := range map[string]**string{AlertTTLEnabledSettingKey: &dbEnabled, AlertGroupTTLDaysSettingKey: &dbDays} {
			s, err := settings.Get(ctx, key)
			if err != nil {
				return AlertTTLConfig{EnabledSource: "db_error"}, err
			}
			if s != nil {
				v := s.Value
				*dst = &v
			}
		}
	}
	return ResolveAlertTTLConfig(dbEnabled, dbDays, getenv("ALERT_TTL_ENABLED"), getenv("ALERT_GROUP_TTL_DAYS")), nil
}

// RunAlertTTLTick 执行一次 TTL 扫描：配置为关闭时什么都不做。
func RunAlertTTLTick(ctx context.Context, settings AlertTTLSettingsReader, closer AlertTTLCloser, getenv func(string) string, now time.Time) (int64, AlertTTLConfig, error) {
	cfg, err := LoadAlertTTLConfig(ctx, settings, getenv)
	if err != nil {
		return 0, cfg, err
	}
	if !cfg.Enabled || closer == nil {
		return 0, cfg, nil
	}
	n, err := closer.AutoCloseStale(ctx, now.UTC(), time.Duration(cfg.TTLDays)*24*time.Hour, repository.FaultQuietTTL, 1000)
	return n, cfg, err
}

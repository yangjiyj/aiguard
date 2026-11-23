// Package logretention 是 log_retention_days（日志与内容留存天数）的唯一解析口径。
//
// control-plane 的清理任务、设置接口，proxy-server 与 gateway-core 写 access_content_logs.retention_until
// 时都用这里的函数，保证“界面能填的值”“写入的保留截止时间”“实际清理的时间点”三者一致。
package logretention

import (
	"errors"
	"strconv"
	"strings"
)

const (
	// SettingKey 是 system_settings 里的键。
	SettingKey = "log_retention_days"
	// MinDays 是删除保护下限：无论怎么配置，日志与内容至少保留这么多天。
	MinDays = 30
	// DefaultDays 是未配置或配置无法解析时的默认值。
	DefaultDays = 90
	// MaxDays 是允许配置的上限。
	MaxDays = 3650
)

// ErrOutOfRange 的文案直接返回给控制台。
var ErrOutOfRange = errors.New("日志与内容留存天数必须是 30 到 3650 的整数（为防误删，最少保留 30 天）")

// Validate 校验管理员提交的值；小于 MinDays、大于 MaxDays 或不是整数时返回中文错误。
func Validate(raw string) (int, error) {
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || days < MinDays || days > MaxDays {
		return 0, ErrOutOfRange
	}
	return days, nil
}

// Resolve 把库里已存的值解析为实际生效天数：无法解析用默认值，低于下限抬到下限，超出上限按上限。
// 历史上界面允许填 1 天，这类旧值在这里统一按 30 天生效。
func Resolve(raw string) int {
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || days <= 0 {
		return DefaultDays
	}
	if days > MaxDays {
		// 宁可多留：超出上限按上限生效，不回落到默认值而提前删除。
		return MaxDays
	}
	if days < MinDays {
		return MinDays
	}
	return days
}

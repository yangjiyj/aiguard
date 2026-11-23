package handler

import (
	"context"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// systemSettingsByKeysVia 给测试桩实现 SystemRepo.GetByKeys：逐键调用桩自己的 Get，
// 不存在的键不在结果里，任一键读取失败整次失败（与一次查询的语义一致）。
func systemSettingsByKeysVia(ctx context.Context, get func(context.Context, string) (*repository.SystemSetting, error), keys []string) ([]*repository.SystemSetting, error) {
	var out []*repository.SystemSetting
	for _, key := range keys {
		setting, err := get(ctx, key)
		if err != nil {
			return nil, err
		}
		if setting != nil {
			out = append(out, setting)
		}
	}
	return out, nil
}

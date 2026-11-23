package handler

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// 响应缓存的系统设置键（与网关 internal/handler/response_cache.go 保持一致）。
const (
	responseCacheEnabledSettingKey        = "response_cache_enabled"
	responseCacheTTLSettingKey            = "response_cache_ttl_seconds"
	responseCacheMaxEntryBytesSettingKey  = "response_cache_max_entry_bytes"
	responseCacheMaxTemperatureSettingKey = "response_cache_max_temperature"
	responseCacheSharedProjectsSettingKey = "response_cache_shared_project_ids"
	responseCacheGenerationSettingKey     = "response_cache_generation"
)

// normalizeResponseCacheSettings 校验并规范化本次提交里的响应缓存设置。
func normalizeResponseCacheSettings(settings map[string]string) error {
	if raw, ok := settings[responseCacheEnabledSettingKey]; ok {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v != "true" && v != "false" {
			return fmt.Errorf("响应缓存开关只能是 true 或 false")
		}
		settings[responseCacheEnabledSettingKey] = v
	}
	intRange := func(key, label string, min, max int) error {
		raw, ok := settings[key]
		if !ok {
			return nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || n < min || n > max {
			return fmt.Errorf("%s需在 %d 到 %d 之间", label, min, max)
		}
		settings[key] = strconv.Itoa(n)
		return nil
	}
	if err := intRange(responseCacheTTLSettingKey, "缓存有效期（秒）", 60, 86400); err != nil {
		return err
	}
	if err := intRange(responseCacheMaxEntryBytesSettingKey, "单条缓存上限（字节）", 1<<10, 1<<20); err != nil {
		return err
	}
	if raw, ok := settings[responseCacheMaxTemperatureSettingKey]; ok {
		f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || f < 0 || f > 2 {
			return fmt.Errorf("可缓存的最高 temperature 需在 0 到 2 之间")
		}
		settings[responseCacheMaxTemperatureSettingKey] = strconv.FormatFloat(f, 'f', -1, 64)
	}
	if raw, ok := settings[responseCacheSharedProjectsSettingKey]; ok {
		var ids []string
		if strings.TrimSpace(raw) == "" {
			ids = []string{}
		} else if err := json.Unmarshal([]byte(raw), &ids); err != nil {
			return fmt.Errorf("共享缓存的应用必须是应用 ID 数组")
		}
		seen := map[string]bool{}
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			id = strings.TrimSpace(id)
			if id == "" || seen[id] {
				continue
			}
			if len(id) > 128 {
				return fmt.Errorf("应用 ID 过长")
			}
			seen[id] = true
			out = append(out, id)
		}
		if len(out) > 200 {
			return fmt.Errorf("共享缓存的应用最多 200 个")
		}
		encoded, _ := json.Marshal(out)
		settings[responseCacheSharedProjectsSettingKey] = string(encoded)
	}
	if raw, ok := settings[responseCacheGenerationSettingKey]; ok {
		n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("缓存代号必须是非负整数")
		}
		settings[responseCacheGenerationSettingKey] = strconv.FormatInt(n, 10)
	}
	return nil
}

// fillResponseCacheDefaults 给控制台展示补上未配置键的出厂值。
func fillResponseCacheDefaults(data map[string]any) {
	defaults := map[string]string{
		responseCacheEnabledSettingKey:        "false",
		responseCacheTTLSettingKey:            "3600",
		responseCacheMaxEntryBytesSettingKey:  "65536",
		responseCacheMaxTemperatureSettingKey: "1",
		responseCacheSharedProjectsSettingKey: "[]",
		responseCacheGenerationSettingKey:     "0",
	}
	for key, value := range defaults {
		if _, ok := data[key]; !ok {
			data[key] = value
		}
	}
}

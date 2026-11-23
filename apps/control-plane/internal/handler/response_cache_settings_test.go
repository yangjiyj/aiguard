package handler

import "testing"

func TestNormalizeResponseCacheSettings(t *testing.T) {
	settings := map[string]string{
		responseCacheEnabledSettingKey:        " TRUE ",
		responseCacheTTLSettingKey:            "600",
		responseCacheMaxTemperatureSettingKey: "0.70",
		responseCacheSharedProjectsSettingKey: `[" p_1 ","p_1","","p_2"]`,
		responseCacheGenerationSettingKey:     "3",
		"block_response_mode":                 "message",
	}
	if err := normalizeResponseCacheSettings(settings); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		responseCacheEnabledSettingKey:        "true",
		responseCacheTTLSettingKey:            "600",
		responseCacheMaxTemperatureSettingKey: "0.7",
		responseCacheSharedProjectsSettingKey: `["p_1","p_2"]`,
		responseCacheGenerationSettingKey:     "3",
		"block_response_mode":                 "message",
	}
	for k, v := range want {
		if settings[k] != v {
			t.Fatalf("%s = %q, want %q", k, settings[k], v)
		}
	}
	for name, bad := range map[string]map[string]string{
		"enabled":     {responseCacheEnabledSettingKey: "yes"},
		"ttl low":     {responseCacheTTLSettingKey: "10"},
		"ttl high":    {responseCacheTTLSettingKey: "999999"},
		"entry bytes": {responseCacheMaxEntryBytesSettingKey: "10"},
		"temperature": {responseCacheMaxTemperatureSettingKey: "3"},
		"projects":    {responseCacheSharedProjectsSettingKey: `{"a":1}`},
		"generation":  {responseCacheGenerationSettingKey: "-1"},
	} {
		if err := normalizeResponseCacheSettings(bad); err == nil {
			t.Fatalf("%s should be rejected", name)
		}
	}
	empty := map[string]string{responseCacheSharedProjectsSettingKey: ""}
	if err := normalizeResponseCacheSettings(empty); err != nil || empty[responseCacheSharedProjectsSettingKey] != "[]" {
		t.Fatalf("empty shared list = %q, %v", empty[responseCacheSharedProjectsSettingKey], err)
	}

	data := map[string]any{responseCacheEnabledSettingKey: "true"}
	fillResponseCacheDefaults(data)
	if data[responseCacheEnabledSettingKey] != "true" || data[responseCacheTTLSettingKey] != "3600" || data[responseCacheSharedProjectsSettingKey] != "[]" {
		t.Fatalf("defaults = %v", data)
	}
}

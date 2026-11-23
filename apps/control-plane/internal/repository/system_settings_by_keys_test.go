package repository

import "testing"

// 复审第四轮：执行模式的两个键一次 WHERE key IN (...) 查询读出。
func TestSystemSettingsByKeysQuery(t *testing.T) {
	got := systemSettingsByKeysQuery(2)
	want := "SELECT key, value, updated_at FROM system_settings WHERE key IN ($1, $2)"
	if got != want {
		t.Fatalf("query=%q want %q", got, want)
	}
}

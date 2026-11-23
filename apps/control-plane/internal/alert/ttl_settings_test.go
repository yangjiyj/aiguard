package alert

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func strp(s string) *string { return &s }

func TestResolveAlertTTLConfig(t *testing.T) {
	cases := []struct {
		name        string
		dbEnabled   *string
		dbDays      *string
		envEnabled  string
		envDays     string
		wantEnabled bool
		wantDays    int
		wantSource  string
	}{
		{"都没有则关闭", nil, nil, "", "", false, 14, "default"},
		{"env 兜底开启", nil, nil, "true", "21", true, 21, "env"},
		{"env 大小写不敏感", nil, nil, "TRUE", "", true, 14, "env"},
		{"DB 优先关闭压过 env 开启", strp("false"), nil, "true", "21", false, 21, "db"},
		{"DB 优先开启压过 env 关闭", strp("true"), strp("30"), "false", "7", true, 30, "db"},
		{"DB 天数优先 env 天数", nil, strp("45"), "true", "7", true, 45, "env"},
		{"DB 空串视为无值回落 env", strp(""), strp(""), "true", "10", true, 10, "env"},
		{"DB 非法开关值视为无值回落 env", strp("maybe"), nil, "true", "", true, 14, "env"},
		{"DB 天数越界回落 env", strp("true"), strp("0"), "", "20", true, 20, "db"},
		{"DB 天数超过 365 回落 env", strp("true"), strp("400"), "", "", true, 14, "db"},
		{"env 天数非法回落默认 14", nil, nil, "true", "abc", true, 14, "env"},
		{"env 天数超过 365 回落默认", nil, nil, "true", "999", true, 14, "env"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveAlertTTLConfig(tc.dbEnabled, tc.dbDays, tc.envEnabled, tc.envDays)
			if got.Enabled != tc.wantEnabled || got.TTLDays != tc.wantDays || got.EnabledSource != tc.wantSource {
				t.Fatalf("got %+v, want enabled=%v days=%d source=%s", got, tc.wantEnabled, tc.wantDays, tc.wantSource)
			}
		})
	}
}

type ttlSettingsStub struct {
	values map[string]string
	err    error
}

func (s *ttlSettingsStub) Get(_ context.Context, key string) (*repository.SystemSetting, error) {
	if s.err != nil {
		return nil, s.err
	}
	if v, ok := s.values[key]; ok {
		return &repository.SystemSetting{Key: key, Value: v}, nil
	}
	return nil, nil
}

type ttlCloserStub struct {
	calls int
	ttl   time.Duration
}

func (c *ttlCloserStub) AutoCloseStale(_ context.Context, _ time.Time, ttl, _ time.Duration, _ int) (int64, error) {
	c.calls++
	c.ttl = ttl
	return 3, nil
}

func TestAlertTTLTickReadsDBEachTick(t *testing.T) {
	settings := &ttlSettingsStub{values: map[string]string{}}
	closer := &ttlCloserStub{}
	getenv := func(string) string { return "" }

	// 默认：DB 无值、env 未设 → 不关闭任何组。
	if n, cfg, err := RunAlertTTLTick(context.Background(), settings, closer, getenv, time.Now()); err != nil || n != 0 || cfg.Enabled || closer.calls != 0 {
		t.Fatalf("default tick must be a no-op: n=%d cfg=%+v err=%v calls=%d", n, cfg, err, closer.calls)
	}
	// 管理员在系统设置里打开，下一次 tick 立即生效，无需重启。
	settings.values[AlertTTLEnabledSettingKey] = "true"
	settings.values[AlertGroupTTLDaysSettingKey] = "30"
	n, cfg, err := RunAlertTTLTick(context.Background(), settings, closer, getenv, time.Now())
	if err != nil || n != 3 || !cfg.Enabled || closer.calls != 1 || closer.ttl != 30*24*time.Hour {
		t.Fatalf("enabled tick: n=%d cfg=%+v err=%v calls=%d ttl=%v", n, cfg, err, closer.calls, closer.ttl)
	}
	// 再关掉，下一次 tick 跳过。
	settings.values[AlertTTLEnabledSettingKey] = "false"
	if _, cfg, _ := RunAlertTTLTick(context.Background(), settings, closer, func(string) string { return "true" }, time.Now()); cfg.Enabled || closer.calls != 1 {
		t.Fatalf("DB false must override env true: cfg=%+v calls=%d", cfg, closer.calls)
	}
}

// DB 读失败时 fail-closed：不关闭，也不回落到 env 的开启值（避免库抖动时按旧 env 误关）。
func TestAlertTTLTickFailsClosedWhenSettingsUnreadable(t *testing.T) {
	settings := &ttlSettingsStub{err: errors.New("db down")}
	closer := &ttlCloserStub{}
	_, cfg, err := RunAlertTTLTick(context.Background(), settings, closer, func(string) string { return "true" }, time.Now())
	if err == nil || cfg.Enabled || closer.calls != 0 {
		t.Fatalf("unreadable settings must skip: cfg=%+v err=%v calls=%d", cfg, err, closer.calls)
	}
}

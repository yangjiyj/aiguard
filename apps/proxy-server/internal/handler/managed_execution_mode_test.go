package handler

import (
	"context"
	"strings"
	"testing"
	"time"
)

type executionModeScanner struct {
	legacy, mode string
	missing      bool
	err          error
}

func (s executionModeScanner) Scan(dest ...any) error {
	if s.err != nil {
		return s.err
	}
	*(dest[0].(*string)) = s.legacy
	*(dest[1].(*string)) = s.mode
	*(dest[2].(*bool)) = !s.missing
	return nil
}

func TestProxyManagedExecutionModeSwitchesAndCachesSnapshot(t *testing.T) {
	// 客户部署不设部署锁：控制台模式双向生效。部署锁（env=true）见
	// TestDeploymentAuditOnlyIsHardCeilingOverManagedProtect。
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	calls := 0
	row := executionModeScanner{legacy: "true", mode: "protect"}
	reader := NewDBSecurityAuditOnlySettingReader(func(_ context.Context, sql string, args ...any) rowScanner {
		calls++
		if len(args) != 2 || args[0] != securityAuditOnlySettingKey || args[1] != securityExecutionModeSettingKey ||
			!strings.Contains(sql, "WHERE key IN ($1, $2)") || !strings.Contains(sql, "FILTER (WHERE key = $2)") {
			t.Fatalf("mode and legacy must use one SQL snapshot: sql=%s args=%v", sql, args)
		}
		return row
	}).(*DBFileDLPSettingReader)
	client := NewSecurityClient("http://127.0.0.1:1").WithSecurityAuditOnlySettingReader(reader)
	ctx := context.Background()
	if client.securityAuditOnly(ctx) {
		t.Fatal("explicit protect did not override legacy=true")
	}
	row = executionModeScanner{legacy: "false", mode: "record"}
	if client.securityAuditOnly(ctx) || calls != 1 {
		t.Fatal("cached snapshot changed before expiry")
	}
	reader.expireAt = time.Time{}
	if !client.securityAuditOnly(ctx) || calls != 2 {
		t.Fatal("record did not apply after expiry")
	}
	row = executionModeScanner{legacy: "true", mode: "protect"}
	reader.expireAt = time.Time{}
	if client.securityAuditOnly(ctx) || calls != 3 {
		t.Fatal("protect did not apply after reverse transition")
	}
	row = executionModeScanner{err: errDBUnavailable}
	reader.expireAt = time.Time{}
	if client.securityAuditOnly(ctx) {
		t.Fatal("refresh failure lost last-good managed protect")
	}
}

func TestProxyUnmanagedExecutionModeKeepsLegacySemantics(t *testing.T) {
	for _, tc := range []struct {
		env, mode, legacy string
		want              bool
	}{
		{"true", "", "false", true}, {"true", "PROTECT", "false", true},
		{"true", " protect ", "false", true}, {"false", "", "false", false},
		{"false", "invalid", "true", true}, {"false", "", "", true},
		{"false", "protect", "true", false}, {"false", "record", "false", true},
	} {
		t.Run(tc.env+"/"+tc.mode+"/"+tc.legacy, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", tc.env)
			reader := NewDBSecurityAuditOnlySettingReader(func(context.Context, string, ...any) rowScanner {
				return executionModeScanner{legacy: tc.legacy, mode: tc.mode}
			})
			client := NewSecurityClient("http://127.0.0.1:1").WithSecurityAuditOnlySettingReader(reader)
			if got := client.securityAuditOnly(context.Background()); got != tc.want {
				t.Fatalf("got audit=%v want %v", got, tc.want)
			}
		})
	}
}

func TestProxyRemovingExplicitModeRestoresLegacyValue(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	mode := "protect"
	legacy := "false"
	reader := NewDBSecurityAuditOnlySettingReader(func(context.Context, string, ...any) rowScanner {
		return executionModeScanner{legacy: legacy, mode: mode}
	}).(*DBFileDLPSettingReader)
	if reader.Enabled(context.Background()) {
		t.Fatal("managed protect was not applied")
	}
	mode, legacy = "", "true"
	reader.expireAt = time.Time{}
	if !reader.Enabled(context.Background()) {
		t.Fatal("removing explicit mode failed to restore the legacy record value")
	}
}

// 2.9.22（设计 D7）：部署变量只在没有显式执行模式时作初值，控制台的 protect 与 record
// 切换都按控制台生效；去掉显式模式后回到部署变量初值（record）。原用例断言“部署锁下切换
// 都不会解除只审计”，随用户 11-17 决定改写。
func TestProxyDeploymentVariableIsInitialValueAcrossManagedTransitions(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	mode := "protect"
	reader := NewDBSecurityAuditOnlySettingReader(func(context.Context, string, ...any) rowScanner {
		return executionModeScanner{legacy: "false", mode: mode}
	}).(*DBFileDLPSettingReader)
	for _, step := range []struct {
		mode string
		want bool
	}{{"protect", false}, {"record", true}, {"protect", false}, {"", true}} {
		mode = step.mode
		reader.expireAt = time.Time{}
		if reader.Enabled(context.Background()) != step.want {
			t.Fatalf("mode %q: record=%v want %v", step.mode, !step.want, step.want)
		}
	}
}

// 代码质量审查第三轮改动：原断言“旧键存了空值时保留上次的防护”。控制面
// resolveSecurityExecutionMode 把空值旧键按安全默认记录处理，下发给引擎、网关的投影也是记录；
// 代理保留防护会对同一请求作出相反的中断决定，所以空值一步改为断言记录。缺行一步断言不变。
func TestProxyMissingAndInvalidLegacyValuesKeepDistinctFallbacks(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	row := executionModeScanner{legacy: "false"}
	reader := NewDBSecurityAuditOnlySettingReader(func(context.Context, string, ...any) rowScanner { return row }).(*DBFileDLPSettingReader)
	if reader.Enabled(context.Background()) {
		t.Fatal("legacy protect was not applied")
	}
	row = executionModeScanner{legacy: ""}
	reader.expireAt = time.Time{}
	if !reader.Enabled(context.Background()) {
		t.Fatal("empty legacy value must resolve to record like the control plane")
	}
	row.missing = true
	reader.expireAt = time.Time{}
	if !reader.Enabled(context.Background()) {
		t.Fatal("missing legacy row must use safe default")
	}
}

func TestProxyNilLegacyQueryKeepsEnvironmentCeiling(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	if !NewDBSecurityAuditOnlySettingReader(nil).Enabled(context.Background()) {
		t.Fatal("nil legacy reader lost deployment ceiling")
	}
}

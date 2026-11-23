package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

type postureSettingRow struct {
	raw, mode string
	err       error
}

func (r postureSettingRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.raw
	*(dest[1].(*string)) = r.mode
	*(dest[2].(*bool)) = true
	return nil
}

func TestSecurityPostureProxyReadsRequestModeAndFailureGetters(t *testing.T) {
	for _, tc := range []struct {
		mode, lock, detection, whitelist string
		record                           bool
	}{
		// 2.9.22（D7）：部署变量为 true 但控制台显式 protect 时按防护（原期望 record=true 随之改写）。
		{"protect", "false", "open", "closed", false}, {"record", "false", "closed", "open", true}, {"protect", "true", "unexpected", "closed", false},
		{"", "true", "open", "closed", true},
	} {
		t.Run(tc.mode+tc.lock+tc.detection, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", tc.lock)
			t.Setenv("PROXY_DETECTION_FAIL_MODE", tc.detection)
			t.Setenv("PROXY_WHITELIST_FAIL_MODE", tc.whitelist)
			t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "true")
			reader := NewDBSecurityAuditOnlySettingReader(func(context.Context, string, ...any) rowScanner {
				return postureSettingRow{raw: "false", mode: tc.mode}
			})
			client := NewSecurityClient("http://unused.invalid")
			client.auditOnlySettings = reader
			proxy := &ProxyHandler{securityClient: client, whitelistChecker: &WhitelistChecker{}}
			status := WithProxySecurityPosture(fakeRuntimeStatus{inspectionscope.RuntimeStatus{Component: "proxy-server"}}, proxy).RuntimeStatus()
			if status.Posture.Validate() != nil {
				t.Fatalf("invalid actual consumer posture: %+v", status.Posture)
			}
			p := status.Posture
			if *p.SecurityAuditOnly != tc.record || *p.SecurityAuditOnly != client.securityAuditOnly(context.Background()) || !*p.ModeSourceVerified {
				t.Fatalf("receipt disagrees with DB request reader: %+v", p)
			}
			wantDetection := "closed"
			if tc.detection == "open" {
				wantDetection = "open"
			}
			if p.DetectionFailMode != wantDetection || p.WhitelistFailMode != tc.whitelist || !*p.CapacityFailClosed {
				t.Fatalf("actual failure getters not consumed: %+v", p)
			}
			if *p.TLSInspectionCapable || *p.InspectionQueueWired {
				t.Fatalf("absent inspection components reported wired: %+v", p)
			}
		})
	}
}

// 代码质量审查第三轮改动：非法旧键原先保留上次的防护，现在与控制面一致按安全默认记录模式
// （见 TestDBSecurityAuditOnlySettingReaderInvalidValueFollowsControlPlaneSafeDefault）。
// invalid-value 子用例的“模式”断言随之改为记录；“不能报已核实”的断言两个子用例都不变。
func TestSecurityPostureProxyDoesNotVerifyHeldModeAfterDatabaseFailureOrInvalidValue(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed-query", true: "invalid-value"}[invalid], func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			fail := false
			reader := NewDBSecurityAuditOnlySettingReader(func(context.Context, string, ...any) rowScanner {
				if !fail {
					return postureSettingRow{raw: "false", mode: "protect"}
				}
				if invalid {
					return postureSettingRow{raw: "invalid"}
				}
				return postureSettingRow{err: errors.New("DB unavailable")}
			}).(*DBFileDLPSettingReader)
			reader.ttl = time.Hour
			if reader.Enabled(context.Background()) {
				t.Fatal("protect fixture resolved record")
			}
			fail = true
			reader.expireAt = time.Time{}
			client := NewSecurityClient("http://unused.invalid")
			client.auditOnlySettings = reader
			p := WithProxySecurityPosture(fakeRuntimeStatus{inspectionscope.RuntimeStatus{}}, &ProxyHandler{securityClient: client}).RuntimeStatus().Posture
			if p == nil || *p.SecurityAuditOnly != invalid || *p.ModeSourceVerified {
				t.Fatalf("held mode falsely verified after failed/invalid refresh: %+v", p)
			}
		})
	}
}

func TestSecurityPostureProxyVerifiesDeploymentRecordLockWhenDatabaseIsUnavailable(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	reader := NewDBSecurityAuditOnlySettingReader(func(context.Context, string, ...any) rowScanner {
		return postureSettingRow{err: errors.New("DB unavailable")}
	})
	client := NewSecurityClient("http://unused.invalid")
	client.auditOnlySettings = reader
	p := WithProxySecurityPosture(fakeRuntimeStatus{inspectionscope.RuntimeStatus{}}, &ProxyHandler{securityClient: client}).RuntimeStatus().Posture
	if p == nil || !*p.SecurityAuditOnly || !*p.DeploymentAuditOnly || !*p.ModeSourceVerified {
		t.Fatalf("certain deployment recording lock reported unknown: %+v", p)
	}
}

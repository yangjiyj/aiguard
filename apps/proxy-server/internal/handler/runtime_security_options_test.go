package handler

// 2.9.22 任务 4.5：独立代理读控制台“故障处理”设置（随网关签名投影下发），没存时才用环境变量。

import (
	"context"
	"errors"
	"testing"
)

type runtimeOptionScope struct {
	fixedInspectionPolicy
	options map[string]string
}

func (s runtimeOptionScope) RuntimeOption(key string) (string, bool) {
	value, ok := s.options[key]
	return value, ok
}

func TestProxyCapacityPolicyReadsConsoleSetting(t *testing.T) {
	for _, tc := range []struct {
		env     string
		options map[string]string
		want    bool
	}{
		{"false", map[string]string{"security_capacity_fail_mode": "closed"}, true},
		{"true", map[string]string{"security_capacity_fail_mode": "open"}, false},
		{"true", nil, true},
		{"false", nil, false},
	} {
		t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", tc.env)
		client := NewSecurityClient("http://unused.invalid").WithInspectionScope(runtimeOptionScope{options: tc.options})
		if got := client.detectionPolicy().FailClosedOnCapacity; got != tc.want {
			t.Fatalf("env=%s options=%v: capacity fail-closed=%v want %v", tc.env, tc.options, got, tc.want)
		}
		action, _, meta := client.inspectionFailure(context.Background(), errors.New("x"), "input_capacity_overflow")
		_ = action
		_ = meta
	}
	var nilClient *SecurityClient
	if nilClient.detectionPolicy().FailClosedOnCapacity != inspectionscopeEnvCapacity() {
		t.Fatal("nil client falls back to environment")
	}
}

func inspectionscopeEnvCapacity() bool {
	return NewSecurityClient("").WithInspectionScope(nil).detectionPolicy().FailClosedOnCapacity
}

// 附件字节送检失败（大文件对象化上传失败）按 upload_inspection_failure_action 处置：
// 缺省照现在转发并记一条告警；选“禁止”时在防护模式下拦，观察留痕下仍只记录。
func TestProxyUploadInspectionFailureFollowsConsoleAction(t *testing.T) {
	t.Setenv("PROXY_DETECTION_FAIL_MODE", "open")
	for _, tc := range []struct {
		auditOnly string
		options   map[string]string
		want      string
	}{
		{"false", nil, "audit"},
		{"false", map[string]string{"upload_inspection_failure_action": "forward_alert"}, "audit"},
		{"false", map[string]string{"upload_inspection_failure_action": "block"}, "block"},
		{"true", map[string]string{"upload_inspection_failure_action": "block"}, "audit"},
	} {
		t.Setenv("SECURITY_AUDIT_ONLY", tc.auditOnly)
		client := NewSecurityClient("http://unused.invalid").WithInspectionScope(runtimeOptionScope{options: tc.options})
		action, findings, meta := client.attachmentUploadFailure(context.Background())
		if action != tc.want || len(findings) != 1 || findings[0]["category"] != "file_content_object_unavailable" || meta == nil {
			t.Fatalf("audit=%s options=%v: action=%s findings=%v", tc.auditOnly, tc.options, action, findings)
		}
	}
}

// 审查第 7 项：独立代理“检测服务不可用”读 guardrail_fail_closed_enabled；库里有该键时以它为准，
// PROXY_DETECTION_FAIL_MODE 只在库里没有时作初值。
func TestProxyDetectionFailureReadsConsoleSetting(t *testing.T) {
	for _, tc := range []struct {
		envMode string
		row     stubScanner
		want    bool
	}{
		{"open", stubScanner{value: "true"}, true},
		{"closed", stubScanner{value: "false"}, false},
		{"closed", stubScanner{err: errNoRows}, true},
		{"open", stubScanner{err: errNoRows}, false},
	} {
		t.Setenv("PROXY_DETECTION_FAIL_MODE", tc.envMode)
		row := tc.row
		reader := NewDBDetectionFailClosedSettingReader(func(context.Context, string, ...any) rowScanner { return row })
		client := NewSecurityClient("http://unused.invalid").WithDetectionFailClosedSettingReader(reader)
		if got := client.detectionPolicy().FailClosedOnDetectionFailure; got != tc.want {
			t.Fatalf("env=%s row=%+v: fail-closed=%v want %v", tc.envMode, tc.row, got, tc.want)
		}
	}
	t.Setenv("PROXY_DETECTION_FAIL_MODE", "closed")
	if !NewSecurityClient("http://unused.invalid").detectionPolicy().FailClosedOnDetectionFailure {
		t.Fatal("没有注入读取器时沿用环境变量")
	}
}

// 上传检测失败只看 upload_inspection_failure_action：选“转发并告警”（含缺省）时，即使打开了
// “检测服务不可用即拦”，附件送检失败也放行并留一条告警，与网关 /v1/files、门户上传一致。
func TestProxyUploadInspectionFailureForwardAlertIgnoresDetectionFailClosed(t *testing.T) {
	t.Setenv("PROXY_DETECTION_FAIL_MODE", "closed")
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	for _, options := range []map[string]string{nil, {"upload_inspection_failure_action": "forward_alert"}} {
		client := NewSecurityClient("http://unused.invalid").WithInspectionScope(runtimeOptionScope{options: options})
		if !client.detectionPolicy().FailClosedOnDetectionFailure {
			t.Fatal("前提：检测失败即拦已打开")
		}
		action, findings, meta := client.attachmentUploadFailure(context.Background())
		if action != "audit" || len(findings) != 1 || meta == nil || meta.DetectionRejected {
			t.Fatalf("options=%v: 应放行并告警，实际 action=%s meta=%+v", options, action, meta)
		}
	}
}

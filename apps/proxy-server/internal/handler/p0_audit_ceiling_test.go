package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 2.9.22（设计 D7）：部署变量 SECURITY_AUDIT_ONLY=true 只在库里没有显式执行模式时作初值；
// 控制台显式选了 protect（managed）就按防护执行。原 P0 硬上限（2026-09-27）断言随用户 11-17 决定改写。
func TestDeploymentAuditOnlyIsOnlyInitialValue(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	r := NewDBSecurityAuditOnlySettingReader(func(_ context.Context, _ string, _ ...any) rowScanner {
		return modeScanner{legacy: "false", mode: "protect", legacyExists: true}
	})
	if r.Enabled(context.Background()) {
		t.Fatal("managed protect must apply even with the deployment variable set")
	}
	client := NewSecurityClient("http://127.0.0.1:0").WithSecurityAuditOnlySettingReader(r)
	if client.SecurityAuditOnly(context.Background()) {
		t.Fatal("security client must follow the console mode")
	}
	initial := NewDBSecurityAuditOnlySettingReader(func(_ context.Context, _ string, _ ...any) rowScanner {
		return modeScanner{legacy: "false", legacyExists: true}
	})
	if !initial.Enabled(context.Background()) {
		t.Fatal("without an explicit mode the deployment variable is the initial value (record)")
	}
}

// 硬锁不影响客户部署：env 未设/为 false 时，控制台 protect 仍然生效。
func TestManagedProtectStillAppliesWithoutDeploymentLock(t *testing.T) {
	for _, env := range []string{"", "false"} {
		t.Setenv("SECURITY_AUDIT_ONLY", env)
		r := NewDBSecurityAuditOnlySettingReader(func(_ context.Context, _ string, _ ...any) rowScanner {
			return modeScanner{legacy: "false", mode: "protect", legacyExists: true}
		})
		if r.Enabled(context.Background()) {
			t.Fatalf("env=%q: managed protect must apply when deployment is not locked", env)
		}
	}
}

// The default ordinary detection policy preserves fail-open in Protect mode.
func TestDurableInspectionFailureDefaultFailOpenInProtect(t *testing.T) {
	t.Setenv("PROXY_DETECTION_FAIL_MODE", "open")
	db := inspectionDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { completedInspection(w, "hello") }))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	action, findings, meta := q.client.checkInputDurable(context.Background(), "tenant", "invalid-protect", req)
	if action == "block" || len(findings) != 0 || meta == nil || meta.SemanticStatus != "incomplete" || meta.SemanticReason != "inspection_invalid_json" {
		t.Fatalf("inspection failure must be recorded and forwarded, got action=%s meta=%+v", action, meta)
	}
}

// The independent capacity option defaults to fail-open in Protect mode.
func TestInspectionQueueDefaultFailOpenInProtect(t *testing.T) {
	t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "false")
	db := inspectionDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { completedInspection(w, "hello") }))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	if err := q.enqueue(context.Background(), "tenant", "full", "host", "audit", simplePlan("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(context.Background(), `UPDATE proxy_inspection_jobs SET payload_bytes=512*1024*1024`); err != nil {
		t.Fatal(err)
	}
	action, _, meta := q.inspect(context.Background(), "tenant", "next", "host", simplePlan("hello"), false)
	if action == "block" || meta == nil || meta.SemanticReason != "inspection_queue_capacity" || meta.SemanticStatus != "incomplete" {
		t.Fatalf("queue unavailable must be a recorded coverage gap, got %s %+v", action, meta)
	}
}

// 用户口径（2026-09-27）：执行模式以控制台为准。审计（record）模式是最高优先级，
// 连管理员配置为"阻断"的受限文件规则也只记录不拦截；只有防护（protect）模式才按策略阻断。
func TestAuditModeSuppressesRestrictedFileBlock(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	h := newRFInputProxyHandler(true, RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "block"})
	action, findings, blocked := callInput(h, codexResponsesRequest("/home/u/合同.pdf"))
	if blocked || action != "audit" {
		t.Fatalf("record mode must not block restricted files, action=%q blocked=%v", action, blocked)
	}
	if len(findings) != 1 || findings[0]["action"] != "audit" {
		t.Fatalf("finding must be kept as audit evidence: %+v", findings)
	}
}

type modeScanner struct {
	legacy       string
	mode         string
	legacyExists bool
}

func (s modeScanner) Scan(dest ...any) error {
	if len(dest) == 3 {
		*(dest[0].(*string)) = s.legacy
		*(dest[1].(*string)) = s.mode
		*(dest[2].(*bool)) = s.legacyExists
		return nil
	}
	*(dest[0].(*string)) = s.legacy
	return nil
}

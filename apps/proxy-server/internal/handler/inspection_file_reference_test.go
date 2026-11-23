package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
)

// r2922 对抗复核：独立代理生产路径（持久化检测队列）只带文件 id 的附件也按控制台“文件引用”两项设置
// 和内容例外处置，与网关同口径；按处置立即决定，不当成“检测未完成”反复重试。
func referencePart(tenant, fileID string) map[string]interface{} {
	return map[string]interface{}{
		"request_id": "synthetic-ref", "content": "", "content_source": "user",
		"context":               map[string]interface{}{"tenant_id": tenant, "host": "api.example.test", "provider": "openai"},
		"inspection_attachment": ExtractedAttachment{ReferenceID: fileID},
	}
}

func referenceFindings(t *testing.T, result map[string]interface{}) []map[string]interface{} {
	t.Helper()
	items, ok := result["findings"].([]interface{})
	if !ok {
		t.Fatalf("findings missing: %+v", result)
	}
	var findings []map[string]interface{}
	for _, item := range items {
		b, _ := json.Marshal(item)
		var finding map[string]interface{}
		_ = json.Unmarshal(b, &finding)
		findings = append(findings, finding)
	}
	return findings
}

func TestDurableFileReferenceFollowsConsoleSettings(t *testing.T) {
	for _, tc := range []struct {
		name          string
		verdictStatus int
		policy        filereference.Policy
		exceptionRule string
		wantAction    string
		wantRule      string
		wantFinding   string
		wantException bool
		wantCalls     int
	}{
		{name: "unverified allow", verdictStatus: http.StatusOK, policy: filereference.Policy{Unverified: filereference.Allow, LookupFailure: filereference.Allow}, wantAction: "allow"},
		{name: "lookup failure allow", verdictStatus: http.StatusInternalServerError, policy: filereference.Policy{Unverified: filereference.Allow, LookupFailure: filereference.Allow}, wantAction: "allow"},
		{name: "unverified alert", verdictStatus: http.StatusOK, policy: filereference.DefaultPolicy(), wantAction: "audit", wantRule: "file-id-unverified", wantFinding: "alert", wantCalls: 1},
		{name: "unverified block", verdictStatus: http.StatusOK, policy: filereference.Policy{Unverified: filereference.Block, LookupFailure: filereference.AlertAllow}, wantAction: "block", wantRule: "file-id-unverified", wantFinding: "block", wantCalls: 1},
		{name: "unverified block exception", verdictStatus: http.StatusOK, policy: filereference.Policy{Unverified: filereference.Block, LookupFailure: filereference.AlertAllow}, exceptionRule: "file-id-unverified", wantAction: "audit", wantRule: "file-id-unverified", wantFinding: "audit", wantException: true, wantCalls: 1},
		{name: "lookup failure block", verdictStatus: http.StatusInternalServerError, policy: filereference.Policy{Unverified: filereference.AlertAllow, LookupFailure: filereference.Block}, exceptionRule: "file-id-lookup-failed", wantAction: "block", wantRule: "file-id-lookup-failed", wantFinding: "block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			cli, _ := newTestSecurityClient(t, fileReferenceExceptionServer(t, tc.verdictStatus, tc.exceptionRule, &calls))
			cli.WithFileReferencePolicyReader(staticProxyFileReferencePolicy(tc.policy))
			result, err := cli.executeInspectionPart(context.Background(), referencePart("t1", "file-synthetic"), true)
			if err != nil || !inspectionComplete(result) {
				t.Fatalf("文件引用按处置立即决定，不是检测未完成：err=%v result=%+v", err, result)
			}
			if result["action"] != tc.wantAction {
				t.Fatalf("action=%v want %s: %+v", result["action"], tc.wantAction, result)
			}
			findings := referenceFindings(t, result)
			if tc.wantRule == "" {
				if len(findings) != 0 {
					t.Fatalf("设为允许不留命中：%+v", findings)
				}
			} else if len(findings) != 1 || findings[0]["rule_id"] != tc.wantRule || findings[0]["action"] != tc.wantFinding ||
				(findings[0]["exception_id"] == "exc-file-ref") != tc.wantException {
				t.Fatalf("命中不符：%+v", findings)
			}
			if calls != tc.wantCalls {
				t.Fatalf("例外核对次数=%d want %d", calls, tc.wantCalls)
			}
		})
	}
}

func TestDurableFileReferenceVerdictBlockStillBlocks(t *testing.T) {
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"block","hit_categories":["phone_cn"]}`))
	})
	cli.WithFileReferencePolicyReader(staticProxyFileReferencePolicy{Unverified: filereference.Allow, LookupFailure: filereference.Allow})
	result, err := cli.executeInspectionPart(context.Background(), referencePart("t1", "file-synthetic"), true)
	if err != nil || !inspectionComplete(result) || result["action"] != "block" {
		t.Fatalf("检测结论为阻断照拦：err=%v result=%+v", err, result)
	}
	findings := referenceFindings(t, result)
	if len(findings) != 1 || findings[0]["rule_id"] != "file-id-verdict-block" || findings[0]["category"] != "file_id_verdict_block" {
		t.Fatalf("命中形态与网关同表：%+v", findings)
	}
}

func TestDurableFileReferenceCanceledLookupIsNotADecision(t *testing.T) {
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"allow"}`))
	})
	cli.WithFileReferencePolicyReader(staticProxyFileReferencePolicy{Unverified: filereference.Block, LookupFailure: filereference.Block})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := cli.executeInspectionPart(ctx, referencePart("t1", "file-synthetic"), true); err == nil {
		t.Fatalf("请求已结束时的查询失败不能写成处置：%+v", result)
	}
}

// 生产路径端到端：持久化队列下两项设为允许不拦、设为阻断照拦、例外放开，都不等满 45 秒。
func TestDurableQueueFileReferenceFollowsConsoleSettings(t *testing.T) {
	if os.Getenv("PROXY_INSPECTION_TEST_DSN") == "" {
		t.Skip("requires isolated PostgreSQL: PROXY_INSPECTION_TEST_DSN")
	}
	for _, tc := range []struct {
		name          string
		policy        filereference.Policy
		exceptionRule string
		want          string
	}{
		{name: "allow", policy: filereference.Policy{Unverified: filereference.Allow, LookupFailure: filereference.Allow}, want: "allow"},
		{name: "block", policy: filereference.Policy{Unverified: filereference.Block, LookupFailure: filereference.Block}, want: "block"},
		{name: "exception", policy: filereference.Policy{Unverified: filereference.Block, LookupFailure: filereference.Block}, exceptionRule: "file-id-unverified", want: "audit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := inspectionDB(t)
			var calls int
			engine := httptest.NewServer(fileReferenceExceptionServer(t, http.StatusOK, tc.exceptionRule, &calls))
			defer engine.Close()
			queue := queueForTest(t, db, engine.URL)
			queue.client.WithFileReferencePolicyReader(staticProxyFileReferencePolicy(tc.policy))
			started := time.Now()
			action, _, meta := queue.inspect(context.Background(), "t1", "durable-ref-"+tc.name, "host", []map[string]interface{}{referencePart("t1", "file-synthetic")}, false)
			if elapsed := time.Since(started); elapsed > 10*time.Second {
				t.Fatalf("按处置立即决定，不反复重试：elapsed=%s", elapsed)
			}
			if action != tc.want || meta == nil || meta.SemanticStatus != "completed" {
				t.Fatalf("action=%s want %s meta=%+v", action, tc.want, meta)
			}
		})
	}
}

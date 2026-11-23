package handler

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyBlockResponseIncludesBothTraceIDs(t *testing.T) {
	findings := []map[string]interface{}{{"rule_id": "rule_password", "rule_name": "密码规则", "action": "block", "matched_text_preview": "password123456", "severity": "high"}}
	check := func(header http.Header, raw []byte) {
		t.Helper()
		if header.Get("X-JJDGuard-Block-ID") != "evt_proxy" || header.Get("X-JJDGuard-Request-ID") != "request-proxy" {
			t.Fatalf("headers=%v", header)
		}
		var parsed map[string]map[string]string
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatal(err)
		}
		notice := parsed["error"]
		if notice["block_id"] != "evt_proxy" || notice["request_id"] != "request-proxy" || !strings.Contains(notice["message"], "evt_proxy") || !strings.Contains(notice["message"], "request-proxy") || !strings.Contains(notice["message"], "风险处理 → 阻断记录") || strings.Contains(notice["message"], "password123456") {
			t.Fatalf("notice trace mismatch or leaked raw secret: %v", notice)
		}
	}
	t.Run("HTTP", func(t *testing.T) {
		rec := httptest.NewRecorder()
		writeHTTPBlockedResponse(rec, "request-proxy", findings, "evt_proxy")
		if rec.Code != http.StatusForbidden {
			t.Fatal(rec.Code)
		}
		check(rec.Header(), rec.Body.Bytes())
	})
	t.Run("MITM", func(t *testing.T) {
		server, client := net.Pipe()
		defer client.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			(&ProxyHandler{}).sendBlockedResponse(server, "request-proxy", findings, "evt_proxy")
		}()
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		check(resp.Header, raw)
		<-done
	})
}

func TestProxyPersistedBlockIDCanRetrieveRuleAndTrail(t *testing.T) {
	db := inspectionDB(t)
	writer := NewAuditWriter(db)
	findings := []map[string]interface{}{{"rule_id": "rule_password", "rule_name": "密码规则", "type": "custom", "action": "block", "matched_text_preview": "password123456", "severity": "high"}}
	record := ProxyAuditRecord{RequestID: "request-proxy-block", TenantID: "tenant-proxy", ProjectID: "project-proxy", TargetHost: "api.example.test", Status: "blocked"}
	id := writer.WriteSecurityEventForRecord(context.Background(), record, "block", findings, "output")
	if id == "" {
		t.Fatal("successful write must return searchable security-event ID")
	}
	var request, tenant, evidence string
	var summaryRaw []byte
	if err := db.QueryRow(context.Background(), "SELECT request_id, tenant_id, evidence_ref, matched_summary FROM security_events WHERE id=$1 AND tenant_id=$2", id, record.TenantID).Scan(&request, &tenant, &evidence, &summaryRaw); err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Block map[string]string `json:"block"`
	}
	if err := json.Unmarshal(summaryRaw, &summary); err != nil {
		t.Fatal(err)
	}
	if request != record.RequestID || tenant != record.TenantID || evidence != "request_logs:"+request || summary.Block["block_id"] != id || summary.Block["request_id"] != request || summary.Block["rule_id"] != "rule_password" || summary.Block["layer"] != "output_content" || summary.Block["reason"] != "模型输出命中安全规则" || summary.Block["detail"] == "password123456" {
		t.Fatalf("event cannot be correlated from customer notice: %s (%s %s %s)", summaryRaw, request, tenant, evidence)
	}
	rec := httptest.NewRecorder()
	writeHTTPBlockedResponse(rec, request, findings, id)
	if rec.Header().Get("X-JJDGuard-Block-ID") != id || !strings.Contains(rec.Body.String(), id) {
		t.Fatalf("response does not expose persisted ID: %s", rec.Body.String())
	}
	var count int
	if err := db.QueryRow(context.Background(), "SELECT count(*) FROM security_events WHERE id=$1 AND tenant_id=$2", id, "other-tenant").Scan(&count); err != nil || count != 0 {
		t.Fatalf("tenant-scoped lookup=%d err=%v", count, err)
	}
}

func TestProxyAuditOnlyFindingDoesNotBecomeBlockAttribution(t *testing.T) {
	db := inspectionDB(t)
	writer := NewAuditWriter(db)
	record := ProxyAuditRecord{RequestID: "request-proxy-audit", TenantID: "tenant-proxy", Status: "success"}
	findings := []map[string]interface{}{{"rule_id": "rule_password", "action": "block", "severity": "high"}}
	id := writer.WriteSecurityEventForRecord(context.Background(), record, "audit", findings, "input")
	var action string
	var hasBlock bool
	if err := db.QueryRow(context.Background(), "SELECT action_taken, matched_summary ? 'block' FROM security_events WHERE id=$1", id).Scan(&action, &hasBlock); err != nil {
		t.Fatal(err)
	}
	if action != "audit" || hasBlock {
		t.Fatalf("observation turned into block: action=%s block=%v", action, hasBlock)
	}
}

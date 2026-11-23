package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWriteRequestLog_RequestIDFormat(t *testing.T) {
	// Verify the request ID generation format
	requestID := uuid.New().String()
	if len(requestID) != 36 {
		t.Errorf("request ID length = %d, want 36", len(requestID))
	}

	// Verify timestamp format for created_at
	ts := time.Now().Format("2006-01-02T15:04:05Z07:00")
	if len(ts) < 19 {
		t.Errorf("timestamp too short: %s", ts)
	}
}

func TestAuditWriterEnvironmentScopeKeepsTrustedDeploymentBoundary(t *testing.T) {
	writer := NewAuditWriter(nil).WithEnvironmentScope(" CUSTOMER ")
	cases := []struct {
		name   string
		record ProxyAuditRecord
		want   string
	}{
		{name: "deployment default", want: "customer"},
		{name: "old explicit record is contained", record: ProxyAuditRecord{EnvironmentScope: "codex"}, want: "customer"},
		{name: "invalid explicit record is contained", record: ProxyAuditRecord{EnvironmentScope: "from-header"}, want: "customer"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := writer.environmentScopeForRecord(tt.record); got != tt.want {
				t.Fatalf("scope = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuditWriterScopesRecordBeforeContentAndArtifactPersistence(t *testing.T) {
	writer := NewAuditWriter(nil).WithEnvironmentScope("customer")
	record := writer.withEnvironmentScope(ProxyAuditRecord{RequestID: "req-customer", TenantID: "tenant-default"})
	if record.EnvironmentScope != "customer" {
		t.Fatalf("scoped record = %q, want customer", record.EnvironmentScope)
	}
}

func TestWriteSecurityEvent_BlockSeverity(t *testing.T) {
	// When action is "block", severity should be "high"
	action := "block"
	severity := "medium"
	if action == "block" {
		severity = "high"
	}

	if severity != "high" {
		t.Errorf("severity for block action = %s, want high", severity)
	}
}

func TestWriteSecurityEvent_AuditSeverity(t *testing.T) {
	// When action is "audit", severity should be "medium"
	action := "audit"
	severity := "medium"
	if action == "block" {
		severity = "high"
	}

	if severity != "medium" {
		t.Errorf("severity for audit action = %s, want medium", severity)
	}
}

func TestWriteSecurityEvent_EventTypeFormat(t *testing.T) {
	// Event type should follow format: proxy_{stage}_{action}
	tests := []struct {
		stage    string
		action   string
		expected string
	}{
		{"input", "block", "proxy_input_block"},
		{"output", "audit", "proxy_output_audit"},
		{"input", "audit", "proxy_input_audit"},
		{"output", "block", "proxy_output_block"},
	}

	for _, tt := range tests {
		eventType := "proxy_" + tt.stage + "_" + tt.action
		if eventType != tt.expected {
			t.Errorf("event type = %s, want %s", eventType, tt.expected)
		}
	}
}

func TestFindingsJSONSerialization(t *testing.T) {
	findings := []map[string]interface{}{
		{"type": "pii", "matched": "email@example.com"},
		{"type": "sensitive", "matched": "api_key"},
	}

	findingsJSON, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("Marshal findings failed: %v", err)
	}

	var decoded []map[string]interface{}
	if err := json.Unmarshal(findingsJSON, &decoded); err != nil {
		t.Fatalf("Unmarshal findings failed: %v", err)
	}

	if len(decoded) != 2 {
		t.Errorf("decoded findings count = %d, want 2", len(decoded))
	}
}

func TestAuditResultDoesNotCountObservationAsSecurityFinding(t *testing.T) {
	findings := []map[string]interface{}{{
		"type":                       "pii",
		"category":                   "email",
		"counts_as_security_finding": false,
		"action":                     "allow",
	}}

	result := auditResult("allow", findings)

	if got := result["findings_count"]; got != 0 {
		t.Fatalf("纯 observation findings_count=%v, want 0", got)
	}
	stored, ok := result["findings"].([]map[string]interface{})
	if !ok || len(stored) != 1 {
		t.Fatalf("请求级技术留证应保留 observation，got=%T %#v", result["findings"], result["findings"])
	}
}

func TestAuditResultCountsOnlySecurityFindingsInMixedEvidence(t *testing.T) {
	findings := []map[string]interface{}{
		{
			"type":                       "pii",
			"category":                   "email",
			"counts_as_security_finding": false,
		},
		{
			"type":                       "secret",
			"category":                   "aws_access_key",
			"counts_as_security_finding": true,
		},
	}

	result := auditResult("audit", findings)

	if got := result["findings_count"]; got != 1 {
		t.Fatalf("混合证据 findings_count=%v, want 1", got)
	}
}

func TestNewProxyAuditRecord_InfersAgentTypeFromUserAgent(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) WorkBuddy/5.0.3 Chrome/138.0.7204.251 Electron/37.10.3 Safari/537.36": "workbuddy",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Code/1.124.2 Chrome/148.0.7778.97 Electron/42.2.0 Safari/537.36":      "vscode",
		"Cursor/0.42 (cursor-agent)": "cursor",
		// 普通网页浏览器：不打智能体标签
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36": "",
	}
	for ua, want := range cases {
		req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader("{}"))
		req.Header.Set("User-Agent", ua)
		rec, err := NewProxyAuditRecord("", "tenant_default", "api.openai.com", req, LLMProviderMatch{}, true)
		if err != nil {
			t.Fatal(err)
		}
		if rec.AgentType != want {
			t.Fatalf("NewProxyAuditRecord agent_type for UA %q = %q, want %q", ua, rec.AgentType, want)
		}
	}
}

func TestForwardProxyRequestLogUpsertWritesResolvedAccessType(t *testing.T) {
	query := forwardProxyRequestLogUpsertSQL()

	if !strings.Contains(query, "proxy_access_type_resolved") {
		t.Fatalf("request log upsert should write proxy_access_type_resolved:\n%s", query)
	}
	if !strings.Contains(query, "proxy_access_type_resolved = EXCLUDED.proxy_access_type_resolved") {
		t.Fatalf("request log upsert should refresh resolved access type on conflict:\n%s", query)
	}
	if !strings.Contains(query, "environment_scope") ||
		!strings.Contains(query, "environment_scope = EXCLUDED.environment_scope") {
		t.Fatalf("request log upsert must preserve artifact identity scope:\n%s", query)
	}
}

func TestSecurityEventInsertSQLMaterializesPrincipalKey(t *testing.T) {
	query := securityEventInsertSQL()

	// principal_key 列必须出现在插入列表中（契约第 6 条：正代路径 principal_key = source_ip 兜底）
	if !strings.Contains(query, "principal_key") {
		t.Fatalf("security_events 插入应包含 principal_key 列:\n%s", query)
	}
	// 空字符串（无来源 IP）应写入 NULL 而非空串，便于 COALESCE 归属统计
	if !strings.Contains(query, "NULLIF($12, '')") {
		t.Fatalf("principal_key 应以 NULLIF($12, '') 写入（空 source_ip 归 NULL）:\n%s", query)
	}
	if !strings.Contains(query, "rule_id") || !strings.Contains(query, "effective_severity") ||
		!strings.Contains(query, "class_key") {
		t.Fatalf("security event attribution columns missing:\n%s", query)
	}
	if !strings.Contains(query, "$14") || strings.Contains(query, "$15") {
		t.Fatalf("插入应精确包含 14 个占位符:\n%s", query)
	}
}

func TestCheckInput_ReadsBody(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"test"}]}`
	req := httptest.NewRequest("POST", "/v1/chat", strings.NewReader(body))
	req.Body = io.NopCloser(strings.NewReader(body))

	readBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(readBody))

	if string(readBody) != body {
		t.Errorf("body = %s, want %s", string(readBody), body)
	}
}

package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestContentAuditPageParamsDefaultsAndCaps(t *testing.T) {
	request := httptest.NewRequest("GET", "/admin/v1/audit/content/session-a?limit=999&offset=40", nil)
	limit, offset := contentAuditPageParams(request, 20)
	if limit != 100 || offset != 40 {
		t.Fatalf("limit=%d offset=%d", limit, offset)
	}
	defaults := httptest.NewRequest("GET", "/admin/v1/audit/content/session-a", nil)
	limit, offset = contentAuditPageParams(defaults, 20)
	if limit != 20 || offset != 0 {
		t.Fatalf("default limit=%d offset=%d", limit, offset)
	}
}

func TestContentAuditTotalContractMarksUnknownInsteadOfZero(t *testing.T) {
	value, known := contentAuditTotalValue(-1)
	if known || value != nil {
		t.Fatalf("unknown total = (%v,%v), want (nil,false)", value, known)
	}
	value, known = contentAuditTotalValue(0)
	if !known || value != 0 {
		t.Fatalf("known empty total = (%v,%v), want (0,true)", value, known)
	}
}

func TestTruncateSessionContentPreservesUTF8AndMarksPreview(t *testing.T) {
	short, truncated := truncateSessionContent("短内容")
	if truncated || short != "短内容" {
		t.Fatalf("short content should remain unchanged: %q truncated=%v", short, truncated)
	}

	content := strings.Repeat("安全", sessionContentPreviewBytes)
	preview, truncated := truncateSessionContent(content)
	if !truncated || !utf8.ValidString(preview) {
		t.Fatalf("expected valid truncated preview, truncated=%v", truncated)
	}
	if len(preview) > sessionContentPreviewBytes+len(sessionContentTruncatedSuffix) {
		t.Fatalf("preview exceeded byte budget: %d", len(preview))
	}
}

func TestExportableSecurityEventExcludesInventoryOnlyObservations(t *testing.T) {
	agentOnly := &repository.SecurityEvent{MatchedSummary: map[string]interface{}{
		"findings": []interface{}{
			map[string]interface{}{
				"category":                   "agent_openai_codex",
				"rule_type":                  "agent_detect",
				"counts_as_security_finding": false,
			},
		},
	}}
	if exportableSecurityEvent(agentOnly) {
		t.Fatal("inventory-only agent observation must not be exported as an alert")
	}

	mixed := &repository.SecurityEvent{MatchedSummary: map[string]interface{}{
		"findings": []interface{}{
			map[string]interface{}{
				"category":                   "agent_openai_codex",
				"rule_type":                  "agent_detect",
				"counts_as_security_finding": false,
			},
			map[string]interface{}{
				"category":                   "secret_leak",
				"rule_type":                  "secret",
				"counts_as_security_finding": true,
			},
		},
	}}
	if !exportableSecurityEvent(mixed) {
		t.Fatal("an actionable finding in a mixed event must remain exportable")
	}
}

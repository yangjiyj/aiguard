package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentIdentityAuditMetadataSurvivesAllAPIWrites(t *testing.T) {
	m := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	w := &RealAuditWriter{db: m, limiter: &mockTokenIncrementer{}}
	e := &modelrouter.RequestEnvelope{RequestID: "identity-test", TenantID: "tenant", AgentType: "agent-tool-call", UserAgent: "custom-client/1", AgentIdentityHeaders: `{"declared_type":"main"}`}
	w.EnsureRequestLog(context.Background(), e)
	w.FinalizeRequestLog(context.Background(), e, nil, "success", 200, 1, nil)
	w.WriteContentLogAnchored(context.Background(), e, "user", "hi", 1, 0)
	count := 0
	for i, q := range m.queries {
		if !strings.Contains(q, "INSERT INTO request_logs") {
			continue
		}
		count++
		if !strings.Contains(q, "agent_identity_headers") || !strings.Contains(q, "proxy_user_agent") {
			t.Fatal("missing metadata columns")
		}
		foundUA, foundHeaders := false, false
		for _, arg := range m.args[i] {
			if v, ok := arg.(string); ok {
				foundUA = foundUA || v == e.UserAgent
				foundHeaders = foundHeaders || v == e.AgentIdentityHeaders
			}
		}
		if !foundUA || !foundHeaders {
			t.Fatal("missing metadata arguments")
		}
	}
	if count != 3 {
		t.Fatal(count)
	}
	s := requestLogSnapshotFromEnvelope(e, time.Now())
	if s.UserAgent != e.UserAgent || s.AgentIdentityHeaders != e.AgentIdentityHeaders {
		t.Fatal("async metadata lost")
	}
}
func TestReverseProxyKeepsSelfReportedNameAndUA(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api.example.com/v1/messages", nil)
	req.Header.Set("User-Agent", "client/1")
	req.Header.Set("X-Agent-Type", "main")
	req.Header.Set("X-JJDGuard-Agent-Name", "custom-task")
	rec, err := newReverseProxyAuditRecord("req", "tenant", "api.example.com", req.URL, req, nil, nil, "success", 200, 0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if rec.UserAgent != "client/1" || !strings.Contains(rec.AgentIdentityHeaders, "custom-task") {
		t.Fatal("identity lost")
	}
}

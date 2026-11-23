package handler

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

func TestMCPDestructiveRegexDoesNotBlockDocumentationExample(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{
		Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow",
	})
	setMCPDestructivePolicy(env, agentguard.ModeStrict, agentguard.DestructiveActionBlock)
	body := `{"jsonrpc":"2.0","id":47,"method":"tools/call","params":{"name":"delete_helper","arguments":{"documentation":"example only: rm -rf /"}}}`

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if w.Code != http.StatusOK || atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("documentation example must not be treated as an executable destructive call: status=%d upstream=%d body=%s",
			w.Code, atomic.LoadInt32(env.upstreamHits), w.Body.String())
	}
}

func TestMCPDestructiveRedlinesComplementStructuredAnalyzer(t *testing.T) {
	for _, arguments := range []string{
		`{"command":"rm -rf /srv/isolated-fixture"}`,
		`{"query":"DROP TABLE isolated_fixture"}`,
		`{"command":"mkfs -t ext4 /dev/isolated-fixture"}`,
	} {
		if hits := matchMCPRedlines(arguments); len(hits) != 1 || hits[0] != "destructive_command" {
			t.Fatalf("destructive command must retain redline coverage alongside structured analysis: arguments=%s hits=%v", arguments, hits)
		}
	}
	arguments := `{"command":"shred -u /srv/isolated-fixture"}`
	if hits := matchMCPRedlines(arguments); len(hits) != 0 {
		t.Fatalf("destructive commands outside the redline categories remain owned by structured analysis: arguments=%s hits=%v", arguments, hits)
	}
}

func TestMCPStructuredSQLDestructionIsBlockedBeforeForward(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{
		Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow",
	})
	setMCPDestructivePolicy(env, agentguard.ModeStrict, agentguard.DestructiveActionBlock)
	body := `{"jsonrpc":"2.0","id":48,"method":"tools/call","params":{"name":"execute_sql","arguments":{"query":"DROP TABLE isolated_fixture"}}}`

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("structured SQL destruction reached upstream %d times", atomic.LoadInt32(env.upstreamHits))
	}
	if w.Code != http.StatusOK {
		t.Fatalf("JSON-RPC safety error status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMCPDestructiveBlockOverridesPermissionConfirmWithoutTicket(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{
		Matched: true, PolicyID: "mcppol_confirm", Mode: "strict", Action: "confirm",
	})
	setMCPDestructivePolicy(env, agentguard.ModeStrict, agentguard.DestructiveActionBlock)
	body := `{"jsonrpc":"2.0","id":49,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"rm -rf /srv/isolated-fixture"}}}`

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if atomic.LoadInt32(env.upstreamHits) != 0 || atomic.LoadInt32(env.confirmations) != 0 {
		t.Fatalf("destructive block must win without forwarding or ticket: upstream=%d confirmations=%d body=%s",
			atomic.LoadInt32(env.upstreamHits), atomic.LoadInt32(env.confirmations), w.Body.String())
	}
}

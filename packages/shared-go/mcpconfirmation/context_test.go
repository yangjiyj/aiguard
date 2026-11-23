package mcpconfirmation

import (
	"strings"
	"testing"
)

const testScopeSecret = "internal-test-secret"

func testReplayContext() ReplayContext {
	return ReplayContext{
		Version: ReplayContextVersion, TenantID: "tenant-a", ProjectID: "project-a",
		UserID: "user-a", ClientID: "client-a", KeyPrefix: "key-a",
		EnvironmentScope: "customer",
		AgentSessionID:   "agent-session-a", MCPSessionID: "mcp-session-a",
		ServerID: "server-a", ToolName: "write", ToolCallID: "number:9",
		ProtocolVersion: "2025-11-25", ToolID: "tool-a",
		SupplyChainRevision: "revision-a", ApprovedSchemaHash: strings.Repeat("a", 64),
		ServerRouteHash: strings.Repeat("b", 64),
		RequestBody:     []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"write","arguments":{"b":2,"a":1}}}`),
	}
}

func TestScopeKeyUsesLengthPrefixAndBindsPrincipalSessionProtocolAndTypedID(t *testing.T) {
	base := testReplayContext()
	key, err := ScopeKey(testScopeSecret, base)
	if err != nil || len(key) != 64 {
		t.Fatalf("scope=(%q,%v)", key, err)
	}
	ambiguousLeft := base
	ambiguousLeft.ClientID, ambiguousLeft.KeyPrefix = "a", "bc"
	ambiguousRight := base
	ambiguousRight.ClientID, ambiguousRight.KeyPrefix = "ab", "c"
	left, _ := ScopeKey(testScopeSecret, ambiguousLeft)
	right, _ := ScopeKey(testScopeSecret, ambiguousRight)
	if left == right {
		t.Fatal("length-prefix ambiguity was not separated")
	}
	for name, mutate := range map[string]func(*ReplayContext){
		"tenant":    func(c *ReplayContext) { c.TenantID = "tenant-b" },
		"principal": func(c *ReplayContext) { c.UserID = "user-b" },
		"server":    func(c *ReplayContext) { c.ServerID = "server-b" },
		"session":   func(c *ReplayContext) { c.MCPSessionID = "mcp-session-b" },
		"protocol":  func(c *ReplayContext) { c.ProtocolVersion = "2025-06-18" },
		"typed id":  func(c *ReplayContext) { c.ToolCallID = "string:9" },
	} {
		changed := base
		mutate(&changed)
		got, _ := ScopeKey(testScopeSecret, changed)
		if got == key {
			t.Fatalf("%s did not change scope key", name)
		}
	}
}

func TestReplayContextV2HMACCompatibilityFixture(t *testing.T) {
	// Fixed values were produced by the released v2 field sequence. Do not
	// derive the expectation with another helper: pending 2.6.5 confirmations
	// must remain verifiable after adding deployment-owned evidence scope.
	replay := testReplayContext()
	replay.EnvironmentScope = ""
	scope, err := ScopeKey(testScopeSecret, replay)
	if err != nil {
		t.Fatal(err)
	}
	if want := "964c464ed131e7eb12f2696d7f8e1438d6995c59d0e4c3a0df0f8c11f24affb8"; scope != want {
		t.Fatalf("released v2 scope key = %q, want %q", scope, want)
	}
	principal, err := PrincipalFingerprint(testScopeSecret, replay)
	if err != nil {
		t.Fatal(err)
	}
	if want := "176bd59e5c24c669b0eefc90e3ddb64c8dd4090bb72b949d032aae492c485b01"; principal != want {
		t.Fatalf("released v2 principal = %q, want %q", principal, want)
	}
}

func TestCanonicalRequestHashNormalizesArgumentsAndBindsApprovedContext(t *testing.T) {
	left := testReplayContext()
	right := testReplayContext()
	right.RequestBody = []byte(`{"params":{"arguments":{"a":1,"b":2},"name":"write"},"method":"tools/call","id":9,"jsonrpc":"2.0"}`)
	leftHash, err := CanonicalRequestHash(left)
	if err != nil {
		t.Fatal(err)
	}
	rightHash, err := CanonicalRequestHash(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftHash != rightHash {
		t.Fatalf("canonical hashes differ: %s != %s", leftHash, rightHash)
	}
	for name, mutate := range map[string]func(*ReplayContext){
		"arguments": func(c *ReplayContext) {
			c.RequestBody = []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"write","arguments":{"a":2,"b":2}}}`)
		},
		"tool id":  func(c *ReplayContext) { c.ToolID = "tool-b" },
		"revision": func(c *ReplayContext) { c.SupplyChainRevision = "revision-b" },
		"schema":   func(c *ReplayContext) { c.ApprovedSchemaHash = strings.Repeat("c", 64) },
		"route":    func(c *ReplayContext) { c.ServerRouteHash = strings.Repeat("d", 64) },
	} {
		changed := left
		mutate(&changed)
		got, err := CanonicalRequestHash(changed)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == leftHash {
			t.Fatalf("%s did not change request hash", name)
		}
	}
}

func TestResponseAADBindsEveryReplayDimension(t *testing.T) {
	replay := testReplayContext()
	requestHash, _ := CanonicalRequestHash(replay)
	aad, err := ResponseAAD(testScopeSecret, replay, "invocation-a", "confirmation-a", requestHash, strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	changed := replay
	changed.ServerID = "server-b"
	other, _ := ResponseAAD(testScopeSecret, changed, "invocation-a", "confirmation-a", requestHash, strings.Repeat("e", 64))
	if string(aad) == string(other) {
		t.Fatal("server did not change response AAD")
	}
	other, _ = ResponseAAD(testScopeSecret, replay, "invocation-b", "confirmation-a", requestHash, strings.Repeat("e", 64))
	if string(aad) == string(other) {
		t.Fatal("invocation did not change response AAD")
	}
}

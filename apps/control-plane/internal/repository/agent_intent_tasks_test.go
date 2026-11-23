package repository

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

func TestIntentTaskFacetScopeStateIsNonAuthorizing(t *testing.T) {
	scopes := []AgentIntentTaskGrant{{
		Action: "file_read", ResourceType: "file", ResourceRefHash: agentintent.DigestString("/workspace/allowed.txt"),
	}}
	if got := intentTaskFacetScopeState(nil, scopes); got != "unverifiable" {
		t.Fatalf("empty/unsupported facets state=%q", got)
	}
	if got := intentTaskFacetScopeState([]agentintent.AuthorizationFacet{{
		Action: "file_read", ResourceType: "file", ResourceID: "/workspace/allowed.txt",
	}}, scopes); got != "matched" {
		t.Fatalf("matching task scope state=%q", got)
	}
	if got := intentTaskFacetScopeState([]agentintent.AuthorizationFacet{{
		Action: "file_write", ResourceType: "file", ResourceID: "/workspace/other.txt",
	}}, scopes); got != "mismatch" {
		t.Fatalf("out-of-task scope state=%q", got)
	}
}

func TestIntentTaskGrantSnapshotJSONDoesNotExposeResourceID(t *testing.T) {
	value := AgentIntentTaskGrant{
		GrantID: "grant", Action: "file_read", ResourceType: "file",
		ResourceID: "/private/workspace/path", ResourceRefHash: strings.Repeat("a", 64),
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "/private/workspace/path") || !strings.Contains(string(raw), "resource_ref_hash") {
		t.Fatalf("task grant snapshot JSON must carry only digest: %s", raw)
	}
}

func TestValidIntentTaskLocatorRequiresCanonicalUUIDv4(t *testing.T) {
	valid := "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	if !validIntentTaskLocator(valid) {
		t.Fatal("canonical UUIDv4 locator rejected")
	}
	for _, invalid := range []string{strings.ToUpper(valid), " " + valid, valid + " ", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"} {
		if validIntentTaskLocator(invalid) {
			t.Errorf("non-canonical or non-v4 locator accepted: %q", invalid)
		}
	}
}

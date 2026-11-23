package repository

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

func TestVerifyResolvedT13AuthorizationRequiresPersistedLiveExactScope(t *testing.T) {
	facet := agentintent.AuthorizationFacet{Action: "file_read", ResourceType: "file", ResourceID: "/workspace/readme.txt"}
	argsHash := "sha256:" + strings.Repeat("a", 64)
	key, err := agentintent.AuthorizationIdempotencyKey("claude-code", "endpoint-a", "session-a", "call-a", argsHash, "Read", facet)
	if err != nil {
		t.Fatal(err)
	}
	requestHash, err := agentAuthorizationRequestHash(AgentAuthorizationRequest{
		Action: facet.Action, ResourceType: facet.ResourceType, ResourceID: facet.ResourceID, IdempotencyKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	decisionJSON, err := json.Marshal(AgentAuthorizationDecision{
		Allowed: true, Reason: "allowed", PrincipalID: "principal-a", Action: facet.Action,
		ResourceType: facet.ResourceType, ResourceID: facet.ResourceID, IdempotencyKey: key, GrantID: "grant-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := struct {
		facet agentintent.AuthorizationFacet
		key   string
		hash  string
	}{facet: facet, key: key, hash: requestHash}
	row := resolvedT13AuthorizationRow{
		key: key, principalID: "principal-a", requestHash: requestHash, state: "complete", requestGrantID: "grant-a",
		decisionJSON: decisionJSON, requestActive: true, principalStatus: "active", principalActive: true,
		grantID: "grant-a", grantAction: facet.Action, grantType: facet.ResourceType, grantResource: facet.ResourceID, grantActive: true,
	}
	decision, err := verifyResolvedT13Authorization(expected, row)
	if err != nil || decision == nil || !decision.Allowed {
		t.Fatalf("valid stored decision unresolved: decision=%+v err=%v", decision, err)
	}

	for name, mutate := range map[string]func(*resolvedT13AuthorizationRow){
		"request hash mismatch": func(v *resolvedT13AuthorizationRow) { v.requestHash = strings.Repeat("b", 64) },
		"expired request":       func(v *resolvedT13AuthorizationRow) { v.requestActive = false },
		"inactive principal":    func(v *resolvedT13AuthorizationRow) { v.principalStatus = "disabled" },
		"revoked principal":     func(v *resolvedT13AuthorizationRow) { v.revoked = true },
		"expired principal":     func(v *resolvedT13AuthorizationRow) { v.principalActive = false },
		"expired grant":         func(v *resolvedT13AuthorizationRow) { v.grantActive = false },
		"wrong grant scope":     func(v *resolvedT13AuthorizationRow) { v.grantResource = "/workspace/other.txt" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := row
			mutate(&changed)
			if _, err := verifyResolvedT13Authorization(expected, changed); err == nil {
				t.Fatal("invalid stored authorization was accepted")
			}
		})
	}
}

func TestValidIntentResolveRequestRejectsDuplicateFacets(t *testing.T) {
	facet := agentintent.AuthorizationFacet{Action: "file_read", ResourceType: "file", ResourceID: "/workspace/readme.txt"}
	request := agentintent.AuthorizationResolveRequest{
		Product: "claude-code", SessionID: "session-a", ToolUseID: "call-a",
		ArgumentsHash: "sha256:" + strings.Repeat("a", 64), ToolName: "Read",
		Facets: []agentintent.AuthorizationFacet{facet, facet},
	}
	if validIntentResolveRequest(request) {
		t.Fatal("duplicate authorization facets were accepted")
	}
}

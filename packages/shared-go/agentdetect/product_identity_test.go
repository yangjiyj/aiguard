package agentdetect

import "testing"

func TestProductEnvelopeIgnoresIncidentalCodexNames(t *testing.T) {
	envelope := `<system-reminder data-role="user-context"><user_info>Workspace Folder: /Users/test/WorkBuddy/task</user_info><identity_context>You are Codex. Legacy instructions.</identity_context><product_identity>You are WorkBuddy, a powerful AI assistant.</product_identity></system-reminder><user_query>Compare Codex and Claude Code.</user_query>`
	if got := InferFromProductEnvelope(envelope); got != "workbuddy" {
		t.Fatal(got)
	}
	for _, text := range []string{`You are WorkBuddy`, `<user_query><product_identity>You are WorkBuddy</product_identity></user_query>`, `quoted: ` + envelope} {
		if got := InferFromProductEnvelope(text); got != "" {
			t.Fatal("ordinary text accepted", got)
		}
	}
}

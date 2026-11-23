package endpointevents

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Real hookd wire batches captured from github.com/yangjiyj/agent-security-platform
// commit a0296bf653d55bb0d56038ce5d30954cf944a05a: claudecode.Process -> queue.Append
// -> uploader.Run(once) against an httptest capture server (gzip body decoded, bytes
// unchanged). See testdata/hookd-a0296bf6/README.md for provenance and sha256.
const (
	hookdT13DenyBatch   = "testdata/hookd-a0296bf6/batch-a-cc-t13-deny.json"
	hookdT15RejectBatch = "testdata/hookd-a0296bf6/batch-b-cc-t15-reject.json"
)

func loadHookdBatch(t *testing.T, name string) (map[string]any, time.Time) {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(name))
	if err != nil {
		t.Fatal(err)
	}
	batch, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHeader(batch); err != nil {
		t.Fatalf("header: %v", err)
	}
	sent, err := time.Parse(time.RFC3339Nano, batch["sent_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return batch, sent
}

func hookdEventSource(event map[string]any) string {
	local, _ := event["local_decision"].(map[string]any)
	source, _ := local["source"].(string)
	return source
}

// validateHookdBatch mirrors the gateway loop: every event must pass or the whole
// batch is rejected. now is the batch sent_at so the captured bytes stay valid.
func validateHookdBatch(batch map[string]any, now time.Time) (int, error) {
	events := batch["events"].([]any)
	for i, item := range events {
		if err := ValidateEvent(item.(map[string]any), now, "metadata"); err != nil {
			return i, err
		}
	}
	return len(events), nil
}

func findHookdSource(t *testing.T, batch map[string]any, source string) map[string]any {
	t.Helper()
	for _, item := range batch["events"].([]any) {
		if event := item.(map[string]any); hookdEventSource(event) == source {
			return event
		}
	}
	t.Fatalf("captured batch has no local_decision.source=%q", source)
	return nil
}

// (a) single T13 trusted-authorization deny event.
func TestHookdA0296bf6SourceAgentAuthorizationAccepted(t *testing.T) {
	batch, now := loadHookdBatch(t, hookdT13DenyBatch)
	event := findHookdSource(t, batch, "agent_authorization")
	if err := ValidateEvent(event, now, "metadata"); err != nil {
		t.Fatalf("agent_authorization rejected: %v", err)
	}
}

// (b) single T15 approval reject event.
func TestHookdA0296bf6SourceAgentApprovalAccepted(t *testing.T) {
	batch, now := loadHookdBatch(t, hookdT15RejectBatch)
	event := findHookdSource(t, batch, "agent_approval")
	if err := ValidateEvent(event, now, "metadata"); err != nil {
		t.Fatalf("agent_approval rejected: %v", err)
	}
	if n, err := validateHookdBatch(batch, now); err != nil {
		t.Fatalf("T15 batch rejected at event %d: %v", n, err)
	}
}

// (c) 7 ordinary events + 1 agent_authorization event: the whole batch must pass.
func TestHookdA0296bf6MixedBatchAccepted(t *testing.T) {
	batch, now := loadHookdBatch(t, hookdT13DenyBatch)
	events := batch["events"].([]any)
	other := 0
	for _, item := range events {
		if hookdEventSource(item.(map[string]any)) != "agent_authorization" {
			other++
		}
	}
	if len(events) != 8 || other != 7 {
		t.Fatalf("fixture shape changed: events=%d other=%d", len(events), other)
	}
	if n, err := validateHookdBatch(batch, now); err != nil {
		t.Fatalf("mixed batch rejected at event %d: %v", n, err)
	}
}

// (d) unknown sources remain rejected; every value hookd a0296bf6 can emit passes.
func TestHookdA0296bf6SourceEnumIsClosed(t *testing.T) {
	batch, now := loadHookdBatch(t, hookdT13DenyBatch)
	event := findHookdSource(t, batch, "agent_authorization")
	local := event["local_decision"].(map[string]any)
	for _, source := range []string{"local", "server", "timeout_fallback", "offline_fallback", "agent_authorization", "agent_approval"} {
		local["source"] = source
		if err := ValidateEvent(event, now, "metadata"); err != nil {
			t.Fatalf("hookd source %q rejected: %v", source, err)
		}
	}
	for _, source := range []string{"bogus", "", "Agent_Authorization", "agent_authorization "} {
		local["source"] = source
		if ValidateEvent(event, now, "metadata") == nil {
			t.Fatalf("unknown source %q accepted", source)
		}
	}
}

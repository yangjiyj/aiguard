package endpointevents

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) map[string]any {
	t.Helper()
	raw := `{"event_id":"11111111-1111-7111-8111-111111111111","event_type":"tool.pre","occurred_at":"TIME","agent":{"product":"claude-code","version":"2.1.278","runtime":"cli"},"session":{"session_id":"session"},"context":{"machine_id":"fixture","hostname":"fixture","os_user":"fixture"},"tool":{"tool_use_id":"call","name":"Bash","type":"system","args_summary":{"command":"printf fixture"}},"local_decision":{"raw":"block","effective":"block","mode":"block","latency_ms":0,"source":"local","policy_version":1}}`
	value, err := Decode([]byte(strings.Replace(raw, "TIME", time.Now().UTC().Format(time.RFC3339Nano), 1)))
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func TestHookdContractCompleteKindsAndPrivacy(t *testing.T) {
	for _, typ := range []string{"session.start", "session.end", "turn.start", "turn.end", "tool.pre", "tool.post", "tool.failure", "tool.denied", "permission.request", "subagent.start", "subagent.stop", "config.change", "instructions.loaded", "context.compact", "asset.snapshot", "adapter.health"} {
		t.Run(typ, func(t *testing.T) {
			v := fixture(t)
			v["event_type"] = typ
			if err := ValidateEvent(v, time.Now(), "metadata"); err != nil {
				t.Fatal(err)
			}
		})
	}
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"unknown root", func(v map[string]any) { v["raw_prompt"] = "private" }},
		{"unknown nested", func(v map[string]any) { v["context"].(map[string]any)["api_key"] = "private" }},
		{"wrong type", func(v map[string]any) { v["tool"] = []any{} }},
		{"uuid", func(v map[string]any) { v["event_id"] = "not-uuid" }},
		{"time", func(v map[string]any) { v["occurred_at"] = "2026-02-30T00:00:00Z" }},
		{"future", func(v map[string]any) { v["occurred_at"] = time.Now().Add(48 * time.Hour).Format(time.RFC3339Nano) }},
		{"required", func(v map[string]any) { delete(v, "session") }},
		{"negative", func(v map[string]any) { v["local_decision"].(map[string]any)["latency_ms"] = json.Number("-1") }},
		{"fraction", func(v map[string]any) { v["local_decision"].(map[string]any)["latency_ms"] = json.Number("0.5") }},
		{"length", func(v map[string]any) { v["session"].(map[string]any)["session_id"] = strings.Repeat("x", 129) }},
		{"content permission", func(v map[string]any) { v["content"] = map[string]any{"user_prompt": "private"} }},
		{"preview permission", func(v map[string]any) { v["tool"].(map[string]any)["result_preview"] = "private" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := fixture(t)
			tc.change(v)
			if ValidateEvent(v, time.Now(), "metadata") == nil {
				t.Fatal("invalid event accepted")
			}
		})
	}
	v := fixture(t)
	v["content"] = map[string]any{"user_prompt": "redacted summary"}
	if err := ValidateEvent(v, time.Now(), "summary"); err != nil {
		t.Fatal(err)
	}
}
func TestHookdContractStrictJSONAndEnvelope(t *testing.T) {
	for _, raw := range []string{`{"x":1,"x":2}`, `{"x":{"secret":1,"secret":2}}`, `{}{}`, `null`} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	v := map[string]any{"schema_version": "events.v1", "endpoint_id": "ep_fixture", "hookd_version": "dev", "sent_at": time.Now().Format(time.RFC3339Nano), "events": []any{fixture(t)}}
	if err := ValidateHeader(v); err != nil {
		t.Fatal(err)
	}
	v["extra"] = true
	if ValidateHeader(v) == nil {
		t.Fatal("extra header accepted")
	}
	delete(v, "extra")
	v["schema_version"] = "1.0"
	if ValidateHeader(v) == nil {
		t.Fatal("wrong version accepted")
	}
}
func TestHookdContractMultiAssetAndError(t *testing.T) {
	v := fixture(t)
	v["event_type"] = "asset.snapshot"
	v["assets"] = []any{map[string]any{"asset_type": "skill", "name": "first", "present": true}, map[string]any{"asset_type": "plugin", "name": "second", "detail": map[string]any{"env_keys": []any{"API_KEY"}, "scope": "project"}}}
	v["error"] = map[string]any{"code": "scan_incomplete", "message": "unreadable source"}
	if err := ValidateEvent(v, time.Now(), "metadata"); err != nil {
		t.Fatal(err)
	}
	v["assets"] = make([]any, 501)
	if ValidateEvent(v, time.Now(), "metadata") == nil {
		t.Fatal("too many assets")
	}
}

func TestHookdLegacyCapturePermission(t *testing.T) {
	for _, raw := range []string{`{"result":{"result":"private"}}`, `{"payload":{"result":["private"]}}`, `{"command":["private"]}`, `{"payload":{"command":{"command":"private"}}}`, `{"result":"private"}`, `{"command":"private"}`, `{"payload":{"result":"private"}}`, `{"payload":{"command":"private"}}`} {
		v, err := Decode([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		for _, level := range []string{"", "metadata", "unknown"} {
			if ValidateLegacyCapture(v, level) == nil {
				t.Fatalf("capture bypass %s", level)
			}
		}
		for _, level := range []string{"summary", "full"} {
			if err := ValidateLegacyCapture(v, level); err != nil {
				t.Fatal(err)
			}
		}
	}
}

package repository

import (
	"encoding/json"
	"testing"
)

func TestControlBoundaryFromHealth(t *testing.T) {
	for _, tc := range []struct {
		name, health, want string
	}{
		{"legacy hookd without report", `{"queue_events":3}`, ""},
		{"empty health", ``, ""},
		{"json null health", `null`, ""},
		{"explicit null report", `{"control_boundary":null}`, ""},
		{"non-object report", `{"control_boundary":"fail-open"}`, ""},
		{"array report", `{"control_boundary":[1]}`, ""},
		{"malformed health", `{"control_boundary":`, ""},
		{"reported", `{"queue_events":1,"control_boundary":{"schema":"jjdguard-control-boundary/v1","hosts":{}}}`, `{"schema":"jjdguard-control-boundary/v1","hosts":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ControlBoundaryFromHealth(json.RawMessage(tc.health))
			if string(got) != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestAdminEndpointSerializesMissingControlBoundaryAsNull(t *testing.T) {
	data, err := json.Marshal(AgentAdminEndpoint{Health: json.RawMessage(`{"queue_events":0}`)})
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(data, &shape); err != nil {
		t.Fatal(err)
	}
	raw, ok := shape["control_boundary"]
	if !ok || string(raw) != "null" {
		t.Fatalf("control_boundary must be present and null for legacy hookd, got %q in %s", raw, data)
	}
}

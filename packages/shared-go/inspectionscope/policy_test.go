package inspectionscope

import (
	"encoding/json"
	"testing"
)

func TestDefaultTargetsAndIndependentUntrustedSources(t *testing.T) {
	p := Default()
	for _, tc := range []struct {
		source       string
		latest, want bool
	}{
		{"user", true, true}, {"user", false, false}, {"model_output", false, true},
		{"system_prompt", false, false}, {"developer", false, false}, {"tool_def", false, false},
		{"assistant_history", false, false}, {"tool_result", false, true}, {"rag_context", false, true},
		{"retrieval_result", false, true}, {"web_content", false, true}, {"unknown", false, true}, {"", false, true},
	} {
		if got := p.Allows(tc.source, tc.latest); got != tc.want {
			t.Errorf("source=%q latest=%v got=%v", tc.source, tc.latest, got)
		}
	}
	p.InspectToolResults = false
	p.InspectBuiltinContext = true
	p.InspectHistory = true
	for _, source := range []string{"tool_result", "rag", "rag_context", "retrieval", "retrieval_result", "web_content"} {
		if p.Allows(source, false) {
			t.Errorf("context/history must not enable %s", source)
		}
	}
	if !p.Allows("future_source", false) {
		t.Fatal("unknown provenance must stay in scope")
	}
}

func TestSignedFieldsRequireCompletePolicyAndKeepExplicitFalse(t *testing.T) {
	var fields Fields
	if p, err := fields.Resolve(); err != nil || p != Default() {
		t.Fatalf("legacy defaults: %+v %v", p, err)
	}
	if err := json.Unmarshal([]byte(`{"inspect_user_input":false}`), &fields); err != nil {
		t.Fatal(err)
	}
	if _, err := fields.Resolve(); err == nil {
		t.Fatal("partial signed scope accepted")
	}
	if err := json.Unmarshal([]byte(`{"inspect_user_input":false,"inspect_model_output":false,"inspect_builtin_context":false,"inspect_history":false,"inspect_tool_results":false}`), &fields); err != nil {
		t.Fatal(err)
	}
	p, err := fields.Resolve()
	if err != nil || p != (Policy{}) {
		t.Fatalf("explicit false lost: %+v %v", p, err)
	}
	values := map[string]any{}
	fields.AddCanonical(values)
	if len(values) != 5 || values["inspect_user_input"] != false {
		t.Fatalf("unsigned fields: %#v", values)
	}
	if p.Fingerprint() == Default().Fingerprint() {
		t.Fatal("policy changes must invalidate detection cache")
	}
}

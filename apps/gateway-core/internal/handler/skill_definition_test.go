package handler

import (
	"encoding/json"
	"testing"
)

func TestSkillDefinitionClassificationIsSharedAcrossLifecycle(t *testing.T) {
	body := []byte(`{"tools":[{"type":"function","function":{"name":"use_skill","description":"load a skill","parameters":{"type":"object"}}}]}`)
	calls := DetectToolCalls(body)
	if len(calls) != 1 || calls[0].Type != "skill" {
		t.Fatalf("definition classification=%+v", calls)
	}
	if proposed := inferToolTypeFromName("use_skill"); proposed != calls[0].Type {
		t.Fatalf("definition type=%q proposed type=%q", calls[0].Type, proposed)
	}
	if got := inferToolType("reskill_model"); got != "unknown" {
		t.Fatalf("substring false positive classified as %q", got)
	}
}

func TestSkillDefinitionHashIsCanonicalAndSensitiveToMeaning(t *testing.T) {
	first := ToolDef{Type: "function", Function: ToolFunc{
		Name: "use_skill", Description: "load approved skill",
		Parameters: json.RawMessage(`{"type":"object","properties":{"skill":{"type":"string"},"version":{"type":"string"}}}`),
	}}
	reordered := ToolDef{Type: "function", Function: ToolFunc{
		Name: "use_skill", Description: "load approved skill",
		Parameters: json.RawMessage(`{"properties":{"version":{"type":"string"},"skill":{"type":"string"}},"type":"object"}`),
	}}
	changed := first
	changed.Function.Description = "load any skill"
	if toolDefinitionHash(first) != toolDefinitionHash(reordered) {
		t.Fatal("schema JSON key order changed definition hash")
	}
	if toolDefinitionHash(first) == toolDefinitionHash(changed) {
		t.Fatal("description change did not change definition hash")
	}
}

package handler

import (
	"context"
	"testing"
)

func TestGuardrailFailClosedProjectionDefaultsFalseAndIsGatewayOnly(t *testing.T) {
	configs, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{"judge_backend": "bundled"}))
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := configs.Gateway[guardrailFailClosedSettingKey]; !ok || value != false {
		t.Fatalf("gateway projection %s=%v present=%v, want false", guardrailFailClosedSettingKey, value, ok)
	}
	if _, ok := configs.Engine[guardrailFailClosedSettingKey]; ok {
		t.Fatalf("engine projection must not carry %s", guardrailFailClosedSettingKey)
	}
}

func TestGuardrailFailClosedProjectionIsSignedAndFollowsSetting(t *testing.T) {
	off, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{"judge_backend": "bundled"}))
	if err != nil {
		t.Fatal(err)
	}
	on, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{"judge_backend": "bundled", guardrailFailClosedSettingKey: "true"}))
	if err != nil {
		t.Fatal(err)
	}
	if on.Gateway[guardrailFailClosedSettingKey] != true {
		t.Fatalf("gateway projection did not follow the setting: %v", on.Gateway[guardrailFailClosedSettingKey])
	}
	if on.GatewayRevision == off.GatewayRevision {
		t.Fatal("gateway revision must change when the fail-closed option changes")
	}
	if on.EngineRevision != off.EngineRevision {
		t.Fatal("engine revision must not depend on the gateway-only fail-closed option")
	}
}

func TestGuardrailFailClosedSettingRejectsNonBoolean(t *testing.T) {
	for _, value := range []string{"true", "false", "TRUE"} {
		if err := validateSemanticSettingValues(context.Background(), map[string]string{guardrailFailClosedSettingKey: value}); err != nil {
			t.Fatalf("value %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"yes", "1", "close"} {
		if err := validateSemanticSettingValues(context.Background(), map[string]string{guardrailFailClosedSettingKey: value}); err == nil {
			t.Fatalf("value %q accepted", value)
		}
	}
}

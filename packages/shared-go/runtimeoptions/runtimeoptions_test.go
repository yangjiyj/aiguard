package runtimeoptions

import "testing"

func TestNormalizeAcceptsContractValues(t *testing.T) {
	for key, cases := range map[string]map[string]string{
		SecurityCapacityFailMode:         {"open": "open", " closed ": "closed"},
		MCPPolicyFailMode:                {"closed": "closed"},
		RetentionFailureMode:             {"open": "open"},
		OutputSecurityMode:               {"stream_enforce": "stream_enforce", "strict_buffered": "strict_buffered", "stream_audit": "stream_audit"},
		OutputStrictMaxBytes:             {"1024": "1024", " 67108864 ": "67108864"},
		UploadInspectionFailureAction:    {"forward_alert": "forward_alert", "block": "block"},
		AgentSecurityMonitorDisposition:  {"observe": "observe", "follow_policy": "follow_policy"},
		ModelOutputClassifiedDisposition: {"observe": "observe"},
		SemanticBlockStages:              {`["agent","input"]`: `["input","agent"]`, `["output"]`: `["output"]`},
	} {
		for raw, want := range cases {
			if got, err := Normalize(key, raw); err != nil || got != want {
				t.Fatalf("%s=%q → %q %v，期望 %q", key, raw, got, err, want)
			}
		}
	}
}

func TestNormalizeRejectsOutOfContractValues(t *testing.T) {
	for key, bad := range map[string][]string{
		SecurityCapacityFailMode:      {"", "close", "maybe"},
		OutputSecurityMode:            {"buffered"},
		OutputStrictMaxBytes:          {"1023", "67108865", "1e3", "012x"},
		UploadInspectionFailureAction: {"allow"},
		SemanticBlockStages:           {"[]", `"input"`, `["input","input"]`, `["bogus"]`, "not-json"},
		"unknown_key":                 {"x"},
	} {
		for _, raw := range bad {
			if _, err := Normalize(key, raw); err == nil {
				t.Fatalf("%s=%q 应被拒", key, raw)
			}
		}
	}
	if MinOutputStrictMaxBytes != 1024 || MaxOutputStrictMaxBytes != 64<<20 {
		t.Fatal("缓冲上限边界只在这里定义")
	}
}

func TestKeyGroups(t *testing.T) {
	for _, key := range GatewayKeys() {
		if !IsGatewayKey(key) || IsEngineKey(key) {
			t.Fatalf("%s 分组不对", key)
		}
	}
	for _, key := range EngineKeys() {
		if !IsEngineKey(key) || IsGatewayKey(key) {
			t.Fatalf("%s 分组不对", key)
		}
	}
	if len(GatewayKeys()) != 6 || len(EngineKeys()) != 3 {
		t.Fatalf("键数变化需同步契约：gateway=%v engine=%v", GatewayKeys(), EngineKeys())
	}
}

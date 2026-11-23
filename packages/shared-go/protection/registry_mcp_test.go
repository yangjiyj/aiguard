package protection

import "testing"

func TestMCPItemsRegisteredWithContractDefaults(t *testing.T) {
	want := map[string][]Action{
		KeyMCPUnadmitted: racb, KeyMCPDrift: racb, KeyMCPDescriptionPoison: rab, KeyMCPShadowDivergence: rab,
		KeyMCPScanUnavailable: rab, KeyMCPOversize: rab, KeyMCPConfirmUnavailable: rab, KeyMCPReplayChanged: rab,
	}
	for key, actions := range want {
		item, ok := Lookup(key)
		if !ok || item.Group != GroupMCP || item.Default != ActionAlertAllow || len(item.Reasons) == 0 {
			t.Fatalf("%s = %+v", key, item)
		}
		if len(item.Actions) != len(actions) {
			t.Fatalf("%s actions = %v", key, item.Actions)
		}
	}
	var s Settings
	if s.IntParam(KeyMCPScanUnavailable, "timeout_seconds") != 12 || s.IntParam(KeyMCPOversize, "max_name_bytes") != 512 ||
		s.IntParam(KeyMCPOversize, "max_description_bytes") != 8192 || s.IntParam(KeyMCPOversize, "max_schema_bytes") != 65536 {
		t.Fatal("MCP parameter defaults differ from the contract")
	}
	if item, ok := ItemForReason("policy_runtime_unavailable"); !ok || item.Key != KeyMCPReplayChanged {
		t.Fatalf("policy_runtime_unavailable -> %+v", item)
	}
	seen := map[string]string{}
	for _, item := range All() {
		for _, reason := range item.Reasons {
			if prev, dup := seen[reason]; dup {
				t.Fatalf("reason %s registered twice (%s, %s)", reason, prev, item.Key)
			}
			seen[reason] = item.Key
		}
	}
}

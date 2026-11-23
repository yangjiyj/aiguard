package agentintegration

import (
	"encoding/json"
	"testing"
)

func TestCredentialEnforcementContract(t *testing.T) {
	raw := []byte(`{"model_restriction":"allowlist","model_allowlist":["模型甲"],"enforcement":"record","effective_enforcement":"record","dlp_enforcement":"block","effective_dlp_enforcement":"record","enforcement_gate":"record_only"}`)
	var key Credential
	if err := json.Unmarshal(raw, &key); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(key)
	var got, want map[string]any
	json.Unmarshal(out, &got)
	json.Unmarshal(raw, &want)
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("凭据响应缺少 %s", k)
		}
	}
}

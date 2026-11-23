package handler

import (
	"strings"
	"testing"
)

const hookdRegistrationFixture = `{"schema_version":"1.0","machine_id":"test-machine","hostname":"test-host","os":"linux","os_version":"linux","arch":"amd64","os_user":"yj","agent":{"product":"claude-code","version":"test-version","install_path_hash":"test-hash"},"adapter":{"name":"claude-code-plugin","version":"0.1.0"},"hookd_version":"0.1.0","capabilities":["pre_tool_block","transcript_read","config_change","subagent","asset_snapshot"]}`

func TestHookdRegistrationEnvelopeProjection(t *testing.T) {
	r, err := decodeAgentRegistration(strings.NewReader(hookdRegistrationFixture))
	if err != nil {
		t.Fatal(err)
	}
	if r.AgentProduct != "claude-code" || r.AgentVersion != "test-version" || r.InstallPathHash != "test-hash" || r.AdapterName != "claude-code-plugin" || r.MachineID != "test-machine" || len(r.Capabilities) != 5 {
		t.Fatalf("lost wire fields: %+v", r)
	}
}
func TestHookdRegistrationRejectsAmbiguousOrUnknownInput(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(hookdRegistrationFixture, `"schema_version":"1.0"`, `"schema_version":"events.v1"`, 1),
		strings.Replace(hookdRegistrationFixture, `"machine_id":"test-machine"`, `"machine_id":"test-machine","machine_id":"other"`, 1),
		strings.Replace(hookdRegistrationFixture, `"product":"claude-code"`, `"product":"claude-code","secret":"value"`, 1),
		strings.Replace(hookdRegistrationFixture, `"schema_version":"1.0"`, `"schema_version":"1.0","agent_product":"other"`, 1),
		strings.Replace(hookdRegistrationFixture, `"adapter":{"name":"claude-code-plugin","version":"0.1.0"}`, `"adapter":null`, 1),
		hookdRegistrationFixture + " {}",
	} {
		if _, err := decodeAgentRegistration(strings.NewReader(raw)); err == nil {
			t.Fatal("invalid registration accepted")
		}
	}
}
func TestHookdRegistrationPreservesLegacyFlatForm(t *testing.T) {
	r, err := decodeAgentRegistration(strings.NewReader(`{"machine_id":"m","hostname":"h","os":"linux","arch":"amd64","agent_product":"claude-code","adapter_name":"legacy"}`))
	if err != nil || r.AgentProduct != "claude-code" || r.AdapterName != "legacy" {
		t.Fatalf("legacy registration: %+v %v", r, err)
	}
}

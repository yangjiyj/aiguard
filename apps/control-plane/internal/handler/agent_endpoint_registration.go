package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/endpointevents"
)

// decodeAgentRegistration accepts the actual hookd 1.0 registration envelope and
// the existing flat registration form, while rejecting ambiguous mixed identities.
func decodeAgentRegistration(body io.Reader) (repository.AgentEndpointRegisterRequest, error) {
	var result repository.AgentEndpointRegisterRequest
	raw, err := io.ReadAll(body)
	if err != nil {
		return result, err
	}
	if _, err = endpointevents.Decode(raw); err != nil {
		return result, err
	}
	var shape map[string]json.RawMessage
	if err = json.Unmarshal(raw, &shape); err != nil {
		return result, err
	}
	_, hasSchema := shape["schema_version"]
	_, hasAgent := shape["agent"]
	_, hasAdapter := shape["adapter"]
	if !hasSchema && !hasAgent && !hasAdapter {
		if err = decodeStrictJSON(bytes.NewReader(raw), &result); err != nil {
			return result, err
		}
		return result, result.Validate()
	}
	for _, key := range []string{"agent_product", "agent_version", "install_path_hash", "adapter_name", "adapter_version"} {
		if _, exists := shape[key]; exists {
			return result, errors.New("mixed registration identity")
		}
	}
	var wire struct {
		SchemaVersion string   `json:"schema_version"`
		MachineID     string   `json:"machine_id"`
		Hostname      string   `json:"hostname"`
		OS            string   `json:"os"`
		OSVersion     string   `json:"os_version"`
		Arch          string   `json:"arch"`
		OSUser        string   `json:"os_user"`
		HookdVersion  string   `json:"hookd_version"`
		Capabilities  []string `json:"capabilities"`
		Agent         *struct {
			Product         string `json:"product"`
			Version         string `json:"version"`
			InstallPathHash string `json:"install_path_hash"`
		} `json:"agent"`
		Adapter *struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"adapter"`
	}
	if err = decodeStrictJSON(bytes.NewReader(raw), &wire); err != nil {
		return result, err
	}
	if wire.SchemaVersion != "1.0" || wire.Agent == nil || wire.Adapter == nil || wire.Adapter.Name == "" || wire.HookdVersion == "" {
		return result, errors.New("invalid hookd registration envelope")
	}
	result = repository.AgentEndpointRegisterRequest{
		MachineID: wire.MachineID, Hostname: wire.Hostname, OS: wire.OS, OSVersion: wire.OSVersion, Arch: wire.Arch, OSUser: wire.OSUser,
		AgentProduct: wire.Agent.Product, AgentVersion: wire.Agent.Version, InstallPathHash: wire.Agent.InstallPathHash,
		AdapterName: wire.Adapter.Name, AdapterVersion: wire.Adapter.Version, HookdVersion: wire.HookdVersion, Capabilities: wire.Capabilities,
	}
	return result, result.Validate()
}

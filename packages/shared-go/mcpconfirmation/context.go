package mcpconfirmation

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const ReplayContextVersion = 2

const (
	scopeKeyDomain   = "jjdguard:mcp-confirmation:scope:v1"
	principalDomain  = "jjdguard:mcp-confirmation:principal:v1"
	responseAADLabel = "jjdguard:mcp-confirmation:result-aad:v2"
)

// ReplayContext is the only plaintext representation of an approved MCP call.
// Control-plane encrypts the JSON form before persistence; gateway-core decrypts
// it only inside the single-use internal execution endpoint.
type ReplayContext struct {
	Version             int             `json:"version"`
	TenantID            string          `json:"tenant_id"`
	ProjectID           string          `json:"project_id,omitempty"`
	UserID              string          `json:"user_id,omitempty"`
	ClientID            string          `json:"client_id,omitempty"`
	KeyPrefix           string          `json:"key_prefix,omitempty"`
	EnvironmentScope    string          `json:"environment_scope,omitempty"`
	AgentType           string          `json:"agent_type,omitempty"`
	AgentSessionID      string          `json:"agent_session_id,omitempty"`
	SourceIP            string          `json:"source_ip,omitempty"`
	OperationID         string          `json:"operation_id,omitempty"`
	TraceID             string          `json:"trace_id,omitempty"`
	OriginalRequest     string          `json:"original_request_id,omitempty"`
	ServerID            string          `json:"server_id"`
	ToolName            string          `json:"tool_name"`
	ToolCallID          string          `json:"tool_call_id"`
	ProtocolVersion     string          `json:"protocol_version"`
	MCPSessionID        string          `json:"mcp_session_id,omitempty"`
	ToolID              string          `json:"tool_id"`
	SupplyChainRevision string          `json:"supply_chain_revision"`
	ApprovedSchemaHash  string          `json:"approved_schema_hash"`
	ServerRouteHash     string          `json:"server_route_hash"`
	RequestBody         json.RawMessage `json:"request_body"`
}

func derivedHMACKey(secret, domain string) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("MCP confirmation scope secret is not configured")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(domain))
	return mac.Sum(nil), nil
}

func writeLengthPrefixed(dst *bytes.Buffer, values ...string) {
	var size [8]byte
	for _, value := range values {
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		dst.Write(size[:])
		dst.WriteString(value)
	}
}

func confirmationSession(c ReplayContext) string {
	if c.MCPSessionID != "" {
		return c.MCPSessionID
	}
	return c.AgentSessionID
}

func ScopeKey(secret string, c ReplayContext) (string, error) {
	key, err := derivedHMACKey(secret, scopeKeyDomain)
	if err != nil {
		return "", err
	}
	var encoded bytes.Buffer
	writeLengthPrefixed(&encoded,
		c.TenantID, c.ClientID, c.KeyPrefix, c.ProjectID, c.UserID,
		c.ServerID, confirmationSession(c), c.ProtocolVersion, c.ToolCallID,
	)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(encoded.Bytes())
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func PrincipalFingerprint(secret string, c ReplayContext) (string, error) {
	key, err := derivedHMACKey(secret, principalDomain)
	if err != nil {
		return "", err
	}
	var encoded bytes.Buffer
	writeLengthPrefixed(&encoded, c.TenantID, c.ClientID, c.KeyPrefix, c.ProjectID, c.UserID)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(encoded.Bytes())
	return hex.EncodeToString(mac.Sum(nil)), nil
}

type canonicalRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  struct {
		Name      string `json:"name"`
		Arguments any    `json:"arguments"`
	} `json:"params"`
}

func canonicalToolsCall(c ReplayContext) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(c.RequestBody))
	decoder.UseNumber()
	var request canonicalRPCRequest
	if err := decoder.Decode(&request); err != nil {
		return nil, fmt.Errorf("decode tools/call: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("tools/call contains trailing JSON")
	}
	if request.JSONRPC != "2.0" || request.Method != "tools/call" ||
		request.Params.Name == "" || request.Params.Name != c.ToolName {
		return nil, errors.New("invalid canonical tools/call")
	}
	canonical := struct {
		Method              string `json:"method"`
		Tool                string `json:"tool"`
		Arguments           any    `json:"arguments"`
		ToolID              string `json:"tool_id"`
		SupplyChainRevision string `json:"supply_chain_revision"`
		ApprovedSchemaHash  string `json:"approved_schema_hash"`
		ServerRouteHash     string `json:"server_route_hash"`
	}{
		Method: "tools/call", Tool: request.Params.Name, Arguments: request.Params.Arguments,
		ToolID: c.ToolID, SupplyChainRevision: c.SupplyChainRevision,
		ApprovedSchemaHash: c.ApprovedSchemaHash, ServerRouteHash: c.ServerRouteHash,
	}
	return json.Marshal(canonical)
}

func CanonicalRequestHash(c ReplayContext) (string, error) {
	canonical, err := canonicalToolsCall(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func ResponseAAD(secret string, c ReplayContext, invocationID, confirmationID, requestHash, responseHash string) ([]byte, error) {
	principal, err := PrincipalFingerprint(secret, c)
	if err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	writeLengthPrefixed(&encoded,
		responseAADLabel, c.TenantID, principal, c.ServerID, invocationID,
		confirmationID, requestHash, responseHash,
	)
	return encoded.Bytes(), nil
}

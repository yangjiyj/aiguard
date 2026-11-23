package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

func mcpResultFixture(t *testing.T) (mcpconfirmation.ReplayContext, *mcpConfirmationExecutionRecord, string) {
	t.Helper()
	secret := "confirmation-result-scope-secret"
	replay := mcpconfirmation.ReplayContext{
		Version: mcpconfirmation.ReplayContextVersion, TenantID: "tenant-a",
		ProjectID: "project-a", UserID: "user-a", ClientID: "client-a", KeyPrefix: "sk-a",
		AgentType: "claude-code", AgentSessionID: "agent-session-a",
		ServerID: "server-a", ToolName: "write", ToolCallID: "number:9",
		ProtocolVersion: mcpProtocolVersionLatest, MCPSessionID: "mcp-session-a",
		ToolID: "tool-a", SupplyChainRevision: "revision-a",
		ApprovedSchemaHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ServerRouteHash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequestBody:        json.RawMessage(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"write","arguments":{"path":"/tmp/safe"}}}`),
	}
	scopeKey, err := mcpconfirmation.ScopeKey(secret, replay)
	if err != nil {
		t.Fatal(err)
	}
	requestHash, err := mcpconfirmation.CanonicalRequestHash(replay)
	if err != nil {
		t.Fatal(err)
	}
	principalHash, err := mcpconfirmation.PrincipalFingerprint(secret, replay)
	if err != nil {
		t.Fatal(err)
	}
	record := &mcpConfirmationExecutionRecord{
		ConfirmationID: "cf-a", InvocationID: "inv-a", TenantID: replay.TenantID,
		ConfirmationState: "approved", ExecutionStatus: "executed", EvidenceStatus: "complete",
		ScopeKey: scopeKey, CanonicalRequestHash: requestHash, PrincipalHash: principalHash,
		ToolID: replay.ToolID, SupplyChainRevision: replay.SupplyChainRevision,
		ApprovedSchemaHash: replay.ApprovedSchemaHash, ServerRouteHash: replay.ServerRouteHash,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	return replay, record, secret
}

func attachEncryptedMCPResult(t *testing.T, secret string, replay mcpconfirmation.ReplayContext, record *mcpConfirmationExecutionRecord, expiresAt time.Time) []byte {
	t.Helper()
	result := []byte(`{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"done"}]}}`)
	digest := sha256.Sum256(result)
	record.ResultHash = hex.EncodeToString(digest[:])
	aad, err := mcpconfirmation.ResponseAAD(secret, replay, record.InvocationID, record.ConfirmationID, record.CanonicalRequestHash, record.ResultHash)
	if err != nil {
		t.Fatal(err)
	}
	record.ResultCiphertext, err = secrets.EncryptMCPResult(result, aad)
	if err != nil {
		t.Fatal(err)
	}
	record.ResultPlaintextBytes = int64(len(result))
	record.ResultHTTPStatus = 200
	record.ResultMediaType = "application/json"
	record.ResultRPCID = replay.ToolCallID
	record.ResultProtocol = replay.ProtocolVersion
	record.ResultSessionID = replay.MCPSessionID
	record.ResultExpiresAt = &expiresAt
	return result
}

func newMCPResultTestProxy(record *mcpConfirmationExecutionRecord, secret string) *MCPProxyHandler {
	client := NewToolRiskClient("http://unused.invalid", "internal-api-secret")
	client.SetMCPConfirmationScopeSecret(secret)
	handler := NewMCPProxyHandler(nil, client, false)
	handler.confirmationExecutionStore = &fakeMCPExecutionStore{record: record}
	return handler
}

func TestMCPConfirmationResultReplaysExactCachedBodyWithoutExecution(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "confirmation-result-encryption-key")
	replay, record, secret := mcpResultFixture(t)
	want := attachEncryptedMCPResult(t, secret, replay, record, time.Now().Add(time.Minute))
	handler := newMCPResultTestProxy(record, secret)

	result := handler.waitMCPConfirmationResult(context.Background(), MCPConfirmationTicket{ConfirmationID: record.ConfirmationID, InvocationID: record.InvocationID}, replay, 0)
	if !result.Terminal || result.ErrorCode != "" || !bytes.Equal(result.Body, want) {
		t.Fatalf("result=%+v body=%s", result, result.Body)
	}
}

func TestMCPConfirmationExpiredResultIsTerminalAndNeverReopened(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "confirmation-result-expiry-key")
	replay, record, secret := mcpResultFixture(t)
	attachEncryptedMCPResult(t, secret, replay, record, time.Now().Add(-time.Second))
	handler := newMCPResultTestProxy(record, secret)

	for i := 0; i < 2; i++ {
		result := handler.waitMCPConfirmationResult(context.Background(), MCPConfirmationTicket{ConfirmationID: record.ConfirmationID, InvocationID: record.InvocationID}, replay, 0)
		if !result.Terminal || result.ErrorCode != "result_expired" || len(result.Body) != 0 {
			t.Fatalf("attempt %d result=%+v", i, result)
		}
	}
	if record.ExecutionStatus != "executed" {
		t.Fatalf("expired result changed execution tombstone: %s", record.ExecutionStatus)
	}
}

func TestMCPConfirmationWaitCancellationReturnsWithoutChangingState(t *testing.T) {
	replay, record, secret := mcpResultFixture(t)
	record.ExecutionStatus = "executing"
	record.EvidenceStatus = "pending"
	record.ResultCiphertext = ""
	handler := newMCPResultTestProxy(record, secret)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	result := handler.waitMCPConfirmationResult(ctx, MCPConfirmationTicket{ConfirmationID: record.ConfirmationID, InvocationID: record.InvocationID}, replay, 5*time.Second)
	if result.ErrorCode != "confirmation_wait_cancelled" || time.Since(started) > time.Second {
		t.Fatalf("cancel result=%+v elapsed=%s", result, time.Since(started))
	}
	if record.ExecutionStatus != "executing" {
		t.Fatalf("client cancellation mutated execution state: %s", record.ExecutionStatus)
	}
}

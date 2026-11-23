package handler

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

func TestMCPModernJSONRPCBatchIsAlwaysRejected(t *testing.T) {
	env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}, http.StatusOK)
	body := buildMCPBatch(2, true)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if !strings.Contains(w.Body.String(), `"code":-32600`) {
		t.Fatalf("MCP 2025-06-18+ 已移除 batch，必须明确拒绝: status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("batch 不得触达上游: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
}

func TestMCPUpstreamRequestStripsCallerCredentialsAndInjectsSavedBearer(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-transport-test-key")
	ciphertext, keyRef, err := secrets.EncryptProviderSecret("upstream-secret")
	if err != nil {
		t.Fatal(err)
	}
	server := &mcpServerRoute{
		ServerURL:      "https://mcp.example/rpc?route=saved",
		AuthCiphertext: ciphertext,
		AuthKeyRef:     keyRef,
	}
	in := httptest.NewRequest(http.MethodPost, "/mcp/s1?api_key=caller-secret&token=caller-secret", strings.NewReader(`{}`))
	in.Header.Set("Authorization", "Bearer caller-secret")
	in.Header.Set("Cookie", "session=caller")
	in.Header.Set("X-Api-Key", "caller-api-key")
	in.Header.Set("Api-Key", "caller-api-key-2")
	in.Header.Set("Connection", "X-Hop-Secret")
	in.Header.Set("X-Hop-Secret", "must-not-forward")
	in.Header.Set("Proxy-Authenticate", "must-not-forward")
	in.Header.Set("Mcp-Session-Id", "session-1")
	in.Header.Set("MCP-Protocol-Version", mcpProtocolVersionLatest)

	out, err := buildMCPUpstreamRequest(context.Background(), server, in, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Header.Get("Authorization"); got != "Bearer upstream-secret" {
		t.Fatalf("saved upstream bearer not injected: %q", got)
	}
	for _, name := range []string{"Cookie", "X-Api-Key", "Api-Key", "X-Hop-Secret", "Proxy-Authenticate"} {
		if got := out.Header.Get(name); got != "" {
			t.Fatalf("caller credential %s leaked: %q", name, got)
		}
	}
	if out.Header.Get("Mcp-Session-Id") != "session-1" ||
		out.Header.Get("Mcp-Protocol-Version") != mcpProtocolVersionLatest {
		t.Fatal("MCP session/protocol headers must survive credential stripping")
	}
	if strings.Contains(out.URL.String(), "upstream-secret") {
		t.Fatal("upstream secret must never enter URL")
	}
	if out.URL.RawQuery != "route=saved" {
		t.Fatalf("caller query credentials leaked or saved route query lost: %q", out.URL.RawQuery)
	}
}

func TestMCPUpstreamRequestInjectsConfiguredCustomHeader(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-transport-test-key")
	ciphertext, keyRef, err := secrets.EncryptProviderSecret("custom-secret")
	if err != nil {
		t.Fatal(err)
	}
	server := &mcpServerRoute{
		ServerURL:      "https://mcp.example/rpc",
		AuthCiphertext: ciphertext,
		AuthKeyRef:     keyRef,
		AuthHeaderName: "X-MCP-Token",
	}
	in := httptest.NewRequest(http.MethodPost, "/mcp/s1", strings.NewReader(`{}`))
	in.Header.Set("X-MCP-Token", "caller-value")
	out, err := buildMCPUpstreamRequest(context.Background(), server, in, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Header.Get("X-MCP-Token"); got != "custom-secret" {
		t.Fatalf("custom upstream header=%q", got)
	}
	if out.Header.Get("Authorization") != "" {
		t.Fatal("custom header mode must not synthesize Authorization")
	}
}

func TestMCPUpstreamCredentialErrorsNeverEchoCiphertextOrPlaintext(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "wrong-key")
	server := &mcpServerRoute{
		ServerURL:      "https://mcp.example/rpc",
		AuthCiphertext: "enc:v1:not-valid-sensitive-ciphertext",
		AuthKeyRef:     "env:JJD_PROVIDER_SECRET_KEY",
	}
	in := httptest.NewRequest(http.MethodPost, "/mcp/s1", strings.NewReader(`{}`))
	_, err := buildMCPUpstreamRequest(context.Background(), server, in, []byte(`{}`))
	if err == nil {
		t.Fatal("invalid ciphertext must fail closed")
	}
	message := err.Error()
	for _, forbidden := range []string{server.AuthCiphertext, "not-valid-sensitive-ciphertext", "wrong-key"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("credential error leaked sensitive material: %q", message)
		}
	}
}

func TestMCPUpstreamNetworkErrorStripsURLSecrets(t *testing.T) {
	root := errors.New("dial failed")
	err := sanitizeMCPUpstreamError(&url.Error{
		Op: "POST", URL: "https://mcp.example/rpc?token=upstream-secret", Err: root,
	})
	if strings.Contains(err.Error(), "upstream-secret") || strings.Contains(err.Error(), "token=") {
		t.Fatalf("upstream error leaked URL query: %q", err)
	}
	if !errors.Is(err, root) {
		t.Fatalf("sanitized error lost root cause: %v", err)
	}
}
func TestMCPProtocolVersionValidation(t *testing.T) {
	for _, version := range []string{mcpProtocolVersionLatest, mcpProtocolVersionPrevious, "2025-03-26", "2024-11-05"} {
		if err := validateMCPProtocolVersion(version); err != nil {
			t.Fatalf("supported version %s rejected: %v", version, err)
		}
	}
	for _, version := range []string{"", "2023-01-01", "2099-01-01", "garbage"} {
		if err := validateMCPProtocolVersion(version); err == nil {
			t.Fatalf("unsupported protocol version %q accepted", version)
		}
	}
}

func TestMCPNonStreamingResponseHasHardCapacity(t *testing.T) {
	tooLarge := bytes.NewReader(bytes.Repeat([]byte("x"), maxMCPNonStreamingResponseBytes+1))
	_, err := readMCPBoundedBody(tooLarge, maxMCPNonStreamingResponseBytes)
	if !errors.Is(err, errMCPResponseTooLarge) {
		t.Fatalf("oversized response error=%v", err)
	}
}

func TestMCPSSEEventAndCumulativeCaps(t *testing.T) {
	oneHugeEvent := "data: " + strings.Repeat("x", maxMCPSSEEventBytes+1) + "\n\n"
	err := validateAndCopyMCPSSE(io.Discard, nil, strings.NewReader(oneHugeEvent))
	if !errors.Is(err, errMCPSSEEventTooLarge) {
		t.Fatalf("oversized SSE event error=%v", err)
	}

	var stream strings.Builder
	event := "data: " + strings.Repeat("x", 1024) + "\n\n"
	for stream.Len()+len(event) <= maxMCPSSECumulativeBytes {
		stream.WriteString(event)
	}
	stream.WriteString(event)
	err = validateAndCopyMCPSSE(io.Discard, nil, strings.NewReader(stream.String()))
	if !errors.Is(err, errMCPSSEStreamTooLarge) {
		t.Fatalf("oversized SSE stream error=%v", err)
	}
}

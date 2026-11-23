package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

// P0-3 invariant R: in record mode no security reason interrupts a request;
// a failed inspection never interrupts in any mode. Every exit decides through
// packages/shared-go/securityexit, whose blocking set is block/reply/deny/quarantine.

var gatewayBlockingActions = []string{"block", "reply", "deny", "quarantine"}

func TestRecordModeNeverEnforces_ChatInputBlockingActions(t *testing.T) {
	for _, action := range gatewayBlockingActions {
		t.Run(action, func(t *testing.T) {
			audit := &MockAuditWriter{}
			h := &ChatCompletionsHandler{
				cfg:            &config.Config{SecurityAuditOnly: true},
				securityClient: &MockSecurityChecker{InputAction: action, InputFindings: []SecurityFinding{{Type: "pii", Severity: "high", Action: action}}},
				auditWriter:    audit,
			}
			req := &ChatCompletionRequest{Model: "glm-5", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
			if _, err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req); err != nil {
				t.Fatalf("record mode interrupted chat input for action=%s: %v", action, err)
			}
			if !hasSecurityEvent(audit, "security_audit_only") {
				t.Fatalf("record mode did not retain the hit: %+v", audit.SecurityEventWrites)
			}
		})
	}
}

func TestProtectModeEnforcesChatInputBlockingSet(t *testing.T) {
	for _, action := range gatewayBlockingActions {
		t.Run(action, func(t *testing.T) {
			h := &ChatCompletionsHandler{
				cfg:            &config.Config{},
				securityClient: &MockSecurityChecker{InputAction: action},
				auditWriter:    &MockAuditWriter{},
			}
			req := &ChatCompletionRequest{Model: "glm-5", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
			if _, err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req); err == nil {
				t.Fatalf("protect mode forwarded blocking action %s", action)
			}
		})
	}
	h := &ChatCompletionsHandler{cfg: &config.Config{}, securityClient: &MockSecurityChecker{InputAction: "mask"}, auditWriter: &MockAuditWriter{}}
	req := &ChatCompletionRequest{Model: "glm-5", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	if _, err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req); err != nil {
		t.Fatalf("mask is a rewrite, not a block: %v", err)
	}
}

func TestDetectionFailureNeverEnforces_ChatInputAndOutput(t *testing.T) {
	for _, auditOnly := range []bool{false, true} {
		cfg := &config.Config{SecurityAuditOnly: auditOnly, GuardrailFailureMode: "close"}
		h := &ChatCompletionsHandler{cfg: cfg, securityClient: &MockSecurityChecker{InputError: errors.New("engine down"), OutputError: errors.New("engine down")}, auditWriter: &MockAuditWriter{}}
		req := &ChatCompletionRequest{Model: "glm-5", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
		if _, err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req); err != nil {
			t.Fatalf("auditOnly=%v: input detection failure interrupted: %v", auditOnly, err)
		}
		respBody := mustMarshalChatResponse(t, ChatCompletionResponse{
			ID: "chatcmpl-gap", Object: "chat.completion", Model: "glm-5",
			Choices: []Choice{{Index: 0, Message: ChoiceMessage{Role: "assistant", Content: "text"}}},
		})
		_, result, err := h.applyOutputSecurity(context.Background(), newFailModeEnvelope(), nil, respBody)
		if err != nil {
			t.Fatalf("auditOnly=%v: output detection failure interrupted: %v", auditOnly, err)
		}
		if result == nil || result.OutputAction != "audit" {
			t.Fatalf("auditOnly=%v: detection failure must record audit, got %+v", auditOnly, result)
		}
	}
}

func TestRecordModeNeverEnforces_ChatBufferedOutput(t *testing.T) {
	for _, action := range gatewayBlockingActions {
		t.Run(action, func(t *testing.T) {
			h := &ChatCompletionsHandler{
				cfg:            &config.Config{SecurityAuditOnly: true},
				securityClient: &MockSecurityChecker{OutputAction: action},
				auditWriter:    &MockAuditWriter{},
			}
			respBody := mustMarshalChatResponse(t, ChatCompletionResponse{
				ID: "chatcmpl-rec", Object: "chat.completion", Model: "glm-5",
				Choices: []Choice{{Index: 0, Message: ChoiceMessage{Role: "assistant", Content: "text"}}},
			})
			secured, result, err := h.applyOutputSecurity(context.Background(), newFailModeEnvelope(), nil, respBody)
			if err != nil {
				t.Fatalf("record mode interrupted output for action=%s: %v", action, err)
			}
			if string(secured) != string(respBody) || result == nil || result.OutputAction != "audit" {
				t.Fatalf("record mode altered output: result=%+v", result)
			}
		})
	}
}

func TestProtectModeEnforcesChatBufferedOutputBlockingSet(t *testing.T) {
	for _, action := range gatewayBlockingActions {
		t.Run(action, func(t *testing.T) {
			h := &ChatCompletionsHandler{cfg: &config.Config{}, securityClient: &MockSecurityChecker{OutputAction: action}, auditWriter: &MockAuditWriter{}}
			respBody := mustMarshalChatResponse(t, ChatCompletionResponse{
				ID: "chatcmpl-pro", Object: "chat.completion", Model: "glm-5",
				Choices: []Choice{{Index: 0, Message: ChoiceMessage{Role: "assistant", Content: "text"}}},
			})
			if _, _, err := h.applyOutputSecurity(context.Background(), newFailModeEnvelope(), nil, respBody); err == nil {
				t.Fatalf("protect mode forwarded output with blocking action %s", action)
			}
		})
	}
}

func TestRecordModeNeverEnforces_EmbeddingsAndImagesInput(t *testing.T) {
	for _, action := range gatewayBlockingActions {
		t.Run(action, func(t *testing.T) {
			emb := &EmbeddingsHandler{cfg: &config.Config{SecurityAuditOnly: true}, securityClient: &MockSecurityChecker{InputAction: action}, auditWriter: &MockAuditWriter{}}
			if err := emb.applyInputSecurity(context.Background(), newFailModeEnvelope(), &EmbeddingsRequest{Model: "e", Input: "x"}); err != nil {
				t.Fatalf("record mode interrupted embeddings for %s: %v", action, err)
			}
			img := &ImagesHandler{cfg: &config.Config{SecurityAuditOnly: true}, securityClient: &MockSecurityChecker{InputAction: action}, auditWriter: &MockAuditWriter{}}
			if _, err := img.applyInputSecurity(context.Background(), newFailModeEnvelope(), &ImagesRequest{Prompt: "p"}, nil, []byte(`{"prompt":"p"}`)); err != nil {
				t.Fatalf("record mode interrupted images for %s: %v", action, err)
			}

			embP := &EmbeddingsHandler{cfg: &config.Config{}, securityClient: &MockSecurityChecker{InputAction: action}, auditWriter: &MockAuditWriter{}}
			if err := embP.applyInputSecurity(context.Background(), newFailModeEnvelope(), &EmbeddingsRequest{Model: "e", Input: "x"}); err == nil {
				t.Fatalf("protect mode forwarded embeddings with %s", action)
			}
			imgP := &ImagesHandler{cfg: &config.Config{}, securityClient: &MockSecurityChecker{InputAction: action}, auditWriter: &MockAuditWriter{}}
			if _, err := imgP.applyInputSecurity(context.Background(), newFailModeEnvelope(), &ImagesRequest{Prompt: "p"}, nil, []byte(`{"prompt":"p"}`)); err == nil {
				t.Fatalf("protect mode forwarded images with %s", action)
			}
		})
	}
}

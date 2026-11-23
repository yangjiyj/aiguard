package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionfmt"
)

const chatToolCallEvidenceSource = "chat_tool_call_id"

func responsesEvidenceCorrelation(req *ResponsesRequest) (string, string) {
	if req == nil {
		return "", ""
	}
	for _, candidate := range []struct{ key, source string }{
		{"thread_id", "responses_client_thread_id"},
		{"task_id", "responses_client_task_id"},
		{"conversation_id", "responses_client_conversation_id"},
		{"session_id", "responses_client_session_id"},
	} {
		if value, ok := req.ClientMetadata[candidate.key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value), candidate.source
		}
	}
	if value := strings.TrimSpace(req.PromptCacheKey); value != "" {
		return value, "responses_prompt_cache_key_candidate"
	}
	return "", ""
}

func workBuddyEvidenceCorrelation(agentType string, messages []Message) (string, string) {
	if strings.TrimSpace(strings.ToLower(agentType)) != "workbuddy" {
		return "", ""
	}
	for _, message := range messages {
		if message.Role != "user" {
			continue
		}
		if workspace := retentionfmt.WorkBuddyWorkspaceFolder(messageText(message.Content)); workspace != "" {
			return workspace, "workbuddy_workspace"
		}
	}
	return "", ""
}

func initializeChatToolEvidenceSubject(envelope *modelrouter.RequestEnvelope) {
	if envelope == nil {
		return
	}
	envelope.EvidenceRunSubjectHash = ""
	if strings.TrimSpace(envelope.TenantID) == "" || strings.TrimSpace(envelope.AgentType) == "" {
		return
	}
	// JSON framing prevents attacker-controlled identity values from creating
	// ambiguous tuples. Freeze logical routing identity before attempts mutate it.
	identity, err := json.Marshal([]string{
		"chat_tool_subject_v1",
		strings.TrimSpace(envelope.TenantID),
		strings.TrimSpace(envelope.EnvironmentScope),
		strings.TrimSpace(envelope.UserID),
		strings.TrimSpace(envelope.ClientID),
		strings.TrimSpace(envelope.ProjectID),
		strings.TrimSpace(envelope.SourceIP),
		strings.TrimSpace(envelope.ProviderID),
		strings.TrimSpace(envelope.Provider),
		strings.TrimSpace(envelope.ModelID),
		strings.TrimSpace(envelope.Model),
		strings.TrimSpace(envelope.EndpointType),
		strings.ToLower(strings.TrimSpace(envelope.AgentType)),
		strings.ToLower(strings.TrimSpace(envelope.AgentRuntime)),
	})
	if err != nil {
		return
	}
	digest := sha256.Sum256(identity)
	envelope.EvidenceRunSubjectHash = hex.EncodeToString(digest[:])
}

func chatToolMessagePrefixHash(req *ChatCompletionRequest, messageCount int) string {
	if req == nil || messageCount < 0 || messageCount > len(req.Messages) {
		return ""
	}
	prefix := struct {
		Version     string    `json:"version"`
		ContextHash string    `json:"context_hash,omitempty"`
		Tools       []ToolDef `json:"tools"`
		Messages    []Message `json:"messages"`
	}{
		Version:     "chat_tool_prefix_v1",
		ContextHash: req.ToolCorrelationContextHash,
		Tools:       req.Tools,
		Messages:    req.Messages[:messageCount],
	}
	encoded, err := json.Marshal(prefix)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func shouldPrepareChatToolEvidence(envelope *modelrouter.RequestEnvelope, req *ChatCompletionRequest) bool {
	if envelope == nil || req == nil || envelope.EvidenceRunSubjectHash == "" || strings.TrimSpace(envelope.SessionID) != "" {
		return false
	}
	if strings.TrimSpace(envelope.EvidenceRunID) != "" && !weakEvidenceRunSource(envelope.EvidenceRunSource) {
		return false
	}
	if len(req.Tools) > 0 || req.ToolCorrelationCandidate {
		return true
	}
	for i := range req.Messages {
		message := req.Messages[i]
		if len(message.ToolCalls) > 0 {
			return true
		}
		role := strings.ToLower(strings.TrimSpace(message.Role))
		if (role == "tool" || role == "function") && message.ToolCallID != "" {
			return true
		}
	}
	return false
}

func responsesToolCorrelationContextHash(req *ResponsesRequest) string {
	if req == nil || len(req.Tools) == 0 {
		return ""
	}
	encoded, err := json.Marshal(struct {
		Version string          `json:"version"`
		Tools   []ResponsesTool `json:"tools"`
	}{Version: "responses_tool_context_v1", Tools: req.Tools})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func strongOpaqueToolCallID(value string) bool {
	if value != strings.TrimSpace(value) || len(value) < 24 {
		return false
	}
	distinct := make(map[rune]struct{}, 16)
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
		distinct[r] = struct{}{}
	}
	return len(distinct) >= 8
}

type chatToolEvidenceAnchor struct {
	ToolCallID string
	PrefixHash string
}

type chatToolProposal struct {
	messageIndex     int
	anchorToolCallID string
	valid            bool
}

func validChatToolCallBatch(calls []ToolCall) []string {
	counts := make(map[string]int, len(calls))
	for i := range calls {
		counts[calls[i].ID]++
	}
	valid := make([]string, 0, len(calls))
	for i := range calls {
		call := calls[i]
		if counts[call.ID] != 1 || call.ProtocolIdentityRejected || !strongOpaqueToolCallID(call.ID) || strings.TrimSpace(call.Function.Name) == "" {
			continue
		}
		valid = append(valid, call.ID)
	}
	return valid
}

func observedChatToolEvidence(req *ChatCompletionRequest) chatToolEvidenceAnchor {
	if req == nil {
		return chatToolEvidenceAnchor{}
	}
	proposals := make(map[string]chatToolProposal)
	for messageIndex := range req.Messages {
		message := req.Messages[messageIndex]
		switch strings.ToLower(strings.TrimSpace(message.Role)) {
		case "assistant":
			for i := range message.ToolCalls {
				if previous, exists := proposals[message.ToolCalls[i].ID]; exists {
					previous.valid = false
					proposals[message.ToolCalls[i].ID] = previous
				}
			}
			batch := validChatToolCallBatch(message.ToolCalls)
			fresh := make([]string, 0, len(batch))
			for _, id := range batch {
				if _, exists := proposals[id]; exists {
					continue
				}
				fresh = append(fresh, id)
			}
			if len(fresh) == 0 {
				continue
			}
			for _, id := range fresh {
				proposals[id] = chatToolProposal{
					messageIndex: messageIndex, anchorToolCallID: fresh[0], valid: true,
				}
			}
		case "tool", "function":
			if !strongOpaqueToolCallID(message.ToolCallID) {
				continue
			}
			proposal, exists := proposals[message.ToolCallID]
			anchor, anchorExists := proposals[proposal.anchorToolCallID]
			if exists && proposal.valid && anchorExists && anchor.valid {
				return chatToolEvidenceAnchor{
					ToolCallID: proposal.anchorToolCallID,
					PrefixHash: chatToolMessagePrefixHash(req, proposal.messageIndex),
				}
			}
		}
	}
	return chatToolEvidenceAnchor{}
}

func proposedChatToolCallID(responseBody []byte) string {
	if len(responseBody) == 0 {
		return ""
	}
	var response ChatCompletionResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return ""
	}
	var selected []string
	for i := range response.Choices {
		if !strings.EqualFold(strings.TrimSpace(response.Choices[i].Message.Role), "assistant") {
			continue
		}
		batch := validChatToolCallBatch(response.Choices[i].Message.ToolCalls)
		if len(batch) == 0 {
			continue
		}
		if selected != nil {
			return ""
		}
		selected = batch
	}
	if len(selected) > 0 {
		return selected[0]
	}
	return ""
}

func bindChatToolEvidence(envelope *modelrouter.RequestEnvelope, prefixHash, toolCallID string) {
	if envelope == nil || strings.TrimSpace(envelope.SessionID) != "" {
		return
	}
	if strings.TrimSpace(envelope.EvidenceRunID) != "" && !weakEvidenceRunSource(envelope.EvidenceRunSource) {
		return
	}
	prefixHash = strings.TrimSpace(prefixHash)
	if !strongOpaqueToolCallID(toolCallID) || prefixHash == "" || envelope.EvidenceRunSubjectHash == "" {
		return
	}
	// Use the complete opaque ID. deriveEvidenceRunID applies the tenant-scoped
	// one-way digest before the key reaches durable storage.
	envelope.EvidenceRunID = deriveEvidenceRunID(
		envelope.TenantID,
		chatToolCallEvidenceSource,
		envelope.EvidenceRunSubjectHash+"\x00"+prefixHash+"\x00"+toolCallID,
	)
	if envelope.EvidenceRunID != "" {
		envelope.EvidenceRunSource = chatToolCallEvidenceSource
	}
}

func weakEvidenceRunSource(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "responses_prompt_cache_key", "responses_prompt_cache_key_candidate":
		return true
	default:
		return false
	}
}

func bindChatToolEvidenceFromRequest(envelope *modelrouter.RequestEnvelope, req *ChatCompletionRequest) {
	anchor := observedChatToolEvidence(req)
	bindChatToolEvidence(envelope, anchor.PrefixHash, anchor.ToolCallID)
}

func bindChatToolEvidenceFromResponse(envelope *modelrouter.RequestEnvelope, responseBody []byte) {
	if envelope == nil {
		return
	}
	bindChatToolEvidence(envelope, envelope.EvidenceRunPrefixHash, proposedChatToolCallID(responseBody))
}

func deriveEvidenceRunID(tenantID, source, key string) string {
	tenantID, source, key = strings.TrimSpace(tenantID), strings.TrimSpace(source), strings.TrimSpace(key)
	if tenantID == "" || source == "" || key == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s", tenantID, source, key)))
	return "run_" + hex.EncodeToString(digest[:16])
}

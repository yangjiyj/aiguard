package handler

import (
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
)

type chatRuntimeContextInput struct {
	requestID   string
	authInfo    *auth.AuthInfo
	request     *ChatCompletionRequest
	modelRecord *modelrouter.ModelRecord
	teamID      string
	routeHint   string
}

func buildChatPartialEnvelope(requestID string, authInfo *auth.AuthInfo, model string, endpointType string) *modelrouter.RequestEnvelope {
	trustedPrincipal := principalForGatewayEndpoint(authInfo.Principal, endpointType, "gateway_api", "")
	return &modelrouter.RequestEnvelope{
		RequestID:                requestID,
		TenantID:                 authInfo.TenantID,
		ProjectID:                authInfo.ProjectID,
		UserID:                   authInfo.UserID,
		ClientID:                 authInfo.KeyID,
		EnvironmentScope:         authInfo.EnvironmentScope,
		AgentIdentityHeaders:     authInfo.AgentIdentityHeaders,
		UserAgent:                authInfo.UserAgent,
		AgentType:                authInfo.AgentType,
		AgentInstanceID:          authInfo.AgentInstanceID,
		AgentRuntime:             authInfo.AgentRuntime,
		AgentDetectionSource:     authInfo.AgentDetectionSource,
		AgentDetectionConfidence: authInfo.AgentDetectionConfidence,
		SessionID:                authInfo.SessionID,
		WorkspaceID:              authInfo.WorkspaceID,
		TraceID:                  authInfo.TraceID,
		LSEEvalRunID:             authInfo.LSEEvalRunID,
		LSETaskID:                authInfo.LSETaskID,
		LSESampleID:              authInfo.LSESampleID,
		LSETargetID:              authInfo.LSETargetID,
		Model:                    model,
		EndpointType:             endpointType,
		SourceIP:                 authInfo.ClientIP,
		Principal:                trustedPrincipal,
	}
}

func buildChatRuntimeEnvelope(input chatRuntimeContextInput) *modelrouter.RequestEnvelope {
	promptTokens, contentSegments := chatPromptRoutingContext(input.request.Messages)
	evidenceKey, evidenceSource := input.request.EvidenceCorrelationKey, input.request.EvidenceCorrelationSource
	if evidenceKey == "" {
		evidenceKey, evidenceSource = workBuddyEvidenceCorrelation(input.authInfo.AgentType, input.request.Messages)
	}
	trustedPrincipal := principalForGatewayEndpoint(input.authInfo.Principal, requestEndpointType(input.request), "gateway_api", input.teamID)
	envelope := &modelrouter.RequestEnvelope{
		RequestID:                input.requestID,
		TenantID:                 input.authInfo.TenantID,
		TeamID:                   input.teamID,
		ProjectID:                input.authInfo.ProjectID,
		UserID:                   input.authInfo.UserID,
		ClientID:                 input.authInfo.KeyID,
		KeyPrefix:                input.authInfo.KeyPrefix,
		EnvironmentScope:         input.authInfo.EnvironmentScope,
		AgentIdentityHeaders:     input.authInfo.AgentIdentityHeaders,
		UserAgent:                input.authInfo.UserAgent,
		AgentType:                input.authInfo.AgentType,
		AgentInstanceID:          input.authInfo.AgentInstanceID,
		AgentRuntime:             input.authInfo.AgentRuntime,
		AgentDetectionSource:     input.authInfo.AgentDetectionSource,
		AgentDetectionConfidence: input.authInfo.AgentDetectionConfidence,
		SessionID:                input.authInfo.SessionID,
		EvidenceRunID:            deriveEvidenceRunID(input.authInfo.TenantID, evidenceSource, evidenceKey),
		EvidenceRunSource:        evidenceSource,
		WorkspaceID:              input.authInfo.WorkspaceID,
		TraceID:                  input.authInfo.TraceID,
		LSEEvalRunID:             input.authInfo.LSEEvalRunID,
		LSETaskID:                input.authInfo.LSETaskID,
		LSESampleID:              input.authInfo.LSESampleID,
		LSETargetID:              input.authInfo.LSETargetID,
		Model:                    input.request.Model,
		ModelID:                  input.modelRecord.ID,
		UpstreamModelID:          input.modelRecord.UpstreamModelID,
		EndpointType:             requestEndpointType(input.request),
		SourceIP:                 input.authInfo.ClientIP,
		Provider:                 input.modelRecord.ProviderType,
		ProviderID:               input.modelRecord.ProviderID,
		ProtocolCapabilities:     input.modelRecord.ProtocolCapabilities,
		RouteHint:                input.routeHint,
		PromptTokens:             promptTokens,
		ContentSegments:          contentSegments,
		Principal:                trustedPrincipal,
	}
	initializeChatToolEvidenceSubject(envelope)
	if shouldPrepareChatToolEvidence(envelope, input.request) {
		envelope.EvidenceRunPrefixHash = chatToolMessagePrefixHash(input.request, len(input.request.Messages))
		bindChatToolEvidenceFromRequest(envelope, input.request)
	}
	return envelope
}

func principalForGatewayEndpoint(base *principal.Context, protocol, entryPoint, applicationDepartmentID string) *principal.Context {
	if base == nil {
		return nil
	}
	copy := *base
	copy.Protocol = protocol
	copy.EntryPoint = entryPoint
	if applicationDepartmentID != "" {
		copy.ApplicationDepartmentID = applicationDepartmentID
	}
	normalized, err := principal.Normalize(copy)
	if err != nil {
		return nil
	}
	return &normalized
}

func requestEndpointType(request *ChatCompletionRequest) string {
	if request != nil && request.EndpointType != "" {
		return request.EndpointType
	}
	return "chat"
}

func chatPromptRoutingContext(messages []Message) (int, []modelrouter.ContentSegment) {
	var promptTokens int
	var contentSegments []modelrouter.ContentSegment
	for _, msg := range messages {
		t := messageText(msg.Content)
		promptTokens += len(t) / 4 // rough estimate: 1 token ~= 4 chars
		if t != "" {
			contentSegments = append(contentSegments, modelrouter.ContentSegment{Type: "text", Content: t})
		}
	}
	return promptTokens, contentSegments
}

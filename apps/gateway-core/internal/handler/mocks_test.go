package handler

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// MockModelResolver implements ModelResolver for testing
type MockModelResolver struct {
	ModelRecord     *modelrouter.ModelRecord
	ModelPolicy     *modelrouter.ModelPolicy
	QuotaPolicy     *modelrouter.QuotaPolicy
	ProviderRecord  *modelrouter.ProviderRecord
	ProvidersByID   map[string]*modelrouter.ProviderRecord
	ProviderAPIKey  string
	ResolveError    error
	PolicyError     error
	QuotaError      error
	ProviderError   error
	CredentialError error
	ReturnEmptyKey  bool // When true, GetProviderCredential returns empty string
}

func (m *MockModelResolver) ResolveModelWithDB(ctx context.Context, tenantID, modelName string) (*modelrouter.ModelRecord, error) {
	if m.ResolveError != nil {
		return nil, m.ResolveError
	}
	if m.ModelRecord == nil {
		return &modelrouter.ModelRecord{
			ID:                   "model-123",
			ProviderID:           "provider-123",
			ModelName:            modelName,
			ProviderType:         "openai",
			ProviderBaseURL:      "https://api.openai.com",
			Status:               "active",
			ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true, ResponsesNative: true, AnthropicMessages: true, Images: true, Embeddings: true, Files: true},
		}, nil
	}
	return m.ModelRecord, nil
}

func (m *MockModelResolver) GetModelPolicy(ctx context.Context, projectID string) (*modelrouter.ModelPolicy, error) {
	if m.PolicyError != nil {
		return nil, m.PolicyError
	}
	if m.ModelPolicy == nil {
		return &modelrouter.ModelPolicy{
			AllowList: []string{},
			DenyList:  []string{},
		}, nil
	}
	return m.ModelPolicy, nil
}

func (m *MockModelResolver) GetQuotaPolicy(ctx context.Context, projectID string) (*modelrouter.QuotaPolicy, error) {
	if m.QuotaError != nil {
		return nil, m.QuotaError
	}
	if m.QuotaPolicy == nil {
		return &modelrouter.QuotaPolicy{
			RPMLimit:          0,
			ConcurrencyLimit:  0,
			DailyTokenLimit:   0,
			MonthlyTokenLimit: 0,
		}, nil
	}
	return m.QuotaPolicy, nil
}

func (m *MockModelResolver) GetProviderCredential(ctx context.Context, providerID string) (string, error) {
	if m.CredentialError != nil {
		return "", m.CredentialError
	}
	if m.ReturnEmptyKey {
		return "", nil // Return empty key without error
	}
	if m.ProviderAPIKey == "" {
		return "mock-api-key", nil
	}
	return m.ProviderAPIKey, nil
}

func (m *MockModelResolver) GetProvider(ctx context.Context, tenantID, providerID string) (*modelrouter.ProviderRecord, error) {
	if m.ProviderError != nil {
		return nil, m.ProviderError
	}
	if m.ProvidersByID != nil {
		if providerRecord, ok := m.ProvidersByID[providerID]; ok {
			return providerRecord, nil
		}
	}
	if m.ProviderRecord != nil {
		return m.ProviderRecord, nil
	}
	return &modelrouter.ProviderRecord{ID: providerID, ProviderType: "openai", BaseURL: "https://api.openai.com", AuthMode: "bearer", Status: "active"}, nil
}

// GetProjectTeamID returns empty string in tests (team scope not exercised here).
func (m *MockModelResolver) GetProjectTeamID(ctx context.Context, projectID string) (string, error) {
	return "", nil
}

// MockRateLimitChecker implements RateLimitChecker for testing
type MockRateLimitChecker struct {
	RPMAllowed         bool
	RPMError           error
	ConcurrencyAllowed bool
	ConcurrencyCount   int64
	ConcurrencyError   error
	DailyAllowed       bool
	DailyError         error
	MonthlyAllowed     bool
	MonthlyError       error

	ReleaseConcurrencyCalls  []string
	IncrementTokenUsageCalls []struct {
		ProjectID    string
		InputTokens  int64
		OutputTokens int64
	}
}

func (m *MockRateLimitChecker) CheckRPM(ctx context.Context, projectID string, rpmLimit int) (bool, error) {
	if m.RPMError != nil {
		return false, m.RPMError
	}
	if m.RPMAllowed {
		return true, nil
	}
	return false, nil // When RPMAllowed is false, rate limited
}

func (m *MockRateLimitChecker) CheckConcurrency(ctx context.Context, projectID string, concurrencyLimit int) (bool, int64, error) {
	if m.ConcurrencyError != nil {
		return false, 0, m.ConcurrencyError
	}
	if m.ConcurrencyAllowed {
		return true, 1, nil
	}
	return false, 0, nil // When ConcurrencyAllowed is false, concurrency limited
}

func (m *MockRateLimitChecker) ReleaseConcurrency(ctx context.Context, projectID string) error {
	m.ReleaseConcurrencyCalls = append(m.ReleaseConcurrencyCalls, projectID)
	return nil
}

func (m *MockRateLimitChecker) CheckDailyTokenLimit(ctx context.Context, projectID string, dailyLimit int64) (bool, int64, error) {
	if m.DailyError != nil {
		return false, 0, m.DailyError
	}
	if m.DailyAllowed {
		return true, 0, nil
	}
	return false, 0, nil // When DailyAllowed is false, daily limit exceeded
}

func (m *MockRateLimitChecker) CheckMonthlyTokenLimit(ctx context.Context, projectID string, monthlyLimit int64) (bool, int64, error) {
	if m.MonthlyError != nil {
		return false, 0, m.MonthlyError
	}
	if m.MonthlyAllowed {
		return true, 0, nil
	}
	return false, 0, nil // When MonthlyAllowed is false, monthly limit exceeded
}

func (m *MockRateLimitChecker) IncrementTokenUsage(ctx context.Context, projectID string, inputTokens, outputTokens int64) error {
	m.IncrementTokenUsageCalls = append(m.IncrementTokenUsageCalls, struct {
		ProjectID    string
		InputTokens  int64
		OutputTokens int64
	}{projectID, inputTokens, outputTokens})
	return nil
}

// MockSecurityChecker implements SecurityChecker for testing
type MockSecurityChecker struct {
	InputAction    string
	InputMasked    string
	InputFindings  []SecurityFinding
	InputError     error
	OutputAction   string
	OutputMasked   string
	OutputFindings []SecurityFinding
	OutputError    error

	SemanticFindings []SecurityFinding
	SemanticError    error

	// P1-B 指纹缓存：CheckInputDetailed 附带回带的版本与原始 findings
	InputRawFindings            json.RawMessage
	InputRulePackVersion        string
	InputEngineBuild            string
	InputSemanticConfigRevision string
	InputSemanticStatus         string
	InputSemanticReason         string

	// ApplyContext 重放桩
	ApplyAction   string
	ApplyFindings []SecurityFinding
	ApplyError    error
	ApplyCalls    []struct {
		RawFindings   string
		ContentSource string
	}

	InputCheckCalls []struct {
		Content      string
		MessageIndex int
		MessageRole  string
	}
	OutputCheckCalls []struct {
		Content     string
		ChoiceIndex int
	}
	// SemanticCheckCalls 由异步旁路的多个并发 goroutine 调用，用 mu 守护（仅测试用）。
	mu                 sync.Mutex
	SemanticCheckCalls []struct {
		Content string
	}
}

// SemanticCallCount 并发安全读取语义检查调用次数（异步旁路 goroutine 并发写）。
func (m *MockSecurityChecker) SemanticCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.SemanticCheckCalls)
}

func (m *MockSecurityChecker) CheckInput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (string, string, []SecurityFinding, error) {
	m.InputCheckCalls = append(m.InputCheckCalls, struct {
		Content      string
		MessageIndex int
		MessageRole  string
	}{content, messageIndex, messageRole})
	if m.InputError != nil {
		return "", "", nil, m.InputError
	}
	action := m.InputAction
	if action == "" {
		action = "allow"
	}
	return action, m.InputMasked, m.InputFindings, nil
}

func (m *MockSecurityChecker) CheckOutput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, choiceIndex int) (string, string, []SecurityFinding, error) {
	m.OutputCheckCalls = append(m.OutputCheckCalls, struct {
		Content     string
		ChoiceIndex int
	}{content, choiceIndex})
	if m.OutputError != nil {
		return "", "", nil, m.OutputError
	}
	action := m.OutputAction
	if action == "" {
		action = "allow"
	}
	return action, m.OutputMasked, m.OutputFindings, nil
}

func (m *MockSecurityChecker) CheckSemanticOnly(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string) ([]SecurityFinding, error) {
	m.mu.Lock()
	m.SemanticCheckCalls = append(m.SemanticCheckCalls, struct {
		Content string
	}{content})
	m.mu.Unlock()
	if m.SemanticError != nil {
		return nil, m.SemanticError
	}
	return m.SemanticFindings, nil
}

func (m *MockSecurityChecker) CheckTriage(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, findings []SecurityFinding) ([]SecurityFinding, error) {
	return findings, nil
}

func (m *MockSecurityChecker) CheckInputDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (*InputCheckOutcome, error) {
	action, masked, findings, err := m.CheckInput(ctx, envelope, content, messageIndex, messageRole, contentSource)
	if err != nil {
		return nil, err
	}
	return &InputCheckOutcome{
		Action: action, MaskedContent: masked, Findings: findings,
		RawFindings:            m.InputRawFindings,
		RulePackVersion:        m.InputRulePackVersion,
		EngineBuild:            m.InputEngineBuild,
		SemanticConfigRevision: m.InputSemanticConfigRevision,
		SemanticStatus:         m.InputSemanticStatus,
		SemanticReason:         m.InputSemanticReason,
	}, nil
}

func (m *MockSecurityChecker) ApplyContext(ctx context.Context, envelope *modelrouter.RequestEnvelope, rawFindings json.RawMessage, contentSource string) (string, []SecurityFinding, error) {
	m.ApplyCalls = append(m.ApplyCalls, struct {
		RawFindings   string
		ContentSource string
	}{string(rawFindings), contentSource})
	if m.ApplyError != nil {
		return "", nil, m.ApplyError
	}
	action := m.ApplyAction
	if action == "" {
		action = "allow"
	}
	return action, m.ApplyFindings, nil
}

// SecurityEventWrite 是 MockAuditWriter 捕获的一次安全事件写入（含指纹重放标注）。
type SecurityEventWrite struct {
	EventID            string
	Envelope           *modelrouter.RequestEnvelope
	ActionTaken        string
	Summary            string
	ScanMode           string
	FirstSeenRequestID string
	Block              *blockAttribution
	MaskUnavailable    bool
}

type SecurityOccurrenceWrite struct {
	RepresentativeEventID string
	RequestID             string
	ContextKey            string
}

// MockAuditWriter implements AuditWriter for testing
type MockAuditWriter struct {
	// mu 守护 WriteSecurityEvent 的记录（异步旁路 goroutine 与主链并发调用）。仅测试用。
	mu                  sync.Mutex
	RequestLogEnsures   []*modelrouter.RequestEnvelope
	RequestLogFinalizes []struct {
		Envelope    *modelrouter.RequestEnvelope
		Status      string
		StatusCode  int
		RespBody    []byte
		AuditResult *AuditResult
	}
	RequestLogFinalizeErrors []error // Track errors from FinalizeRequestLog
	SecurityEventWrites      []SecurityEventWrite
	SecurityOccurrenceWrites []SecurityOccurrenceWrite
	// OnSecurityEvent 可选回调：用于异步路径的确定性等待（命中即收到 actionTaken+findings）。
	// nil 时无副作用，对既有测试零影响。
	OnSecurityEvent  func(actionTaken string, findings []SecurityFinding)
	ContentLogWrites []struct {
		Envelope     *modelrouter.RequestEnvelope
		Role         string
		Content      string
		Tokens       int
		MessageIndex *int
	}
	AgentSessionUpserts []*modelrouter.RequestEnvelope
}

func (m *MockAuditWriter) EnsureRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
	m.RequestLogEnsures = append(m.RequestLogEnsures, envelope)
}

func (m *MockAuditWriter) FinalizeRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, respBody []byte, status string, upstreamStatusCode int, latencyMs int, auditResult *AuditResult) {
	m.RequestLogFinalizes = append(m.RequestLogFinalizes, struct {
		Envelope    *modelrouter.RequestEnvelope
		Status      string
		StatusCode  int
		RespBody    []byte
		AuditResult *AuditResult
	}{envelope, status, upstreamStatusCode, append([]byte(nil), respBody...), auditResult})
}

func (m *MockAuditWriter) WriteSecurityEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding, actionTaken, summary string) {
	m.mu.Lock()
	eventID := securityEventIDFromContext(ctx)
	if eventID == "" {
		eventID = newAuditID("evt_")
	}
	w := SecurityEventWrite{EventID: eventID, Envelope: envelope, ActionTaken: actionTaken, Summary: summary}
	matchedSummary := map[string]interface{}{}
	annotateSecurityEventBlock(ctx, envelope, eventID, findings, actionTaken, summary, matchedSummary)
	if block, ok := matchedSummary["block"].(blockAttribution); ok {
		w.Block = &block
	}
	w.MaskUnavailable, _ = matchedSummary["mask_unavailable"].(bool)
	if first, ok := fingerprintReuseFromContext(ctx); ok {
		w.ScanMode = "fingerprint_reuse"
		w.FirstSeenRequestID = first
	}
	m.SecurityEventWrites = append(m.SecurityEventWrites, w)
	cb := m.OnSecurityEvent
	m.mu.Unlock()
	if cb != nil {
		cb(actionTaken, findings)
	}
}

func (m *MockAuditWriter) RecordSecurityEventOccurrence(
	_ context.Context,
	envelope *modelrouter.RequestEnvelope,
	representativeEventID, contextKey string,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SecurityOccurrenceWrites = append(m.SecurityOccurrenceWrites, SecurityOccurrenceWrite{
		RepresentativeEventID: representativeEventID,
		RequestID:             envelope.RequestID,
		ContextKey:            contextKey,
	})
	return nil
}

func (m *MockAuditWriter) WriteContentLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens int) {
	m.ContentLogWrites = append(m.ContentLogWrites, struct {
		Envelope     *modelrouter.RequestEnvelope
		Role         string
		Content      string
		Tokens       int
		MessageIndex *int
	}{envelope, role, content, tokens, nil})
}

func (m *MockAuditWriter) WriteContentLogAnchored(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens, messageIndex int) {
	m.ContentLogWrites = append(m.ContentLogWrites, struct {
		Envelope     *modelrouter.RequestEnvelope
		Role         string
		Content      string
		Tokens       int
		MessageIndex *int
	}{envelope, role, content, tokens, &messageIndex})
}

func (m *MockAuditWriter) UpsertAgentSession(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
	m.AgentSessionUpserts = append(m.AgentSessionUpserts, envelope)
}

func (m *MockAuditWriter) AnnotateTriage(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding) {
}

// MockProviderCaller implements ProviderCaller for testing
type MockProviderCaller struct {
	CallResponse            []byte
	CallError               error
	TransformResponseResult []byte
	TransformResponseError  error
	TransformRequestResult  []byte
	TransformRequestError   error

	CallCalls             [][]byte
	CallEnvelopes         []*modelrouter.RequestEnvelope
	TransformRequestCalls []struct {
		Envelope *modelrouter.RequestEnvelope
		RawBody  []byte
	}
}

func (m *MockProviderCaller) TransformRequest(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error) {
	m.TransformRequestCalls = append(m.TransformRequestCalls, struct {
		Envelope *modelrouter.RequestEnvelope
		RawBody  []byte
	}{envelope, rawBody})
	if m.TransformRequestError != nil {
		return nil, m.TransformRequestError
	}
	if m.TransformRequestResult != nil {
		return m.TransformRequestResult, nil
	}
	return rawBody, nil // Default: pass through
}

func (m *MockProviderCaller) Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error) {
	m.CallCalls = append(m.CallCalls, providerReq)
	m.CallEnvelopes = append(m.CallEnvelopes, envelope)

	if m.CallError != nil {
		return nil, m.CallError
	}
	if m.CallResponse != nil {
		return m.CallResponse, nil
	}

	// Return appropriate response based on endpoint type
	if envelope.EndpointType == "embeddings" {
		resp := EmbeddingsResponse{
			Object: "list",
			Data: []EmbeddingData{
				{
					Object:    "embedding",
					Index:     0,
					Embedding: []float64{0.1, 0.2, 0.3},
				},
			},
			Model: envelope.Model,
			Usage: EmbeddingsUsage{
				PromptTokens: 10,
				TotalTokens:  10,
			},
		}
		data, _ := json.Marshal(resp)
		return data, nil
	}
	if envelope.EndpointType == "messages" {
		if body, err := json.Marshal(map[string]any{
			"id": "msg_test", "type": "message", "role": "assistant",
			"model":       envelope.Model,
			"content":     []any{map[string]any{"type": "text", "text": "Hello! How can I help?"}},
			"stop_reason": "end_turn", "stop_sequence": nil,
			"usage": map[string]int{"input_tokens": 10, "output_tokens": 20},
		}); err == nil {
			return body, nil
		}
	}

	// Default: chat completion response
	resp := ChatCompletionResponse{
		ID:      "chatcmpl-test",
		Object:  "chat.completion",
		Created: 1716399600,
		Model:   "gpt-4",
		Choices: []Choice{
			{
				Index: 0,
				Message: ChoiceMessage{
					Role:    "assistant",
					Content: "Hello! How can I help?",
				},
				FinishReason: "stop",
			},
		},
		Usage: Usage{
			PromptTokens:     10,
			CompletionTokens: 20,
			TotalTokens:      30,
		},
	}
	data, _ := json.Marshal(resp)
	return data, nil
}

// CallStreaming mirrors Call for tests: 累积器真实行为由 provider 包单测覆盖,
// handler 层只需保证接口被满足且与 Call 等价(默认开关 false 时根本不会被调用)。
func (m *MockProviderCaller) CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error) {
	if m.CallError == nil && m.CallResponse == nil && envelope.EndpointType == "messages" {
		return []byte("event: message_start\n" +
			"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_test\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-test\",\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\n" +
			"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello! How can I help?\"}}\n\n" +
			"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":20}}\n\n" +
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"), nil
	}
	return m.Call(ctx, envelope, providerReq)
}

func (m *MockProviderCaller) TransformResponse(respBody []byte) ([]byte, error) {
	if m.TransformResponseError != nil {
		return nil, m.TransformResponseError
	}
	if m.TransformResponseResult != nil {
		return m.TransformResponseResult, nil
	}
	return respBody, nil
}

// MockProviderAdapterFactory returns mock provider callers
type MockProviderAdapterFactory struct {
	MockProviderCaller  *MockProviderCaller
	CallersByProviderID map[string]ProviderCaller
	CreatedRecords      []*modelrouter.ModelRecord
	CreatedAPIKeys      []string
}

func (f *MockProviderAdapterFactory) CreateAdapter(modelRecord *modelrouter.ModelRecord, apiKey string) ProviderCaller {
	if modelRecord != nil {
		recordCopy := *modelRecord
		f.CreatedRecords = append(f.CreatedRecords, &recordCopy)
	} else {
		f.CreatedRecords = append(f.CreatedRecords, nil)
	}
	f.CreatedAPIKeys = append(f.CreatedAPIKeys, apiKey)
	if f.CallersByProviderID != nil && modelRecord != nil {
		if caller, ok := f.CallersByProviderID[modelRecord.ProviderID]; ok {
			return caller
		}
	}
	if f.MockProviderCaller == nil {
		return &MockProviderCaller{}
	}
	return f.MockProviderCaller
}

package handler

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

// 任务 2.6：路由 fallback 链按 FallbackChain 顺序真执行。
// 规格：主模型 5xx→自动切到链中下一个并成功。
//
// 该测试直接驱动 attemptFallbackCall 的多跳能力：fallback 计划串成链表
// （planB.Next = planC），主调用以 5xx 失败后应自动沿链切到下一跳并成功。
func TestAttemptFallbackCall_WalksChainToNextOnUpstream5xx(t *testing.T) {
	// 链中第一跳 provider-b 仍返回 5xx（应继续沿链下探）。
	callerB := &MockProviderCaller{
		CallError: &provider.UpstreamHTTPError{
			StatusCode: http.StatusBadGateway,
			Message:    "bad gateway",
		},
	}
	// 链中第二跳 provider-c 成功返回。
	callerC := &MockProviderCaller{
		CallResponse: []byte(`{"id":"ok","object":"chat.completion"}`),
	}

	planC := &FallbackProviderPlan{
		ProviderID:   "provider-c",
		ProviderType: "openai",
		Caller:       callerC,
	}
	planB := &FallbackProviderPlan{
		ProviderID:   "provider-b",
		ProviderType: "openai",
		Caller:       callerB,
		Next:         planC,
	}

	envelope := &modelrouter.RequestEnvelope{
		ProviderID:   "provider-a",
		Provider:     "openai",
		EndpointType: "chat",
	}

	// 主模型（provider-a）以 5xx 失败，触发兜底。
	primaryErr := &provider.UpstreamHTTPError{
		StatusCode: http.StatusServiceUnavailable,
		Message:    "primary down",
	}

	result := attemptFallbackCall(context.Background(), envelope, []byte(`{"model":"gpt-4"}`), primaryErr, planB, false)

	if result.Err != nil {
		t.Fatalf("Expected chain to succeed on provider-c, got err: %v", result.Err)
	}
	if result.Caller != callerC {
		t.Fatalf("Expected winning caller to be provider-c's caller")
	}
	if len(callerB.CallCalls) != 1 {
		t.Fatalf("Expected provider-b to be attempted once, got %d", len(callerB.CallCalls))
	}
	if len(callerC.CallCalls) != 1 {
		t.Fatalf("Expected provider-c to be attempted once, got %d", len(callerC.CallCalls))
	}
	if envelope.ProviderID != "provider-c" {
		t.Fatalf("Expected envelope.ProviderID swapped to provider-c, got %q", envelope.ProviderID)
	}
	if result.FallbackProviderID != "provider-c" {
		t.Fatalf("Expected FallbackProviderID=provider-c (final winning hop), got %q", result.FallbackProviderID)
	}
	if !result.Attempted {
		t.Fatalf("Expected Attempted=true")
	}
}

// 单跳链：主 5xx → planB 立即成功（链长度为 1，不递归）。回归保护。
func TestAttemptFallbackCall_SingleHopChainStillWorks(t *testing.T) {
	callerB := &MockProviderCaller{
		CallResponse: []byte(`{"id":"ok","object":"chat.completion"}`),
	}
	planB := &FallbackProviderPlan{
		ProviderID:   "provider-b",
		ProviderType: "openai",
		Caller:       callerB,
	}
	envelope := &modelrouter.RequestEnvelope{ProviderID: "provider-a", Provider: "openai", EndpointType: "chat"}
	primaryErr := &provider.UpstreamHTTPError{StatusCode: http.StatusBadGateway, Message: "down"}

	result := attemptFallbackCall(context.Background(), envelope, []byte(`{}`), primaryErr, planB, false)
	if result.Err != nil {
		t.Fatalf("Expected single-hop fallback success, got err: %v", result.Err)
	}
	if result.Caller != callerB {
		t.Fatalf("Expected winning caller to be provider-b's caller")
	}
	if len(callerB.CallCalls) != 1 {
		t.Fatalf("Expected provider-b attempted once, got %d", len(callerB.CallCalls))
	}
}

func TestAttemptFallbackCallSkipsProtocolIncompatibleHop(t *testing.T) {
	chatOnly := &MockProviderCaller{CallError: &provider.UpstreamHTTPError{StatusCode: http.StatusBadGateway}}
	messages := &MockProviderCaller{CallResponse: []byte(`{"ok":true}`)}
	planB := &FallbackProviderPlan{
		ProviderID:   "provider-chat",
		ProviderType: "custom",
		Caller:       chatOnly,
		Route: modelrouter.ModelRecord{
			ProviderID:           "provider-chat",
			ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true},
		},
		Next: &FallbackProviderPlan{
			ProviderID:   "provider-messages",
			ProviderType: "anthropic",
			Caller:       messages,
			Route: modelrouter.ModelRecord{
				ProviderID:           "provider-messages",
				ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true},
			},
		},
	}
	envelope := &modelrouter.RequestEnvelope{ProviderID: "provider-a", Provider: "custom", EndpointType: "messages"}
	result := attemptFallbackCall(context.Background(), envelope, []byte(`{"messages":[]}`), &provider.UpstreamHTTPError{StatusCode: http.StatusBadGateway}, planB, false)
	if result.Err != nil || result.Caller != messages || len(chatOnly.CallCalls) != 0 || len(messages.CallCalls) != 1 {
		t.Fatalf("protocol-incompatible fallback was called: result=%+v chat=%d messages=%d", result, len(chatOnly.CallCalls), len(messages.CallCalls))
	}
}

func TestAttemptFallbackCallSkipsUnsupportedAdapterHop(t *testing.T) {
	winning := &MockProviderCaller{CallResponse: []byte(`{"ok":true}`)}
	plan := &FallbackProviderPlan{
		ProviderID:   "provider-unknown",
		ProviderType: "future-provider",
		Route: modelrouter.ModelRecord{
			ProviderID:           "provider-unknown",
			ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true},
		},
		Next: &FallbackProviderPlan{
			ProviderID:   "provider-known",
			ProviderType: "openai",
			Caller:       winning,
			Route: modelrouter.ModelRecord{
				ProviderID:           "provider-known",
				ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true},
			},
		},
	}
	envelope := &modelrouter.RequestEnvelope{ProviderID: "provider-primary", Provider: "openai", EndpointType: "chat"}
	result := attemptFallbackCall(context.Background(), envelope, []byte(`{"model":"customer-coding-prod"}`), &provider.UpstreamHTTPError{StatusCode: http.StatusBadGateway}, plan, false)
	if result.Err != nil || result.Caller != winning || len(winning.CallCalls) != 1 {
		t.Fatalf("unsupported adapter hop was not skipped: result=%+v calls=%d", result, len(winning.CallCalls))
	}
	if envelope.ProviderID != "provider-known" {
		t.Fatalf("envelope provider=%q, want provider-known", envelope.ProviderID)
	}
}

func TestAttemptFallbackCall_DoesNotRetryAfterRequestContextEnds(t *testing.T) {
	caller := &MockProviderCaller{CallResponse: []byte(`{"ok":true}`)}
	plan := &FallbackProviderPlan{
		ProviderID: "provider-b", ProviderType: "openai",
		Caller: caller,
	}
	envelope := &modelrouter.RequestEnvelope{ProviderID: "provider-a", Provider: "openai", EndpointType: "messages"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := attemptFallbackCall(ctx, envelope, []byte(`{}`), context.DeadlineExceeded, plan, false)

	if result.Attempted || !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("canceled request retried fallback: %+v", result)
	}
	if len(caller.CallCalls) != 0 {
		t.Fatalf("fallback caller was invoked %d times", len(caller.CallCalls))
	}
	if envelope.ProviderID != "provider-a" || envelope.Provider != "openai" {
		t.Fatalf("canceled request mutated envelope: %+v", envelope)
	}
}

func TestAttemptFallbackCall_UsesUnifiedStatusMatrix(t *testing.T) {
	caller := &MockProviderCaller{CallResponse: []byte(`{"ok":true}`)}
	plan := &FallbackProviderPlan{
		ProviderID: "provider-b", ProviderType: "openai",
		Caller: caller,
	}
	envelope := &modelrouter.RequestEnvelope{ProviderID: "provider-a", Provider: "openai", EndpointType: "messages"}

	for _, status := range []int{408, 429, 500} {
		result := attemptFallbackCall(
			context.Background(), envelope, []byte(`{"model":"logical"}`),
			&provider.UpstreamHTTPError{StatusCode: status}, plan, false,
		)
		if !result.Attempted || result.Err != nil {
			t.Fatalf("status %d did not retry fallback: %+v", status, result)
		}
	}

	before := len(caller.CallCalls)
	for _, status := range []int{400, 401, 403, 404, 409, 413, 422} {
		result := attemptFallbackCall(
			context.Background(), envelope, []byte(`{"model":"logical"}`),
			&provider.UpstreamHTTPError{StatusCode: status}, plan, false,
		)
		if result.Attempted || len(caller.CallCalls) != before {
			t.Fatalf("status %d unexpectedly retried fallback: %+v calls=%d", status, result, len(caller.CallCalls))
		}
	}
}

// buildFallbackChainPlan 应从 ProviderDecision.FallbackChain 构造链表，
// 跳过链首（主 provider 自身），按顺序串接 [1:] 各跳。
func TestBuildFallbackChainPlan_LinksChainSkippingPrimary(t *testing.T) {
	callerB := &MockProviderCaller{}
	callerC := &MockProviderCaller{}
	factory := &MockProviderAdapterFactory{
		CallersByProviderID: map[string]ProviderCaller{
			"provider-b": callerB,
			"provider-c": callerC,
		},
	}
	resolver := &MockModelResolver{}
	modelRecord := &modelrouter.ModelRecord{
		ProviderID:   "provider-a",
		ProviderType: "openai",
	}
	provDec := &modelrouter.ProviderDecision{
		ProviderID:    "provider-a",
		FallbackChain: []string{"provider-a", "provider-b", "provider-c"},
	}

	plan := buildFallbackChainPlan(context.Background(), resolver, factory, "tenant-1", modelRecord, provDec)
	if plan == nil {
		t.Fatalf("Expected a chain plan for a 3-element FallbackChain")
	}
	if plan.ProviderID != "provider-b" {
		t.Fatalf("Expected first hop provider-b (chain[1]), got %q", plan.ProviderID)
	}
	if plan.Caller != callerB {
		t.Fatalf("Expected first hop caller to be provider-b's")
	}
	if plan.Next == nil || plan.Next.ProviderID != "provider-c" {
		t.Fatalf("Expected second hop provider-c (chain[2])")
	}
	if plan.Next.Caller != callerC {
		t.Fatalf("Expected second hop caller to be provider-c's")
	}
	if plan.Next.Next != nil {
		t.Fatalf("Expected chain to terminate after provider-c")
	}
	if got := fallbackChainLength(plan); got != 2 {
		t.Fatalf("Expected fallbackChainLength=2, got %d", got)
	}
}

// 链少于 2 个元素（无真实兜底目标）→ 返回 nil，不构造空链。
func TestBuildFallbackChainPlan_NilWhenChainTooShort(t *testing.T) {
	factory := &MockProviderAdapterFactory{}
	resolver := &MockModelResolver{}
	modelRecord := &modelrouter.ModelRecord{ProviderID: "provider-a", ProviderType: "openai"}
	provDec := &modelrouter.ProviderDecision{
		ProviderID:    "provider-a",
		FallbackChain: []string{"provider-a"},
	}
	if plan := buildFallbackChainPlan(context.Background(), resolver, factory, "tenant-1", modelRecord, provDec); plan != nil {
		t.Fatalf("Expected nil chain plan for single-element FallbackChain")
	}
}

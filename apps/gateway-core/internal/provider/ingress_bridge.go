package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// AdaptIngress reuses a capability-selected Chat adapter for the normalized
// stateless Responses contract or for Messages over Gemini/Bedrock. It never
// infers upstream endpoint support, and does not alter the audit envelope.
func AdaptIngress(adapter ProviderAdapter, envelope *modelrouter.RequestEnvelope) ProviderAdapter {
	if adapter == nil || envelope == nil {
		return adapter
	}
	upstream := strings.ToLower(strings.TrimSpace(envelope.UpstreamProtocol))
	responses := envelope.EndpointType == "responses" && upstream != "" && upstream != "responses"
	messages := envelope.EndpointType == "messages" && (upstream == "gemini" || upstream == "bedrock_converse")
	if !responses && !messages {
		return adapter
	}
	bridge := &ingressBridgeAdapter{ProviderAdapter: adapter, messages: messages}
	if stream, ok := adapter.(StreamAdapter); ok {
		return &streamIngressBridgeAdapter{ingressBridgeAdapter: bridge, stream: stream}
	}
	return bridge
}

type ingressBridgeAdapter struct {
	ProviderAdapter
	messages bool
}

func (a *ingressBridgeAdapter) SupportsEndpoint(endpoint string) bool {
	if endpoint == "responses" || endpoint == "messages" {
		return a.ProviderAdapter.SupportsEndpoint("chat")
	}
	return a.ProviderAdapter.SupportsEndpoint(endpoint)
}

func chatBridgeEnvelope(envelope *modelrouter.RequestEnvelope) *modelrouter.RequestEnvelope {
	if envelope == nil {
		return nil
	}
	clone := *envelope
	clone.EndpointType = "chat"
	return &clone
}

func (a *ingressBridgeAdapter) TransformRequest(envelope *modelrouter.RequestEnvelope, raw []byte) ([]byte, error) {
	clone := chatBridgeEnvelope(envelope)
	if a.messages {
		var err error
		raw, err = transformAnthropicMessagesToChat(clone, raw)
		if err != nil {
			return nil, err
		}
	}
	return a.ProviderAdapter.TransformRequest(clone, raw)
}

func (a *ingressBridgeAdapter) Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error) {
	clone := chatBridgeEnvelope(envelope)
	result, err := a.ProviderAdapter.Call(ctx, clone, payload)
	if envelope != nil && clone != nil {
		envelope.UpstreamTTFTMs = clone.UpstreamTTFTMs
	}
	return result, err
}

func (a *ingressBridgeAdapter) CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error) {
	clone := chatBridgeEnvelope(envelope)
	result, err := a.ProviderAdapter.CallStreaming(ctx, clone, payload)
	if envelope != nil && clone != nil {
		envelope.UpstreamTTFTMs = clone.UpstreamTTFTMs
	}
	return result, err
}

func (a *ingressBridgeAdapter) TransformResponseForEnvelope(envelope *modelrouter.RequestEnvelope, raw []byte) ([]byte, error) {
	var result []byte
	var err error
	if contextual, ok := a.ProviderAdapter.(interface {
		TransformResponseForEnvelope(*modelrouter.RequestEnvelope, []byte) ([]byte, error)
	}); ok {
		result, err = contextual.TransformResponseForEnvelope(chatBridgeEnvelope(envelope), raw)
	} else {
		result, err = a.ProviderAdapter.TransformResponse(raw)
	}
	if err != nil {
		return nil, err
	}
	if a.messages {
		return transformChatResponseToAnthropicMessages(envelope, result)
	}
	return result, nil
}

type streamIngressBridgeAdapter struct {
	*ingressBridgeAdapter
	stream StreamAdapter
}

func (a *streamIngressBridgeAdapter) OpenStream(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) (relay.StreamReader, StreamResponseMeta, error) {
	if a.stream == nil {
		return nil, StreamResponseMeta{}, fmt.Errorf("%w: streaming bridge unavailable", ErrEndpointNotSupported)
	}
	return a.stream.OpenStream(ctx, chatBridgeEnvelope(envelope), payload)
}

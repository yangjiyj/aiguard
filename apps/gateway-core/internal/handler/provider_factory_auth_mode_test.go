package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

func TestRealProviderAdapterFactoryPassesProviderAuthMode(t *testing.T) {
	caller := (&RealProviderAdapterFactory{}).CreateAdapter(&modelrouter.ModelRecord{
		ProviderType:     "custom",
		ProviderBaseURL:  "https://upstream.example.test/only/chat",
		ProviderAuthMode: "authorization_raw",
	}, "raw-key")
	adapter, ok := caller.(*provider.OpenAICompatibleAdapter)
	if !ok {
		t.Fatalf("adapter type = %T", caller)
	}
	if adapter.AuthMode != "authorization_raw" {
		t.Fatalf("AuthMode = %q", adapter.AuthMode)
	}
}

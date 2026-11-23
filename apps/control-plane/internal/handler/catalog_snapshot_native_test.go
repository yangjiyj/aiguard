package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"testing"
)

func TestCatalogNativeAnthropicProbeUsesOnlyMessagesAndValidatedBody(t *testing.T) {
	for _, valid := range []bool{true, false} {
		provider := &repository.Provider{ProviderType: "anthropic", BaseURL: "https://native.example/v1", AuthMode: "api_key"}
		prober := &modelOperationsProberStub{result: catalog.ModelProbeResult{OK: true, HTTPStatus: 200, PayloadValidated: valid}}
		protocols, record, err := probeCatalogModelProtocols(context.Background(), prober, provider, "fixture-secret", "anthropic/claude-fixture")
		if len(prober.requests) != 1 || prober.requests[0].Protocol != "messages" || prober.requests[0].AuthMode != "x-api-key" {
			t.Fatal("native Messages was not actually probed")
		}
		if valid {
			if err != nil || protocols["anthropic_messages"] != true || len(record.Endpoints) != 1 || record.Endpoints[0].EndpointType != "messages" || record.Endpoints[0].State != "supported" {
				t.Fatalf("invalid native proof: %+v %v", record, err)
			}
		} else if err == nil {
			t.Fatal("unvalidated body admitted")
		}
	}
}

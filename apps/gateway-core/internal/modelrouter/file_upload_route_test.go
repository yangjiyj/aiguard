package modelrouter

import (
	"errors"
	"testing"
)

func TestSelectUniqueFileUploadRouteAllowsMultipleModelsOnOneProvider(t *testing.T) {
	route, err := selectUniqueFileUploadRoute([]ModelRecord{
		{ID: "model-a", ProviderID: "provider-1", ProviderType: "openai", ProtocolCapabilities: ProtocolCapabilities{Explicit: true, Files: true}},
		{ID: "model-b", ProviderID: "provider-1", ProviderType: "openai", ProtocolCapabilities: ProtocolCapabilities{Explicit: true, Files: true}},
		{ID: "responses-only", ProviderID: "provider-2", ProtocolCapabilities: ProtocolCapabilities{Explicit: true, ResponsesNative: true}},
		{ID: "legacy", ProviderID: "provider-3"},
	})
	if err != nil {
		t.Fatalf("select unique route: %v", err)
	}
	if route.ProviderID != "provider-1" {
		t.Fatalf("provider = %q", route.ProviderID)
	}
}

func TestSelectUniqueFileUploadRouteRejectsAmbiguousProviders(t *testing.T) {
	_, err := selectUniqueFileUploadRoute([]ModelRecord{
		{ID: "model-a", ProviderID: "provider-1", ProtocolCapabilities: ProtocolCapabilities{Explicit: true, Files: true}},
		{ID: "model-b", ProviderID: "provider-2", ProtocolCapabilities: ProtocolCapabilities{Explicit: true, Files: true}},
	})
	if !errors.Is(err, ErrAmbiguousFileUploadRoute) {
		t.Fatalf("error = %v, want ambiguous route", err)
	}
}

func TestSelectUniqueFileUploadRouteRejectsNoExplicitProvider(t *testing.T) {
	_, err := selectUniqueFileUploadRoute([]ModelRecord{
		{ID: "legacy", ProviderID: "provider-1"},
		{ID: "responses", ProviderID: "provider-2", ProtocolCapabilities: ProtocolCapabilities{Explicit: true, ResponsesNative: true}},
	})
	if !errors.Is(err, ErrNoFileUploadRoute) {
		t.Fatalf("error = %v, want no route", err)
	}
}

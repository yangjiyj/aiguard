package repository

import (
	"encoding/hex"
	"testing"
)

func TestVerifiedModelSyncProviderConfigDigestIsDeterministicAndBound(t *testing.T) {
	base := VerifiedModelSyncProviderConfigDigest("azure", "https://azure.example.test", "api-key")
	if len(base) != 64 {
		t.Fatalf("digest length=%d want=64", len(base))
	}
	if _, err := hex.DecodeString(base); err != nil {
		t.Fatalf("digest is not lowercase hex SHA-256: %q: %v", base, err)
	}
	if again := VerifiedModelSyncProviderConfigDigest("azure", "https://azure.example.test", "api-key"); again != base {
		t.Fatalf("digest is not deterministic: %q != %q", again, base)
	}
	for _, tc := range []struct {
		name, providerType, baseURL, authMode string
	}{
		{name: "provider type", providerType: "openai", baseURL: "https://azure.example.test", authMode: "api-key"},
		{name: "base URL", providerType: "azure", baseURL: "https://other.example.test", authMode: "api-key"},
		{name: "auth mode", providerType: "azure", baseURL: "https://azure.example.test", authMode: "bearer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerifiedModelSyncProviderConfigDigest(tc.providerType, tc.baseURL, tc.authMode); got == base {
				t.Fatalf("changed %s retained digest %q", tc.name, got)
			}
		})
	}
}

func TestVerifiedModelSyncActiveSetDigestIsDeterministicAndBound(t *testing.T) {
	models := []*Model{
		{ID: "m2", ProviderID: "provider-a", ModelName: "gpt-5.4", UpstreamModelID: "deployment-b", Status: "active"},
		{ID: "m1", ProviderID: "provider-a", ModelName: "gpt-5.5", UpstreamModelID: "deployment-a", Status: "active"},
		{ID: "m-disabled", ProviderID: "provider-a", ModelName: "old", UpstreamModelID: "old", Status: "disabled"},
		{ID: "m-other", ProviderID: "provider-b", ModelName: "other", UpstreamModelID: "other", Status: "active"},
		nil,
	}
	base := VerifiedModelSyncActiveSetDigest(models, "provider-a")
	if len(base) != 64 {
		t.Fatalf("digest length=%d want=64", len(base))
	}
	if _, err := hex.DecodeString(base); err != nil {
		t.Fatalf("digest is not lowercase hex SHA-256: %q: %v", base, err)
	}
	reversed := []*Model{models[4], models[3], models[2], models[1], models[0]}
	if got := VerifiedModelSyncActiveSetDigest(reversed, "provider-a"); got != base {
		t.Fatalf("digest depends on row order: %q != %q", got, base)
	}

	changedUpstream := cloneVerifiedDigestModels(models)
	changedUpstream[0].UpstreamModelID = "deployment-changed"
	if got := VerifiedModelSyncActiveSetDigest(changedUpstream, "provider-a"); got == base {
		t.Fatal("active upstream change did not change digest")
	}
	changedMembership := cloneVerifiedDigestModels(models)
	changedMembership[1].Status = "disabled"
	if got := VerifiedModelSyncActiveSetDigest(changedMembership, "provider-a"); got == base {
		t.Fatal("active membership change did not change digest")
	}
	ignoredDisabled := cloneVerifiedDigestModels(models)
	ignoredDisabled[2].UpstreamModelID = "disabled-change"
	if got := VerifiedModelSyncActiveSetDigest(ignoredDisabled, "provider-a"); got != base {
		t.Fatalf("disabled model changed active-set digest: %q != %q", got, base)
	}
}

func cloneVerifiedDigestModels(models []*Model) []*Model {
	cloned := make([]*Model, len(models))
	for i, model := range models {
		if model == nil {
			continue
		}
		copyModel := *model
		cloned[i] = &copyModel
	}
	return cloned
}

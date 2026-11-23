package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/modelops"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

type modelOperationsProberStub struct {
	requests []catalog.ModelProbeRequest
	result   catalog.ModelProbeResult
	onProbe  func()
}

func (p *modelOperationsProberStub) Probe(_ context.Context, r catalog.ModelProbeRequest) catalog.ModelProbeResult {
	p.requests = append(p.requests, r)
	if p.onProbe != nil {
		p.onProbe()
	}
	return p.result
}

func modelOperationsExecutorFixture(t *testing.T) (*ModelOperationsExecutor, modelops.Target, *repository.Model, *repository.Provider, *repository.ProviderCredential, *modelOperationsProberStub) {
	t.Helper()
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "model-operations-test-only-encryption-key")
	ciphertext, _, err := secrets.EncryptProviderSecret("fixture-secret")
	if err != nil {
		t.Fatal(err)
	}
	m := &repository.Model{ID: "model-1", ProviderID: "provider-1", ModelName: "public-claude", UpstreamModelID: "claude-fixture", Status: "active", Capabilities: map[string]interface{}{"manual": true}}
	p := &repository.Provider{ID: "provider-1", TenantID: "tenant-1", Name: "upstream", ProviderType: "custom", BaseURL: "https://fixture.example/v1", AuthMode: "api_key", Status: "active"}
	c := &repository.ProviderCredential{ID: "credential-1", ProviderID: p.ID, SecretCiphertext: ciphertext, Status: "active"}
	prober := &modelOperationsProberStub{result: catalog.ModelProbeResult{OK: true, HTTPStatus: 200, PayloadValidated: true, LatencyMS: 23}}
	d := &Dependencies{ModelRepo: &MockModelRepository{Models: map[string]*repository.Model{m.ID: m}}, ProviderRepo: &MockProviderRepository{Providers: map[string]*repository.Provider{p.ID: p}, Credentials: map[string]*repository.ProviderCredential{p.ID: c}}, ModelProber: prober}
	target := modelops.Target{ModelID: m.ID, ProviderID: p.ID, ModelName: m.ModelName, UpstreamModelID: m.UpstreamModelID, Protocol: "messages", CredentialID: c.ID, ModelStatus: m.Status, ProviderStatus: p.Status, ConfigDigest: repository.VerifiedModelSyncProviderConfigDigest(p.ProviderType, p.BaseURL, p.AuthMode), IdentityDigest: modelops.TargetIdentityDigest(p, c, m), MaxOutputTokens: 32, TimeoutSeconds: 11}
	return NewModelOperationsExecutor(d), target, m, p, c, prober
}

func TestModelOperationsExecutorUsesSavedCredentialMappingBudgetAndKeepsManualState(t *testing.T) {
	e, target, m, p, _, prober := modelOperationsExecutorFixture(t)
	result := e.Execute(context.Background(), "tenant-1", target)
	if !result.Success || !result.BodyValidated || result.HTTPStatus != 200 || result.LatencyMS != 23 || len(prober.requests) != 1 {
		t.Fatalf("result=%+v calls=%d", result, len(prober.requests))
	}
	req := prober.requests[0]
	if req.BaseURL != p.BaseURL || req.APIKey != "fixture-secret" || req.DeploymentName != m.UpstreamModelID || req.Protocol != "messages" || req.MaxOutputTokens != 32 || req.Timeout != 11*time.Second {
		t.Fatalf("request did not use saved authenticated config/budget")
	}
	if m.Status != "active" || m.Capabilities["manual"] != true {
		t.Fatal("probe changed administrator model configuration")
	}
}

func TestModelOperationsExecutorRejectsCrossTenantAndPreProbeIdentityDrift(t *testing.T) {
	for _, kind := range []string{"tenant", "mapping", "provider", "credential", "ciphertext", "disabled_model", "disabled_provider"} {
		t.Run(kind, func(t *testing.T) {
			e, target, m, p, c, prober := modelOperationsExecutorFixture(t)
			tenant := "tenant-1"
			switch kind {
			case "tenant":
				tenant = "other"
			case "mapping":
				m.UpstreamModelID = "new"
			case "provider":
				p.BaseURL = "https://changed.example"
			case "credential":
				c.ID = "new"
			case "ciphertext":
				c.SecretCiphertext = "different-secret"
			case "disabled_model":
				m.Status = "disabled"
			case "disabled_provider":
				p.Status = "disabled"
			}
			outcome := e.Execute(context.Background(), tenant, target)
			if outcome.Success || outcome.ErrorKind != "config_changed" || len(prober.requests) != 0 {
				t.Fatalf("outcome=%+v requests=%d", outcome, len(prober.requests))
			}
		})
	}
}

func TestModelOperationsExecutorRejectsPostProbeCredentialDriftAndInvalidPayload(t *testing.T) {
	e, target, _, _, c, prober := modelOperationsExecutorFixture(t)
	prober.onProbe = func() { c.SecretCiphertext = "rotated" }
	result := e.Execute(context.Background(), "tenant-1", target)
	if result.Success || result.BodyValidated || result.ErrorKind != "config_changed" || len(prober.requests) != 1 {
		t.Fatalf("result=%+v", result)
	}
	e, target, _, _, _, prober = modelOperationsExecutorFixture(t)
	prober.result.PayloadValidated = false
	result = e.Execute(context.Background(), "tenant-1", target)
	if result.Success || result.ErrorKind != "invalid_body" {
		t.Fatalf("HTTP 200 alone accepted: %+v", result)
	}
}

func TestModelOperationsExecutorNativeMessagesAzureAndUnsupportedProtocols(t *testing.T) {
	for _, tc := range []struct {
		provider, protocol, auth string
		wantCall                 bool
	}{{"anthropic", "messages", "x-api-key", true}, {"azure", "chat", "api-key", true}, {"Azure", "responses", "api-key", true}, {"Anthropic", "messages", "x-api-key", true}, {"anthropic", "chat", "", false}, {"gemini", "chat", "api_key", true}, {"bedrock", "messages", "", false}, {"vertex", "chat", "api_key", true}} {
		t.Run(tc.provider+tc.protocol, func(t *testing.T) {
			e, target, m, p, c, prober := modelOperationsExecutorFixture(t)
			p.ProviderType = tc.provider
			target.Protocol = tc.protocol
			target.ConfigDigest = repository.VerifiedModelSyncProviderConfigDigest(p.ProviderType, p.BaseURL, p.AuthMode)
			target.IdentityDigest = modelops.TargetIdentityDigest(p, c, m)
			result := e.Execute(context.Background(), "tenant-1", target)
			if tc.wantCall {
				if !result.Success || len(prober.requests) != 1 || prober.requests[0].AuthMode != tc.auth {
					t.Fatalf("result=%+v calls=%d", result, len(prober.requests))
				}
			} else if result.Success || result.ErrorKind != "unsupported" || len(prober.requests) != 0 {
				t.Fatalf("result=%+v calls=%d", result, len(prober.requests))
			}
		})
	}
}

func TestModelOperationsExecutorCancelsBeforeNetworkAndSanitizesErrors(t *testing.T) {
	e, target, _, _, _, prober := modelOperationsExecutorFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := e.Execute(ctx, "tenant-1", target)
	if result.Success || result.ErrorKind != "cancelled" || len(prober.requests) != 0 {
		t.Fatalf("result=%+v", result)
	}
	prober.result = catalog.ModelProbeResult{ErrorKind: "secret-private-error", Message: "fixture-secret response"}
	result = e.Execute(context.Background(), "tenant-1", target)
	if result.Success || result.ErrorKind != "upstream_error" || strings.Contains(result.ErrorKind, "secret") {
		t.Fatalf("result=%+v", result)
	}
}

func TestModelOperationsExecutorPendingRequiresExplicitManualProbe(t *testing.T) {
	for _, manual := range []bool{false, true} {
		e, target, m, p, c, prober := modelOperationsExecutorFixture(t)
		m.Status = "pending"
		target.ModelStatus = m.Status
		target.IdentityDigest = modelops.TargetIdentityDigest(p, c, m)
		target.ManualProbe = manual
		outcome := e.Execute(context.Background(), "tenant-1", target)
		if outcome.Success != manual || len(prober.requests) != map[bool]int{false: 0, true: 1}[manual] || m.Status != "pending" {
			t.Fatalf("manual=%v outcome=%+v calls=%d status=%s", manual, outcome, len(prober.requests), m.Status)
		}
	}
}

func TestNativeModelOperationsPreservesCredentialRotationGuard(t *testing.T) {
	for _, typ := range []string{"gemini", "vertex", "bedrock"} {
		t.Run(typ, func(t *testing.T) {
			e, target, m, p, c, prober := modelOperationsExecutorFixture(t)
			p.ProviderType = typ
			target.Protocol = "chat"
			target.ConfigDigest = repository.VerifiedModelSyncProviderConfigDigest(p.ProviderType, p.BaseURL, p.AuthMode)
			target.IdentityDigest = modelops.TargetIdentityDigest(p, c, m)
			prober.onProbe = func() { c.SecretCiphertext = "rotated" }
			result := e.Execute(context.Background(), "tenant-1", target)
			if result.Success || result.ErrorKind != "config_changed" || len(prober.requests) != 1 || prober.requests[0].ProviderType != typ || m.Status != "active" {
				t.Fatalf("native rotation guard failed %+v", result)
			}
		})
	}
}

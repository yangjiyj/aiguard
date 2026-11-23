package handler

import (
	"context"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/modelops"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/providercompat"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// ModelOperationsExecutor resolves saved tenant-owned configuration. It never
// accepts request-provided URLs, credentials, or model deployment names.
type ModelOperationsExecutor struct{ deps *Dependencies }

func NewModelOperationsExecutor(deps *Dependencies) *ModelOperationsExecutor {
	return &ModelOperationsExecutor{deps: deps}
}

func (e *ModelOperationsExecutor) Execute(ctx context.Context, tenantID string, target modelops.Target) modelops.Outcome {
	if ctx.Err() != nil {
		return modelops.Outcome{ErrorKind: catalog.ModelProbeErrorCancelled}
	}
	model, provider, credential, valid := e.loadIdentity(ctx, tenantID, target)
	if !valid {
		return modelops.Outcome{ErrorKind: "config_changed"}
	}
	protocol := target.Protocol
	authMode := provider.AuthMode
	if !modelops.ProtocolSupported(provider.ProviderType, protocol) {
		return modelops.Outcome{ErrorKind: "unsupported"}
	}
	switch {
	case providercompat.OpenAICompatible(provider.ProviderType):
		if strings.EqualFold(strings.TrimSpace(provider.ProviderType), "azure") {
			authMode = "api-key"
		}
	case nativeModelProbeProvider(provider.ProviderType) && protocol == "chat":
		// The saved native credential selects generateContent or Converse.
	case strings.EqualFold(strings.TrimSpace(provider.ProviderType), "anthropic") && protocol == "messages":
		authMode = "x-api-key"
	default:
		return modelops.Outcome{ErrorKind: "unsupported"}
	}
	apiKey, err := secrets.DecryptProviderSecret(credential.SecretCiphertext)
	if err != nil || strings.TrimSpace(apiKey) == "" {
		return modelops.Outcome{ErrorKind: catalog.ModelProbeErrorUnauthorized}
	}
	if protocol == "chat" {
		protocol = "chat_completions"
	}
	deployment := model.UpstreamModelID
	if deployment == "" {
		deployment = model.ModelName
	}
	probeCtx := ctx
	if nativeModelProbeProvider(provider.ProviderType) {
		proxy, err := loadConfiguredOutboundProxyURL(ctx, e.deps)
		if err != nil {
			return modelops.Outcome{ErrorKind: "invalid_request"}
		}
		probeCtx = catalog.WithOutboundProxy(ctx, proxy)
	}
	result := probeModelSafely(probeCtx, e.deps.ModelProber, catalog.ModelProbeRequest{
		ProviderType: provider.ProviderType,
		BaseURL:      provider.BaseURL, APIKey: apiKey, AuthMode: authMode,
		DeploymentName: deployment, Protocol: protocol, MaxOutputTokens: target.MaxOutputTokens, Timeout: time.Duration(target.TimeoutSeconds) * time.Second,
	})
	// A credential rotation or changed mapping invalidates evidence even if the
	// request itself succeeded. The store repeats this check under row locks.
	if _, _, _, valid = e.loadIdentity(ctx, tenantID, target); !valid {
		return modelops.Outcome{HTTPStatus: result.HTTPStatus, LatencyMS: result.LatencyMS, ErrorKind: "config_changed"}
	}
	outcome := modelops.Outcome{
		Success: result.OK && result.PayloadValidated, HTTPStatus: result.HTTPStatus,
		BodyValidated: result.PayloadValidated, LatencyMS: result.LatencyMS,
	}
	if !outcome.Success {
		outcome.ErrorKind = safeProbeErrorKind(result.ErrorKind)
		if result.OK && !result.PayloadValidated {
			outcome.ErrorKind = "invalid_body"
		}
	}
	return outcome
}

func (e *ModelOperationsExecutor) loadIdentity(ctx context.Context, tenantID string, target modelops.Target) (*repository.Model, *repository.Provider, *repository.ProviderCredential, bool) {
	if e == nil || e.deps == nil || e.deps.ModelRepo == nil || e.deps.ProviderRepo == nil || e.deps.ModelProber == nil {
		return nil, nil, nil, false
	}
	model, err := e.deps.ModelRepo.GetByID(ctx, target.ModelID)
	if err != nil || model == nil || model.ProviderID != target.ProviderID {
		return nil, nil, nil, false
	}
	provider, err := e.deps.ProviderRepo.GetByID(ctx, tenantID, model.ProviderID)
	if err != nil || provider == nil || provider.TenantID != tenantID || provider.Status != "active" || (model.Status != "active" && !(target.ManualProbe && model.Status == "pending")) {
		return nil, nil, nil, false
	}
	credential, err := e.deps.ProviderRepo.GetCredential(ctx, provider.ID)
	if err != nil || credential == nil || credential.ProviderID != provider.ID || credential.Status != "active" || credential.ID != target.CredentialID {
		return nil, nil, nil, false
	}
	if model.UpstreamModelID != target.UpstreamModelID || model.ModelName != target.ModelName || provider.Status != target.ProviderStatus || model.Status != target.ModelStatus {
		return nil, nil, nil, false
	}
	if repository.VerifiedModelSyncProviderConfigDigest(provider.ProviderType, provider.BaseURL, provider.AuthMode) != target.ConfigDigest {
		return nil, nil, nil, false
	}
	if modelops.TargetIdentityDigest(provider, credential, model) != target.IdentityDigest {
		return nil, nil, nil, false
	}
	return model, provider, credential, true
}

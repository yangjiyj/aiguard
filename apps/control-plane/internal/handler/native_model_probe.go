package handler

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/google/uuid"
)

func nativeModelProbeProvider(typ string) bool {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "gemini", "vertex", "bedrock":
		return true
	}
	return false
}
func probeNativeModelProtocols(ctx context.Context, prober catalog.ModelProber, provider *repository.Provider, key, deployment string) (map[string]interface{}, repository.ModelProtocolProbeRecord, error) {
	result := probeModelSafely(ctx, prober, catalog.ModelProbeRequest{ProviderType: provider.ProviderType, BaseURL: provider.BaseURL, APIKey: key, AuthMode: provider.AuthMode, DeploymentName: deployment, Protocol: "chat_completions", MaxOutputTokens: 1024})
	if !result.OK || !result.PayloadValidated || result.HTTPStatus != 200 {
		return nil, repository.ModelProtocolProbeRecord{}, errors.New("native model generation could not be verified")
	}
	now := time.Now().UTC()
	record := repository.ModelProtocolProbeRecord{SourceVersion: "native-protocol-probe-" + uuid.NewString(), ProviderConfigDigest: repository.VerifiedModelSyncProviderConfigDigest(provider.ProviderType, provider.BaseURL, provider.AuthMode), VerifiedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour), Endpoints: []repository.ModelEndpointProbeResult{{EndpointType: "chat", State: "supported"}}}
	return map[string]interface{}{"chat_completions": true, "metadata": map[string]interface{}{"verified": true, "source": "live_native_protocol_probe", "version": record.SourceVersion}}, record, nil
}

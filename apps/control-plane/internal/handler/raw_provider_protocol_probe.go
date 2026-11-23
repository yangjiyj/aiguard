package handler

import (
	"context"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/google/uuid"
)

type providerProtocolProbeUpdater interface {
	UpdateWithCredentialAndProtocolProbe(context.Context, *repository.Provider, *repository.ProviderCredential, repository.ProviderProtocolProbeSnapshot, map[string]interface{}, repository.ModelProtocolProbeRecord) error
}

func rawChatProtocolProbeRecord(provider *repository.Provider) (map[string]interface{}, repository.ModelProtocolProbeRecord) {
	now := time.Now().UTC()
	version := "raw-chat-probe-" + uuid.NewString()
	record := repository.ModelProtocolProbeRecord{
		SourceVersion:        version,
		ProviderConfigDigest: repository.VerifiedModelSyncProviderConfigDigest(provider.ProviderType, provider.BaseURL, provider.AuthMode),
		VerifiedAt:           now, ExpiresAt: now.Add(30 * 24 * time.Hour),
		Endpoints: []repository.ModelEndpointProbeResult{{EndpointType: "chat", State: "supported"}},
	}
	capabilities := map[string]interface{}{"protocols": map[string]interface{}{
		"chat_completions": true,
		"metadata":         map[string]interface{}{"verified": true, "source": "live_protocol_probe", "version": version},
	}}
	return capabilities, record
}

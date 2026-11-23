package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrProviderProtocolProbeConflict = errors.New("provider protocol probe identity changed")

type ProviderProtocolProbeSnapshot struct {
	ProviderConfigDigest string
	ProviderUpdatedAt    time.Time
	CredentialID         string
	SecretCiphertext     string
	ModelID              string
	ModelName            string
	UpstreamModelID      string
	ModelStatus          string
}

type providerProtocolProbeUpdate struct {
	Snapshot     ProviderProtocolProbeSnapshot
	Capabilities map[string]interface{}
	Record       ModelProtocolProbeRecord
}

func (r *ProviderRepository) UpdateWithCredentialAndProtocolProbe(ctx context.Context, provider *Provider, credential *ProviderCredential, snapshot ProviderProtocolProbeSnapshot, capabilities map[string]interface{}, record ModelProtocolProbeRecord) error {
	if provider == nil || provider.AuthMode != "authorization_raw" || snapshot.ModelID == "" || snapshot.CredentialID == "" || snapshot.ProviderConfigDigest == "" || snapshot.ModelStatus != "active" {
		return fmt.Errorf("invalid raw provider probe identity")
	}
	if record.SourceVersion == "" || record.ProviderConfigDigest != VerifiedModelSyncProviderConfigDigest(provider.ProviderType, provider.BaseURL, provider.AuthMode) || record.VerifiedAt.IsZero() || record.ExpiresAt.Sub(record.VerifiedAt) != 30*24*time.Hour || len(record.Endpoints) != 1 || record.Endpoints[0].EndpointType != "chat" || record.Endpoints[0].State != "supported" {
		return fmt.Errorf("invalid verified raw chat probe record")
	}
	return r.updateWithCredentialAndProbe(ctx, provider, credential, &providerProtocolProbeUpdate{Snapshot: snapshot, Capabilities: capabilities, Record: record})
}

func validateProviderProbeSnapshot(ctx context.Context, tx pgx.Tx, provider *Provider, snapshot ProviderProtocolProbeSnapshot) error {
	var providerType, baseURL, authMode string
	var updatedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT provider_type,COALESCE(base_url,''),COALESCE(auth_mode,''),updated_at FROM providers WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, provider.ID, provider.TenantID).Scan(&providerType, &baseURL, &authMode, &updatedAt); err != nil {
		return fmt.Errorf("load provider probe identity: %w", err)
	}
	if VerifiedModelSyncProviderConfigDigest(providerType, baseURL, authMode) != snapshot.ProviderConfigDigest || !updatedAt.Equal(snapshot.ProviderUpdatedAt) {
		return ErrProviderProtocolProbeConflict
	}
	var modelName, upstream, status string
	if err := tx.QueryRow(ctx, `SELECT model_name,COALESCE(upstream_model_id,''),status FROM models WHERE id=$1 AND provider_id=$2 FOR UPDATE`, snapshot.ModelID, provider.ID).Scan(&modelName, &upstream, &status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrProviderProtocolProbeConflict
		}
		return fmt.Errorf("load model probe identity: %w", err)
	}
	if modelName != snapshot.ModelName || upstream != snapshot.UpstreamModelID || status != snapshot.ModelStatus {
		return ErrProviderProtocolProbeConflict
	}
	var credentialID, ciphertext string
	if err := tx.QueryRow(ctx, `SELECT id,COALESCE(secret_ciphertext,'') FROM provider_credentials WHERE provider_id=$1 AND status='active' ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE`, provider.ID).Scan(&credentialID, &ciphertext); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrProviderProtocolProbeConflict
		}
		return fmt.Errorf("load credential probe identity: %w", err)
	}
	if credentialID != snapshot.CredentialID || ciphertext != snapshot.SecretCiphertext {
		return ErrProviderProtocolProbeConflict
	}
	return nil
}

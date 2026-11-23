package handler

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// reverseProxyArtifactID is deterministic for a retained byte hash or upload
// reference fingerprint, so retried events and later references create links to
// one artifact row without storing the original reference value.
func reverseProxyArtifactID(tenantID, environmentScope, provider, requestID string, candidate retentionartifact.Candidate) string {
	environmentScope = retentionartifact.NormalizeEnvironmentScope(environmentScope)
	fingerprint := strings.TrimSpace(candidate.ReferenceFingerprint)
	if fingerprint == "" {
		fingerprint = strings.TrimSpace(candidate.OriginalSHA256)
	}
	if fingerprint == "" {
		fingerprint = requestID + "|" + candidate.StableKey()
	}
	return "rta_" + hashReverseProxyValue(tenantID + "|" + environmentScope + "|" + provider + "|" + fingerprint)[:24]
}

func (r *reverseProxyDBAuditRecorder) retainReverseProxyArtifacts(ctx context.Context, record reverseProxyAuditRecord, candidates []retentionartifact.Candidate, retentionUntil time.Time) {
	if r == nil || r.db == nil || len(candidates) == 0 {
		return
	}
	provider := firstReverseProxyNonEmpty(record.Provider, record.Product, "reverse_proxy")
	environmentScope := retentionartifact.NormalizeEnvironmentScope(r.environmentScope)
	repository := retentionartifact.Repository{DB: r.db}
	writer := retentionartifact.Writer{Store: r.artifactStore}
	for _, candidate := range retentionartifact.Deduplicate(candidates) {
		if candidate.Validate() != nil {
			continue
		}
		result := writer.Retain(ctx, retentionartifact.RetainInput{
			TenantID: record.TenantID, RequestID: record.RequestID, Provider: provider,
			RetentionUntil: retentionUntil, Candidate: candidate,
		})
		referenceHash := strings.TrimSpace(candidate.ReferenceFingerprint)
		if referenceHash == "" {
			referenceHash = strings.TrimSpace(candidate.OriginalSHA256)
		}
		artifactID := reverseProxyArtifactID(record.TenantID, environmentScope, provider, record.RequestID, candidate)
		artifact := retentionartifact.ArtifactRecord{
			ID: artifactID, TenantID: record.TenantID, EnvironmentScope: environmentScope, SourceRequestID: record.RequestID,
			Provider: provider, SourceReferenceHash: referenceHash, Kind: candidate.Kind,
			DisplayName: result.DisplayName, MediaType: result.MediaType, ByteSize: result.ByteSize,
			SHA256: result.OriginalSHA256, Status: result.Status,
			OriginalObjectKey: result.OriginalObjectKey, PreviewObjectKey: result.PreviewObjectKey,
			StorageBackend: result.StorageBackend, FailureCode: result.FailureCode,
			RetentionUntil: retentionUntil,
		}
		link := retentionartifact.ArtifactLink{
			ID:       "ral_" + hashReverseProxyValue(record.TenantID + "|" + record.RequestID + "|" + artifactID + "|" + string(candidate.Direction))[:24],
			TenantID: record.TenantID, EnvironmentScope: environmentScope, RequestID: record.RequestID, ArtifactID: artifactID,
			Direction: candidate.Direction, Ordinal: candidate.Ordinal,
		}
		if err := repository.Save(ctx, artifact, link); err != nil {
			log.Printf("Failed to write reverse proxy artifact retention request_id=%s: %v", record.RequestID, err)
		}
	}
}

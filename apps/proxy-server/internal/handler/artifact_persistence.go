package handler

import (
	"context"
	"log"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

type proxyRetainedArtifactWrite struct {
	artifact retentionartifact.ArtifactRecord
	link     retentionartifact.ArtifactLink
}

func (a *AuditWriter) persistRetainedArtifacts(ctx context.Context, record ProxyAuditRecord, retentionUntil time.Time, items []retainedAttachmentMetadata) {
	if a == nil || a.db == nil {
		return
	}
	repository := retentionartifact.Repository{DB: a.db}
	for _, write := range buildProxyRetainedArtifactWrites(record, retentionUntil, items) {
		if write.artifact.SourceReferenceHash != "" {
			existing, found, err := repository.FindByReference(
				ctx,
				record.TenantID,
				write.artifact.Provider,
				write.artifact.EnvironmentScope,
				write.artifact.SourceReferenceHash,
			)
			if err != nil {
				log.Printf("Failed to resolve normalized forward proxy artifact request_id=%s: %v", record.RequestID, err)
				continue
			}
			if found {
				write = reconcileExistingProxyArtifact(record, write, *existing, retentionUntil)
			}
		}
		if err := repository.Save(ctx, write.artifact, write.link); err != nil {
			log.Printf("Failed to write normalized forward proxy artifact request_id=%s: %v", record.RequestID, err)
		}
	}
}

func reconcileExistingProxyArtifact(record ProxyAuditRecord, write proxyRetainedArtifactWrite, existing retentionartifact.ArtifactRecord, retentionUntil time.Time) proxyRetainedArtifactWrite {
	preservingExistingBytes := existing.Status == retentionartifact.RetentionStatusRetained &&
		write.artifact.Status != retentionartifact.RetentionStatusRetained
	if preservingExistingBytes {
		write.artifact = existing
	} else {
		write.artifact.ID = existing.ID
	}
	if !preservingExistingBytes &&
		write.artifact.Status != retentionartifact.RetentionStatusRetained &&
		write.artifact.RetentionUntil.Before(retentionUntil) {
		write.artifact.RetentionUntil = retentionUntil
	}
	write.link.ArtifactID = existing.ID
	write.link.ID = proxyArtifactLinkID(record, existing.ID, write.link.Direction)
	return write
}

func buildProxyRetainedArtifactWrites(record ProxyAuditRecord, retentionUntil time.Time, items []retainedAttachmentMetadata) []proxyRetainedArtifactWrite {
	provider := firstNonEmpty(record.Provider, record.Product, "forward_proxy")
	environmentScope := retentionartifact.NormalizeEnvironmentScope(record.EnvironmentScope)
	writes := make([]proxyRetainedArtifactWrite, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for ordinal, item := range items {
		direction := retentionartifact.DirectionInput
		if strings.EqualFold(strings.TrimSpace(item.Stage), "response") || strings.EqualFold(strings.TrimSpace(item.Stage), "output") {
			direction = retentionartifact.DirectionOutput
		}
		kind := retentionartifact.KindFile
		mediaType := strings.ToLower(strings.TrimSpace(strings.Split(item.ContentType, ";")[0]))
		if strings.HasPrefix(mediaType, "image/") {
			kind = retentionartifact.KindImage
		}

		identity := ""
		if strings.TrimSpace(item.ReferenceID) != "" {
			identity = hashValue("reference\x00" + strings.TrimSpace(item.ReferenceID))
		}
		if identity == "" {
			identity = strings.ToLower(strings.TrimSpace(item.SHA256))
		}
		if identity == "" && strings.TrimSpace(item.ObjectKey) != "" {
			identity = hashValue("object\x00" + strings.TrimSpace(item.ObjectKey))
		}
		if identity == "" {
			identity = hashValue(record.RequestID + "\x00" + string(direction) + "\x00" + string(kind) + "\x00" + strconv.Itoa(ordinal))
		}
		artifactID := "rta_" + hashValue(record.TenantID + "\x00" + environmentScope + "\x00" + provider + "\x00" + identity)[:24]
		linkKey := record.TenantID + "\x00" + record.RequestID + "\x00" + artifactID + "\x00" + string(direction)
		if _, exists := seen[linkKey]; exists {
			continue
		}
		seen[linkKey] = struct{}{}

		status, failureCode := normalizedProxyArtifactStatus(item)
		artifactRetentionUntil := normalizedProxyArtifactRetentionUntil(item, status, retentionUntil)
		artifact := retentionartifact.ArtifactRecord{
			ID: artifactID, TenantID: record.TenantID, EnvironmentScope: environmentScope, SourceRequestID: record.RequestID,
			Provider: provider, SourceReferenceHash: identity, Kind: kind,
			DisplayName: proxyArtifactDisplayName(item.FileName, kind), MediaType: item.ContentType, ByteSize: item.Size,
			SHA256: strings.ToLower(strings.TrimSpace(item.SHA256)), Status: status,
			OriginalObjectKey: strings.TrimSpace(item.ObjectKey),
			StorageBackend:    strings.TrimSpace(item.StorageBackend), FailureCode: failureCode,
			RetentionUntil: artifactRetentionUntil,
		}
		link := retentionartifact.ArtifactLink{
			ID: proxyArtifactLinkID(record, artifactID, direction), TenantID: record.TenantID, EnvironmentScope: environmentScope,
			RequestID: record.RequestID, ArtifactID: artifactID, Direction: direction, Ordinal: ordinal,
		}
		writes = append(writes, proxyRetainedArtifactWrite{artifact: artifact, link: link})
	}
	return writes
}

func normalizedProxyArtifactRetentionUntil(item retainedAttachmentMetadata, status retentionartifact.RetentionStatus, fallback time.Time) time.Time {
	if status == retentionartifact.RetentionStatusRetained && strings.TrimSpace(item.RetentionUntil) != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(item.RetentionUntil)); err == nil && !parsed.IsZero() {
			return parsed.UTC()
		}
	}
	return fallback.UTC()
}

func proxyArtifactLinkID(record ProxyAuditRecord, artifactID string, direction retentionartifact.Direction) string {
	key := record.TenantID + "\x00" + record.RequestID + "\x00" + artifactID + "\x00" + string(direction)
	return "ral_" + hashValue(key)[:24]
}

func proxyArtifactDisplayName(name string, kind retentionartifact.Kind) string {
	name = path.Base(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, name)
	if name == "" || name == "." {
		if kind == retentionartifact.KindImage {
			return "artifact-image"
		}
		return "artifact-file"
	}
	return name
}

func normalizedProxyArtifactStatus(item retainedAttachmentMetadata) (retentionartifact.RetentionStatus, string) {
	status := strings.ToLower(strings.TrimSpace(item.RetentionStatus))
	if strings.TrimSpace(item.ObjectKey) != "" && (status == "externalized" || status == "retained") {
		return retentionartifact.RetentionStatusRetained, ""
	}
	switch status {
	case "reference_only", "url_only", "":
		return retentionartifact.RetentionStatusReferenceOnly, ""
	case "oversize_unretained":
		return retentionartifact.RetentionStatusOversizeUnretained, ""
	default:
		return retentionartifact.RetentionStatusFailed, sanitizeRetainedStorageText(status)
	}
}

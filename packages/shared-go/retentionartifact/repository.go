package retentionartifact

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type RepositoryDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Repository struct {
	DB RepositoryDB
}

type ArtifactRecord struct {
	ID                  string
	TenantID            string
	EnvironmentScope    string
	SourceRequestID     string
	Provider            string
	SourceReferenceHash string
	Kind                Kind
	DisplayName         string
	MediaType           string
	ByteSize            int64
	SHA256              string
	Status              RetentionStatus
	OriginalObjectKey   string
	PreviewObjectKey    string
	StorageBackend      string
	FailureCode         string
	RetentionUntil      time.Time
}

type ArtifactLink struct {
	ID               string
	TenantID         string
	EnvironmentScope string
	RequestID        string
	ArtifactID       string
	Direction        Direction
	Ordinal          int
}

const artifactUpsertSQL = `
INSERT INTO retained_artifacts (
    id, tenant_id, source_request_id, provider, source_reference_hash,
    kind, display_name, media_type, byte_size, sha256, retention_status,
    original_object_key, preview_object_key, storage_backend, failure_code,
    retention_until, environment_scope, created_at, updated_at
) VALUES (
    $1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''),
    $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, 0), NULLIF($10, ''),
    $11, NULLIF($12, ''), NULLIF($13, ''), NULLIF($14, ''), NULLIF($15, ''),
    NULLIF($16, 'epoch'::timestamptz),
    COALESCE(
        (SELECT environment_scope FROM request_logs
         WHERE tenant_id = $2::varchar(64) AND request_id = $3::varchar(64)),
        NULLIF($17, ''),
        'legacy-unclassified'
    ),
    now(), now()
)
ON CONFLICT (id) DO UPDATE SET
    display_name = CASE
        WHEN retained_artifacts.retention_status = 'retained' AND EXCLUDED.retention_status <> 'retained'
            THEN retained_artifacts.display_name
        ELSE COALESCE(EXCLUDED.display_name, retained_artifacts.display_name) END,
    media_type = CASE
        WHEN retained_artifacts.retention_status = 'retained' AND EXCLUDED.retention_status <> 'retained'
            THEN retained_artifacts.media_type
        ELSE COALESCE(EXCLUDED.media_type, retained_artifacts.media_type) END,
    byte_size = CASE
        WHEN retained_artifacts.retention_status = 'retained' AND EXCLUDED.retention_status <> 'retained'
            THEN retained_artifacts.byte_size
        ELSE COALESCE(EXCLUDED.byte_size, retained_artifacts.byte_size) END,
    sha256 = CASE
        WHEN retained_artifacts.retention_status = 'retained' AND EXCLUDED.retention_status <> 'retained'
            THEN retained_artifacts.sha256
        ELSE COALESCE(EXCLUDED.sha256, retained_artifacts.sha256) END,
    retention_status = CASE
        WHEN retained_artifacts.retention_status = 'retained' THEN retained_artifacts.retention_status
        ELSE EXCLUDED.retention_status END,
    original_object_key = CASE
        WHEN EXCLUDED.retention_status = 'retained'
            THEN COALESCE(EXCLUDED.original_object_key, retained_artifacts.original_object_key)
        WHEN retained_artifacts.retention_status = 'retained'
            THEN retained_artifacts.original_object_key
        ELSE COALESCE(EXCLUDED.original_object_key, retained_artifacts.original_object_key) END,
    preview_object_key = CASE
        WHEN EXCLUDED.retention_status = 'retained'
            THEN EXCLUDED.preview_object_key
        WHEN retained_artifacts.retention_status = 'retained'
            THEN retained_artifacts.preview_object_key
        ELSE COALESCE(EXCLUDED.preview_object_key, retained_artifacts.preview_object_key) END,
    storage_backend = CASE
        WHEN retained_artifacts.retention_status = 'retained' AND EXCLUDED.retention_status <> 'retained'
            THEN retained_artifacts.storage_backend
        ELSE COALESCE(EXCLUDED.storage_backend, retained_artifacts.storage_backend) END,
    failure_code = CASE
        WHEN EXCLUDED.retention_status = 'retained' THEN NULL
        WHEN retained_artifacts.retention_status = 'retained' THEN retained_artifacts.failure_code
        ELSE COALESCE(EXCLUDED.failure_code, retained_artifacts.failure_code) END,
    retention_until = CASE
        WHEN EXCLUDED.retention_status = 'retained'
            THEN COALESCE(EXCLUDED.retention_until, retained_artifacts.retention_until)
        WHEN retained_artifacts.retention_status = 'retained'
            THEN retained_artifacts.retention_until
        ELSE GREATEST(retained_artifacts.retention_until, EXCLUDED.retention_until) END,
    updated_at = now()
WHERE retained_artifacts.tenant_id = EXCLUDED.tenant_id
  AND retained_artifacts.environment_scope = EXCLUDED.environment_scope`

const artifactLinkSQL = `
INSERT INTO access_content_artifact_links (
    id, tenant_id, request_id, artifact_id, direction, ordinal, environment_scope, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    COALESCE(
        (SELECT environment_scope FROM request_logs
         WHERE tenant_id = $2::varchar(64) AND request_id = $3::varchar(64)),
        NULLIF($7, ''),
        'legacy-unclassified'
    ),
    now()
)
ON CONFLICT (tenant_id, request_id, artifact_id, direction)
DO UPDATE SET
    ordinal = LEAST(access_content_artifact_links.ordinal, EXCLUDED.ordinal),
    environment_scope = access_content_artifact_links.environment_scope
WHERE access_content_artifact_links.environment_scope = EXCLUDED.environment_scope`

const artifactReferenceLookupSQL = `
SELECT id, tenant_id, COALESCE(source_request_id, ''), COALESCE(provider, ''),
       COALESCE(source_reference_hash, ''), kind, COALESCE(display_name, ''),
       COALESCE(media_type, ''), COALESCE(byte_size, 0), COALESCE(sha256, ''),
       retention_status, COALESCE(original_object_key, ''), COALESCE(preview_object_key, ''),
       COALESCE(storage_backend, ''), COALESCE(failure_code, ''), retention_until,
       environment_scope
FROM retained_artifacts
WHERE tenant_id = $1 AND provider = $2 AND environment_scope = $3
  AND source_reference_hash = $4
ORDER BY updated_at DESC
LIMIT 1`

func (r Repository) Save(ctx context.Context, artifact ArtifactRecord, link ArtifactLink) error {
	if r.DB == nil {
		return errors.New("artifact repository is nil")
	}
	if artifact.TenantID == "" || artifact.ID == "" || link.TenantID == "" ||
		link.RequestID == "" || link.ArtifactID == "" || artifact.TenantID != link.TenantID ||
		artifact.ID != link.ArtifactID {
		return errors.New("invalid artifact record or link")
	}
	if err := (Result{Status: artifact.Status}).Validate(); err != nil {
		return err
	}
	if artifact.Status == RetentionStatusRetained && strings.TrimSpace(artifact.OriginalObjectKey) == "" {
		return errors.New("retained artifact requires an original object key")
	}
	artifact.EnvironmentScope = NormalizeEnvironmentScope(artifact.EnvironmentScope)
	link.EnvironmentScope = NormalizeEnvironmentScope(link.EnvironmentScope)
	if artifact.EnvironmentScope != link.EnvironmentScope {
		return errors.New("artifact and link environment scope mismatch")
	}
	tag, err := r.DB.Exec(ctx, artifactUpsertSQL,
		artifact.ID, artifact.TenantID, artifact.SourceRequestID, artifact.Provider,
		artifact.SourceReferenceHash, artifact.Kind, artifact.DisplayName, artifact.MediaType,
		artifact.ByteSize, artifact.SHA256, artifact.Status, artifact.OriginalObjectKey,
		artifact.PreviewObjectKey, artifact.StorageBackend, artifact.FailureCode,
		retentionArgument(artifact.RetentionUntil), artifact.EnvironmentScope,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("artifact identity conflicts with another tenant or environment scope")
	}
	tag, err = r.DB.Exec(ctx, artifactLinkSQL, link.ID, link.TenantID, link.RequestID,
		link.ArtifactID, link.Direction, link.Ordinal, link.EnvironmentScope)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("artifact link conflicts with another environment scope")
	}
	return nil
}

func (r Repository) FindByReference(ctx context.Context, tenantID, provider, environmentScope, referenceHash string) (*ArtifactRecord, bool, error) {
	if r.DB == nil || tenantID == "" || provider == "" || referenceHash == "" {
		return nil, false, nil
	}
	environmentScope = NormalizeEnvironmentScope(environmentScope)
	var item ArtifactRecord
	if err := r.DB.QueryRow(ctx, artifactReferenceLookupSQL, tenantID, provider, environmentScope, referenceHash).Scan(
		&item.ID, &item.TenantID, &item.SourceRequestID, &item.Provider, &item.SourceReferenceHash,
		&item.Kind, &item.DisplayName, &item.MediaType, &item.ByteSize, &item.SHA256,
		&item.Status, &item.OriginalObjectKey, &item.PreviewObjectKey, &item.StorageBackend,
		&item.FailureCode, &item.RetentionUntil, &item.EnvironmentScope,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &item, true, nil
}

func retentionArgument(value time.Time) time.Time {
	if value.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return value.UTC()
}

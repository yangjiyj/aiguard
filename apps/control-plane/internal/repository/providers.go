package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrProviderReferencedByRoutingPolicy = errors.New("provider is referenced by an enabled model routing policy")
var ErrProviderNotRestorable = errors.New("provider has no recoverable credential")

// Provider represents a provider record
type Provider struct {
	ID                  string
	TenantID            string
	Name                string
	ProviderType        string
	BaseURL             string
	AuthMode            string
	IsDefault           bool
	HasCredential       bool
	CredentialUpdatedAt *time.Time
	Status              string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// ProviderCredential represents provider credentials
type ProviderCredential struct {
	ID               string
	ProviderID       string
	CredentialName   string
	SecretCiphertext string
	KMSKeyRef        string
	Status           string
	RotatedAt        *time.Time
	CreatedAt        time.Time
}

// ListCredentialHistory returns credential history for a provider, newest first.
func (r *ProviderRepository) ListCredentialHistory(ctx context.Context, providerID string) ([]*ProviderCredential, error) {
	query := `
		SELECT id, provider_id, credential_name, secret_ciphertext, kms_key_ref, status, rotated_at, created_at
		FROM provider_credentials
		WHERE provider_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, providerID)
	if err != nil {
		return nil, fmt.Errorf("failed to list credential history: %w", err)
	}
	defer rows.Close()

	history := []*ProviderCredential{}
	for rows.Next() {
		var cred ProviderCredential
		if err := rows.Scan(
			&cred.ID,
			&cred.ProviderID,
			&cred.CredentialName,
			&cred.SecretCiphertext,
			&cred.KMSKeyRef,
			&cred.Status,
			&cred.RotatedAt,
			&cred.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan credential history: %w", err)
		}
		history = append(history, &cred)
	}

	return history, nil
}

// ProviderRepository handles provider database operations
type ProviderRepository struct {
	db *pgxpool.Pool
}

// NewProviderRepository creates a new provider repository
func NewProviderRepository(db *pgxpool.Pool) *ProviderRepository {
	return &ProviderRepository{db: db}
}

// GetByID retrieves a provider by ID within a tenant.
func (r *ProviderRepository) GetByID(ctx context.Context, tenantID, id string) (*Provider, error) {
	query := `
		SELECT id, tenant_id, name, provider_type, base_url, auth_mode, is_default,
		       EXISTS (
		           SELECT 1
		           FROM provider_credentials pc
		           WHERE pc.provider_id = providers.id AND pc.status = 'active'
		       ) AS has_credential,
		       cred.credential_updated_at,
		       status, created_at, updated_at
		FROM providers
		LEFT JOIN LATERAL (
			SELECT COALESCE(pc.rotated_at, pc.created_at) AS credential_updated_at
			FROM provider_credentials pc
			WHERE pc.provider_id = providers.id AND pc.status = 'active'
			ORDER BY pc.created_at DESC
			LIMIT 1
		) cred ON TRUE
		WHERE tenant_id = $1 AND id = $2 AND status <> 'deleted'
	`

	row := r.db.QueryRow(ctx, query, tenantID, id)
	var provider Provider
	err := row.Scan(
		&provider.ID,
		&provider.TenantID,
		&provider.Name,
		&provider.ProviderType,
		&provider.BaseURL,
		&provider.AuthMode,
		&provider.IsDefault,
		&provider.HasCredential,
		&provider.CredentialUpdatedAt,
		&provider.Status,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}
	return &provider, nil
}

// List retrieves providers for a tenant, or all providers if tenantID is empty
func (r *ProviderRepository) List(ctx context.Context, tenantID string) ([]*Provider, error) {
	var query string
	var args []interface{}

	if tenantID != "" {
		query = `
			SELECT id, tenant_id, name, provider_type, base_url, auth_mode, is_default,
			       EXISTS (
			           SELECT 1
			           FROM provider_credentials pc
			           WHERE pc.provider_id = providers.id AND pc.status = 'active'
			       ) AS has_credential,
			       cred.credential_updated_at,
			       status, created_at, updated_at
			FROM providers
			LEFT JOIN LATERAL (
				SELECT COALESCE(pc.rotated_at, pc.created_at) AS credential_updated_at
				FROM provider_credentials pc
				WHERE pc.provider_id = providers.id AND pc.status = 'active'
				ORDER BY pc.created_at DESC
				LIMIT 1
			) cred ON TRUE
			WHERE tenant_id = $1 AND status <> 'deleted'
			ORDER BY created_at DESC
		`
		args = []interface{}{tenantID}
	} else {
		query = `
			SELECT id, tenant_id, name, provider_type, base_url, auth_mode, is_default,
			       EXISTS (
			           SELECT 1
			           FROM provider_credentials pc
			           WHERE pc.provider_id = providers.id AND pc.status = 'active'
			       ) AS has_credential,
			       cred.credential_updated_at,
			       status, created_at, updated_at
			FROM providers
			LEFT JOIN LATERAL (
				SELECT COALESCE(pc.rotated_at, pc.created_at) AS credential_updated_at
				FROM provider_credentials pc
				WHERE pc.provider_id = providers.id AND pc.status = 'active'
				ORDER BY pc.created_at DESC
				LIMIT 1
			) cred ON TRUE
			WHERE status <> 'deleted'
			ORDER BY created_at DESC
		`
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list providers: %w", err)
	}
	defer rows.Close()

	providers := []*Provider{}
	for rows.Next() {
		var provider Provider
		err := rows.Scan(
			&provider.ID,
			&provider.TenantID,
			&provider.Name,
			&provider.ProviderType,
			&provider.BaseURL,
			&provider.AuthMode,
			&provider.IsDefault,
			&provider.HasCredential,
			&provider.CredentialUpdatedAt,
			&provider.Status,
			&provider.CreatedAt,
			&provider.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		providers = append(providers, &provider)
	}
	return providers, nil
}

// Create creates a new provider
func (r *ProviderRepository) Create(ctx context.Context, provider *Provider) error {
	if provider.ID == "" {
		provider.ID = "prov_" + uuid.New().String()[:8]
	}

	query := `
		INSERT INTO providers (id, tenant_id, name, provider_type, base_url, auth_mode, is_default, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.Exec(ctx, query,
		provider.ID,
		provider.TenantID,
		provider.Name,
		provider.ProviderType,
		provider.BaseURL,
		provider.AuthMode,
		provider.IsDefault,
		provider.Status,
	)

	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}
	return nil
}

// Update updates a provider
func (r *ProviderRepository) Update(ctx context.Context, provider *Provider) error {
	query := `
		UPDATE providers
		SET name = $2, base_url = $3, auth_mode = $4, is_default = $5, status = $6, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $7
	`

	result, err := r.db.Exec(ctx, query,
		provider.ID,
		provider.Name,
		provider.BaseURL,
		provider.AuthMode,
		provider.IsDefault,
		provider.Status,
		provider.TenantID,
	)

	if err != nil {
		return fmt.Errorf("failed to update provider: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("provider not found")
	}
	return nil
}

// GetCredential retrieves provider credentials
func (r *ProviderRepository) GetCredential(ctx context.Context, providerID string) (*ProviderCredential, error) {
	query := `
		SELECT id, provider_id, credential_name, secret_ciphertext, kms_key_ref, status, rotated_at, created_at
		FROM provider_credentials
		WHERE provider_id = $1 AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`

	row := r.db.QueryRow(ctx, query, providerID)
	var cred ProviderCredential
	err := row.Scan(
		&cred.ID,
		&cred.ProviderID,
		&cred.CredentialName,
		&cred.SecretCiphertext,
		&cred.KMSKeyRef,
		&cred.Status,
		&cred.RotatedAt,
		&cred.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}
	return &cred, nil
}

// CreateCredential creates provider credentials
func (r *ProviderRepository) CreateCredential(ctx context.Context, cred *ProviderCredential) error {
	if cred.ID == "" {
		cred.ID = "cred_" + uuid.New().String()[:8]
	}

	query := `
		INSERT INTO provider_credentials (id, provider_id, credential_name, secret_ciphertext, kms_key_ref, status, rotated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.Exec(ctx, query,
		cred.ID,
		cred.ProviderID,
		cred.CredentialName,
		cred.SecretCiphertext,
		cred.KMSKeyRef,
		cred.Status,
		cred.RotatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}
	return nil
}

// CreateWithCredential creates a provider and its credential atomically.
func (r *ProviderRepository) CreateWithCredential(ctx context.Context, provider *Provider, cred *ProviderCredential) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if provider.ID == "" {
		provider.ID = "prov_" + uuid.New().String()[:8]
	}

	createProviderQuery := `
		INSERT INTO providers (id, tenant_id, name, provider_type, base_url, auth_mode, is_default, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	if _, err := tx.Exec(ctx, createProviderQuery,
		provider.ID,
		provider.TenantID,
		provider.Name,
		provider.ProviderType,
		provider.BaseURL,
		provider.AuthMode,
		provider.IsDefault,
		provider.Status,
	); err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	if cred != nil {
		if err := insertCredential(ctx, tx, provider.ID, cred); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit provider creation: %w", err)
	}
	return nil
}

// CreateWithCredentialAndModel creates a complete-chat provider bundle in one transaction.
func (r *ProviderRepository) CreateWithCredentialAndModel(ctx context.Context, provider *Provider, cred *ProviderCredential, model *Model) error {
	if cred == nil || model == nil {
		return fmt.Errorf("credential and model are required")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if provider.ID == "" {
		provider.ID = "prov_" + uuid.New().String()[:8]
	}
	if model.ID == "" {
		model.ID = "model_" + uuid.New().String()[:8]
	}
	model.ProviderID = provider.ID
	if _, err := tx.Exec(ctx, `
		INSERT INTO providers (id, tenant_id, name, provider_type, base_url, auth_mode, is_default, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, provider.ID, provider.TenantID, provider.Name, provider.ProviderType, provider.BaseURL, provider.AuthMode, provider.IsDefault, provider.Status); err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}
	if err := insertCredential(ctx, tx, provider.ID, cred); err != nil {
		return err
	}
	capabilities, err := json.Marshal(model.Capabilities)
	if err != nil {
		return fmt.Errorf("failed to encode model capabilities: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO models (id, provider_id, model_name, model_label, upstream_model_id, capabilities_json, pricing_json, context_window, status)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, '{}', $7, $8)
	`, model.ID, model.ProviderID, model.ModelName, model.ModelLabel, nullableString(model.UpstreamModelID), string(capabilities), model.ContextWindow, model.Status); err != nil {
		return fmt.Errorf("failed to create model: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit provider creation: %w", err)
	}
	return nil
}

// UpdateWithCredential updates a provider and rotates its credential atomically.
// Transitioning a provider out of the active pool additionally converges any
// enabled v2 routing policies that reference it.
func (r *ProviderRepository) UpdateWithCredential(ctx context.Context, provider *Provider, cred *ProviderCredential) error {
	return r.updateWithCredentialAndProbe(ctx, provider, cred, nil)
}

func (r *ProviderRepository) updateWithCredentialAndProbe(ctx context.Context, provider *Provider, cred *ProviderCredential, probe *providerProtocolProbeUpdate) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('model-routing-provider-lifecycle:' || $1, 0))`, provider.TenantID); err != nil {
		return fmt.Errorf("failed to lock provider routing lifecycle: %w", err)
	}

	var previousStatus string
	err = tx.QueryRow(ctx, `
		SELECT status
		FROM providers
		WHERE id = $1 AND tenant_id = $2
		FOR UPDATE
	`, provider.ID, provider.TenantID).Scan(&previousStatus)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("provider not found")
		}
		return fmt.Errorf("failed to lock provider: %w", err)
	}
	if probe != nil {
		if err := validateProviderProbeSnapshot(ctx, tx, provider, probe.Snapshot); err != nil {
			return err
		}
	}

	updateProviderQuery := `
		UPDATE providers
		SET name = $2, base_url = $3, auth_mode = $4, is_default = $5, status = $6, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $7
	`

	result, err := tx.Exec(ctx, updateProviderQuery,
		provider.ID,
		provider.Name,
		provider.BaseURL,
		provider.AuthMode,
		provider.IsDefault,
		provider.Status,
		provider.TenantID,
	)
	if err != nil {
		return fmt.Errorf("failed to update provider: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("provider not found")
	}

	if previousStatus == "active" && provider.Status != "" && provider.Status != "active" {
		if err := convergeRoutingPoliciesForProvider(ctx, tx, provider.TenantID, provider.ID); err != nil {
			return err
		}
	}

	if cred != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE provider_credentials
			SET status = 'rotated', rotated_at = COALESCE(rotated_at, NOW())
			WHERE provider_id = $1 AND status = 'active'
		`, provider.ID); err != nil {
			return fmt.Errorf("failed to rotate existing credentials: %w", err)
		}
		if err := insertCredential(ctx, tx, provider.ID, cred); err != nil {
			return err
		}
	}

	if probe != nil {
		encoded, err := json.Marshal(probe.Capabilities)
		if err != nil {
			return fmt.Errorf("encode raw chat probe capabilities: %w", err)
		}
		if err := recordModelProtocolProbeTx(ctx, tx, provider.TenantID, provider.ID, probe.Snapshot.ModelID, encoded, probe.Record); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit provider update: %w", err)
	}
	return nil
}

type credentialQuerier interface {
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
}

func insertCredential(ctx context.Context, execer credentialQuerier, providerID string, cred *ProviderCredential) error {
	if cred.ID == "" {
		cred.ID = "cred_" + uuid.New().String()[:8]
	}
	cred.ProviderID = providerID

	query := `
		INSERT INTO provider_credentials (id, provider_id, credential_name, secret_ciphertext, kms_key_ref, status, rotated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	if _, err := execer.Exec(ctx, query,
		cred.ID,
		cred.ProviderID,
		cred.CredentialName,
		cred.SecretCiphertext,
		cred.KMSKeyRef,
		cred.Status,
		cred.RotatedAt,
	); err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	return nil
}

// Delete removes a provider from runtime while retaining historical references.
func (r *ProviderRepository) Delete(ctx context.Context, tenantID, id string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('model-routing-provider-lifecycle:' || $1, 0))`, tenantID); err != nil {
		return fmt.Errorf("failed to lock provider routing lifecycle: %w", err)
	}

	var lockedProviderID string
	err = tx.QueryRow(ctx, `
		SELECT id
		FROM providers
		WHERE tenant_id = $1 AND id = $2 AND status <> 'deleted'
		FOR UPDATE
	`, tenantID, id).Scan(&lockedProviderID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("provider not found")
		}
		return fmt.Errorf("failed to lock provider: %w", err)
	}

	// 上游退出可用池时自动收敛引用它的模型路由策略，避免留下无处处理的失效规则。
	if err := convergeRoutingPoliciesForProvider(ctx, tx, tenantID, id); err != nil {
		return err
	}

	credentialRows, err := tx.Query(ctx, `
		SELECT id
		FROM provider_credentials
		WHERE provider_id = $1
		FOR UPDATE
	`, id)
	if err != nil {
		return fmt.Errorf("failed to lock provider credentials: %w", err)
	}
	for credentialRows.Next() {
		var credentialID string
		if scanErr := credentialRows.Scan(&credentialID); scanErr != nil {
			credentialRows.Close()
			return fmt.Errorf("failed to scan provider credential lock: %w", scanErr)
		}
	}
	credentialRowsErr := credentialRows.Err()
	credentialRows.Close()
	if credentialRowsErr != nil {
		return fmt.Errorf("failed to iterate provider credential locks: %w", credentialRowsErr)
	}

	if _, err = tx.Exec(ctx, `UPDATE models SET status = 'inactive' WHERE provider_id = $1`, id); err != nil {
		return fmt.Errorf("failed to deactivate provider models: %w", err)
	}

	if _, err = tx.Exec(ctx, `
		UPDATE provider_credentials
		SET status = 'revoked'
		WHERE provider_id = $1 AND status = 'active'
	`, id); err != nil {
		return fmt.Errorf("failed to revoke provider credentials: %w", err)
	}

	if _, err = tx.Exec(ctx, `
		UPDATE providers
		SET status = 'deleted'
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, id); err != nil {
		return fmt.Errorf("failed to delete provider: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit provider deletion: %w", err)
	}
	return nil
}

// ListDeleted returns only recovery metadata. Endpoint and credential material
// are intentionally excluded from this administrator-facing recovery list.
func (r *ProviderRepository) ListDeleted(ctx context.Context, tenantID string) ([]*Provider, error) {
	rows, err := r.db.Query(ctx, `
		SELECT p.id, p.tenant_id, p.name, p.provider_type, p.status,
		       EXISTS (
			   SELECT 1 FROM provider_credentials pc
			   WHERE pc.provider_id=p.id AND pc.status='revoked'
			     AND COALESCE(pc.secret_ciphertext, '') <> ''
		       ) AS has_recoverable_credential
		FROM providers p
		WHERE p.tenant_id=$1 AND p.status='deleted'
		ORDER BY p.updated_at DESC, p.id
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list deleted providers: %w", err)
	}
	defer rows.Close()
	providers := make([]*Provider, 0)
	for rows.Next() {
		provider := &Provider{}
		if err := rows.Scan(&provider.ID, &provider.TenantID, &provider.Name, &provider.ProviderType, &provider.Status, &provider.HasCredential); err != nil {
			return nil, fmt.Errorf("failed to scan deleted provider: %w", err)
		}
		providers = append(providers, provider)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate deleted providers: %w", err)
	}
	return providers, nil
}

// Restore explicitly reactivates a soft-deleted provider and its newest
// deletion-revoked credential. Models stay inactive until an administrator
// performs a fresh model sync, so intentionally disabled models are not revived.
func (r *ProviderRepository) Restore(ctx context.Context, tenantID, id string) (*Provider, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin provider restore: %w", err)
	}
	defer tx.Rollback(ctx)

	provider := &Provider{}
	if err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, name, provider_type, status
		FROM providers
		WHERE tenant_id=$1 AND id=$2 AND status='deleted'
		FOR UPDATE
	`, tenantID, id).Scan(&provider.ID, &provider.TenantID, &provider.Name, &provider.ProviderType, &provider.Status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("provider not found")
		}
		return nil, fmt.Errorf("failed to lock deleted provider: %w", err)
	}

	var credentialID string
	if err := tx.QueryRow(ctx, `
		SELECT id
		FROM provider_credentials
		WHERE provider_id=$1 AND status='revoked'
		  AND COALESCE(secret_ciphertext, '') <> ''
		ORDER BY created_at DESC, id DESC
		LIMIT 1
		FOR UPDATE
	`, id).Scan(&credentialID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotRestorable
		}
		return nil, fmt.Errorf("failed to lock recoverable credential: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE provider_credentials SET status='active' WHERE provider_id=$1 AND id=$2`, id, credentialID); err != nil {
		return nil, fmt.Errorf("failed to restore provider credential: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE providers SET status='active', updated_at=NOW() WHERE tenant_id=$1 AND id=$2`, tenantID, id); err != nil {
		return nil, fmt.Errorf("failed to restore provider: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit provider restore: %w", err)
	}
	provider.Status = "active"
	provider.HasCredential = true
	return provider, nil
}

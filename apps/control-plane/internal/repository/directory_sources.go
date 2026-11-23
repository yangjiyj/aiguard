package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DirectoryKind string

const (
	DirectoryKindActiveDirectory DirectoryKind = "ad"
	DirectoryKindLDAP            DirectoryKind = "ldap"
)

const (
	DirectoryReconciliationReasonFullSyncFailed = "full_sync_failed"
	DirectoryReconciliationReasonPostSyncFailed = "post_sync_activation_failed"
	DirectoryReconciliationReasonClearFailed    = "reconciliation_clear_failed"
)

var (
	ErrDirectorySourceChanged               = errors.New("directory source changed")
	ErrDirectorySourceActivating            = errors.New("directory source activation in progress")
	ErrDirectoryReconciliationReasonInvalid = errors.New("directory reconciliation reason is invalid")
)

const directoryActivationLockSeed int64 = 0x4a4a4447

var directoryReconciliationReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type DirectorySource struct {
	ID                            string
	TenantID                      string
	Kind                          DirectoryKind
	DisplayName                   string
	ConnectionURL                 string
	BindDN                        string
	BindPasswordEnc               string
	CACertPEM                     string
	BaseDN                        string
	UsersDN                       string
	UserFilter                    string
	StableIDAttribute             string
	UsernameAttribute             string
	EmailAttribute                string
	NameAttribute                 string
	Status                        string
	Version                       int
	RuntimeComponentID            string
	ConfigDigest                  string
	RuntimeReconciliationRequired bool
	RuntimeReconciliationReason   string
	LastTestedAt                  *time.Time
	LastTestResult                *TestResult
	CreatedAt                     time.Time
	UpdatedAt                     time.Time
}

type DirectorySourceRepository struct{ db *pgxpool.Pool }

func NewDirectorySourceRepository(db *pgxpool.Pool) *DirectorySourceRepository {
	return &DirectorySourceRepository{db: db}
}

type DirectoryActivationClaim struct {
	mu       sync.Mutex
	conn     *pgxpool.Conn
	tenantID string
}

func (r *DirectorySourceRepository) ClaimActivation(ctx context.Context, tenantID string) (*DirectoryActivationClaim, error) {
	if r == nil || r.db == nil || tenantID == "" {
		return nil, errors.New("directory activation tenant is required")
	}
	conn, err := r.db.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire directory activation connection: %w", err)
	}
	var locked bool
	if err := conn.QueryRow(ctx,
		"SELECT pg_try_advisory_lock(hashtextextended($1, $2))",
		tenantID, directoryActivationLockSeed,
	).Scan(&locked); err != nil {
		raw := conn.Hijack()
		_ = raw.Close(context.Background())
		return nil, fmt.Errorf("claim directory activation: %w", err)
	}
	if !locked {
		conn.Release()
		return nil, ErrDirectorySourceActivating
	}
	return &DirectoryActivationClaim{conn: conn, tenantID: tenantID}, nil
}

func (claim *DirectoryActivationClaim) Release(ctx context.Context) error {
	if claim == nil {
		return nil
	}
	claim.mu.Lock()
	defer claim.mu.Unlock()
	if claim.conn == nil {
		return nil
	}
	conn := claim.conn
	claim.conn = nil
	var unlocked bool
	err := conn.QueryRow(ctx,
		"SELECT pg_advisory_unlock(hashtextextended($1, $2))",
		claim.tenantID, directoryActivationLockSeed,
	).Scan(&unlocked)
	if err != nil || !unlocked {
		raw := conn.Hijack()
		_ = raw.Close(context.Background())
		if err != nil {
			return fmt.Errorf("release directory activation: %w", err)
		}
		return errors.New("release directory activation: lock was not held")
	}
	conn.Release()
	return nil
}

const directorySourceColumns = `id, tenant_id, kind, display_name, connection_url, bind_dn,
    bind_password_enc, ca_cert_pem, base_dn, users_dn, user_filter, stable_id_attribute,
    username_attribute, email_attribute, name_attribute, status, version,
    runtime_component_id, config_digest, runtime_reconciliation_required,
    runtime_reconciliation_reason, last_tested_at, last_test_result,
    created_at, updated_at`

func scanDirectorySource(row pgx.Row) (*DirectorySource, error) {
	var source DirectorySource
	var lastTestedAt sql.NullTime
	var encodedResult []byte
	if err := row.Scan(
		&source.ID, &source.TenantID, &source.Kind, &source.DisplayName,
		&source.ConnectionURL, &source.BindDN, &source.BindPasswordEnc,
		&source.CACertPEM,
		&source.BaseDN, &source.UsersDN, &source.UserFilter,
		&source.StableIDAttribute, &source.UsernameAttribute,
		&source.EmailAttribute, &source.NameAttribute, &source.Status,
		&source.Version, &source.RuntimeComponentID, &source.ConfigDigest,
		&source.RuntimeReconciliationRequired,
		&source.RuntimeReconciliationReason,
		&lastTestedAt, &encodedResult, &source.CreatedAt, &source.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if lastTestedAt.Valid {
		value := lastTestedAt.Time
		source.LastTestedAt = &value
	}
	if len(encodedResult) > 0 {
		var result TestResult
		if err := json.Unmarshal(encodedResult, &result); err != nil {
			return nil, fmt.Errorf("decode directory test result: %w", err)
		}
		source.LastTestResult = &result
	}
	return &source, nil
}

func (r *DirectorySourceRepository) GetDraft(ctx context.Context, tenantID string) (*DirectorySource, error) {
	source, err := scanDirectorySource(r.db.QueryRow(ctx, `SELECT `+directorySourceColumns+` FROM directory_sources
        WHERE tenant_id=$1 ORDER BY updated_at DESC LIMIT 1`, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return source, err
}

func (r *DirectorySourceRepository) UpsertDraft(ctx context.Context, source *DirectorySource) error {
	if source == nil || source.TenantID == "" {
		return errors.New("directory source tenant is required")
	}
	if source.ID == "" {
		source.ID = "dir_" + uuid.NewString()[:8]
	}
	if source.Kind != DirectoryKindActiveDirectory && source.Kind != DirectoryKindLDAP {
		return errors.New("directory source kind is invalid")
	}
	if source.StableIDAttribute == "" {
		if source.Kind == DirectoryKindActiveDirectory {
			source.StableIDAttribute, source.UsernameAttribute = "objectGUID", "sAMAccountName"
		} else {
			source.StableIDAttribute, source.UsernameAttribute = "entryUUID", "uid"
		}
	}
	if source.UsernameAttribute == "" {
		return errors.New("directory source username attribute is required")
	}
	if source.EmailAttribute == "" {
		source.EmailAttribute = "mail"
	}
	if source.NameAttribute == "" {
		source.NameAttribute = "displayName"
	}
	if source.UserFilter == "" {
		source.UserFilter = "(objectClass=person)"
	}
	if source.Version == 0 {
		source.Version = 1
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin directory source draft: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var locked bool
	if err := tx.QueryRow(ctx,
		"SELECT pg_try_advisory_xact_lock(hashtextextended($1, $2))",
		source.TenantID, directoryActivationLockSeed,
	).Scan(&locked); err != nil {
		return fmt.Errorf("claim directory source draft: %w", err)
	}
	if !locked {
		return ErrDirectorySourceActivating
	}
	row := tx.QueryRow(ctx, `INSERT INTO directory_sources (
        id, tenant_id, kind, display_name, connection_url, bind_dn, bind_password_enc,
        ca_cert_pem, base_dn, users_dn, user_filter, stable_id_attribute, username_attribute,
        email_attribute, name_attribute, status, version
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'draft',$16)
    ON CONFLICT (id) DO UPDATE SET
        kind=EXCLUDED.kind, display_name=EXCLUDED.display_name,
        connection_url=EXCLUDED.connection_url, bind_dn=EXCLUDED.bind_dn,
        bind_password_enc=CASE WHEN EXCLUDED.bind_password_enc='' THEN directory_sources.bind_password_enc ELSE EXCLUDED.bind_password_enc END,
        ca_cert_pem=EXCLUDED.ca_cert_pem,
        base_dn=EXCLUDED.base_dn, users_dn=EXCLUDED.users_dn, user_filter=EXCLUDED.user_filter,
        stable_id_attribute=EXCLUDED.stable_id_attribute, username_attribute=EXCLUDED.username_attribute,
        email_attribute=EXCLUDED.email_attribute, name_attribute=EXCLUDED.name_attribute,
        status='draft', version=directory_sources.version+1, updated_at=now()
    WHERE directory_sources.tenant_id=EXCLUDED.tenant_id AND directory_sources.version=$16
    RETURNING version`,
		source.ID, source.TenantID, source.Kind, source.DisplayName, source.ConnectionURL,
		source.BindDN, source.BindPasswordEnc, source.CACertPEM, source.BaseDN, source.UsersDN, source.UserFilter,
		source.StableIDAttribute, source.UsernameAttribute, source.EmailAttribute, source.NameAttribute,
		source.Version)
	var version int
	if err := row.Scan(&version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDirectorySourceChanged
		}
		return fmt.Errorf("upsert directory source: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit directory source draft: %w", err)
	}
	source.Version, source.Status = version, "draft"
	return nil
}

func (r *DirectorySourceRepository) UpdateTestResult(ctx context.Context, tenantID, id string, expectedVersion int, result *TestResult) error {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode directory test result: %w", err)
	}
	ct, err := r.db.Exec(ctx, `
        UPDATE directory_sources
        SET last_tested_at=now(), last_test_result=$3,
            status=CASE WHEN $4 THEN 'tested' ELSE 'draft' END, updated_at=now()
        WHERE tenant_id=$1 AND id=$2 AND status='draft' AND version=$5`,
		tenantID, id, resultJSON, result.Success, expectedVersion)
	if err != nil {
		return fmt.Errorf("update directory test result: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrDirectorySourceChanged
	}
	return nil
}

func (r *DirectorySourceRepository) MarkRuntimeReconciliationRequired(
	ctx context.Context,
	tenantID string,
	sourceID string,
	reason string,
) error {
	if !directoryReconciliationReasonPattern.MatchString(reason) {
		return ErrDirectoryReconciliationReasonInvalid
	}
	result, err := r.db.Exec(ctx, `
        UPDATE directory_sources
        SET runtime_reconciliation_required=true,
            runtime_reconciliation_reason=$3,
            updated_at=now()
        WHERE tenant_id=$1 AND id=$2
    `, tenantID, sourceID, reason)
	if err != nil {
		return fmt.Errorf("mark directory runtime reconciliation: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrDirectorySourceChanged
	}
	return nil
}

func (r *DirectorySourceRepository) ClearRuntimeReconciliation(
	ctx context.Context,
	tenantID string,
	sourceID string,
) error {
	result, err := r.db.Exec(ctx, `
        UPDATE directory_sources
        SET runtime_reconciliation_required=false,
            runtime_reconciliation_reason='',
            updated_at=now()
        WHERE tenant_id=$1 AND id=$2
    `, tenantID, sourceID)
	if err != nil {
		return fmt.Errorf("clear directory runtime reconciliation: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrDirectorySourceChanged
	}
	return nil
}

func (r *DirectorySourceRepository) GetByID(ctx context.Context, tenantID, sourceID string) (*DirectorySource, error) {
	source, err := scanDirectorySource(r.db.QueryRow(ctx, "SELECT "+directorySourceColumns+" FROM directory_sources WHERE tenant_id=$1 AND id=$2", tenantID, sourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return source, err
}

func (r *DirectorySourceRepository) GetActive(ctx context.Context, tenantID string) (*DirectorySource, error) {
	source, err := scanDirectorySource(r.db.QueryRow(ctx, "SELECT "+directorySourceColumns+" FROM directory_sources WHERE tenant_id=$1 AND status='active' ORDER BY updated_at DESC LIMIT 1", tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return source, err
}

func (r *DirectorySourceRepository) GetActivatable(ctx context.Context, tenantID string) (*DirectorySource, error) {
	source, err := scanDirectorySource(r.db.QueryRow(ctx, "SELECT "+directorySourceColumns+" FROM directory_sources WHERE tenant_id=$1 AND status IN ('tested','disabled') ORDER BY CASE status WHEN 'tested' THEN 0 ELSE 1 END, updated_at DESC LIMIT 1", tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return source, err
}

func (r *DirectorySourceRepository) Activate(ctx context.Context, tenantID, sourceID string, expectedVersion int) error {
	result, err := r.db.Exec(ctx, "UPDATE directory_sources SET status='active', updated_at=now() WHERE tenant_id=$1 AND id=$2 AND version=$3 AND status IN ('tested','disabled')", tenantID, sourceID, expectedVersion)
	if err != nil {
		return fmt.Errorf("activate directory source: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrDirectorySourceChanged
	}
	return nil
}

func (r *DirectorySourceRepository) Disable(ctx context.Context, tenantID, sourceID string, expectedVersion int) error {
	result, err := r.db.Exec(ctx, "UPDATE directory_sources SET status='disabled', updated_at=now() WHERE tenant_id=$1 AND id=$2 AND version=$3 AND status='active'", tenantID, sourceID, expectedVersion)
	if err != nil {
		return fmt.Errorf("disable directory source: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrDirectorySourceChanged
	}
	return nil
}

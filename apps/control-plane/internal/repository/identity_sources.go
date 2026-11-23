package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrIdentitySourceChanged = errors.New("identity source changed during connection test")

type TestResult struct {
	Success bool        `json:"success"`
	Stages  []TestStage `json:"stages"`
	Error   string      `json:"error,omitempty"`
	// Hints：非阻断的发现性提示，不影响 Success。
	Hints    []string `json:"hints,omitempty"`
	TestedAt string   `json:"tested_at"`
}

type TestStage struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type IdentitySource struct {
	ID                   string
	TenantID             string
	DisplayName          string
	Protocol             string
	IssuerURL            string
	ClientID             string
	ClientSecretEnc      string
	Scopes               string
	SubjectClaim         string
	UsernameClaim        string
	NameClaim            string
	EmailClaim           string
	PhoneClaim           string
	DeptCodeClaim        string
	DeptNameClaim        string
	GroupsClaim          string
	SignatureMode        string // jwks（默认）/ none
	SkipProfileReview    bool
	Status               string
	IsDefault            bool
	Version              int
	RuntimeAlias         string
	ConfigDigest         string
	AppliedVersion       int
	PublishStatus        string
	LastPublishError     string
	PublishedBy          string
	PublishedAt          *time.Time
	LastTestedAt         *time.Time
	LastTestResult       *TestResult
	LastPublishedAt      *time.Time
	LastRuntimeCheckedAt *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type IdentityDeptMapping struct {
	ID               string
	TenantID         string
	IdentitySourceID string
	MatchValue       string
	MappedTeamID     string
	MappedProjectID  string
	Priority         int
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type IdentitySourceRepository struct {
	db *pgxpool.Pool
}

func NewIdentitySourceRepository(db *pgxpool.Pool) *IdentitySourceRepository {
	return &IdentitySourceRepository{db: db}
}

const isCols = `id, tenant_id, display_name, protocol, issuer_url, client_id, client_secret_enc,
	scopes, subject_claim, username_claim, name_claim, email_claim, phone_claim,
	dept_code_claim, dept_name_claim, groups_claim, status, is_default, version,
	COALESCE(published_by,''), published_at, last_tested_at, last_test_result,
	COALESCE(runtime_alias,''), COALESCE(config_digest,''), COALESCE(applied_version,0),
	publish_status, COALESCE(last_publish_error,''), last_published_at, last_runtime_checked_at,
	created_at, updated_at, signature_mode, skip_profile_review`

func scanIdentitySource(row pgx.Row) (*IdentitySource, error) {
	var s IdentitySource
	var publishedAt, lastTestedAt, lastPublishedAt, lastRuntimeCheckedAt sql.NullTime
	var lastTestResult []byte
	if err := row.Scan(
		&s.ID, &s.TenantID, &s.DisplayName, &s.Protocol, &s.IssuerURL, &s.ClientID, &s.ClientSecretEnc,
		&s.Scopes, &s.SubjectClaim, &s.UsernameClaim, &s.NameClaim, &s.EmailClaim, &s.PhoneClaim,
		&s.DeptCodeClaim, &s.DeptNameClaim, &s.GroupsClaim, &s.Status, &s.IsDefault, &s.Version,
		&s.PublishedBy, &publishedAt, &lastTestedAt, &lastTestResult,
		&s.RuntimeAlias, &s.ConfigDigest, &s.AppliedVersion, &s.PublishStatus, &s.LastPublishError,
		&lastPublishedAt, &lastRuntimeCheckedAt, &s.CreatedAt, &s.UpdatedAt,
		&s.SignatureMode, &s.SkipProfileReview,
	); err != nil {
		return nil, err
	}
	if publishedAt.Valid {
		t := publishedAt.Time
		s.PublishedAt = &t
	}
	if lastTestedAt.Valid {
		t := lastTestedAt.Time
		s.LastTestedAt = &t
	}
	if len(lastTestResult) > 0 {
		var tr TestResult
		if err := json.Unmarshal(lastTestResult, &tr); err == nil {
			s.LastTestResult = &tr
		}
	}
	if lastPublishedAt.Valid {
		t := lastPublishedAt.Time
		s.LastPublishedAt = &t
	}
	if lastRuntimeCheckedAt.Valid {
		t := lastRuntimeCheckedAt.Time
		s.LastRuntimeCheckedAt = &t
	}
	return &s, nil
}

func (r *IdentitySourceRepository) GetByID(ctx context.Context, tenantID, id string) (*IdentitySource, error) {
	s, err := scanIdentitySource(r.db.QueryRow(ctx, `SELECT `+isCols+` FROM identity_sources WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return s, err
}

// DefaultRuntimeAlias 是历史默认身份源的运行态 alias（9.2 前唯一的身份源）。
const DefaultRuntimeAlias = "enterprise"

// 无 alias 参数的方法保持 9.2 前的语义：作用于历史默认身份源。
func (r *IdentitySourceRepository) GetActive(ctx context.Context, tenantID string) (*IdentitySource, error) {
	return r.GetActiveByAlias(ctx, tenantID, DefaultRuntimeAlias)
}

func (r *IdentitySourceRepository) GetTested(ctx context.Context, tenantID string) (*IdentitySource, error) {
	return r.GetTestedByAlias(ctx, tenantID, DefaultRuntimeAlias)
}

func (r *IdentitySourceRepository) GetPending(ctx context.Context, tenantID string) (*IdentitySource, error) {
	return r.GetPendingByAlias(ctx, tenantID, DefaultRuntimeAlias)
}

func (r *IdentitySourceRepository) GetDraft(ctx context.Context, tenantID string) (*IdentitySource, error) {
	return r.GetDraftByAlias(ctx, tenantID, DefaultRuntimeAlias)
}

func (r *IdentitySourceRepository) queryOne(ctx context.Context, where string, args ...any) (*IdentitySource, error) {
	s, err := scanIdentitySource(r.db.QueryRow(ctx, `SELECT `+isCols+` FROM identity_sources WHERE `+where, args...))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *IdentitySourceRepository) GetActiveByAlias(ctx context.Context, tenantID, alias string) (*IdentitySource, error) {
	return r.queryOne(ctx, `tenant_id=$1 AND runtime_alias=$2 AND status='active' LIMIT 1`, tenantID, alias)
}

func (r *IdentitySourceRepository) GetTestedByAlias(ctx context.Context, tenantID, alias string) (*IdentitySource, error) {
	return r.queryOne(ctx, `tenant_id=$1 AND runtime_alias=$2 AND status IN ('tested','disabled') ORDER BY CASE status WHEN 'tested' THEN 0 ELSE 1 END, updated_at DESC LIMIT 1`, tenantID, alias)
}

func (r *IdentitySourceRepository) GetPendingByAlias(ctx context.Context, tenantID, alias string) (*IdentitySource, error) {
	return r.queryOne(ctx, `tenant_id=$1 AND runtime_alias=$2 AND status IN ('draft','tested') ORDER BY updated_at DESC LIMIT 1`, tenantID, alias)
}

func (r *IdentitySourceRepository) GetDraftByAlias(ctx context.Context, tenantID, alias string) (*IdentitySource, error) {
	return r.queryOne(ctx, `tenant_id=$1 AND runtime_alias=$2 AND status='draft' ORDER BY updated_at DESC LIMIT 1`, tenantID, alias)
}

// ListActive 返回租户所有已启用身份源（每个 alias 至多一条），默认身份源在前。
func (r *IdentitySourceRepository) ListActive(ctx context.Context, tenantID string) ([]*IdentitySource, error) {
	return r.list(ctx, `tenant_id=$1 AND status='active' ORDER BY (runtime_alias='enterprise') DESC, created_at, id`, tenantID)
}

// ListAliases 返回租户下所有身份源的 alias（含未启用），用于配置页列出多个身份源。
func (r *IdentitySourceRepository) ListAliases(ctx context.Context, tenantID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT runtime_alias FROM identity_sources WHERE tenant_id=$1
		GROUP BY runtime_alias ORDER BY (runtime_alias='enterprise') DESC, MIN(created_at), runtime_alias`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list identity source aliases: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *IdentitySourceRepository) list(ctx context.Context, where string, args ...any) ([]*IdentitySource, error) {
	rows, err := r.db.Query(ctx, `SELECT `+isCols+` FROM identity_sources WHERE `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("list identity sources: %w", err)
	}
	defer rows.Close()
	out := []*IdentitySource{}
	for rows.Next() {
		s, err := scanIdentitySource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *IdentitySourceRepository) GetAll(ctx context.Context, tenantID string) ([]*IdentitySource, error) {
	rows, err := r.db.Query(ctx, `SELECT `+isCols+` FROM identity_sources WHERE tenant_id=$1 ORDER BY status DESC, updated_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list identity sources: %w", err)
	}
	defer rows.Close()
	out := []*IdentitySource{}
	for rows.Next() {
		s, err := scanIdentitySource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *IdentitySourceRepository) UpsertDraft(ctx context.Context, src *IdentitySource) error {
	if src.ID == "" {
		src.ID = "ids_" + uuid.New().String()[:8]
	}
	if src.Protocol == "" {
		src.Protocol = "oidc"
	}
	if src.RuntimeAlias == "" {
		src.RuntimeAlias = DefaultRuntimeAlias
	}
	src.Status = "draft"
	if src.Version <= 0 {
		src.Version = 1
	}
	if src.Scopes == "" {
		src.Scopes = "openid profile email"
	}
	if src.SubjectClaim == "" {
		src.SubjectClaim = "sub"
	}
	if src.UsernameClaim == "" {
		src.UsernameClaim = "preferred_username"
	}
	if src.NameClaim == "" {
		src.NameClaim = "name"
	}
	if src.EmailClaim == "" {
		src.EmailClaim = "email"
	}
	if src.PhoneClaim == "" {
		src.PhoneClaim = "phone_number"
	}
	if src.DeptCodeClaim == "" {
		src.DeptCodeClaim = "department_code"
	}
	if src.DeptNameClaim == "" {
		src.DeptNameClaim = "department_name"
	}
	if src.GroupsClaim == "" {
		src.GroupsClaim = "groups"
	}
	if src.SignatureMode == "" {
		src.SignatureMode = "jwks"
	}

	query := `
		INSERT INTO identity_sources (id, tenant_id, display_name, protocol, issuer_url, client_id, client_secret_enc,
			scopes, subject_claim, username_claim, name_claim, email_claim, phone_claim,
			dept_code_claim, dept_name_claim, groups_claim, status, is_default, version, runtime_alias,
			signature_mode, skip_profile_review)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
		ON CONFLICT (id) DO UPDATE SET
			display_name=EXCLUDED.display_name, protocol=EXCLUDED.protocol, issuer_url=EXCLUDED.issuer_url,
			client_id=EXCLUDED.client_id, client_secret_enc=CASE WHEN EXCLUDED.client_secret_enc='' THEN identity_sources.client_secret_enc ELSE EXCLUDED.client_secret_enc END,
			scopes=EXCLUDED.scopes, subject_claim=EXCLUDED.subject_claim, username_claim=EXCLUDED.username_claim,
			name_claim=EXCLUDED.name_claim, email_claim=EXCLUDED.email_claim, phone_claim=EXCLUDED.phone_claim,
			dept_code_claim=EXCLUDED.dept_code_claim, dept_name_claim=EXCLUDED.dept_name_claim, groups_claim=EXCLUDED.groups_claim,
			signature_mode=EXCLUDED.signature_mode, skip_profile_review=EXCLUDED.skip_profile_review,
			status='draft', is_default=EXCLUDED.is_default, version=identity_sources.version+1,
			last_tested_at=NULL, last_test_result=NULL, updated_at=now()
			WHERE identity_sources.tenant_id=EXCLUDED.tenant_id
				AND identity_sources.runtime_alias=EXCLUDED.runtime_alias
				AND identity_sources.status IN ('draft','tested')
				AND identity_sources.version=EXCLUDED.version
		RETURNING version`
	err := r.db.QueryRow(ctx, query,
		src.ID, src.TenantID, src.DisplayName, src.Protocol, src.IssuerURL, src.ClientID, src.ClientSecretEnc,
		src.Scopes, src.SubjectClaim, src.UsernameClaim, src.NameClaim, src.EmailClaim, src.PhoneClaim,
		src.DeptCodeClaim, src.DeptNameClaim, src.GroupsClaim, src.Status, src.IsDefault, src.Version, src.RuntimeAlias,
		src.SignatureMode, src.SkipProfileReview).Scan(&src.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrIdentitySourceChanged
	}
	if err != nil {
		return fmt.Errorf("upsert identity source draft: %w", err)
	}
	return nil
}

func (r *IdentitySourceRepository) UpdateTestResult(ctx context.Context, tenantID, id string, expectedVersion int, result *TestResult) error {
	resultJSON, _ := json.Marshal(result)
	ct, err := r.db.Exec(ctx, `
		UPDATE identity_sources SET last_tested_at=now(), last_test_result=$3, status=CASE WHEN $4 THEN 'tested' ELSE 'draft' END, updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND status='draft' AND version=$5`,
		tenantID, id, resultJSON, result.Success, expectedVersion)
	if err != nil {
		return fmt.Errorf("update test result: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrIdentitySourceChanged
	}
	return nil
}

// Identity activation is committed only through CommitPublication after runtime verification.

type PublicationCommit struct {
	TenantID        string
	SourceID        string
	ExpectedVersion int
	RuntimeAlias    string
	ConfigDigest    string
	PublishedBy     string
}

type PublicationEvent struct {
	TenantID      string
	SourceID      string
	SourceVersion int
	Action        string
	ActorUserID   string
	Result        string
	ConfigDigest  string
	ErrorCode     string
}

func (r *IdentitySourceRepository) MarkPublishing(ctx context.Context, tenantID, id string, expectedVersion int) error {
	ct, err := r.db.Exec(ctx, `
		UPDATE identity_sources
		SET publish_status='publishing', last_publish_error=NULL, updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND status IN ('tested','active','disabled') AND version=$3
		  AND publish_status IN ('not_published','active','error','drifted','disabled')`,
		tenantID, id, expectedVersion)
	if err != nil {
		return fmt.Errorf("mark identity source publishing: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrIdentitySourceChanged
	}
	return nil
}

func (r *IdentitySourceRepository) CommitPublication(ctx context.Context, in PublicationCommit) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin identity publication: %w", err)
	}
	defer tx.Rollback(ctx)

	var version int
	var status, publishStatus, alias string
	err = tx.QueryRow(ctx, `
		SELECT version, status, publish_status, runtime_alias
		FROM identity_sources
		WHERE tenant_id=$1 AND id=$2
		FOR UPDATE`, in.TenantID, in.SourceID).Scan(&version, &status, &publishStatus, &alias)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrIdentitySourceChanged
	}
	if err != nil {
		return fmt.Errorf("lock identity source publication: %w", err)
	}
	if version != in.ExpectedVersion || (status != "tested" && status != "active" && status != "disabled") ||
		publishStatus != "publishing" {
		return ErrIdentitySourceChanged
	}
	// 9.2：身份源的运行态 alias 在创建时由服务端派生并固定；发布方传入的 alias 必须一致。
	if in.RuntimeAlias != "" && in.RuntimeAlias != alias {
		return ErrIdentitySourceChanged
	}

	if _, err := tx.Exec(ctx, `
		UPDATE identity_sources
		SET status='disabled', is_default=false, publish_status='disabled', updated_at=now()
		WHERE tenant_id=$1 AND status='active' AND id<>$2 AND runtime_alias=$3`,
		in.TenantID, in.SourceID, alias); err != nil {
		return fmt.Errorf("disable previous identity publication: %w", err)
	}

	ct, err := tx.Exec(ctx, `
		UPDATE identity_sources
		SET status='active', is_default=(runtime_alias=$5), published_by=$4, published_at=now(),
		    config_digest=$6, applied_version=$3,
		    publish_status='active', last_publish_error=NULL,
		    last_published_at=now(), last_runtime_checked_at=now(), updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND version=$3
		  AND status IN ('tested','active','disabled') AND publish_status='publishing'`,
		in.TenantID, in.SourceID, in.ExpectedVersion, nullableString(in.PublishedBy),
		DefaultRuntimeAlias, in.ConfigDigest)
	if err != nil {
		return fmt.Errorf("commit identity publication: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrIdentitySourceChanged
	}

	action := "publish"
	if status == "active" {
		action = "reconcile"
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO identity_publication_events
			(tenant_id, identity_source_id, source_version, action, actor_user_id, result, config_digest)
		VALUES ($1,$2,$3,$4,$5,'succeeded',$6)`,
		in.TenantID, in.SourceID, in.ExpectedVersion, action, nullableString(in.PublishedBy), nullableString(in.ConfigDigest)); err != nil {
		return fmt.Errorf("record identity publication: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit identity publication transaction: %w", err)
	}
	return nil
}

func stablePublicationErrorCode(code string) string {
	if code == "" || len(code) > 64 {
		return "identity_runtime_error"
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return "identity_runtime_error"
		}
	}
	return code
}

func (r *IdentitySourceRepository) MarkPublicationError(ctx context.Context, tenantID, id, code, _ string) error {
	safeCode := stablePublicationErrorCode(code)
	ct, err := r.db.Exec(ctx, `
		UPDATE identity_sources
		SET publish_status='error', last_publish_error=$3, last_runtime_checked_at=now(), updated_at=now()
		WHERE tenant_id=$1 AND id=$2`, tenantID, id, safeCode)
	if err != nil {
		return fmt.Errorf("mark identity publication error: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrIdentitySourceChanged
	}
	return nil
}

func (r *IdentitySourceRepository) MarkRuntimeStatus(ctx context.Context, tenantID, id, status string) error {
	switch status {
	case "not_published", "publishing", "active", "error", "drifted", "disabled":
	default:
		return fmt.Errorf("invalid identity runtime status")
	}
	ct, err := r.db.Exec(ctx, `
		UPDATE identity_sources
		SET publish_status=$3, last_runtime_checked_at=now(), updated_at=now()
		WHERE tenant_id=$1 AND id=$2`, tenantID, id, status)
	if err != nil {
		return fmt.Errorf("mark identity runtime status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrIdentitySourceChanged
	}
	return nil
}

func (r *IdentitySourceRepository) RecordPublicationEvent(ctx context.Context, event PublicationEvent) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO identity_publication_events
			(tenant_id, identity_source_id, source_version, action, actor_user_id, result, config_digest, error_code)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		event.TenantID, event.SourceID, event.SourceVersion, event.Action,
		nullableString(event.ActorUserID), event.Result, nullableString(event.ConfigDigest), nullableString(event.ErrorCode))
	if err != nil {
		return fmt.Errorf("record identity publication event: %w", err)
	}
	return nil
}

func (r *IdentitySourceRepository) Disable(ctx context.Context, tenantID, id string) error {
	ct, err := r.db.Exec(ctx, `UPDATE identity_sources SET status='disabled', is_default=false, publish_status='disabled', last_runtime_checked_at=now(), updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("disable identity source: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("identity source not found")
	}
	return nil
}

func (r *IdentitySourceRepository) ListDeptMappings(ctx context.Context, tenantID, sourceID string) ([]*IdentityDeptMapping, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, identity_source_id, match_value, COALESCE(mapped_team_id,''), COALESCE(mapped_project_id,''), priority, enabled, created_at, updated_at
		FROM identity_dept_mappings WHERE tenant_id=$1 AND identity_source_id=$2 ORDER BY priority ASC, match_value ASC`,
		tenantID, sourceID)
	if err != nil {
		return nil, fmt.Errorf("list dept mappings: %w", err)
	}
	defer rows.Close()
	out := []*IdentityDeptMapping{}
	for rows.Next() {
		var m IdentityDeptMapping
		if err := rows.Scan(&m.ID, &m.TenantID, &m.IdentitySourceID, &m.MatchValue, &m.MappedTeamID, &m.MappedProjectID, &m.Priority, &m.Enabled, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

func (r *IdentitySourceRepository) UpsertDeptMapping(ctx context.Context, m *IdentityDeptMapping) error {
	if m.Priority == 0 {
		m.Priority = 100
	}
	if m.ID == "" {
		m.ID = "idm_" + uuid.New().String()[:8]
		_, err := r.db.Exec(ctx, `
			INSERT INTO identity_dept_mappings (id, tenant_id, identity_source_id, match_value, mapped_team_id, mapped_project_id, priority, enabled)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			m.ID, m.TenantID, m.IdentitySourceID, m.MatchValue, nullableString(m.MappedTeamID), nullableString(m.MappedProjectID), m.Priority, m.Enabled)
		if err != nil {
			return fmt.Errorf("create dept mapping: %w", err)
		}
		return nil
	}
	ct, err := r.db.Exec(ctx, `
		UPDATE identity_dept_mappings
		SET match_value=$3, mapped_team_id=$4, mapped_project_id=$5, priority=$6, enabled=$7, updated_at=now()
		WHERE tenant_id=$1 AND id=$2`,
		m.TenantID, m.ID, m.MatchValue, nullableString(m.MappedTeamID), nullableString(m.MappedProjectID), m.Priority, m.Enabled)
	if err != nil {
		return fmt.Errorf("update dept mapping: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("dept mapping not found")
	}
	return nil
}

func (r *IdentitySourceRepository) DeleteDeptMapping(ctx context.Context, tenantID, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM identity_dept_mappings WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("delete dept mapping: %w", err)
	}
	return nil
}

// ErrAdoptTargetNotActive：同 alias 下已有启用中的身份源，而要采纳的目标不是它——运行态属于启用中的那条。
var ErrAdoptTargetNotActive = errors.New("identity source is not the active source of its runtime alias")

// ErrAdoptTargetNotAdoptable：身份源处于编辑中（draft/tested），不能采纳运行态。
var ErrAdoptTargetNotAdoptable = errors.New("identity source is being edited and cannot adopt runtime settings")

// AdoptRuntimeInput 是「采纳运行态」写库的入参。UsernameClaim 为空表示无法反推，保持库内原值。
type AdoptRuntimeInput struct {
	TenantID string
	SourceID string
	// Version 是调用方读取身份源时看到的版本；事务内版本不一致说明期间被他人修改，返回 ErrIdentitySourceChanged。
	Version           int
	SignatureMode     string
	UsernameClaim     string
	SkipProfileReview bool
	ConfigDigest      string
}

// SameAliasSource 是与采纳目标共用运行态 alias 的其他记录（只读提示，绝不修改）。
type SameAliasSource struct {
	ID            string
	Status        string
	Version       int
	PublishStatus string
}

type AdoptRuntimeResult struct {
	SameAliasSources []SameAliasSource
}

// AdoptRuntimeSettings 把从运行态反推出的选项写入指定身份源并更新期望配置摘要。
// 只改 signature_mode / username_claim / skip_profile_review / config_digest，不改 version 与 applied_version，
// 不改同 alias 的其他记录。整个过程不触碰 Keycloak。
func (r *IdentitySourceRepository) AdoptRuntimeSettings(ctx context.Context, in AdoptRuntimeInput) (AdoptRuntimeResult, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return AdoptRuntimeResult{}, fmt.Errorf("begin adopt identity runtime: %w", err)
	}
	defer tx.Rollback(ctx)

	var alias, status string
	var version int
	err = tx.QueryRow(ctx, `SELECT runtime_alias, status, version FROM identity_sources WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
		in.TenantID, in.SourceID).Scan(&alias, &status, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdoptRuntimeResult{}, ErrIdentitySourceChanged
	}
	if err != nil {
		return AdoptRuntimeResult{}, fmt.Errorf("lock identity source for adopt: %w", err)
	}
	if status != "active" && status != "disabled" {
		return AdoptRuntimeResult{}, ErrAdoptTargetNotAdoptable
	}
	if version != in.Version {
		return AdoptRuntimeResult{}, ErrIdentitySourceChanged
	}

	rows, err := tx.Query(ctx, `SELECT id, status, version, publish_status FROM identity_sources
		WHERE tenant_id=$1 AND runtime_alias=$2 AND id<>$3 ORDER BY created_at, id`, in.TenantID, alias, in.SourceID)
	if err != nil {
		return AdoptRuntimeResult{}, fmt.Errorf("list same-alias identity sources: %w", err)
	}
	var result AdoptRuntimeResult
	otherActive := false
	for rows.Next() {
		var o SameAliasSource
		if err := rows.Scan(&o.ID, &o.Status, &o.Version, &o.PublishStatus); err != nil {
			rows.Close()
			return AdoptRuntimeResult{}, err
		}
		if o.Status == "active" {
			otherActive = true
		}
		result.SameAliasSources = append(result.SameAliasSources, o)
	}
	rows.Close()
	if rows.Err() != nil {
		return AdoptRuntimeResult{}, rows.Err()
	}
	if status != "active" && otherActive {
		return AdoptRuntimeResult{}, ErrAdoptTargetNotActive
	}

	if _, err := tx.Exec(ctx, `
		UPDATE identity_sources
		SET signature_mode=$3, skip_profile_review=$4,
		    username_claim=CASE WHEN $5='' THEN username_claim ELSE $5 END,
		    config_digest=$6, updated_at=now()
		WHERE tenant_id=$1 AND id=$2`,
		in.TenantID, in.SourceID, in.SignatureMode, in.SkipProfileReview, in.UsernameClaim, in.ConfigDigest); err != nil {
		return AdoptRuntimeResult{}, fmt.Errorf("adopt identity runtime settings: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return AdoptRuntimeResult{}, fmt.Errorf("commit adopt identity runtime: %w", err)
	}
	return result, nil
}

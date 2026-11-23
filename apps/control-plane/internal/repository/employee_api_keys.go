package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/packages/shared-go/authhelpers"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"time"
)

var (
	ErrEmployeeKeyEncryptionUnavailable = errors.New("employee credential encryption unavailable")
	ErrEmployeeKeyDenied                = errors.New("employee credential authorization denied")
	ErrEmployeeKeyConflict              = errors.New("employee credential changed")
	ErrEmployeeKeyAlreadyClaimed        = errors.New("employee credential already claimed")
)

// EmployeeAPIKey is safe metadata; credential material has no exported field.
type EmployeeAPIKey struct {
	ModelAllowlist []string   `json:"model_allowlist"`
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	UserID         string     `json:"user_id"`
	ProjectID      string     `json:"project_id"`
	Name           string     `json:"name"`
	KeyPrefix      string     `json:"prefix"`
	Generation     int64      `json:"generation"`
	FirstClaimAt   *time.Time `json:"first_claim_at"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      *time.Time `json:"expires_at"`
	Status         string     `json:"status"`
	Scopes         []string   `json:"scopes"`
}

type EmployeeAPIKeyRepository struct{ db *pgxpool.Pool }

func NewEmployeeAPIKeyRepository(db *pgxpool.Pool) *EmployeeAPIKeyRepository {
	return &EmployeeAPIKeyRepository{db: db}
}

type employeeKeyIdentity struct {
	role         string
	department   string
	version      int64
	localVersion int64
}
type storedEmployeeKey struct {
	*EmployeeAPIKey
	ciphertext, hash, department, role string
	version                            int64
	deleted                            bool
}

func lockEmployeeKeyIdentity(ctx context.Context, tx pgx.Tx, tenant, user string, expectedLocalVersion ...int64) (employeeKeyIdentity, error) {
	var identity employeeKeyIdentity
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(user) == "" {
		return identity, ErrEmployeeKeyDenied
	}
	err := tx.QueryRow(ctx, `SELECT u.department_id,u.department_version,u.local_credential_version,u.role
 FROM users u JOIN tenants tenant ON tenant.id=u.tenant_id
 JOIN teams department ON department.id=u.department_id AND department.tenant_id=u.tenant_id
 WHERE u.tenant_id=$1 AND u.id=$2 AND u.status='active' AND u.role=ANY($3)
 AND NOT u.must_change_password AND u.department_assignment_mode NOT IN ('emergency','service')
 AND u.department_version>0 AND u.local_credential_version>0 AND tenant.status='active'
 FOR UPDATE OF u FOR SHARE OF tenant,department`, tenant, user, roles.PortalRoles()).Scan(&identity.department, &identity.version, &identity.localVersion, &identity.role)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity, ErrEmployeeKeyDenied
	}
	if err == nil && len(expectedLocalVersion) > 0 && (len(expectedLocalVersion) != 1 || expectedLocalVersion[0] <= 0 || expectedLocalVersion[0] != identity.localVersion) {
		return identity, ErrEmployeeKeyDenied
	}
	return identity, err
}

func validateEmployeeKeyProject(ctx context.Context, tx pgx.Tx, tenant, user, project string, identity employeeKeyIdentity) error {
	var id string
	err := tx.QueryRow(ctx, `SELECT p.id FROM projects p
 JOIN users u ON u.tenant_id=p.tenant_id AND u.id=$2
 JOIN teams department ON department.id=u.department_id AND department.tenant_id=u.tenant_id
 WHERE p.tenant_id=$1 AND p.id=$3 AND p.status='active'
 AND EXISTS(SELECT 1 FROM project_users membership WHERE membership.project_id=p.id AND membership.user_id=u.id)
 AND (p.team_id=u.department_id OR (department.system_key='unassigned'
   AND EXISTS(SELECT 1 FROM teams fallback WHERE fallback.tenant_id=u.tenant_id AND fallback.id=p.team_id AND fallback.system_key='chat_default')
   AND NOT EXISTS(SELECT 1 FROM projects own WHERE own.tenant_id=u.tenant_id AND own.team_id=u.department_id AND own.status='active')))
 AND p.id=(SELECT chosen.id FROM projects chosen WHERE chosen.tenant_id=u.tenant_id AND chosen.team_id=p.team_id AND chosen.status='active' ORDER BY chosen.created_at,chosen.id LIMIT 1)
 AND u.department_id=$4 AND u.department_version=$5
 FOR SHARE OF p`, tenant, user, project, identity.department, identity.version).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrEmployeeKeyDenied
	}
	return err
}

func loadEmployeeKey(ctx context.Context, tx pgx.Tx, tenant, user string) (*storedEmployeeKey, error) {
	stored := &storedEmployeeKey{EmployeeAPIKey: &EmployeeAPIKey{}}
	var scopes []byte
	err := tx.QueryRow(ctx, `SELECT m.key_id,m.tenant_id,m.user_id,k.project_id,COALESCE(k.name,''),k.key_prefix,
 m.generation,m.first_claim_at,k.created_at,k.expires_at,k.status,k.scopes_json,COALESCE(k.key_ciphertext,''),k.key_hash,m.department_id,m.department_version,m.issued_role,k.model_allowlist,k.deleted_at IS NOT NULL
 FROM employee_api_keys m JOIN internal_keys k ON k.id=m.key_id AND k.tenant_id=m.tenant_id AND k.user_id=m.user_id
 WHERE m.tenant_id=$1 AND m.user_id=$2 FOR UPDATE OF m,k`, tenant, user).Scan(
		&stored.ID, &stored.TenantID, &stored.UserID, &stored.ProjectID, &stored.Name, &stored.KeyPrefix, &stored.Generation,
		&stored.FirstClaimAt, &stored.CreatedAt, &stored.ExpiresAt, &stored.Status, &scopes, &stored.ciphertext, &stored.hash, &stored.department, &stored.version, &stored.role, &stored.ModelAllowlist, &stored.deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	stored.Scopes = parseScopesJSON(scopes)
	return stored, nil
}
func employeeKeyUsable(key *storedEmployeeKey, identity employeeKeyIdentity) bool {
	return key != nil && key.Status == "active" && (key.ExpiresAt == nil || key.ExpiresAt.After(time.Now())) && key.department == identity.department && key.version == identity.version && key.role == identity.role
}
func decryptEmployeeKey(key *storedEmployeeKey) (string, error) {
	if key == nil || key.ciphertext == "" {
		return "", ErrEmployeeKeyEncryptionUnavailable
	}
	raw, err := secrets.DecryptProviderSecret(key.ciphertext)
	if err != nil || raw == "" || authhelpers.HashKey(raw) != key.hash {
		return "", errors.New("employee credential decryption failed")
	}
	return raw, nil
}

func createEmployeeKey(ctx context.Context, tx pgx.Tx, tenant, user, project string, identity employeeKeyIdentity, previous *storedEmployeeKey, claimed bool) (*EmployeeAPIKey, string, error) {
	raw := authhelpers.GenerateKey()
	ciphertext, _, err := secrets.EncryptProviderSecret(raw)
	if err != nil {
		return nil, "", fmt.Errorf("employee credential encryption: %w", err)
	}
	key := &EmployeeAPIKey{ID: "key_" + uuid.New().String(), TenantID: tenant, UserID: user, ProjectID: project, Name: "个人 API Key", KeyPrefix: raw[:8], Generation: 1, Status: "active", Scopes: []string{"chat", "models", "responses", "embeddings"}}
	if previous != nil {
		key.ModelAllowlist = append([]string{}, previous.ModelAllowlist...)
		key.Generation = previous.Generation + 1
		if key.Generation <= 0 {
			return nil, "", errors.New("employee credential generation exhausted")
		}
		_, err = tx.Exec(ctx, `UPDATE internal_keys SET status='revoked' WHERE id=$1 AND tenant_id=$2 AND user_id=$3`, previous.ID, tenant, user)
		if err != nil {
			return nil, "", err
		}
	}
	scopes, _ := json.Marshal(key.Scopes)
	err = tx.QueryRow(ctx, `INSERT INTO internal_keys(id,tenant_id,project_id,user_id,key_hash,key_prefix,scopes_json,name,status,key_ciphertext,model_allowlist)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,COALESCE($10::text[],'{}')) RETURNING created_at`, key.ID, tenant, project, user, authhelpers.HashKey(raw), key.KeyPrefix, scopes, key.Name, ciphertext, key.ModelAllowlist).Scan(&key.CreatedAt)
	if err != nil {
		return nil, "", err
	}
	err = tx.QueryRow(ctx, `INSERT INTO employee_api_keys(tenant_id,user_id,key_id,department_id,department_version,generation,first_claim_at,issued_role)
 VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $7 THEN NOW() ELSE NULL END,$8)
 ON CONFLICT(tenant_id,user_id) DO UPDATE SET key_id=EXCLUDED.key_id,department_id=EXCLUDED.department_id,
 department_version=EXCLUDED.department_version,generation=EXCLUDED.generation,first_claim_at=EXCLUDED.first_claim_at,issued_role=EXCLUDED.issued_role,updated_at=NOW()
 RETURNING first_claim_at`, tenant, user, key.ID, identity.department, identity.version, key.Generation, claimed, identity.role).Scan(&key.FirstClaimAt)
	if err != nil {
		return nil, "", err
	}
	action := "employee_key_create"
	if previous != nil {
		action = "employee_key_rotate"
	}
	detail, _ := json.Marshal(map[string]any{"user_id": user, "key_id": key.ID, "project_id": project, "generation": key.Generation, "actor": "employee-credential-service"})
	_, err = tx.Exec(ctx, `INSERT INTO audit_operations(id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address)
 VALUES($1,$2,$3,$4,$5::jsonb,'key',$6,'')`, uuid.NewString(), tenant, user, action, string(detail), key.ID)
	return key, raw, err
}

func (r *EmployeeAPIKeyRepository) Ensure(ctx context.Context, tenant, user, project, department string, version int64, expectedLocalVersion ...int64) (*EmployeeAPIKey, bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	identity, err := lockEmployeeKeyIdentity(ctx, tx, tenant, user, expectedLocalVersion...)
	if err != nil {
		return nil, false, err
	}
	if identity.department != department || identity.version != version {
		return nil, false, ErrEmployeeKeyDenied
	}
	if err = validateEmployeeKeyProject(ctx, tx, tenant, user, project, identity); err != nil {
		return nil, false, err
	}
	previous, err := loadEmployeeKey(ctx, tx, tenant, user)
	if err != nil {
		return nil, false, err
	}
	if employeeKeyUsable(previous, identity) && previous.ProjectID == project {
		if err = tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		return previous.EmployeeAPIKey, false, nil
	}
	key, _, err := createEmployeeKey(ctx, tx, tenant, user, project, identity, previous, false)
	if err != nil {
		return nil, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

func (r *EmployeeAPIKeyRepository) Current(ctx context.Context, tenant, user string, expectedLocalVersion ...int64) (*EmployeeAPIKey, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	identity, err := lockEmployeeKeyIdentity(ctx, tx, tenant, user, expectedLocalVersion...)
	if err != nil {
		return nil, err
	}
	key, err := loadEmployeeKey(ctx, tx, tenant, user)
	if err != nil {
		return nil, err
	}
	if key == nil || key.deleted {
		return nil, nil
	}
	if key.department != identity.department || key.version != identity.version || key.role != identity.role {
		return nil, ErrEmployeeKeyDenied
	}
	if err = validateEmployeeKeyProject(ctx, tx, tenant, user, key.ProjectID, identity); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return key.EmployeeAPIKey, nil
}

func (r *EmployeeAPIKeyRepository) Claim(ctx context.Context, tenant, user, expectedID string, generation int64, expectedLocalVersion ...int64) (*EmployeeAPIKey, string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	identity, err := lockEmployeeKeyIdentity(ctx, tx, tenant, user, expectedLocalVersion...)
	if err != nil {
		return nil, "", err
	}
	key, err := loadEmployeeKey(ctx, tx, tenant, user)
	if err != nil {
		return nil, "", err
	}
	if key == nil || expectedID == "" || generation <= 0 || key.ID != expectedID || key.Generation != generation {
		return nil, "", ErrEmployeeKeyConflict
	}
	if !employeeKeyUsable(key, identity) {
		return nil, "", ErrEmployeeKeyDenied
	}
	if err = validateEmployeeKeyProject(ctx, tx, tenant, user, key.ProjectID, identity); err != nil {
		return nil, "", err
	}
	if key.FirstClaimAt != nil {
		return nil, "", ErrEmployeeKeyAlreadyClaimed
	}
	raw, err := decryptEmployeeKey(key)
	if err != nil {
		return nil, "", err
	}
	err = tx.QueryRow(ctx, `UPDATE employee_api_keys SET first_claim_at=NOW(),updated_at=NOW() WHERE tenant_id=$1 AND user_id=$2 RETURNING first_claim_at`, tenant, user).Scan(&key.FirstClaimAt)
	if err != nil {
		return nil, "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return key.EmployeeAPIKey, raw, nil
}

func (r *EmployeeAPIKeyRepository) Reset(ctx context.Context, tenant, user, expectedID string, generation int64, project, department string, version int64, expectedLocalVersion ...int64) (*EmployeeAPIKey, string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	identity, err := lockEmployeeKeyIdentity(ctx, tx, tenant, user, expectedLocalVersion...)
	if err != nil {
		return nil, "", err
	}
	if identity.department != department || identity.version != version {
		return nil, "", ErrEmployeeKeyDenied
	}
	if err = validateEmployeeKeyProject(ctx, tx, tenant, user, project, identity); err != nil {
		return nil, "", err
	}
	previous, err := loadEmployeeKey(ctx, tx, tenant, user)
	if err != nil {
		return nil, "", err
	}
	if previous == nil || expectedID == "" || generation <= 0 || previous.ID != expectedID || previous.Generation != generation {
		return nil, "", ErrEmployeeKeyConflict
	}
	key, raw, err := createEmployeeKey(ctx, tx, tenant, user, project, identity, previous, true)
	if err != nil {
		return nil, "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return key, raw, nil
}

// Credential is for the trusted Chat service, never a browser response or JWT.
// Retrieving it does not consume the employee's one-time first claim.
func (r *EmployeeAPIKeyRepository) Credential(ctx context.Context, tenant, user string, expectedLocalVersion ...int64) (*EmployeeAPIKey, string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	identity, err := lockEmployeeKeyIdentity(ctx, tx, tenant, user, expectedLocalVersion...)
	if err != nil {
		return nil, "", err
	}
	key, err := loadEmployeeKey(ctx, tx, tenant, user)
	if err != nil {
		return nil, "", err
	}
	if !employeeKeyUsable(key, identity) {
		return nil, "", ErrEmployeeKeyDenied
	}
	if err = validateEmployeeKeyProject(ctx, tx, tenant, user, key.ProjectID, identity); err != nil {
		return nil, "", err
	}
	raw, err := decryptEmployeeKey(key)
	if err != nil {
		return nil, "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return key.EmployeeAPIKey, raw, nil
}

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/packages/shared-go/authhelpers"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/google/uuid"
)

const MaxPortalUserActiveKeys = 5

var ErrOwnedKeyLimitReached = errors.New("active personal key limit reached")

var ErrOwnedKeyRevoked = errors.New("revoked key cannot be reactivated")

type OwnedKeyUpdate struct {
	Name           *string   `json:"name,omitempty"`
	Status         *string   `json:"status,omitempty"`
	ModelAllowlist *[]string `json:"model_allowlist,omitempty"`
}

// User/key locks serialize edits with employee rotation/revocation and identity moves.
func (r *InternalKeyRepository) UpdateOwned(ctx context.Context, tenant, key, user string, input OwnedKeyUpdate) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var actor string
	if err = tx.QueryRow(ctx, "SELECT id FROM users WHERE tenant_id=$1 AND id=$2 AND status='active' FOR UPDATE", tenant, user).Scan(&actor); err != nil {
		return err
	}
	var status string
	var managed bool
	if err = tx.QueryRow(ctx, `SELECT k.status,EXISTS(SELECT 1 FROM employee_api_keys m WHERE m.tenant_id=k.tenant_id AND m.key_id=k.id) FROM internal_keys k WHERE k.tenant_id=$1 AND k.id=$2 AND k.user_id=$3 AND k.deleted_at IS NULL FOR UPDATE OF k`, tenant, key, user).Scan(&status, &managed); err != nil {
		return err
	}
	if status == "revoked" {
		return ErrOwnedKeyRevoked
	}
	if input.Status != nil && *input.Status != "active" && *input.Status != "disabled" {
		return modelaccess.ErrInvalidPolicy
	}
	var names any
	if input.ModelAllowlist != nil {
		access, err := modelaccess.ReadAccess(ctx, tx, tenant, user)
		if err != nil {
			return err
		}
		normalized, err := modelaccess.NormalizeKeyAllowlist(*input.ModelAllowlist, access)
		if err != nil {
			return err
		}
		names = normalized
	}
	if input.Status != nil && *input.Status == "active" {
		if status != "active" && !managed {
			var count int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM internal_keys k WHERE k.tenant_id=$1 AND k.user_id=$2 AND k.status='active' AND NOT EXISTS(SELECT 1 FROM employee_api_keys m WHERE m.tenant_id=k.tenant_id AND m.key_id=k.id)`, tenant, user).Scan(&count); err != nil {
				return err
			}
			if count >= MaxPortalUserActiveKeys {
				return ErrOwnedKeyLimitReached
			}
		}
		access, err := modelaccess.ReadAccess(ctx, tx, tenant, user)
		if err != nil {
			return err
		}
		if !access.ChatAllowed {
			return modelaccess.ErrKeyModelUnauthorized
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE internal_keys SET name=CASE WHEN $4::text IS NULL THEN name ELSE NULLIF($4,'') END,
 status=COALESCE($5,status),model_allowlist=COALESCE($6::text[],model_allowlist)
 WHERE tenant_id=$1 AND id=$2 AND user_id=$3`, tenant, key, user, input.Name, input.Status, names); err != nil {
		return err
	}
	if err = writeTransactionalOperationAudit(ctx, tx, tenant, user, "portal_update_key", "key", key, map[string]any{"key_id": key, "models_changed": input.ModelAllowlist != nil, "status_changed": input.Status != nil}); err != nil {
		return err
	}
	return commitWithOperationAudit(ctx, tx)
}

var ErrOwnedKeyEncryptionUnavailable = errors.New("key encryption unavailable")

func (r *InternalKeyRepository) RotateOwned(ctx context.Context, tenant, id, user string) (*InternalKey, string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	var actor string
	err = tx.QueryRow(ctx, `SELECT u.id FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.status='active' AND t.status='active' FOR UPDATE OF u FOR SHARE OF t`, tenant, user).Scan(&actor)
	if err != nil {
		return nil, "", err
	}
	key := &InternalKey{TenantID: tenant, UserID: user}
	var scopes []byte
	err = tx.QueryRow(ctx, `SELECT project_id,COALESCE(name,''),scopes_json,expires_at,status,model_allowlist FROM internal_keys k
 WHERE k.tenant_id=$1 AND k.id=$2 AND k.user_id=$3
 AND NOT EXISTS(SELECT 1 FROM employee_api_keys m WHERE m.tenant_id=k.tenant_id AND m.key_id=k.id) FOR UPDATE OF k`, tenant, id, user).Scan(&key.ProjectID, &key.Name, &scopes, &key.ExpiresAt, &key.Status, &key.ModelAllowlist)
	if err != nil {
		return nil, "", err
	}
	if key.Status == "revoked" {
		return nil, "", ErrOwnedKeyRevoked
	}
	if err = json.Unmarshal(scopes, &key.Scopes); err != nil {
		return nil, "", err
	}
	raw := authhelpers.GenerateKey()
	cipher, _, err := secrets.EncryptProviderSecret(raw)
	if err != nil {
		return nil, "", ErrOwnedKeyEncryptionUnavailable
	}
	key.ID = "key_" + uuid.NewString()
	key.KeyHash = authhelpers.HashKey(raw)
	key.KeyPrefix = raw[:8]
	key.KeyCiphertext = cipher
	if _, err = tx.Exec(ctx, "UPDATE internal_keys SET status='revoked' WHERE tenant_id=$1 AND id=$2 AND user_id=$3", tenant, id, user); err != nil {
		return nil, "", err
	}
	err = tx.QueryRow(ctx, `INSERT INTO internal_keys(id,tenant_id,project_id,user_id,name,key_hash,key_prefix,key_ciphertext,scopes_json,expires_at,status,model_allowlist)
 VALUES($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8,$9,$10,$11,$12) RETURNING created_at`, key.ID, tenant, key.ProjectID, user, key.Name, key.KeyHash, key.KeyPrefix, cipher, scopes, key.ExpiresAt, key.Status, key.ModelAllowlist).Scan(&key.CreatedAt)
	if err != nil {
		return nil, "", err
	}
	if err = writeTransactionalOperationAudit(ctx, tx, tenant, user, "portal_rotate_key", "key", key.ID, map[string]any{"previous_key_id": id, "key_id": key.ID}); err != nil {
		return nil, "", err
	}
	if err = commitWithOperationAudit(ctx, tx); err != nil {
		return nil, "", err
	}
	return key, raw, nil
}

var ErrOwnedKeyAuthorizationDenied = errors.New("personal key authorization changed")

// Creation and reactivation share a user lock and count, so concurrent requests
// cannot bypass the five-key limit. Current grants are rechecked in this transaction.
func (r *InternalKeyRepository) CreatePortalOwned(ctx context.Context, key *InternalKey, raw string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var user string
	if err = tx.QueryRow(ctx, `SELECT u.id FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.status='active' AND t.status='active' FOR UPDATE OF u FOR SHARE OF t`, key.TenantID, key.UserID).Scan(&user); err != nil {
		return err
	}
	access, err := modelaccess.ReadAccess(ctx, tx, key.TenantID, key.UserID)
	if err != nil {
		return err
	}
	if !access.ChatAllowed {
		return ErrOwnedKeyAuthorizationDenied
	}
	key.ModelAllowlist, err = modelaccess.NormalizeKeyAllowlist(key.ModelAllowlist, access)
	if err != nil {
		return err
	}
	var assigned bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects p JOIN project_users m ON m.project_id=p.id AND m.user_id=$3 WHERE p.tenant_id=$1 AND p.id=$2 AND p.team_id=$4 AND p.status='active')`, key.TenantID, key.ProjectID, key.UserID, access.DepartmentID).Scan(&assigned); err != nil {
		return err
	}
	if !assigned {
		return ErrOwnedKeyAuthorizationDenied
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM internal_keys k WHERE k.tenant_id=$1 AND k.user_id=$2 AND k.status='active' AND NOT EXISTS(SELECT 1 FROM employee_api_keys m WHERE m.tenant_id=k.tenant_id AND m.key_id=k.id)`, key.TenantID, key.UserID).Scan(&count); err != nil {
		return err
	}
	if count >= MaxPortalUserActiveKeys {
		return ErrOwnedKeyLimitReached
	}
	if err = createInternalKey(ctx, tx, key, raw); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

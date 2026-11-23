package repository

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelcatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUserModelSelfGrantForbidden = errors.New("tenant administrator cannot grant self")
	ErrUserModelConflict           = errors.New("user model policy changed")
	ErrUserModelOutsideDepartment  = errors.New("model is outside the department ceiling")
	ErrUserModelUnavailable        = errors.New("user is not eligible for Chat models")
)

type UserModelRepository struct{ db *pgxpool.Pool }

func NewUserModelRepository(db *pgxpool.Pool) *UserModelRepository {
	return &UserModelRepository{db: db}
}
func (r *UserModelRepository) GetAccess(ctx context.Context, tenantID, userID string) (*modelaccess.Access, error) {
	a, err := modelaccess.ReadAccess(ctx, r.db, tenantID, userID)
	if err != nil {
		return nil, err
	}
	err = r.db.QueryRow(ctx, `SELECT ARRAY(SELECT DISTINCT m.model_name::text FROM models m JOIN providers p ON p.id=m.provider_id WHERE p.tenant_id=$1 AND (`+modelcatalog.CallablePredicate+`) ORDER BY m.model_name::text)`, tenantID).Scan(&a.CallableModels)
	return a, err
}

func (r *UserModelRepository) SetPolicy(ctx context.Context, tenantID, userID, actorID string, policy modelaccess.Policy, version int64) (*modelaccess.Access, error) {
	policy, err := modelaccess.Normalize(policy)
	if err != nil {
		return nil, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = lockModelGrantUser(ctx, tx, tenantID, userID, actorID); err != nil {
		return nil, err
	}
	current, err := modelaccess.ReadAccess(ctx, tx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if !current.ChatAllowed {
		return nil, ErrUserModelUnavailable
	}
	if current.Version != version {
		return nil, ErrUserModelConflict
	}
	available := make(map[string]bool, len(current.DepartmentModels))
	for _, name := range current.DepartmentModels {
		available[name] = true
	}
	for _, name := range policy.ModelNames {
		if !available[name] {
			return nil, ErrUserModelOutsideDepartment
		}
	}
	names, err := json.Marshal(policy.ModelNames)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO user_model_policies (tenant_id,user_id,mode,model_names,updated_by)
 VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id,user_id) DO UPDATE
 SET mode=EXCLUDED.mode,model_names=EXCLUDED.model_names,updated_by=EXCLUDED.updated_by,
     version=user_model_policies.version+1,updated_at=now()`, tenantID, userID, policy.Mode, names, actorID)
	if err != nil {
		return nil, err
	}
	access, err := modelaccess.ReadAccess(ctx, tx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if err = auditUserModelChange(ctx, tx, tenantID, userID, actorID, "user.model_access.updated", map[string]any{"mode": access.Mode, "model_count": len(access.ModelNames), "version": access.Version}); err != nil {
		return nil, err
	}
	if err = commitWithOperationAudit(ctx, tx); err != nil {
		return nil, err
	}
	return access, nil
}

func auditUserModelChange(ctx context.Context, tx pgx.Tx, tenant, user, actor, action string, detail map[string]any) error {
	detail["user_id"] = user
	return writeTransactionalOperationAudit(ctx, tx, tenant, actor, action, "user", user, detail)
}

func lockModelGrantUser(ctx context.Context, tx pgx.Tx, tenant, user, actor string) error {
	var id string
	return tx.QueryRow(ctx, `SELECT u.id FROM users u WHERE u.tenant_id=$1 AND u.id=$2
 AND EXISTS(SELECT 1 FROM users admin WHERE admin.tenant_id=u.tenant_id AND admin.id=$3 AND admin.status='active' AND admin.role IN ('platform_admin','tenant_admin')) FOR UPDATE OF u`, tenant, user, actor).Scan(&id)
}

// Expiry is enforced by ReadAccess immediately. This sweep writes each expiry
// audit exactly once, including grants of users who never open another session.
func auditExpiredModelGrants(ctx context.Context, tx pgx.Tx, tenant, user string) error {
	rows, err := tx.Query(ctx, `WITH due AS (
 SELECT id FROM user_model_extra_grants WHERE revoked_at IS NULL AND expiry_audited_at IS NULL
 AND expires_at<=statement_timestamp() AND ($1::text='' OR tenant_id=$1) AND ($2::text='' OR user_id=$2)
 ORDER BY expires_at,id LIMIT 500 FOR UPDATE SKIP LOCKED
 ), expired AS (
 UPDATE user_model_extra_grants g SET expiry_audited_at=statement_timestamp() FROM due WHERE g.id=due.id
 RETURNING g.id,g.tenant_id,g.user_id,g.model,g.expires_at
 ) INSERT INTO audit_operations(id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address)
 SELECT 'extra-expired:'||id,tenant_id,NULL,'user.model_extra.expired',
 jsonb_build_object('grant_id',id,'user_id',user_id,'model',model,'expires_at',expires_at,'actor','system'),
 'user',user_id,'' FROM expired RETURNING id,tenant_id,action_detail,target_id`, tenant, user)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, tenantID, target string
		var raw []byte
		if err := rows.Scan(&id, &tenantID, &raw, &target); err != nil {
			return err
		}
		detail := map[string]any{}
		if err := json.Unmarshal(raw, &detail); err != nil {
			return err
		}
		queueOperationAudit(ctx, tx, CommittedOperationAudit{TenantID: tenantID, AuditOperation: AuditOperation{ID: id, ActionType: "user.model_extra.expired", ActionDetail: detail, TargetType: "user", TargetID: target}})
	}
	return rows.Err()
}

func (r *UserModelRepository) ExpireExtraGrants(ctx context.Context) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = auditExpiredModelGrants(ctx, tx, "", ""); err != nil {
		return err
	}
	return commitWithOperationAudit(ctx, tx)
}

func (r *UserModelRepository) AddExtraGrant(ctx context.Context, tenant, user, actor string, grant modelaccess.ExtraGrant) (*modelaccess.ExtraGrant, error) {
	normalized, err := modelaccess.NormalizeExtraGrant(grant, time.Now())
	if err != nil {
		return nil, err
	}
	grant = normalized
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = lockModelGrantUser(ctx, tx, tenant, user, actor); err != nil {
		return nil, err
	}
	if user == actor {
		var role string
		if err := tx.QueryRow(ctx, "SELECT role FROM users WHERE tenant_id=$1 AND id=$2", tenant, actor).Scan(&role); err != nil {
			return nil, err
		}
		if role == "tenant_admin" {
			return nil, ErrUserModelSelfGrantForbidden
		}
	}
	current, err := modelaccess.ReadAccess(ctx, tx, tenant, user)
	if err != nil {
		return nil, err
	}
	if !current.ChatAllowed {
		return nil, ErrUserModelUnavailable
	}
	var available bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM models m JOIN providers p ON p.id=m.provider_id WHERE p.tenant_id=$1 AND m.model_name=$2 AND (`+modelcatalog.CallablePredicate+`))`, tenant, grant.Model).Scan(&available); err != nil {
		return nil, err
	}
	if !available {
		return nil, ErrUserModelUnavailable
	}
	if err = auditExpiredModelGrants(ctx, tx, tenant, user); err != nil {
		return nil, err
	}
	grant.ID = "extra_" + uuid.NewString()
	grant.CreatedBy = actor
	err = tx.QueryRow(ctx, `INSERT INTO user_model_extra_grants(id,tenant_id,user_id,model,reason,expires_at,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`, grant.ID, tenant, user, grant.Model, grant.Reason, grant.ExpiresAt, actor).Scan(&grant.CreatedAt)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return nil, ErrUserModelConflict
		}
		return nil, err
	}
	if err = auditUserModelChange(ctx, tx, tenant, user, actor, "user.model_extra.granted", map[string]any{"grant_id": grant.ID, "model": grant.Model, "reason": grant.Reason, "expires_at": grant.ExpiresAt, "self_grant": actor == user}); err != nil {
		return nil, err
	}
	if err = commitWithOperationAudit(ctx, tx); err != nil {
		return nil, err
	}
	return &grant, nil
}

func (r *UserModelRepository) RevokeExtraGrant(ctx context.Context, tenant, user, actor, id string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = lockModelGrantUser(ctx, tx, tenant, user, actor); err != nil {
		return err
	}
	var model string
	err = tx.QueryRow(ctx, `UPDATE user_model_extra_grants SET revoked_at=statement_timestamp(),revoked_by=$4
 WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL RETURNING model`, tenant, user, id, actor).Scan(&model)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_model_extra_grants WHERE tenant_id=$1 AND user_id=$2 AND id=$3)`, tenant, user, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return pgx.ErrNoRows
		}
	} else if err != nil {
		return err
	} else if err = auditUserModelChange(ctx, tx, tenant, user, actor, "user.model_extra.revoked", map[string]any{"grant_id": id, "model": model}); err != nil {
		return err
	}
	return commitWithOperationAudit(ctx, tx)
}

package modelaccess

import (
	"context"
	"encoding/json"
	"fmt"

	"time"

	"github.com/jackc/pgx/v5"
)

type Queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Access struct {
	Policy
	ExtraGrants       []ExtraGrant      `json:"extra_grants"`
	ModelSources      map[string]string `json:"model_sources"`
	StaleModels       []string          `json:"stale_models"`
	CallableModels    []string          `json:"-"`
	SnapshotAt        time.Time         `json:"-"`
	UserID            string            `json:"user_id"`
	DepartmentID      string            `json:"department_id"`
	DepartmentName    string            `json:"department_name"`
	DepartmentModels  []string          `json:"department_models"`
	EffectiveModels   []string          `json:"effective_models"`
	Version           int64             `json:"version"`
	DepartmentVersion int64             `json:"department_version"`
	ChatAllowed       bool              `json:"chat_allowed"`
	Role              string            `json:"-"`
	ModelReferences   map[string]string `json:"-"`
	KnownModelNames   []string          `json:"-"`
}

// ReadAccess reads identity, authorization inventory, department, narrowing and extra
// grants in one uncached database statement. Every join is tenant-scoped.
func ReadAccess(ctx context.Context, db Queryer, tenantID, userID string) (*Access, error) {
	var a Access
	var names, references, grants []byte
	err := db.QueryRow(ctx, `
 WITH inventory AS (
 SELECT m.id,m.model_name
 FROM models m JOIN providers p ON p.id=m.provider_id WHERE p.tenant_id=$1
 ), granted AS (
 -- 部门授权只算当前可用的模型：已删除供应商、已停用模型不能出现在授权清单里
 -- （与控制台 TeamModelRepository.ListAllowedModelNames 同一口径）。
 SELECT m.id,m.model_name
 FROM models m JOIN providers p ON p.id=m.provider_id
 WHERE p.tenant_id=$1 AND p.status='active' AND m.status='active'
 )
 SELECT u.id,u.role,COALESCE(u.department_id,''),COALESCE(t.name,''),u.department_version,
 u.status='active' AND t.id IS NOT NULL AND COALESCE(t.system_key,'')<>'unassigned' AND COALESCE(u.department_assignment_mode,'') NOT IN ('emergency','service'),
 COALESCE(um.mode,'inherit'),COALESCE(um.model_names,'[]'::jsonb),COALESCE(um.version,0),
 ARRAY(SELECT DISTINCT i.model_name::text FROM granted i LEFT JOIN team_models tm ON tm.team_id=t.id AND tm.model_id=i.id
  WHERE (t.model_access_mode='all_active' OR (t.model_access_mode='allowlist' AND tm.allowed=TRUE)) ORDER BY i.model_name::text),
 COALESCE((SELECT jsonb_object_agg(i.id,i.model_name) FROM inventory i),'{}'::jsonb),
 ARRAY(SELECT DISTINCT i.model_name::text FROM inventory i ORDER BY i.model_name::text),
 COALESCE((SELECT jsonb_agg(jsonb_build_object('id',g.id,'model',g.model,'reason',g.reason,'expires_at',g.expires_at,
  'created_by',g.created_by,'created_at',g.created_at,'revoked_at',g.revoked_at) ORDER BY g.created_at,g.id)
  FROM user_model_extra_grants g WHERE g.tenant_id=u.tenant_id AND g.user_id=u.id),'[]'::jsonb),statement_timestamp()
 FROM users u LEFT JOIN teams t ON t.id=u.department_id AND t.tenant_id=u.tenant_id
 LEFT JOIN user_model_policies um ON um.user_id=u.id AND um.tenant_id=u.tenant_id
 WHERE u.tenant_id=$1 AND u.id=$2`, tenantID, userID).Scan(
		&a.UserID, &a.Role, &a.DepartmentID, &a.DepartmentName, &a.DepartmentVersion, &a.ChatAllowed,
		&a.Mode, &names, &a.Version, &a.DepartmentModels, &references, &a.KnownModelNames, &grants, &a.SnapshotAt)
	if err != nil {
		return nil, err
	}
	for _, item := range []struct {
		raw    []byte
		target any
	}{{names, &a.ModelNames}, {references, &a.ModelReferences}, {grants, &a.ExtraGrants}} {
		if err = json.Unmarshal(item.raw, item.target); err != nil {
			return nil, fmt.Errorf("invalid stored model access: %w", err)
		}
	}
	a.EffectiveModels, a.ModelSources, a.StaleModels, err = ResolveWithExtras(a.DepartmentModels, a.Policy, a.ExtraGrants, a.CallableModels, a.SnapshotAt)
	if err != nil {
		return nil, err
	}
	if !a.ChatAllowed {
		a.EffectiveModels = []string{}
		a.ModelSources = map[string]string{}
	}
	return &a, nil
}

func (a *Access) Allows(name string) bool {
	if !a.ChatAllowed {
		return false
	}
	for _, allowed := range a.EffectiveModels {
		if name == allowed {
			return true
		}
	}
	return false
}

// AllowsReference handles server-side routing/downgrade references. Internal
// model IDs are normalized only through the current tenant's
// catalog; unknown aliases and models outside the personal ceiling deny.
func (a *Access) AllowsReference(ref string) bool {
	if a.Allows(ref) {
		return true
	}
	// Routing resolves exact logical names before IDs across the entire tenant.
	for _, name := range a.KnownModelNames {
		if name == ref {
			return false
		}
	}
	name, ok := a.ModelReferences[ref]
	return ok && a.Allows(name)
}

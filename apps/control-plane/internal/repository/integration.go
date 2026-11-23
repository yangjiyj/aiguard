package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"time"

	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IntegrationRepository struct{ db *pgxpool.Pool }

func NewIntegrationRepository(db *pgxpool.Pool) *IntegrationRepository {
	return &IntegrationRepository{db: db}
}

const credentialColumns = `id,agent_instance_id,project_id,COALESCE(name,''),key_prefix,scopes_json,status,created_at,expires_at,model_restriction,model_allowlist,model_enforcement,dlp_enforcement`

func scanIntegrationCredential(row interface{ Scan(...any) error }) (*ai.Credential, error) {
	var k ai.Credential
	var scopes []byte
	err := row.Scan(&k.KeyID, &k.AgentInstanceID, &k.ProjectID, &k.Name, &k.KeyPrefix, &scopes, &k.Status, &k.CreatedAt, &k.ExpiresAt, &k.ModelRestriction, &k.ModelAllowlist, &k.Enforcement, &k.DLPEnforcement)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ai.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(scopes, &k.Scopes); err != nil {
		return nil, err
	}
	k.ResolveEnforcement()
	return &k, nil
}

func integrationDBError(err error) error {
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "23505" {
		return ai.ErrConflict
	}
	return err
}

// A failed successor insert rolls back the predecessor revocation as well.
func (r *IntegrationRepository) IssueCredential(ctx context.Context, tenant string, input ai.Credential, rawKey, replacedID string) (*ai.Credential, error) {
	if !ai.ValidID(input.AgentInstanceID) || len(rawKey) < 8 {
		return nil, ai.ErrInvalid
	}
	hash := sha256.Sum256([]byte(rawKey))
	hashString := hex.EncodeToString(hash[:])
	cipher, _, err := secrets.EncryptProviderSecret(rawKey)
	if err != nil && !errors.Is(err, secrets.ErrSecretKeyNotConfigured) {
		return nil, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Serialize new integration issuers for this hash without constraining historical rows.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, hashString); err != nil {
		return nil, err
	}
	if replacedID != "" {
		old, err := scanIntegrationCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM internal_keys WHERE id=$1 AND tenant_id=$2 AND agent_instance_id IS NOT NULL FOR UPDATE`, replacedID, tenant))
		if err != nil {
			return nil, err
		}
		if old.Status != "active" {
			return nil, ai.ErrConflict
		}
		input.AgentInstanceID, input.ProjectID, input.Scopes, input.Name = old.AgentInstanceID, old.ProjectID, old.Scopes, old.Name
		input.ModelRestriction, input.ModelAllowlist, input.Enforcement, input.DLPEnforcement = old.ModelRestriction, old.ModelAllowlist, old.Enforcement, old.DLPEnforcement
		if input.ExpiresAt == nil {
			input.ExpiresAt = old.ExpiresAt
		}
		if _, err = tx.Exec(ctx, `UPDATE internal_keys SET status='revoked' WHERE id=$1 AND tenant_id=$2`, replacedID, tenant); err != nil {
			return nil, err
		}
	}
	if input.Enforcement == "" {
		input.Enforcement = "record"
	}
	if input.DLPEnforcement == "" {
		input.DLPEnforcement = "record"
	}
	if err = ai.ValidateCredentialControls(input); err != nil {
		return nil, err
	}
	if err = validateIntegrationModels(ctx, tx, tenant, input.ModelAllowlist); err != nil {
		return nil, err
	}
	if input.ModelAllowlist == nil {
		input.ModelAllowlist = []string{}
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM internal_keys WHERE key_hash=$1)`, hashString).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, ai.ErrConflict
	}
	var projectID string
	if err = tx.QueryRow(ctx, `SELECT id FROM projects WHERE id=$1 AND tenant_id=$2 FOR KEY SHARE`, input.ProjectID, tenant).Scan(&projectID); errors.Is(err, pgx.ErrNoRows) {
		return nil, ai.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	scopes, err := json.Marshal(input.Scopes)
	if err != nil {
		return nil, err
	}
	key, err := scanIntegrationCredential(tx.QueryRow(ctx, `INSERT INTO internal_keys(id,tenant_id,project_id,name,key_hash,key_prefix,scopes_json,status,expires_at,key_ciphertext,agent_instance_id,model_restriction,model_allowlist,model_enforcement,dlp_enforcement)
        VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,NULLIF($9,''),$10,$11,$12,$13,$14) RETURNING `+credentialColumns,
		"key_"+uuid.NewString(), tenant, input.ProjectID, input.Name, hashString, rawKey[:8], scopes, input.ExpiresAt, cipher, input.AgentInstanceID, input.ModelRestriction, input.ModelAllowlist, input.Enforcement, input.DLPEnforcement))
	if err != nil {
		return nil, integrationDBError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return key, nil
}

func (r *IntegrationRepository) ListCredentials(ctx context.Context, tenant, agent string) ([]ai.Credential, error) {
	rows, err := r.db.Query(ctx, `SELECT `+credentialColumns+` FROM internal_keys WHERE tenant_id=$1 AND agent_instance_id=$2 ORDER BY created_at DESC,id DESC`, tenant, agent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ai.Credential{}
	for rows.Next() {
		k, err := scanIntegrationCredential(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *k)
	}
	return items, rows.Err()
}

func (r *IntegrationRepository) RevokeCredential(ctx context.Context, tenant, id string) (*ai.Credential, error) {
	return scanIntegrationCredential(r.db.QueryRow(ctx, `UPDATE internal_keys SET status='revoked' WHERE tenant_id=$1 AND id=$2 AND agent_instance_id IS NOT NULL RETURNING `+credentialColumns, tenant, id))
}

const integrationPolicyColumns = `id,tenant_id,agent_instance_id,action,enabled,mode,mcp_server_id,version::text,updated_at`

func scanIntegrationPolicy(row interface{ Scan(...any) error }) (*ai.Policy, error) {
	var p ai.Policy
	err := row.Scan(&p.ID, &p.TenantID, &p.AgentInstanceID, &p.Action, &p.Enabled, &p.Mode, &p.MCPServerID, &p.Version, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ai.ErrNotFound
	}
	return &p, err
}

func (r *IntegrationRepository) WritePolicy(ctx context.Context, tenant, id, expected string, input ai.Policy) (*ai.Policy, error) {
	if err := ai.ValidatePolicy(input); err != nil {
		return nil, err
	}
	var version int64
	if id != "" {
		var err error
		version, err = strconv.ParseInt(expected, 10, 64)
		if err != nil || version < 1 {
			return nil, ai.ErrInvalid
		}
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Bind the native route ID in the same transaction as the policy write.
	// The lock prevents concurrent deletion until this write has committed.
	if input.Action == "disable_mcp" && input.MCPServerID != "" {
		var serverID string
		if err = tx.QueryRow(ctx, `SELECT id FROM mcp_servers WHERE tenant_id=$1 AND id=$2 FOR KEY SHARE`, tenant, input.MCPServerID).Scan(&serverID); errors.Is(err, pgx.ErrNoRows) {
			return nil, ai.ErrNotFound
		} else if err != nil {
			return nil, err
		}
	}
	var p *ai.Policy
	if id == "" {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM internal_keys WHERE tenant_id=$1 AND agent_instance_id=$2)`, tenant, input.AgentInstanceID).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, ai.ErrNotFound
		}
		p, err = scanIntegrationPolicy(tx.QueryRow(ctx, `INSERT INTO integration_agent_policies(id,tenant_id,agent_instance_id,action,enabled,mode,mcp_server_id)
            VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING `+integrationPolicyColumns, "tri_policy_"+uuid.NewString(), tenant, input.AgentInstanceID, input.Action, input.Enabled, input.Mode, input.MCPServerID))
	} else {
		p, err = scanIntegrationPolicy(tx.QueryRow(ctx, `UPDATE integration_agent_policies SET enabled=$3,mode=$4,version=version+1,updated_at=now()
        WHERE tenant_id=$1 AND id=$2 AND version=$5 AND agent_instance_id=$6 AND action=$7 AND mcp_server_id=$8 RETURNING `+integrationPolicyColumns,
			tenant, id, input.Enabled, input.Mode, version, input.AgentInstanceID, input.Action, input.MCPServerID))
		if errors.Is(err, ai.ErrNotFound) {
			if _, findErr := scanIntegrationPolicy(tx.QueryRow(ctx, `SELECT `+integrationPolicyColumns+` FROM integration_agent_policies WHERE tenant_id=$1 AND id=$2`, tenant, id)); findErr != nil {
				return nil, findErr
			}
			return nil, ai.ErrConflict
		}
	}
	if err != nil {
		return nil, integrationDBError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (r *IntegrationRepository) GetPolicy(ctx context.Context, tenant, id string) (*ai.Policy, error) {
	return scanIntegrationPolicy(r.db.QueryRow(ctx, `SELECT `+integrationPolicyColumns+` FROM integration_agent_policies WHERE tenant_id=$1 AND id=$2`, tenant, id))
}

func (r *IntegrationRepository) ListPolicies(ctx context.Context, tenant, agent string) ([]ai.Policy, error) {
	rows, err := r.db.Query(ctx, `SELECT `+integrationPolicyColumns+` FROM integration_agent_policies WHERE tenant_id=$1 AND ($2='' OR agent_instance_id=$2) ORDER BY id`, tenant, agent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ai.Policy{}
	for rows.Next() {
		p, err := scanIntegrationPolicy(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *p)
	}
	return items, rows.Err()
}

func (r *IntegrationRepository) EnforcementStatus(ctx context.Context, tenant, id, expected string, requireHit bool, roster []string) (*ai.Status, error) {
	p, err := r.GetPolicy(ctx, tenant, id)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT instance_id,boot_id,last_seen_at,mode FROM integration_gateway_instances ORDER BY instance_id`)
	if err != nil {
		return nil, err
	}
	nodes := []ai.Instance{}
	for rows.Next() {
		var n ai.Instance
		if err = rows.Scan(&n.InstanceID, &n.BootID, &n.LastSeenAt, &n.Mode); err != nil {
			rows.Close()
			return nil, err
		}
		nodes = append(nodes, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = r.db.Query(ctx, `SELECT r.instance_id,r.boot_id,r.loaded_version::text,r.loaded_at,r.hit_count,r.blocked_count FROM integration_gateway_receipts r WHERE r.policy_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	receipts := []ai.Receipt{}
	for rows.Next() {
		var rec ai.Receipt
		if err = rows.Scan(&rec.InstanceID, &rec.BootID, &rec.LoadedVersion, &rec.LoadedAt, &rec.HitCount, &rec.BlockedCount); err != nil {
			return nil, err
		}
		rec.RuleHits = []ai.RuleHits{{RuleID: p.Action, HitCount: rec.HitCount, BlockedCount: rec.BlockedCount}}
		receipts = append(receipts, rec)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	result := ai.EvaluateStatus(*p, nodes, receipts, roster, expected, requireHit, time.Now().UTC())
	return &result, nil
}

type IntegrationEvent struct {
	ID              string           `json:"id"`
	RequestID       string           `json:"request_id"`
	AgentInstanceID string           `json:"agent_instance_id"`
	CreatedAt       time.Time        `json:"created_at"`
	ProjectID       string           `json:"project_id"`
	ClientID        string           `json:"client_id"`
	AgentType       string           `json:"agent_type"`
	Model           string           `json:"model"`
	ModelID         string           `json:"model_id"`
	Usage           IntegrationUsage `json:"usage"`
	Status          string           `json:"status"`
	StatusCode      int              `json:"status_code"`
	Action          string           `json:"action"`
	EventIDs        []string         `json:"event_ids"`
	NativeURL       string           `json:"native_url"`
}

func (r *IntegrationRepository) ListEvents(ctx context.Context, tenant, agent string, start, end time.Time, limit, offset int) ([]IntegrationEvent, int, error) {
	where := `rl.tenant_id=$1 AND ($2='' OR rl.agent_instance_id=$2) AND rl.created_at>=$3 AND rl.created_at<=$4`
	var total int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM request_logs rl WHERE `+where, tenant, agent, start, end).Scan(&total); err != nil {
		return nil, 0, err
	}
	// Metering evidence is eligible only in the existing row's exact native
	// credential domain. Revoked keys remain valid historical identity; no new
	// content or billing permission is granted by this counts-only projection.
	rows, err := r.db.Query(ctx, `SELECT rl.id,rl.request_id,COALESCE(rl.agent_instance_id,''),rl.created_at,COALESCE(rl.project_id,''),COALESCE(rl.client_id,''),COALESCE(rl.agent_type,''),COALESCE(m.model_name,''),COALESCE(rl.request_status,''),COALESCE(rl.upstream_status_code,0),COALESCE(ev.action,'allow'),COALESCE(ev.ids,'[]'::jsonb),
          COALESCE(rl.model_id,''),rl.input_tokens,rl.output_tokens,
          COALESCE(rl.output_audit_result->'response_metadata'->>'usage_source',''),
          jsonb_build_object('usage_source',uf.raw_usage_json->'usage_source','upstream_usage',uf.raw_usage_json->'upstream_usage','upstream_usage_available',uf.raw_usage_json->'upstream_usage_available'),COALESCE(uf.estimated,true)
        FROM request_logs rl LEFT JOIN models m ON m.id=rl.model_id
        LEFT JOIN billing_usage_facts uf ON uf.tenant_id=rl.tenant_id AND uf.request_id=rl.request_id
          AND uf.client_id=rl.client_id AND uf.project_id=rl.project_id AND uf.model_id=rl.model_id
          AND EXISTS (SELECT 1 FROM internal_keys k WHERE k.tenant_id=rl.tenant_id AND k.id=rl.client_id
            AND k.project_id=rl.project_id AND k.agent_instance_id=rl.agent_instance_id AND k.agent_instance_id<>'')
        LEFT JOIN LATERAL (SELECT max(action_taken) AS action,jsonb_agg(id ORDER BY id) AS ids FROM security_events WHERE tenant_id=rl.tenant_id AND request_id=rl.request_id) ev ON true
        WHERE `+where+` ORDER BY rl.created_at DESC,rl.id DESC LIMIT $5 OFFSET $6`, tenant, agent, start, end, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []IntegrationEvent{}
	for rows.Next() {
		var e IntegrationEvent
		var ids []byte
		var input, output *int64
		var source string
		var evidence []byte
		var estimated bool
		if err = rows.Scan(&e.ID, &e.RequestID, &e.AgentInstanceID, &e.CreatedAt, &e.ProjectID, &e.ClientID, &e.AgentType, &e.Model, &e.Status, &e.StatusCode, &e.Action, &ids, &e.ModelID, &input, &output, &source, &evidence, &estimated); err != nil {
			return nil, 0, err
		}
		if err = json.Unmarshal(ids, &e.EventIDs); err != nil {
			return nil, 0, err
		}
		e.Usage = projectIntegrationUsage(source, evidence, input, output, estimated)
		e.NativeURL = "/audit/access-retention?request_id=" + url.QueryEscape(e.RequestID)
		items = append(items, e)
	}
	return items, total, rows.Err()
}

type IntegrationUpstream struct {
	ProviderID string `json:"provider_id"`
	ModelID    string `json:"model_id"`
	Model      string `json:"model"`
	BaseURL    string `json:"base_url"`
	Enabled    bool   `json:"enabled"`
}

type IntegrationProject struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

func (r *IntegrationRepository) ListProjects(ctx context.Context, tenant string) ([]IntegrationProject, error) {
	rows, err := r.db.Query(ctx, `SELECT id, name, status FROM projects WHERE tenant_id=$1 ORDER BY name, id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projects := []IntegrationProject{}
	for rows.Next() {
		var project IntegrationProject
		if err = rows.Scan(&project.ID, &project.Name, &project.Status); err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	return projects, rows.Err()
}

func (r *IntegrationRepository) ListUpstreams(ctx context.Context, tenant string) ([]IntegrationUpstream, error) {
	rows, err := r.db.Query(ctx, `SELECT p.id,m.id,m.model_name,p.base_url,(p.status='active' AND m.status='active') FROM providers p JOIN models m ON m.provider_id=p.id WHERE p.tenant_id=$1 ORDER BY p.id,m.id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []IntegrationUpstream{}
	for rows.Next() {
		var u IntegrationUpstream
		if err = rows.Scan(&u.ProviderID, &u.ModelID, &u.Model, &u.BaseURL, &u.Enabled); err != nil {
			return nil, err
		}
		u.BaseURL = ai.SafeURL(u.BaseURL)
		items = append(items, u)
	}
	return items, rows.Err()
}

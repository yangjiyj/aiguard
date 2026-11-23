package repository

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"time"
)

var ErrIdentityScope = errors.New("identity scope requires a stable caller and fingerprint or a dedicated key declaration")
var ErrIdentityConflict = errors.New("an active registration overlaps this scope; revoke it first")

type AgentIdentityRecord struct {
	UserName     string    `json:"user_name"`
	KeyName      string    `json:"key_name"`
	ProjectName  string    `json:"project_name"`
	RequestID    string    `json:"request_id"`
	CreatedAt    time.Time `json:"created_at"`
	AgentType    string    `json:"agent_type"`
	Source       string    `json:"source"`
	DeclaredType string    `json:"declared_type"`
	DeclaredName string    `json:"declared_name"`
	UserAgent    string    `json:"user_agent"`
	ClientID     string    `json:"client_id"`
	UserID       string    `json:"user_id"`
	SourceIP     string    `json:"source_ip"`
	Channel      string    `json:"channel"`
	Environment  string    `json:"environment"`
}

type AgentIdentityRule struct {
	OperatorName string     `json:"operator_name"`
	KeyName      string     `json:"key_name"`
	ID           string     `json:"id"`
	RequestID    string     `json:"request_id"`
	AgentType    string     `json:"agent_type"`
	Scope        string     `json:"scope"`
	ClientID     string     `json:"client_id"`
	Channel      string     `json:"channel"`
	Environment  string     `json:"environment"`
	UserAgent    string     `json:"user_agent"`
	DeclaredType string     `json:"declared_type"`
	DeclaredName string     `json:"declared_name"`
	Note         string     `json:"note"`
	OperatorID   string     `json:"operator_id"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
}

type AgentIdentityRepository struct{ db *pgxpool.Pool }

func NewAgentIdentityRepository(db *pgxpool.Pool) *AgentIdentityRepository {
	return &AgentIdentityRepository{db: db}
}

const identityRecordSelect = `SELECT request_id,created_at,COALESCE(agent_type,''),COALESCE(agent_detection_source,''),
 COALESCE(agent_identity_headers->>'declared_type',agent_identity_observed->>'type',agent_type,''),
 COALESCE(agent_identity_headers->>'declared_name',''),COALESCE(proxy_user_agent,''),COALESCE(client_id,''),COALESCE(user_id,''),
 COALESCE(NULLIF(source_ip,''),proxy_source_ip,''),COALESCE(proxy_mode,''),COALESCE(environment_scope,''),
 COALESCE((SELECT u.username FROM users u WHERE u.id=request_logs.user_id AND u.tenant_id=request_logs.tenant_id),''),
 COALESCE((SELECT k.name FROM internal_keys k WHERE k.id=request_logs.client_id AND k.tenant_id=request_logs.tenant_id),''),
 COALESCE((SELECT p.name FROM projects p WHERE p.id=COALESCE((SELECT k.project_id FROM internal_keys k WHERE k.id=request_logs.client_id AND k.tenant_id=request_logs.tenant_id),request_logs.project_id) AND p.tenant_id=request_logs.tenant_id),'') FROM request_logs `

func scanIdentity(row pgx.Row) (a AgentIdentityRecord, err error) {
	err = row.Scan(&a.RequestID, &a.CreatedAt, &a.AgentType, &a.Source, &a.DeclaredType, &a.DeclaredName, &a.UserAgent, &a.ClientID, &a.UserID, &a.SourceIP, &a.Channel, &a.Environment, &a.UserName, &a.KeyName, &a.ProjectName)
	return
}
func (r *AgentIdentityRepository) Pending(ctx context.Context, tenant, keyword string, offset int) ([]AgentIdentityRecord, bool, error) {
	rows, err := r.db.Query(ctx, identityRecordSelect+`WHERE tenant_id=$1 AND NOT agent_identity_known(agent_type)
 AND COALESCE(agent_type,'')<>'' AND created_at >= now()-interval '7 days'
 AND ($2='' OR strpos(lower(COALESCE(agent_type,'') || ' ' || COALESCE(client_id,'') || ' ' || COALESCE(proxy_user_agent,'') || ' ' || COALESCE(source_ip,proxy_source_ip,'')),lower($2))>0)
 ORDER BY created_at DESC,request_id DESC LIMIT 51 OFFSET $3`, tenant, keyword, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	result := []AgentIdentityRecord{}
	for rows.Next() {
		a, err := scanIdentity(rows)
		if err != nil {
			return nil, false, err
		}
		result = append(result, a)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(result) > 50
	if more {
		result = result[:50]
	}
	return result, more, nil
}
func ValidIdentityScope(a AgentIdentityRecord, scope string, dedicated bool) bool {
	switch scope {
	case "request":
		return true
	case "fingerprint":
		return a.ClientID != "" && (a.UserAgent != "" || a.DeclaredName != "" || (a.DeclaredType != "" && a.DeclaredType != "agent-tool-call" && a.Source != "content" && a.Source != "user_agent_runtime"))
	case "dedicated_key":
		return a.ClientID != "" && dedicated
	}
	return false
}
func (r *AgentIdentityRepository) Confirm(ctx context.Context, tenant, operator, requestID, product, scope, note string, dedicated bool) (string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	// Serialise registrations per tenant to reject overlapping scopes atomically.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,830))`, tenant); err != nil {
		return "", err
	}
	a, err := scanIdentity(tx.QueryRow(ctx, identityRecordSelect+`WHERE tenant_id=$1 AND request_id=$2 AND NOT agent_identity_known(agent_type) FOR UPDATE`, tenant, requestID))
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if !ValidIdentityScope(a, scope, dedicated) {
		return "", ErrIdentityScope
	}
	var known bool
	if err = tx.QueryRow(ctx, `SELECT agent_identity_known($1)`, product).Scan(&known); err != nil {
		return "", err
	}
	if !known || len(strings.TrimSpace(note)) < 2 || len(note) > 1000 {
		return "", ErrIdentityScope
	}
	var conflict bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_identity_rules WHERE tenant_id=$1 AND revoked_at IS NULL
 AND environment_scope=$2 AND channel=$3 AND (
 (scope='request' AND request_id=$4) OR
 ($5<>'request' AND scope<>'request' AND client_id=$6 AND
 (scope='dedicated_key' OR $5='dedicated_key' OR (user_agent=$7 AND declared_type=$8 AND declared_name=$9)))))`,
		tenant, a.Environment, a.Channel, a.RequestID, scope, a.ClientID, a.UserAgent, a.DeclaredType, a.DeclaredName).Scan(&conflict)
	if err != nil {
		return "", err
	}
	if conflict {
		return "", ErrIdentityConflict
	}
	id := "air_" + uuid.NewString()
	_, err = tx.Exec(ctx, `INSERT INTO agent_identity_rules(id,tenant_id,environment_scope,channel,client_id,request_id,user_agent,declared_type,declared_name,scope,agent_type,note,operator_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id, tenant, a.Environment, a.Channel, a.ClientID, a.RequestID, a.UserAgent, a.DeclaredType, a.DeclaredName, scope, product, strings.TrimSpace(note), operator)
	if err != nil {
		return "", err
	}
	// Only the reviewed record is backfilled. Other historical records need their own review.
	_, err = tx.Exec(ctx, `UPDATE request_logs SET internal_title_request = NULL, agent_identity_rule_id=NULL,agent_type=agent_type WHERE tenant_id=$1 AND request_id=$2`, tenant, requestID)
	if err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}
func (r *AgentIdentityRepository) Rules(ctx context.Context, tenant string) ([]AgentIdentityRule, error) {
	rows, err := r.db.Query(ctx, `SELECT id,request_id,agent_type,scope,client_id,channel,environment_scope,user_agent,declared_type,declared_name,note,operator_id,created_at,revoked_at, COALESCE((SELECT u.username FROM users u WHERE u.id=agent_identity_rules.operator_id AND u.tenant_id=agent_identity_rules.tenant_id),''), COALESCE((SELECT k.name FROM internal_keys k WHERE k.id=agent_identity_rules.client_id AND k.tenant_id=agent_identity_rules.tenant_id),'') FROM agent_identity_rules WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentIdentityRule{}
	for rows.Next() {
		var a AgentIdentityRule
		if err = rows.Scan(&a.ID, &a.RequestID, &a.AgentType, &a.Scope, &a.ClientID, &a.Channel, &a.Environment, &a.UserAgent, &a.DeclaredType, &a.DeclaredName, &a.Note, &a.OperatorID, &a.CreatedAt, &a.RevokedAt, &a.OperatorName, &a.KeyName); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (r *AgentIdentityRepository) Revoke(ctx context.Context, tenant, operator, id string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,830))`, tenant); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_identity_rules SET revoked_at=now(),revoked_by=$3 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, tenant, id, operator)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = tx.Exec(ctx, `UPDATE request_logs SET internal_title_request = NULL, agent_type=agent_type WHERE tenant_id=$1 AND agent_identity_rule_id=$2`, tenant, id)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

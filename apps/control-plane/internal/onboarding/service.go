package onboarding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const InitializationKey = "enterprise_chat_defaults_v1"

type Status struct {
	TenantID      string     `json:"tenant_id"`
	Key           string     `json:"initialization_key"`
	State         string     `json:"status"`
	AttemptCount  int        `json:"attempt_count"`
	LastErrorCode string     `json:"last_error_code,omitempty"`
	RequestedAt   time.Time  `json:"requested_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

type Service struct {
	db  *pgxpool.Pool
	now func() time.Time
}

func NewService(db *pgxpool.Pool) *Service {
	return &Service{db: db, now: time.Now}
}

// Initialize is the optional installer-armed maintenance initializer. It keeps
// the existing retry/status contract for the admin console and also provisions
// the billing/system defaults that are not needed to authorize Chat.
func (s *Service) Initialize(ctx context.Context, tenantID, actorUserID string) error {
	if s == nil || s.db == nil || tenantID == "" || actorUserID == "" {
		return nil
	}
	claimed, err := s.claim(ctx, tenantID, actorUserID)
	if err != nil || !claimed {
		return err
	}
	if err := s.apply(ctx, tenantID, actorUserID); err != nil {
		if markErr := s.markFailed(context.WithoutCancel(ctx), tenantID); markErr != nil {
			return fmt.Errorf("initialize enterprise defaults: %v; persist retry state: %w", err, markErr)
		}
		return err
	}
	return nil
}

// EnsureChatDefaults is the request-path safety net for the employee portal.
//
// Chat must not depend on an operator opening the initialization page (or on an
// installer having successfully armed deployment_initializations). The first
// portal identity request calls this method and it creates only missing Chat
// context rows. Existing team model access, project ownership, and identity
// mappings are deliberately preserved so an administrator's configuration is
// the source of truth. The operation is transactional and safe under concurrent
// first requests.
func (s *Service) EnsureChatDefaults(ctx context.Context, tenantID string) error {
	if s == nil || s.db == nil || strings.TrimSpace(tenantID) == "" {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin Chat defaults: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenantID+":"+InitializationKey+":chat"); err != nil {
		return fmt.Errorf("lock Chat defaults: %w", err)
	}

	suffix := stableSuffix(tenantID)
	teamID := "team_chat_" + suffix
	if _, err := tx.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path,is_system,system_key,model_access_mode)
		VALUES ($1::varchar,$2,'Chat 默认部门',('/'||$1::text)::varchar,TRUE,'chat_default','all_active')
		ON CONFLICT (tenant_id,system_key) WHERE system_key IS NOT NULL DO NOTHING
	`, teamID, tenantID); err != nil {
		return fmt.Errorf("ensure Chat department: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM teams WHERE tenant_id=$1 AND system_key='chat_default'`, tenantID).Scan(&teamID); err != nil {
		return fmt.Errorf("resolve Chat department: %w", err)
	}

	projectID := "project_chat_" + suffix
	if _, err := tx.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,code,environment,owner_user_id,status,team_id,system_key)
		VALUES ($1,$2,'企业 AI 对话项目','chat','production',NULL,'active',$3,'chat_default')
		ON CONFLICT (tenant_id,system_key) WHERE system_key IS NOT NULL DO NOTHING
	`, projectID, tenantID, teamID); err != nil {
		return fmt.Errorf("ensure Chat project: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM projects WHERE tenant_id=$1 AND system_key='chat_default'`, tenantID).Scan(&projectID); err != nil {
		return fmt.Errorf("resolve Chat project: %w", err)
	}

	policyID := "mpol_chat_" + suffix
	if _, err := tx.Exec(ctx, `
		INSERT INTO model_policies (id,tenant_id,project_id,scope_type,scope_ref,allow_models_json,deny_models_json)
		VALUES ($1,$2,$3,'project','', '[]'::jsonb, '[]'::jsonb)
		ON CONFLICT (id) DO NOTHING
	`, policyID, tenantID, projectID); err != nil {
		return fmt.Errorf("ensure Chat model policy: %w", err)
	}

	// Only create the fallback when the tenant has not configured one. An
	// administrator-provided LDAP/AD/OIDC mapping remains untouched.
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_identity_defaults (tenant_id,default_department_id,fallback_source_types,enabled)
		VALUES ($1,$2,ARRAY['oidc','ldap','ad']::varchar(16)[],TRUE)
		ON CONFLICT (tenant_id) DO NOTHING
	`, tenantID, teamID); err != nil {
		return fmt.Errorf("ensure identity fallback: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Chat defaults: %w", err)
	}
	return nil
}

func (s *Service) claim(ctx context.Context, tenantID, actorUserID string) (bool, error) {
	staleBefore := s.now().UTC().Add(-2 * time.Minute)
	var claimed bool
	err := s.db.QueryRow(ctx, `
		UPDATE deployment_initializations
		SET status='running', attempt_count=attempt_count+1,
		    started_at=NOW(), updated_at=NOW(), actor_user_id=$3,
		    last_error_code='', last_error_at=NULL
		WHERE tenant_id=$1 AND initialization_key=$2 AND fresh_install=TRUE
		  AND (status IN ('pending','failed') OR (status='running' AND updated_at < $4))
		RETURNING TRUE
	`, tenantID, InitializationKey, actorUserID, staleBefore).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim enterprise initialization: %w", err)
	}
	return claimed, nil
}

func (s *Service) apply(ctx context.Context, tenantID, actorUserID string) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin enterprise initialization: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenantID+":"+InitializationKey); err != nil {
		return fmt.Errorf("lock enterprise initialization: %w", err)
	}
	var state string
	if err := tx.QueryRow(ctx, `
		SELECT status FROM deployment_initializations
		WHERE tenant_id=$1 AND initialization_key=$2
		FOR UPDATE
	`, tenantID, InitializationKey).Scan(&state); err != nil {
		return fmt.Errorf("read enterprise initialization state: %w", err)
	}
	if state == "completed" {
		return tx.Commit(ctx)
	}
	if state != "running" {
		return fmt.Errorf("enterprise initialization is not claimed")
	}

	suffix := stableSuffix(tenantID)
	teamID := "team_chat_" + suffix
	projectID := "project_chat_" + suffix
	policyID := "mpol_chat_" + suffix
	tariffID := "tariff_flat_" + suffix
	tariffRuleID := "tariff_rule_flat_" + suffix

	if _, err := tx.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path,is_system,system_key,model_access_mode)
		VALUES ($1::varchar,$2,'Chat 默认部门',('/'||$1::text)::varchar,TRUE,'chat_default','all_active')
		ON CONFLICT (tenant_id,system_key) WHERE system_key IS NOT NULL
		DO UPDATE SET model_access_mode='all_active'
	`, teamID, tenantID); err != nil {
		return fmt.Errorf("initialize Chat department: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM teams WHERE tenant_id=$1 AND system_key='chat_default'`, tenantID).Scan(&teamID); err != nil {
		return fmt.Errorf("resolve Chat department: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,code,environment,owner_user_id,status,team_id,system_key)
		VALUES ($1,$2,'企业 AI 对话项目','chat','production',$3,'active',$4,'chat_default')
		ON CONFLICT (tenant_id,system_key) WHERE system_key IS NOT NULL
		DO UPDATE SET team_id=EXCLUDED.team_id,status='active'
	`, projectID, tenantID, actorUserID, teamID); err != nil {
		return fmt.Errorf("initialize Chat project: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM projects WHERE tenant_id=$1 AND system_key='chat_default'`, tenantID).Scan(&projectID); err != nil {
		return fmt.Errorf("resolve Chat project: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO model_policies (id,tenant_id,project_id,scope_type,scope_ref,allow_models_json,deny_models_json)
		VALUES ($1,$2,$3,'project','', '[]'::jsonb, '[]'::jsonb)
		ON CONFLICT (id) DO UPDATE SET allow_models_json='[]'::jsonb,deny_models_json='[]'::jsonb,updated_at=NOW()
	`, policyID, tenantID, projectID); err != nil {
		return fmt.Errorf("initialize all-active model policy: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_identity_defaults (tenant_id,default_department_id,fallback_source_types,enabled)
		VALUES ($1,$2,ARRAY['oidc','ldap','ad']::varchar(16)[],TRUE)
		ON CONFLICT (tenant_id) DO UPDATE SET
		  default_department_id=EXCLUDED.default_department_id,
		  fallback_source_types=EXCLUDED.fallback_source_types,
		  enabled=TRUE,updated_at=NOW()
	`, tenantID, teamID); err != nil {
		return fmt.Errorf("initialize identity department fallback: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO billing_tariff_plans (id,tenant_id,name,version,status,timezone,effective_at,created_by)
		VALUES ($1,$2,'默认平价计费',1,'active','Asia/Shanghai',NOW(),$3)
		ON CONFLICT (tenant_id,name,version) DO NOTHING
	`, tariffID, tenantID, actorUserID); err != nil {
		return fmt.Errorf("initialize default tariff: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM billing_tariff_plans WHERE tenant_id=$1 AND name='默认平价计费' AND version=1`, tenantID).Scan(&tariffID); err != nil {
		return fmt.Errorf("resolve default tariff: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO billing_tariff_rules (
		  id,tenant_id,plan_id,code,name,band,weekdays,start_minute,end_minute,multiplier_ppm,priority
		) VALUES ($1,$2,$3,'flat-all-day','全天平价','flat',ARRAY[1,2,3,4,5,6,7]::smallint[],0,1440,1000000,1000)
		ON CONFLICT (plan_id,code) DO NOTHING
	`, tariffRuleID, tenantID, tariffID); err != nil {
		return fmt.Errorf("initialize flat tariff rule: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM billing_tariff_rules WHERE tenant_id=$1 AND plan_id=$2 AND model_name IS NULL`, tenantID, tariffID); err != nil {
		return fmt.Errorf("remove global tariff rule: %w", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT m.model_name
		FROM models m
		JOIN providers p ON p.id=m.provider_id
		WHERE p.tenant_id=$1 AND m.status='active' AND p.status='active' AND NULLIF(TRIM(m.model_name),'') IS NOT NULL
		ORDER BY m.model_name
	`, tenantID)
	if err != nil {
		return fmt.Errorf("list active models for default tariff: %w", err)
	}
	for rows.Next() {
		var modelName string
		if err := rows.Scan(&modelName); err != nil {
			rows.Close()
			return fmt.Errorf("scan active model for default tariff: %w", err)
		}
		modelName = strings.TrimSpace(modelName)
		ruleID := "tariff_rule_flat_" + stableSuffix(tenantID+"|"+modelName)
		code := "flat-all-day-" + stableSuffix(modelName)
		if _, err := tx.Exec(ctx, `
			INSERT INTO billing_tariff_rules (id,tenant_id,plan_id,code,name,model_name,band,weekdays,start_minute,end_minute,multiplier_ppm,priority)
			VALUES ($1,$2,$3,$4,'?????????',$5,'flat',ARRAY[1,2,3,4,5,6,7]::smallint[],0,1440,1000000,1000)
			ON CONFLICT (plan_id,code) DO NOTHING
		`, ruleID, tenantID, tariffID, code, modelName); err != nil {
			rows.Close()
			return fmt.Errorf("initialize model tariff rule: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read active models for default tariff: %w", err)
	}
	rows.Close()
	if _, err := tx.Exec(ctx, `
		INSERT INTO system_settings(key,value,updated_at) VALUES
		  ('chat_portal_enabled','true',NOW()),
		  ('billing_mode_default','metering',NOW()),
		  ('billing_currency_default','CNY',NOW())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()
	`); err != nil {
		return fmt.Errorf("initialize enterprise settings: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_operations (
		  id,user_id,action_type,action_detail,target_type,target_id,tenant_id,created_at
		) VALUES (
		  $1,$2,'fresh_install_initialized',
		  jsonb_build_object('department_id',$3::text,'project_id',$4::text,'model_access_mode','all_active','billing_mode','metering'),
		  'deployment_initialization',$5,$6,NOW()
		)
		ON CONFLICT (id) DO NOTHING
	`, "audit_init_"+stableSuffix(tenantID+actorUserID), actorUserID, teamID, projectID, InitializationKey, tenantID); err != nil {
		return fmt.Errorf("audit enterprise initialization: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE deployment_initializations
		SET status='completed',completed_at=NOW(),updated_at=NOW(),last_error_code='',
		    details_json=jsonb_build_object(
		      'department_id',$3::text,'project_id',$4::text,'model_access_mode','all_active',
		      'identity_fallback','oidc,ldap,ad','billing_mode','metering','tariff','flat-1.0'
		    )
		WHERE tenant_id=$1 AND initialization_key=$2 AND status='running'
	`, tenantID, InitializationKey, teamID, projectID); err != nil {
		return fmt.Errorf("complete enterprise initialization: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit enterprise initialization: %w", err)
	}
	return nil
}

func (s *Service) markFailed(ctx context.Context, tenantID string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := s.db.Exec(ctx, `
		UPDATE deployment_initializations
		SET status='failed',last_error_code='initialization_failed',last_error_at=NOW(),updated_at=NOW()
		WHERE tenant_id=$1 AND initialization_key=$2 AND status='running'
	`, tenantID, InitializationKey)
	return err
}

func (s *Service) GetStatus(ctx context.Context, tenantID string) (*Status, error) {
	if s == nil || s.db == nil || tenantID == "" {
		return nil, nil
	}
	var status Status
	err := s.db.QueryRow(ctx, `
		SELECT tenant_id,initialization_key,status,attempt_count,last_error_code,
		       requested_at,updated_at,completed_at
		FROM deployment_initializations
		WHERE tenant_id=$1 AND initialization_key=$2
	`, tenantID, InitializationKey).Scan(
		&status.TenantID, &status.Key, &status.State, &status.AttemptCount, &status.LastErrorCode,
		&status.RequestedAt, &status.UpdatedAt, &status.CompletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get enterprise initialization status: %w", err)
	}
	return &status, nil
}

func stableSuffix(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:20]
}

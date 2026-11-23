package localidentity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresProvisioner struct {
	db                *pgxpool.Pool
	issuer            string
	nativeServiceOnly bool
	standaloneLocal   bool
}

var _ Provisioner = (*PostgresProvisioner)(nil)

// NewNativeServiceProvisioner has no SSO client and accepts only the sealed service role.
func NewNativeServiceProvisioner(db *pgxpool.Pool) (*PostgresProvisioner, error) {
	if db == nil {
		return nil, ErrInvalidConfig
	}
	return &PostgresProvisioner{db: db, nativeServiceOnly: true}, nil
}

// NewStandaloneProvisioner is selected only when the runtime is explicitly
// absent. Native-runtime failures never construct this provisioner.
func NewStandaloneProvisioner(db *pgxpool.Pool) (*PostgresProvisioner, error) {
	if db == nil {
		return nil, ErrInvalidConfig
	}
	return &PostgresProvisioner{db: db, issuer: "urn:jjdguard:local", standaloneLocal: true}, nil
}
func (p *PostgresProvisioner) Standalone() bool { return p.standaloneLocal }

func NewProvisioner(db *pgxpool.Pool, issuer string) (*PostgresProvisioner, error) {
	parsed, err := url.Parse(strings.TrimSpace(issuer))
	if db == nil || err != nil || parsed.Hostname() == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	return &PostgresProvisioner{db: db, issuer: strings.TrimSuffix(parsed.String(), "/")}, nil
}

func (p *PostgresProvisioner) Provision(ctx context.Context, in ProvisionInput) error {
	if p.nativeServiceOnly && (in.Role != "platform_connector" || in.AssignmentMode != "service") {
		return ErrInvalidInput
	}
	if strings.TrimSpace(in.ID) == "" || strings.TrimSpace(in.TenantID) == "" ||
		strings.TrimSpace(in.Username) == "" || strings.TrimSpace(in.PasswordHash) == "" ||
		strings.TrimSpace(in.Role) == "" || strings.TrimSpace(in.Status) == "" ||
		strings.TrimSpace(in.ActorID) == "" {
		return ErrInvalidInput
	}
	emergency := in.AssignmentMode == "emergency"
	service := in.AssignmentMode == "service"
	if service && (in.Role != "platform_connector" || in.Status != "active" || in.MustChangePassword) {
		return ErrInvalidInput
	}
	if p.standaloneLocal && !emergency && !service {
		if in.ExternalSubject != "" && in.ExternalSubject != in.ID {
			return ErrInvalidInput
		}
		in.ExternalSubject = in.ID
	}
	if emergency || service {
		if in.DepartmentID != "" || in.ExternalSubject != "" {
			return ErrInvalidInput
		}
	} else if strings.TrimSpace(in.DepartmentID) == "" ||
		strings.TrimSpace(in.ExternalSubject) == "" {
		return ErrInvalidInput
	}

	tx, err := p.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin local identity provision: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO users (
			id,tenant_id,username,email,phone,password_hash,must_change_password,
			role,status,department_id,department_assignment_mode,
			department_assignment_source,department_resolved_at
		) VALUES (
			$1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8,$9,NULLIF($10,''),
			$11,$12,NOW()
		)
	`, in.ID, in.TenantID, in.Username, in.Email, in.Phone, in.PasswordHash,
		in.MustChangePassword, in.Role, in.Status, in.DepartmentID,
		in.AssignmentMode, in.AssignmentSource)
	if err != nil {
		return fmt.Errorf("insert local identity user: %w", err)
	}

	if !emergency && !service {
		_, err = tx.Exec(ctx, `
			INSERT INTO user_identity_links (
				id,tenant_id,user_id,issuer,source_type,source_id,external_subject,local_runtime_managed
			) VALUES ($1,$2,$3,$4,'local','',$5,$6)
		`, uuid.NewString(), in.TenantID, in.ID, p.issuer, in.ExternalSubject, !p.standaloneLocal)
		if err != nil {
			return fmt.Errorf("bind local identity subject: %w", err)
		}
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO permission_grants (
			id,tenant_id,user_id,scope_type,scope_id,role,granted_by
		) VALUES ($1,$2,$3,'tenant',$2,$4,$5)
	`, "grant_"+uuid.NewString(), in.TenantID, in.ID, in.Role, in.ActorID)
	if err != nil {
		return fmt.Errorf("grant local identity role: %w", err)
	}
	owner := "native"
	if p.standaloneLocal {
		owner = "standalone"
	}
	detail, err := json.Marshal(map[string]string{
		"user_id": in.ID, "role": in.Role,
		"assignment_mode": in.AssignmentMode, "actor_id": in.ActorID, "credential_owner": owner,
	})
	if err != nil {
		return fmt.Errorf("encode local identity creation audit: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_operations (
			id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address
		) VALUES (
			$1,$2,(SELECT id FROM users WHERE tenant_id=$2::varchar AND id=$3::varchar),
			'user.create',$4::jsonb,'user',$5,''
		)
	`, uuid.NewString(), in.TenantID, in.ActorID, string(detail), in.ID); err != nil {
		return fmt.Errorf("record local identity creation audit: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO identity_cache_invalidation_outbox (
			id,tenant_id,user_id,old_department_id,new_department_id,status
		) VALUES ($1,$2,$3,'',$4,'pending')
	`, "identity-cache-"+uuid.NewString(), in.TenantID, in.ID, in.DepartmentID); err != nil {
		return fmt.Errorf("enqueue local identity creation invalidation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit local identity provision: %w", err)
	}
	return nil
}

func (p *PostgresProvisioner) Activate(ctx context.Context, tenantID, userID string) error {
	tag, err := p.db.Exec(ctx, `
		UPDATE users SET status='active',updated_at=NOW()
		WHERE tenant_id=$1 AND id=$2 AND status='provisioning'
	`, tenantID, userID)
	if err != nil {
		return fmt.Errorf("activate local identity user: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresProvisioner) BindEmergencyIdentityAndTransition(
	ctx context.Context,
	in EmergencyDemotionInput,
) error {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.UserID = strings.TrimSpace(in.UserID)
	in.ExternalSubject = strings.TrimSpace(in.ExternalSubject)
	in.Role = strings.TrimSpace(in.Role)
	in.DepartmentID = strings.TrimSpace(in.DepartmentID)
	in.ActorID = strings.TrimSpace(in.ActorID)
	if in.TenantID == "" || in.UserID == "" || in.ExternalSubject == "" ||
		in.PasswordHash == "" || in.DepartmentID == "" || in.ActorID == "" {
		return ErrInvalidInput
	}
	switch in.Role {
	case "tenant_admin", "dept_manager", "developer", "viewer":
	default:
		return ErrInvalidInput
	}

	tx, err := p.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin emergency identity demotion: %w", err)
	}
	defer tx.Rollback(ctx)

	var oldDepartmentID, oldRole, oldMode string
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(department_id,''),role,department_assignment_mode
		FROM users
		WHERE tenant_id=$1 AND id=$2
		FOR UPDATE
	`, in.TenantID, in.UserID).Scan(&oldDepartmentID, &oldRole, &oldMode)
	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock emergency identity user: %w", err)
	}
	if oldRole != "platform_admin" || oldMode != "emergency" {
		return ErrConflict
	}

	var departmentExists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM teams
			WHERE tenant_id=$1 AND id=$2 AND COALESCE(is_system,FALSE)=FALSE
		)
	`, in.TenantID, in.DepartmentID).Scan(&departmentExists); err != nil {
		return fmt.Errorf("validate emergency demotion department: %w", err)
	}
	if !departmentExists {
		return ErrNotFound
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO user_identity_links (
			id,tenant_id,user_id,issuer,source_type,source_id,external_subject,local_runtime_managed
		) VALUES ($1,$2,$3,$4,'local','',$5,$6)
	`, uuid.NewString(), in.TenantID, in.UserID, p.issuer, in.ExternalSubject, !p.standaloneLocal); err != nil {
		return fmt.Errorf("bind emergency local identity subject: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET password_hash=$3,must_change_password=TRUE,local_credential_version=local_credential_version+1,
		    role=$4,department_id=$5,
		    department_assignment_mode='manual',
		    department_assignment_source='admin',
		    department_assignment_rule_id=NULL,
		    department_resolved_at=NOW(),updated_at=NOW()
		WHERE tenant_id=$1 AND id=$2
	`, in.TenantID, in.UserID, in.PasswordHash, in.Role, in.DepartmentID); err != nil {
		return fmt.Errorf("transition emergency local identity user: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM permission_grants
		WHERE tenant_id=$1 AND user_id=$2 AND scope_type='tenant' AND scope_id=$1
	`, in.TenantID, in.UserID); err != nil {
		return fmt.Errorf("delete emergency tenant grants: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO permission_grants (
			id,tenant_id,user_id,scope_type,scope_id,role,granted_by
		) VALUES ($1,$2,$3,'tenant',$2,$4,$5)
	`, "grant_"+uuid.NewString(), in.TenantID, in.UserID, in.Role, in.ActorID); err != nil {
		return fmt.Errorf("create emergency demotion tenant grant: %w", err)
	}

	owner := "native"
	if p.standaloneLocal {
		owner = "standalone"
	}
	detail, err := json.Marshal(map[string]string{
		"user_id": in.UserID, "old_department_id": oldDepartmentID,
		"new_department_id": in.DepartmentID, "old_role": oldRole,
		"new_role": in.Role, "source_id": "admin", "rule_id": "", "actor_id": in.ActorID, "credential_owner": owner,
	})
	if err != nil {
		return fmt.Errorf("encode emergency demotion audit: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_operations (
			id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address
		) VALUES (
			$1,$2::varchar,
			(SELECT id FROM users WHERE tenant_id=$2::varchar AND id=$3::varchar),
			'identity.department.changed',$4::jsonb,'user',$5,''
		)
	`, uuid.NewString(), in.TenantID, in.ActorID, string(detail), in.UserID); err != nil {
		return fmt.Errorf("record emergency demotion audit: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO identity_cache_invalidation_outbox (
			id,tenant_id,user_id,old_department_id,new_department_id,status
		) VALUES ($1,$2,$3,$4,$5,'pending')
	`, "identity-cache-"+uuid.NewString(), in.TenantID, in.UserID, oldDepartmentID, in.DepartmentID); err != nil {
		return fmt.Errorf("enqueue emergency demotion invalidation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit emergency identity demotion: %w", err)
	}
	return nil
}

func (p *PostgresProvisioner) TransitionStatus(ctx context.Context, in StatusTransitionInput) error {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.UserID = strings.TrimSpace(in.UserID)
	in.Status = strings.TrimSpace(in.Status)
	in.ActorID = strings.TrimSpace(in.ActorID)
	if in.TenantID == "" || in.UserID == "" || in.ActorID == "" ||
		(in.Status != "active" && in.Status != "disabled") {
		return ErrInvalidInput
	}

	tx, err := p.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin local identity status transition: %w", err)
	}
	defer tx.Rollback(ctx)

	var oldStatus, departmentID string
	err = tx.QueryRow(ctx, `
		SELECT status,COALESCE(department_id,'')
		FROM users
		WHERE tenant_id=$1 AND id=$2
		FOR UPDATE
	`, in.TenantID, in.UserID).Scan(&oldStatus, &departmentID)
	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock local identity status user: %w", err)
	}
	if oldStatus == "reconciliation_required" {
		return ErrReconciliationRequired
	}
	if oldStatus == in.Status {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET status=$3::varchar,local_credential_version=local_credential_version+CASE WHEN $3::varchar='disabled' THEN 1 ELSE 0 END,updated_at=NOW()
		WHERE tenant_id=$1 AND id=$2
	`, in.TenantID, in.UserID, in.Status); err != nil {
		return fmt.Errorf("update local identity status: %w", err)
	}
	detail, err := json.Marshal(map[string]string{
		"user_id": in.UserID, "old_status": oldStatus,
		"new_status": in.Status, "actor_id": in.ActorID,
	})
	if err != nil {
		return fmt.Errorf("encode local identity status audit: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_operations (
			id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address
		) VALUES (
			$1,$2,(SELECT id FROM users WHERE tenant_id=$2::varchar AND id=$3::varchar),
			'user.status.update',$4::jsonb,'user',$5,''
		)
	`, uuid.NewString(), in.TenantID, in.ActorID, string(detail), in.UserID); err != nil {
		return fmt.Errorf("record local identity status audit: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO identity_cache_invalidation_outbox (
			id,tenant_id,user_id,old_department_id,new_department_id,status
		) VALUES ($1,$2,$3,$4,$4,'pending')
	`, "identity-cache-"+uuid.NewString(), in.TenantID, in.UserID, departmentID); err != nil {
		return fmt.Errorf("enqueue local identity status invalidation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit local identity status transition: %w", err)
	}
	return nil
}

// MarkReconciliationRequired 记录一条对账标记并写操作审计。
//
// audit_operations.user_id 是带外键的「执行人」列：执行人在库里查不到（或被操作的用户已被删除）时它会是 NULL，
// 这是预期。因此被操作用户、执行人和 subject 指纹的原值始终写进 action_detail，事后靠它们追溯；
// 用户行已删除时 UPDATE users 命中 0 行也不是错误。subject 本身绝不写入。
func (p *PostgresProvisioner) MarkReconciliationRequired(ctx context.Context, in ReconciliationInput) error {
	fingerprintBytes, fingerprintErr := hex.DecodeString(in.SubjectFingerprint)
	validSubjectReference := in.Provider == "keycloak" && fingerprintErr == nil && len(fingerprintBytes) == 32
	validAbsentSubject := in.Provider == "local" && in.SubjectFingerprint == ""
	if strings.TrimSpace(in.ID) == "" || strings.TrimSpace(in.TenantID) == "" ||
		strings.TrimSpace(in.UserID) == "" || strings.TrimSpace(in.ActorID) == "" ||
		(!validSubjectReference && !validAbsentSubject) ||
		!isSafeReconciliationToken(in.Reason) || !isSafeReconciliationToken(in.Operation) ||
		!isSafeReconciliationToken(in.Stage) || in.Source != "local" {
		return ErrInvalidInput
	}
	detail, err := json.Marshal(map[string]string{
		"user_id": in.UserID, "reason": in.Reason, "actor_id": in.ActorID,
		"subject_fingerprint": strings.ToLower(in.SubjectFingerprint),
		"operation":           in.Operation, "stage": in.Stage,
		"provider": in.Provider, "source": in.Source,
	})
	if err != nil {
		return fmt.Errorf("encode local identity reconciliation: %w", err)
	}
	tx, err := p.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin local identity reconciliation: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		UPDATE users SET status='reconciliation_required',updated_at=NOW()
		WHERE tenant_id=$1 AND id=$2 AND status<>'disabled'
	`, in.TenantID, in.UserID); err != nil {
		return fmt.Errorf("mark local identity user for reconciliation: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_operations (
			id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address
		) VALUES (
			$1,$2,
			(SELECT id FROM users WHERE tenant_id=$3 AND id=$4),
			'local_identity.reconciliation_required',$5::jsonb,'user',$6,''
		)
	`, in.ID, in.TenantID, in.TenantID, in.ActorID, string(detail), in.UserID); err != nil {
		return fmt.Errorf("record local identity reconciliation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit local identity reconciliation: %w", err)
	}
	return nil
}

func isSafeReconciliationToken(value string) bool {
	if len(value) == 0 || len(value) > 96 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') ||
			char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func (p *PostgresProvisioner) DeleteProvisioned(ctx context.Context, tenantID, userID string) error {
	tag, err := p.db.Exec(ctx, `
		DELETE FROM users
		WHERE tenant_id=$1 AND id=$2 AND status IN ('provisioning','reconciliation_required')
	`, tenantID, userID)
	if err != nil {
		return fmt.Errorf("delete provisioned local identity user: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresProvisioner) ExternalSubject(ctx context.Context, tenantID, userID string) (string, error) {
	var subject string
	err := p.db.QueryRow(ctx, `
		SELECT external_subject FROM user_identity_links
		WHERE tenant_id=$1 AND user_id=$2 AND issuer=$3 AND source_type='local'
	`, tenantID, userID, p.issuer).Scan(&subject)
	if err == pgx.ErrNoRows {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get local identity subject: %w", err)
	}
	return subject, nil
}

func (p *PostgresProvisioner) UpdatePasswordHash(
	ctx context.Context,
	tenantID, userID, passwordHash string,
	mustChangePassword bool,
) error {
	if passwordHash == "" {
		return ErrInvalidInput
	}
	tag, err := p.db.Exec(ctx, `
		UPDATE users
		SET password_hash=$3,must_change_password=$4,local_credential_version=local_credential_version+1,updated_at=NOW()
		WHERE tenant_id=$1 AND id=$2
	`, tenantID, userID, passwordHash, mustChangePassword)
	if err != nil {
		return fmt.Errorf("update local identity password hash: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditDisposition struct {
	CaseSeenThrough *time.Time
	ID              string
	TenantID        string
	SubjectType     string
	SubjectID       string
	Status          string
	Note            string
	OperatorID      string
	OperatorName    string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type AuditDispositionRepository struct {
	db *pgxpool.Pool
}

func NewAuditDispositionRepository(db *pgxpool.Pool) *AuditDispositionRepository {
	return &AuditDispositionRepository{db: db}
}

func buildAuditDispositionSubjectAuthorizationQuery(subjectType string, scoped bool) (string, error) {
	scope := ""
	if scoped {
		scope = " AND project_id = ANY($3)"
	}
	switch subjectType {
	case "request":
		return "SELECT EXISTS (SELECT 1 FROM request_logs WHERE tenant_id = $1 AND request_id = $2" + scope + ")", nil
	case "security_event":
		return "SELECT EXISTS (SELECT 1 FROM security_events WHERE tenant_id = $1 AND id = $2" + scope + ")", nil
	case "tool_call":
		if !scoped {
			return "SELECT EXISTS (SELECT 1 FROM tool_call_logs WHERE tenant_id = $1 AND id = $2)", nil
		}
		return `SELECT EXISTS (
			SELECT 1 FROM tool_call_logs tcl
			LEFT JOIN request_logs rl ON rl.tenant_id = tcl.tenant_id AND rl.request_id = tcl.request_id
			WHERE tcl.tenant_id = $1 AND tcl.id = $2
			  AND COALESCE(NULLIF(tcl.application_id, ''), rl.project_id) = ANY($3)
		)`, nil
	case "session":
		if !scoped {
			return "SELECT EXISTS (SELECT 1 FROM content_logs cl WHERE cl.tenant_id = $1 AND cl.session_id = $2)", nil
		}
		return `SELECT
			EXISTS (
				SELECT 1 FROM content_logs cl
				JOIN request_logs rl ON rl.tenant_id = cl.tenant_id AND rl.id = cl.request_id
				WHERE cl.tenant_id = $1 AND cl.session_id = $2 AND rl.project_id = ANY($3)
			)
			AND NOT EXISTS (
				SELECT 1 FROM content_logs cl
				LEFT JOIN request_logs rl ON rl.tenant_id = cl.tenant_id AND rl.id = cl.request_id
				WHERE cl.tenant_id = $1 AND cl.session_id = $2
				  AND (rl.id IS NULL OR rl.project_id IS NULL OR NOT (rl.project_id = ANY($3)))
			)`, nil
	default:
		return "", fmt.Errorf("unsupported disposition subject type")
	}
}

func (r *AuditDispositionRepository) AuthorizeAuditDispositionSubject(ctx context.Context, tenantID, subjectType, subjectID string, projectIDs []string) (bool, error) {
	if subjectType == "alert_case" {
		materialized, err := r.prepareAlertCaseAuthorization(ctx, tenantID)
		if err != nil {
			return false, err
		}
		return authorizeAlertCaseSnapshotWith(ctx, r.db, tenantID, subjectID, projectIDs, nil, materialized)
	}
	return authorizeAuditDispositionSubject(ctx, r.db, tenantID, subjectType, subjectID, projectIDs)
}

// prepareAlertCaseAuthorization 在处置事务之外消化本租户的待重算队列，决定授权能否读物化的案件。
func (r *AuditDispositionRepository) prepareAlertCaseAuthorization(ctx context.Context, tenantID string) (bool, error) {
	if alertCaseStoreOff {
		return false, nil
	}
	useMeta, err := alertCaseReadMetadata(ctx, r.db)
	if err != nil {
		return false, err
	}
	return prepareAlertCaseReads(ctx, r.db, useMeta, tenantID, true)
}

func authorizeAuditDispositionSubject(ctx context.Context, db auditDispositionQueryRower, tenantID, subjectType, subjectID string, projectIDs []string) (bool, error) {
	if subjectType == "alert_case" {
		return authorizeAlertCase(ctx, db, tenantID, subjectID, projectIDs)
	}
	query, err := buildAuditDispositionSubjectAuthorizationQuery(subjectType, projectIDs != nil)
	if err != nil {
		return false, err
	}
	args := []interface{}{tenantID, subjectID}
	if projectIDs != nil {
		args = append(args, projectIDs)
	}
	var allowed bool
	if err := db.QueryRow(ctx, query, args...).Scan(&allowed); err != nil {
		return false, fmt.Errorf("authorize audit disposition subject: %w", err)
	}
	return allowed, nil
}

func buildAuditDispositionActionTargetAuthorizationQuery(subjectType, action string, scoped bool) (string, error) {
	scope := ""
	switch subjectType {
	case "request":
		if scoped {
			scope = " AND rl.project_id = ANY($4)"
		}
		return auditDispositionTargetQuery(`
			SELECT rl.tenant_id, rl.user_id AS subject_user_id, rl.client_id
			FROM request_logs rl
			WHERE rl.tenant_id = $1 AND rl.request_id = $2`+scope, action)
	case "security_event":
		if scoped {
			scope = " AND se.project_id = ANY($4)"
		}
		return auditDispositionTargetQuery(`
			SELECT se.tenant_id, COALESCE(se.user_id, rl.user_id) AS subject_user_id, rl.client_id
			FROM security_events se
			LEFT JOIN request_logs rl ON rl.tenant_id = se.tenant_id AND rl.request_id = se.request_id
			WHERE se.tenant_id = $1 AND se.id = $2`+scope, action)
	case "tool_call":
		if scoped {
			scope = " AND COALESCE(NULLIF(tcl.application_id, ''), rl.project_id) = ANY($4)"
		}
		return auditDispositionTargetQuery(`
			SELECT tcl.tenant_id, COALESCE(tcl.user_id, rl.user_id) AS subject_user_id, rl.client_id
			FROM tool_call_logs tcl
			LEFT JOIN request_logs rl ON rl.tenant_id = tcl.tenant_id AND rl.request_id = tcl.request_id
			WHERE tcl.tenant_id = $1 AND tcl.id = $2`+scope, action)
	case "session":
		if scoped {
			scope = " AND rl.project_id = ANY($4)"
		}
		return auditDispositionTargetQuery(`
			SELECT cl.tenant_id, COALESCE(cl.user_id, rl.user_id) AS subject_user_id, rl.client_id
			FROM content_logs cl
			JOIN request_logs rl ON rl.tenant_id = cl.tenant_id AND rl.id = cl.request_id
			WHERE cl.tenant_id = $1 AND cl.session_id = $2`+scope, action)
	default:
		return "", fmt.Errorf("unsupported disposition subject type")
	}
}

func auditDispositionTargetQuery(subjectEvidence, action string) (string, error) {
	targetPredicate := ""
	switch action {
	case "revoke_key":
		targetPredicate = "linked_key.id = $3"
	case "ban_user":
		targetPredicate = `target_user.id = $3
			AND (target_user.id = evidence.subject_user_id OR target_user.id = linked_key.user_id)`
	default:
		return "", fmt.Errorf("unsupported disposition action")
	}
	return `
		WITH subject_evidence AS (` + subjectEvidence + `)
		SELECT EXISTS (
			SELECT 1
			FROM subject_evidence evidence
			LEFT JOIN internal_keys linked_key
			  ON linked_key.tenant_id = evidence.tenant_id
			 AND (
			   linked_key.id = evidence.client_id
			   OR (LEFT(evidence.client_id, 7) = 'caller_' AND LEFT(linked_key.key_hash, 12) = SUBSTRING(evidence.client_id FROM 8))
			 )
			LEFT JOIN users target_user ON target_user.tenant_id = evidence.tenant_id AND target_user.id = $3
			WHERE evidence.tenant_id = $1 AND ` + targetPredicate + `
		)`, nil
}

func authorizeAuditDispositionActionTarget(
	ctx context.Context,
	db auditDispositionQueryRower,
	tenantID, subjectType, subjectID, action, target string,
	projectIDs []string,
) (bool, error) {
	query, err := buildAuditDispositionActionTargetAuthorizationQuery(subjectType, action, projectIDs != nil)
	if err != nil {
		return false, err
	}
	args := []interface{}{tenantID, subjectID, target}
	if projectIDs != nil {
		args = append(args, projectIDs)
	}
	var allowed bool
	if err := db.QueryRow(ctx, query, args...).Scan(&allowed); err != nil {
		return false, fmt.Errorf("authorize audit disposition action target: %w", err)
	}
	return allowed, nil
}

func (r *AuditDispositionRepository) Upsert(ctx context.Context, d *AuditDisposition) (*AuditDisposition, error) {
	out, err := upsertAuditDisposition(ctx, r.db, d)
	if err == nil {
		syncAlertCaseRefs(ctx, r.db, d.TenantID, alertCaseDispositionRefs(d.SubjectType, d.SubjectID, ""))
	}
	return out, err
}

type auditDispositionQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (r *AuditDispositionRepository) UpsertAuthorized(
	ctx context.Context,
	d *AuditDisposition,
	projectIDs []string,
	action, actionTarget string,
) (*AuditDisposition, error) {
	if d.SubjectType == "alert_case" && (d.CaseSeenThrough == nil || d.CaseSeenThrough.After(time.Now())) {
		return nil, fmt.Errorf("case review requires a non-future observed snapshot")
	}

	materializedCase := false
	if d.SubjectType == "alert_case" {
		var err error
		if materializedCase, err = r.prepareAlertCaseAuthorization(ctx, d.TenantID); err != nil {
			return nil, err
		}
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if d.SubjectType == "alert_case" {
		if _, err = tx.Exec(ctx, "SET LOCAL jit=off"); err != nil {
			return nil, err
		}
	}

	var allowed bool
	if d.SubjectType == "alert_case" {
		allowed, err = authorizeAlertCaseSnapshotWith(ctx, tx, d.TenantID, d.SubjectID, projectIDs, d.CaseSeenThrough, materializedCase)
	} else {
		allowed, err = authorizeAuditDispositionSubject(ctx, tx, d.TenantID, d.SubjectType, d.SubjectID, projectIDs)
	}
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrNotFound
	}
	if action != "" {
		allowed, err = authorizeAuditDispositionActionTarget(
			ctx, tx, d.TenantID, d.SubjectType, d.SubjectID, action, actionTarget, projectIDs,
		)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrNotFound
		}
	}

	groupID := ""
	if d.SubjectType == "security_event" {
		err = tx.QueryRow(ctx, `SELECT COALESCE(alert_group_id,'') FROM security_events WHERE tenant_id=$1 AND id=$2 FOR SHARE`, d.TenantID, d.SubjectID).Scan(&groupID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
	}
	out, err := upsertAuditDisposition(ctx, tx, d)
	if err != nil {
		return nil, err
	}
	if d.SubjectType == "security_event" {
		if err := updateLinkedAlertGroupDisposition(ctx, tx, d, groupID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	syncAlertCaseRefs(ctx, r.db, d.TenantID, alertCaseDispositionRefs(d.SubjectType, d.SubjectID, groupID))
	return out, nil
}

// alertCaseDispositionRefs 是一次处置会登记的物化条目：处置对象本身，以及跟着改了状态的告警组。
func alertCaseDispositionRefs(subjectType, subjectID, groupID string) map[string][]string {
	refs := map[string][]string{}
	switch subjectType {
	case "security_event":
		refs["event"] = []string{subjectID}
	case "request":
		refs["request"] = []string{subjectID}
	case "alert_case":
		refs["case"] = []string{subjectID}
	}
	if groupID != "" {
		refs["group"] = []string{groupID}
	}
	return refs
}

// UpsertLinked writes the event disposition and its linked group's reversible
// notification silence in one transaction. Event evidence is never modified.
func (r *AuditDispositionRepository) UpsertLinked(ctx context.Context, d *AuditDisposition) (*AuditDisposition, error) {
	if d.SubjectType != "security_event" {
		return r.Upsert(ctx, d)
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var groupID string
	err = tx.QueryRow(ctx, `SELECT COALESCE(alert_group_id,'') FROM security_events WHERE tenant_id=$1 AND id=$2 FOR SHARE`, d.TenantID, d.SubjectID).Scan(&groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out, err := upsertAuditDisposition(ctx, tx, d)
	if err != nil {
		return nil, err
	}
	// A legacy event may not yet have alert_group_id. Only a persisted
	// representative-event match in this tenant is accepted as fallback linkage.
	if err = updateLinkedAlertGroupDisposition(ctx, tx, d, groupID); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	syncAlertCaseRefs(ctx, r.db, d.TenantID, alertCaseDispositionRefs(d.SubjectType, d.SubjectID, groupID))
	return out, nil
}

func updateLinkedAlertGroupDisposition(ctx context.Context, tx pgx.Tx, d *AuditDisposition, groupID string) error {
	_, err := tx.Exec(ctx, `
	 UPDATE alert_groups ag SET
  status = CASE WHEN $3 = 'false_positive' THEN 'false_positive'
                WHEN $3 IN ('resolved','accepted') THEN 'resolved'
                WHEN EXISTS(SELECT 1 FROM alert_groups active WHERE active.tenant_id=ag.tenant_id AND active.group_key=ag.group_key AND active.id<>ag.id AND active.status IN ('open','acknowledged')) THEN 'resolved'
                ELSE 'open' END,
  false_positive_at = CASE WHEN $3='false_positive' THEN NOW() ELSE NULL END,
  closed_at = CASE WHEN $3='false_positive' OR $3 IN ('resolved','accepted') THEN NOW() ELSE NULL END,
  disposition_by = NULLIF($4,''), disposition_note = NULLIF($5,''), updated_at=NOW()
 WHERE ag.tenant_id=$1
 AND (ag.id=NULLIF($6,'') OR ($6='' AND ag.representative_event_id=$2))
	 AND ($3='false_positive' OR ag.status='false_positive')
	 `, d.TenantID, d.SubjectID, d.Status, d.OperatorID, d.Note, groupID)
	if err != nil {
		return fmt.Errorf("linked alert group disposition: %w", err)
	}
	return nil
}

func upsertAuditDisposition(ctx context.Context, db auditDispositionQueryRower, d *AuditDisposition) (*AuditDisposition, error) {
	query := `
		INSERT INTO audit_dispositions (
			tenant_id, subject_type, subject_id, status, note, operator_id, operator_name
		)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''))
		ON CONFLICT (tenant_id, subject_type, subject_id)
		DO UPDATE SET
			status = EXCLUDED.status,
			note = EXCLUDED.note,
			operator_id = EXCLUDED.operator_id,
			operator_name = EXCLUDED.operator_name,
			updated_at = NOW()
		RETURNING
			id, tenant_id, subject_type, subject_id, status,
			COALESCE(note, ''), COALESCE(operator_id, ''), COALESCE(operator_name, ''),
			created_at, updated_at
	`

	args := []interface{}{d.TenantID, d.SubjectType, d.SubjectID, d.Status, d.Note, d.OperatorID, d.OperatorName}
	if d.SubjectType == "alert_case" {
		query = strings.Replace(query, "status, note, operator_id, operator_name\n", "status, note, operator_id, operator_name, case_seen_through\n", 1)
		query = strings.Replace(query, "NULLIF($7, ''))", "NULLIF($7, ''), $8)", 1)
		query = strings.Replace(query, "updated_at = NOW()", "updated_at = NOW(), case_seen_through = EXCLUDED.case_seen_through", 1)
		args = append(args, d.CaseSeenThrough)
	}
	var out AuditDisposition
	err := db.QueryRow(ctx, query, args...).Scan(
		&out.ID,
		&out.TenantID,
		&out.SubjectType,
		&out.SubjectID,
		&out.Status,
		&out.Note,
		&out.OperatorID,
		&out.OperatorName,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert audit disposition: %w", err)
	}
	return &out, nil
}

func (r *AuditDispositionRepository) List(ctx context.Context, tenantID, subjectType, subjectID string, limit, offset int) ([]*AuditDisposition, int, error) {
	args := []interface{}{tenantID}
	where := []string{"tenant_id = $1"}
	if subjectType != "" {
		args = append(args, subjectType)
		where = append(where, fmt.Sprintf("subject_type = $%d", len(args)))
	}
	if subjectID != "" {
		args = append(args, subjectID)
		where = append(where, fmt.Sprintf("subject_id = $%d", len(args)))
	}

	query := `
		SELECT
			id, tenant_id, subject_type, subject_id, status,
			COALESCE(note, ''), COALESCE(operator_id, ''), COALESCE(operator_name, ''),
			created_at, updated_at
		FROM audit_dispositions
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY updated_at DESC
	`
	args = append(args, limit, offset)
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit dispositions: %w", err)
	}
	defer rows.Close()

	items := []*AuditDisposition{}
	for rows.Next() {
		var item AuditDisposition
		if err := rows.Scan(
			&item.ID,
			&item.TenantID,
			&item.SubjectType,
			&item.SubjectID,
			&item.Status,
			&item.Note,
			&item.OperatorID,
			&item.OperatorName,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		items = append(items, &item)
	}

	countArgs := args[:len(args)-2]
	countQuery := "SELECT COUNT(*) FROM audit_dispositions WHERE " + strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit dispositions: %w", err)
	}
	return items, total, nil
}

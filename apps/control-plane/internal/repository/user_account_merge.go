package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"sort"
	"time"
)

var (
	ErrAccountMergeWalletNotEmpty = errors.New("账号钱包余额或预留金额非零，暂不能合并，请先处理余额")
	ErrAccountMergeInactive       = errors.New("account merge user is inactive")
	ErrAccountMergeProjectMissing = errors.New("selected department has no default project")
	ErrAccountMergeForbidden      = errors.New("account merge is forbidden")
	ErrAccountMergeChoices        = errors.New("account merge requires explicit choices")
	ErrAccountMergeConflict       = errors.New("account merge preview changed")
	ErrAccountMergeUnavailable    = errors.New("account merge identity unavailable")
)

type AccountMergeInput struct {
	PreviewVersion string            `json:"preview_version"`
	Choices        map[string]string `json:"choices"`
}
type AccountMergeUser struct {
	ExternalSubject   string `json:"external_subject"`
	ID                string `json:"id"`
	Username          string `json:"username"`
	Role              string `json:"role"`
	Status            string `json:"status"`
	DepartmentID      string `json:"department_id"`
	DepartmentName    string `json:"department_name"`
	DepartmentVersion int64  `json:"department_version"`
	CredentialVersion int64  `json:"local_credential_version"`
	AssignmentMode    string `json:"department_assignment_mode"`
}
type AccountMergePreview struct {
	IdentityLinks       []mergeLink      `json:"identity_links"`
	SourceUserID        string           `json:"source_user_id"`
	TargetUserID        string           `json:"target_user_id"`
	Source              AccountMergeUser `json:"source"`
	Target              AccountMergeUser `json:"target"`
	Version             string           `json:"preview_version"`
	RequiredChoices     []string         `json:"required_choices"`
	SourceIdentityCount int              `json:"source_identity_count"`
	SourceKeyCount      int              `json:"source_key_count"`
	BillingHistory      string           `json:"billing_history"`
	SessionHistory      string           `json:"session_history"`
	Policies            []mergePolicy    `json:"personal_policies"`
	Grants              []mergeGrant     `json:"extra_grants"`
	Wallets             []mergeWallet    `json:"wallets"`
}
type mergePolicy struct {
	UserID  string   `json:"user_id"`
	Mode    string   `json:"mode"`
	Names   []string `json:"model_names"`
	Version int64    `json:"version"`
}
type mergeGrant struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	Model         string     `json:"model"`
	Expires       *time.Time `json:"expires_at"`
	Revoked       *time.Time `json:"revoked_at"`
	ExpiryAudited *time.Time `json:"expiry_audited_at"`
	Reason        string     `json:"reason"`
	CreatedBy     string     `json:"created_by"`
}
type mergeKey struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Status    string `json:"status"`
	ProjectID string `json:"project_id"`
}
type mergeEmployeeKey struct {
	UserID     string `json:"user_id"`
	KeyID      string `json:"key_id"`
	Generation int64  `json:"generation"`
}
type mergeWallet struct {
	UserID   string `json:"user_id"`
	Currency string `json:"currency"`
	Balance  int64  `json:"balance_micros"`
	Reserved int64  `json:"reserved_micros"`
}
type mergeLink struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	SourceType string `json:"source_type"`
	Subject    string `json:"external_subject"`
}
type mergeSnapshot struct {
	Source       AccountMergeUser   `json:"source"`
	Target       AccountMergeUser   `json:"target"`
	Policies     []mergePolicy      `json:"policies"`
	Grants       []mergeGrant       `json:"grants"`
	Keys         []mergeKey         `json:"keys"`
	EmployeeKeys []mergeEmployeeKey `json:"employee_keys"`
	Wallets      []mergeWallet      `json:"wallets"`
	Links        []mergeLink        `json:"links"`
}
type UserAccountMergeRepository struct{ db *pgxpool.Pool }

func NewUserAccountMergeRepository(db *pgxpool.Pool) *UserAccountMergeRepository {
	return &UserAccountMergeRepository{db: db}
}

func mergeSnapshotRead(ctx context.Context, db identityBindingDBTX, tenant, source, target, actor string) (mergeSnapshot, *AccountMergePreview, error) {
	var allowed bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.status='active' AND t.status='active' AND u.role IN ('platform_admin','tenant_admin'))`, tenant, actor).Scan(&allowed); err != nil {
		return mergeSnapshot{}, nil, err
	}
	if !allowed || actor == source || actor == target {
		return mergeSnapshot{}, nil, ErrAccountMergeForbidden
	}
	if source == target {
		return mergeSnapshot{}, nil, ErrAccountMergeUnavailable
	}
	var raw []byte
	err := db.QueryRow(ctx, `SELECT jsonb_build_object(
 'source',(SELECT to_jsonb(x) FROM (SELECT id,username,role,status,COALESCE(external_subject,'') external_subject,COALESCE(department_id,'') department_id,COALESCE((SELECT name FROM teams WHERE id=users.department_id AND tenant_id=$1),'') department_name,department_version,local_credential_version,department_assignment_mode FROM users WHERE tenant_id=$1 AND id=$2) x),
 'target',(SELECT to_jsonb(x) FROM (SELECT id,username,role,status,COALESCE(external_subject,'') external_subject,COALESCE(department_id,'') department_id,COALESCE((SELECT name FROM teams WHERE id=users.department_id AND tenant_id=$1),'') department_name,department_version,local_credential_version,department_assignment_mode FROM users WHERE tenant_id=$1 AND id=$3) x),
 'policies',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY user_id),'[]') FROM (SELECT user_id,mode,model_names,version FROM user_model_policies WHERE tenant_id=$1 AND user_id IN($2,$3)) x),
 'grants',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM (SELECT id,user_id,model,expires_at,revoked_at,expiry_audited_at,reason,created_by FROM user_model_extra_grants WHERE tenant_id=$1 AND user_id IN($2,$3)) x),
 'keys',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM (SELECT id,user_id,status,project_id FROM internal_keys WHERE tenant_id=$1 AND user_id IN($2,$3)) x),
 'employee_keys',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY user_id),'[]') FROM (SELECT user_id,key_id,generation FROM employee_api_keys WHERE tenant_id=$1 AND user_id IN($2,$3)) x),
 'wallets',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY user_id,currency),'[]') FROM (SELECT user_id,currency,balance_micros,reserved_micros FROM billing_wallets WHERE tenant_id=$1 AND user_id IN($2,$3)) x),
 'links',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM (SELECT id,user_id,source_type,external_subject FROM user_identity_links WHERE tenant_id=$1 AND user_id IN($2,$3)) x)
 )`, tenant, source, target).Scan(&raw)
	if err != nil {
		return mergeSnapshot{}, nil, err
	}
	var s mergeSnapshot
	if err = json.Unmarshal(raw, &s); err != nil {
		return s, nil, err
	}
	if s.Source.ID != source || s.Target.ID != target {
		return s, nil, ErrAccountMergeUnavailable
	}
	if s.Source.Status != "active" || s.Target.Status != "active" {
		return s, nil, ErrAccountMergeInactive
	}
	if !roles.CanLoginPortal(s.Source.Role) || !roles.CanLoginPortal(s.Target.Role) {
		return s, nil, ErrAccountMergeUnavailable
	}
	if s.Source.AssignmentMode == "emergency" || s.Source.AssignmentMode == "service" || s.Target.AssignmentMode == "emergency" || s.Target.AssignmentMode == "service" {
		return s, nil, ErrAccountMergeForbidden
	}
	var actorRole string
	if err = db.QueryRow(ctx, "SELECT role FROM users WHERE tenant_id=$1 AND id=$2", tenant, actor).Scan(&actorRole); err != nil {
		return s, nil, err
	}
	if actorRole == "tenant_admin" {
		ordinary := func(role string) bool {
			return role == roles.ChatUser || role == roles.Developer || role == roles.Viewer
		}
		if !ordinary(s.Source.Role) || !ordinary(s.Target.Role) {
			return s, nil, ErrAccountMergeForbidden
		}
	}
	stable := s
	stable.Wallets = append([]mergeWallet(nil), s.Wallets...)
	for i := range stable.Wallets {
		stable.Wallets[i].Balance = 0
		stable.Wallets[i].Reserved = 0
	}
	hashBytes, err := json.Marshal(stable)
	if err != nil {
		return s, nil, err
	}
	sum := sha256.Sum256(hashBytes)
	p := &AccountMergePreview{SourceUserID: source, TargetUserID: target, Source: s.Source, Target: s.Target, Version: hex.EncodeToString(sum[:]), RequiredChoices: []string{}, BillingHistory: "只追加历史归属标注，不改写账本、已结算金额或自动转移余额", SessionHistory: "历史归属追加到目标账号；源账号所有旧登录在停用后失效"}
	for _, link := range s.Links {
		if link.UserID == source {
			p.IdentityLinks = append(p.IdentityLinks, link)
		}
	}
	p.Policies = s.Policies
	p.Grants = s.Grants
	p.Wallets = s.Wallets
	if s.Source.DepartmentID != s.Target.DepartmentID {
		p.RequiredChoices = append(p.RequiredChoices, "department")
	}
	policies := map[string]mergePolicy{source: {Mode: "inherit", Names: []string{}}, target: {Mode: "inherit", Names: []string{}}}
	for _, v := range s.Policies {
		policies[v.UserID] = v
	}
	a, b := policies[source], policies[target]
	a.UserID = ""
	b.UserID = ""
	a.Version = 0
	b.Version = 0
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) != string(bj) {
		p.RequiredChoices = append(p.RequiredChoices, "personal_policy")
	}
	sg, tg := map[string]bool{}, map[string]bool{}
	for _, g := range s.Grants {
		if g.Revoked == nil && (g.Expires == nil || g.Expires.After(time.Now())) {
			if g.UserID == source {
				sg[g.Model] = true
			} else {
				tg[g.Model] = true
			}
		}
	}
	if len(sg) > 0 {
		p.RequiredChoices = append(p.RequiredChoices, "extra_grants")
	}
	for model := range sg {
		if tg[model] {
			p.RequiredChoices = append(p.RequiredChoices, "extra:"+model)
		}
	}
	for _, k := range s.Keys {
		if k.UserID == source && k.Status == "active" {
			p.SourceKeyCount++
		}
	}
	if p.SourceKeyCount > 0 {
		p.RequiredChoices = append(p.RequiredChoices, "api_keys")
	}
	for _, k := range s.EmployeeKeys {
		if k.UserID == source {
			p.RequiredChoices = append(p.RequiredChoices, "employee_key")
		}
	}
	walletChoice := false
	for _, w := range s.Wallets {
		if w.UserID == source && (w.Balance != 0 || w.Reserved != 0) {
			walletChoice = true
		}
	}
	if walletChoice {
		p.RequiredChoices = append(p.RequiredChoices, "wallet_balance")
	}
	for _, link := range s.Links {
		if link.UserID == source {
			p.SourceIdentityCount++
		}
	}
	sort.Strings(p.RequiredChoices)
	return s, p, nil
}

func (r *UserAccountMergeRepository) Preview(ctx context.Context, tenant, source, target, actor string) (*AccountMergePreview, error) {
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	_, p, err := mergeSnapshotRead(ctx, tx, tenant, source, target, actor)
	if err != nil {
		return nil, err
	}
	return p, commitWithOperationAudit(ctx, tx)
}

func mergeChoicesValid(p *AccountMergePreview, in AccountMergeInput) bool {
	for _, field := range p.RequiredChoices {
		choice := in.Choices[field]
		valid := choice == "source" || choice == "target"
		switch field {
		case "extra_grants":
			valid = valid || choice == "union"
		case "api_keys":
			valid = choice == "revoke_source" || choice == "move_source"
		case "employee_key":
			valid = valid || choice == "revoke_both"
		case "wallet_balance":
			valid = choice == "retain_read_only"
		}
		if !valid {
			return false
		}
	}
	for field, choice := range in.Choices {
		if choice == "" {
			return false
		}
		found := false
		for _, required := range p.RequiredChoices {
			if field == required {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (r *UserAccountMergeRepository) mergeOnce(ctx context.Context, tenant, source, target, actor string, in AccountMergeInput) (*AccountMergePreview, error) {
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id FROM users WHERE tenant_id=$1 AND id IN($2,$3) ORDER BY id FOR UPDATE`, tenant, source, target)
	if err != nil {
		return nil, err
	}
	rows.Close()
	s, p, err := mergeSnapshotRead(ctx, tx, tenant, source, target, actor)
	if err != nil {
		return nil, err
	}
	for _, wallet := range s.Wallets {
		if wallet.Balance != 0 || wallet.Reserved != 0 {
			return nil, ErrAccountMergeWalletNotEmpty
		}
	}
	if p.Version != in.PreviewVersion {
		return nil, ErrAccountMergeConflict
	}
	if !mergeChoicesValid(p, in) {
		return nil, ErrAccountMergeChoices
	}
	department := s.Target.DepartmentID
	if in.Choices["department"] == "source" {
		department = s.Source.DepartmentID
	}
	if in.Choices["department"] == "source" {
		if _, err = tx.Exec(ctx, `UPDATE users SET department_id=NULLIF($3,''),department_assignment_mode='manual',department_assignment_source='admin',department_assignment_rule_id=NULL,department_resolved_at=now(),updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, target, department); err != nil {
			return nil, err
		}
	}
	if department != s.Target.DepartmentID {
		itx := &identityBindingTx{tx: tx}
		if err = itx.RecordDepartmentChange(ctx, identitybinding.DepartmentChangeEvent{EventID: "identity-cache-" + uuid.NewString(), TenantID: tenant, UserID: target, OldDepartmentID: s.Target.DepartmentID, NewDepartmentID: department, SourceID: "admin", ActorID: actor}); err != nil {
			return nil, err
		}
	}

	if in.Choices["personal_policy"] == "source" {
		mode, names := "inherit", []string{}
		for _, v := range s.Policies {
			if v.UserID == source {
				mode = v.Mode
				names = v.Names
			}
		}
		raw, _ := json.Marshal(names)
		if _, err = tx.Exec(ctx, `INSERT INTO user_model_policies(tenant_id,user_id,mode,model_names,updated_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,user_id) DO UPDATE SET mode=EXCLUDED.mode,model_names=EXCLUDED.model_names,updated_by=EXCLUDED.updated_by,updated_at=now(),version=user_model_policies.version+1`, tenant, target, mode, raw, actor); err != nil {
			return nil, err
		}
	}

	// Expired rows may still occupy the current-grant unique index until the
	// periodic audit sweep. Close and audit them in this same transaction.
	now := time.Now()
	for _, g := range s.Grants {
		if g.Revoked == nil && g.Expires != nil && !g.Expires.After(now) && g.ExpiryAudited == nil {
			if _, err = tx.Exec(ctx, "UPDATE user_model_extra_grants SET expiry_audited_at=now() WHERE tenant_id=$1 AND id=$2", tenant, g.ID); err != nil {
				return nil, err
			}
			if err = auditUserModelChange(ctx, tx, tenant, g.UserID, actor, "user.model_extra.expired", map[string]any{"grant_id": g.ID, "model": g.Model, "reason": "account_merge"}); err != nil {
				return nil, err
			}
		}
	}
	sourceGrants, targetGrants := map[string]mergeGrant{}, map[string]mergeGrant{}
	for _, g := range s.Grants {
		if g.Revoked != nil || (g.Expires != nil && !g.Expires.After(now)) {
			continue
		}
		if g.UserID == source {
			sourceGrants[g.Model] = g
		} else {
			targetGrants[g.Model] = g
		}
	}
	revokeGrant := func(g mergeGrant) error {
		if _, err := tx.Exec(ctx, "UPDATE user_model_extra_grants SET revoked_at=now(),revoked_by=$3 WHERE tenant_id=$1 AND id=$2", tenant, g.ID, actor); err != nil {
			return err
		}
		return auditUserModelChange(ctx, tx, tenant, g.UserID, actor, "user.model_extra.revoked", map[string]any{"grant_id": g.ID, "model": g.Model, "reason": "account_merge"})
	}
	extraChoice := in.Choices["extra_grants"]
	// Per-model decisions override the overall selection for duplicate models.
	for model, g := range targetGrants {
		_, duplicate := sourceGrants[model]
		drop := extraChoice == "source"
		if duplicate {
			drop = in.Choices["extra:"+model] == "source"
		}
		if drop {
			if err = revokeGrant(g); err != nil {
				return nil, err
			}
		}
	}
	for model, g := range sourceGrants {
		_, duplicate := targetGrants[model]
		keep := extraChoice == "source" || extraChoice == "union"
		if duplicate {
			keep = in.Choices["extra:"+model] == "source"
		}
		if !keep {
			if err = revokeGrant(g); err != nil {
				return nil, err
			}
			continue
		}
		if _, err = tx.Exec(ctx, "UPDATE user_model_extra_grants SET user_id=$3 WHERE tenant_id=$1 AND id=$2", tenant, g.ID, target); err != nil {
			return nil, err
		}
		if err = auditUserModelChange(ctx, tx, tenant, target, actor, "user.model_extra.transferred", map[string]any{"grant_id": g.ID, "model": g.Model, "source_user_id": source, "reason": g.Reason}); err != nil {
			return nil, err
		}
	}
	employeeChoice := in.Choices["employee_key"]
	var sourceEmployee, targetEmployee string
	for _, k := range s.EmployeeKeys {
		if k.UserID == source {
			sourceEmployee = k.KeyID
		} else {
			targetEmployee = k.KeyID
		}
	}
	retainedEmployee := targetEmployee
	if employeeChoice == "source" {
		retainedEmployee = sourceEmployee
	}
	if employeeChoice == "revoke_both" {
		retainedEmployee = ""
	}
	// Decide employee Keys independently of the personal-Key selection.
	movedKeys := []string{}
	for _, k := range s.Keys {
		employee := k.ID == sourceEmployee || k.ID == targetEmployee
		move := k.UserID == source && ((employee && k.ID == retainedEmployee) || (!employee && in.Choices["api_keys"] == "move_source" && k.Status == "active"))
		revoke := (employee && k.ID != retainedEmployee) || (k.UserID == source && !move)
		if revoke {
			if _, err = tx.Exec(ctx, "UPDATE internal_keys SET status='revoked' WHERE tenant_id=$1 AND id=$2 AND status<>'revoked'", tenant, k.ID); err != nil {
				return nil, err
			}
			if k.Status != "revoked" {
				if err = auditUserModelChange(ctx, tx, tenant, k.UserID, actor, "user.api_key.revoked", map[string]any{"key_id": k.ID, "reason": "account_merge"}); err != nil {
					return nil, err
				}
			}
		} else if move {
			movedKeys = append(movedKeys, k.ID)
			if _, err = tx.Exec(ctx, "UPDATE internal_keys SET user_id=$3 WHERE tenant_id=$1 AND id=$2", tenant, k.ID, target); err != nil {
				return nil, err
			}
		}
	}

	if retainedEmployee == "" {
		if _, err = tx.Exec(ctx, "DELETE FROM employee_api_keys WHERE tenant_id=$1 AND user_id=$2", tenant, target); err != nil {
			return nil, err
		}
	} else if retainedEmployee == sourceEmployee {
		if _, err = tx.Exec(ctx, "DELETE FROM employee_api_keys WHERE tenant_id=$1 AND user_id=$2", tenant, target); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, `UPDATE employee_api_keys m SET user_id=$3::varchar,issued_role=u.role,department_id=u.department_id,department_version=u.department_version,updated_at=now()
   FROM users u WHERE u.tenant_id=$1 AND u.id=$3::varchar AND m.tenant_id=$1 AND m.user_id=$2`, tenant, source, target); err != nil {
			return nil, err
		}
	} else {
		if _, err = tx.Exec(ctx, `UPDATE employee_api_keys m SET department_id=u.department_id,department_version=u.department_version,updated_at=now()
   FROM users u WHERE u.tenant_id=$1 AND u.id=$2 AND m.tenant_id=$1 AND m.user_id=$2`, tenant, target); err != nil {
			return nil, err
		}
	}
	if sourceEmployee != "" {
		if _, err = tx.Exec(ctx, "DELETE FROM employee_api_keys WHERE tenant_id=$1 AND user_id=$2", tenant, source); err != nil {
			return nil, err
		}
	}
	if len(movedKeys) > 0 {
		var project string
		err = tx.QueryRow(ctx, `SELECT p.id FROM projects p JOIN teams d ON d.tenant_id=p.tenant_id AND d.id=$2::varchar
    WHERE p.tenant_id=$1 AND p.status='active' AND (p.team_id=d.id OR
      (d.system_key='unassigned' AND EXISTS(SELECT 1 FROM teams fallback WHERE fallback.tenant_id=$1 AND fallback.id=p.team_id AND fallback.system_key='chat_default')
       AND NOT EXISTS(SELECT 1 FROM projects own WHERE own.tenant_id=$1 AND own.team_id=d.id AND own.status='active')))
    ORDER BY p.created_at,p.id LIMIT 1`, tenant, department).Scan(&project)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAccountMergeProjectMissing
		}
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO project_users(project_id,user_id,role) VALUES($1,$2,'developer') ON CONFLICT DO NOTHING", project, target); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, "UPDATE internal_keys SET project_id=$3 WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND id=ANY($4)", tenant, target, project, movedKeys); err != nil {
			return nil, err
		}
	}

	for _, table := range []string{"user_identity_links", "directory_user_links"} {
		if _, err = tx.Exec(ctx, `UPDATE `+table+` SET user_id=$3,updated_at=now() WHERE tenant_id=$1 AND user_id=$2`, tenant, source, target); err != nil {
			return nil, err
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM chat_login_tickets WHERE tenant_id=$1 AND user_id IN($2,$3)`, tenant, source, target); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET status='disabled',external_subject=NULL,local_credential_version=local_credential_version+1,updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, source); err != nil {
		return nil, err
	}
	savedChoices := map[string]string{}
	for k, v := range in.Choices {
		savedChoices[k] = v
	}
	savedChoices["source_external_subject"] = s.Source.ExternalSubject
	decisions, _ := json.Marshal(savedChoices)
	if _, err = tx.Exec(ctx, `INSERT INTO user_account_merges(tenant_id,source_user_id,target_user_id,merged_by,choices) VALUES($1,$2,$3,$4,$5)`, tenant, source, target, actor, decisions); err != nil {
		return nil, err
	}
	if err = auditUserModelChange(ctx, tx, tenant, target, actor, "user.account.merged", map[string]any{"source_user_id": source, "target_user_id": target, "choices": in.Choices, "billing_history": "attribution_only"}); err != nil {
		return nil, err
	}
	if err = commitWithOperationAudit(ctx, tx); err != nil {
		return nil, err
	}
	return p, nil
}

// HistoryUserIDs authorizes historic source rows through the committed merge
// annotation. It never rewrites their original identity, settled amount or hash.
func (r *UserAccountMergeRepository) HistoryUserIDs(ctx context.Context, tenant, target string) ([]string, error) {
	rows, err := r.db.Query(ctx, `WITH RECURSIVE owners(id) AS (SELECT id FROM users WHERE tenant_id=$1 AND id=$2 AND status='active' UNION SELECT m.source_user_id FROM user_account_merges m JOIN owners o ON m.target_user_id=o.id WHERE m.tenant_id=$1) SELECT id FROM owners ORDER BY id`, tenant, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (r *UserAccountMergeRepository) rebindOnce(ctx context.Context, tenant, source, target, actor, linkID, previewVersion string) error {
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id FROM users WHERE tenant_id=$1 AND id IN($2,$3) ORDER BY id FOR UPDATE`, tenant, source, target)
	if err != nil {
		return err
	}
	rows.Close()
	_, p, err := mergeSnapshotRead(ctx, tx, tenant, source, target, actor)
	if err != nil {
		return err
	}
	if previewVersion == "" || p.Version != previewVersion {
		return ErrAccountMergeConflict
	}

	var kind, sourceID, subject string
	err = tx.QueryRow(ctx, `UPDATE user_identity_links SET user_id=$4,updated_at=now() WHERE tenant_id=$1 AND user_id=$2 AND id=$3 RETURNING source_type,source_id,external_subject`, tenant, source, linkID, target).Scan(&kind, &sourceID, &subject)
	if err != nil {
		return err
	}
	if kind == "ldap" || kind == "ad" {
		if _, err = tx.Exec(ctx, `UPDATE directory_user_links SET user_id=$4,updated_at=now() WHERE tenant_id=$1 AND directory_source_id=$2 AND external_object_id=$3`, tenant, sourceID, subject, target); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET local_credential_version=local_credential_version+1,updated_at=now() WHERE tenant_id=$1 AND id IN($2,$3)`, tenant, source, target); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM chat_login_tickets WHERE tenant_id=$1 AND user_id IN($2,$3)`, tenant, source, target); err != nil {
		return err
	}
	if err = auditUserModelChange(ctx, tx, tenant, target, actor, "user.identity.rebound", map[string]any{"source_user_id": source, "target_user_id": target, "identity_link_id": linkID, "source_type": kind}); err != nil {
		return err
	}
	return commitWithOperationAudit(ctx, tx)
}

func (r *UserAccountMergeRepository) PossibleDuplicates(ctx context.Context, tenant string) (map[string][]string, error) {
	rows, err := r.db.Query(ctx, `WITH eligible AS (
 SELECT id,username,email FROM users u WHERE u.tenant_id=$1 AND u.status='active'
 AND NOT EXISTS(SELECT 1 FROM user_account_merges m WHERE m.tenant_id=$1 AND m.source_user_id=u.id)
 ), identities AS (
 SELECT id user_id,'username:'||lower(btrim(username)) identity FROM eligible WHERE btrim(username)<>''
 UNION ALL SELECT id,'email:'||lower(btrim(email)) FROM eligible WHERE btrim(COALESCE(email,''))<>''
 UNION ALL SELECT l.user_id,'subject:'||l.source_type||':'||l.issuer||':'||COALESCE(l.source_id,'')||':'||lower(btrim(l.external_subject))
 FROM user_identity_links l JOIN eligible e ON e.id=l.user_id WHERE l.tenant_id=$1 AND btrim(l.external_subject)<>''
 UNION ALL SELECT l.user_id,'directory:'||l.directory_source_id||':'||lower(btrim(l.external_object_id))
 FROM directory_user_links l JOIN eligible e ON e.id=l.user_id WHERE l.tenant_id=$1 AND btrim(l.external_object_id)<>''
 ) SELECT identity,array_agg(DISTINCT user_id ORDER BY user_id) FROM identities GROUP BY identity HAVING count(DISTINCT user_id)>1`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	peers := map[string]map[string]bool{}
	for rows.Next() {
		var identity string
		var users []string
		if err := rows.Scan(&identity, &users); err != nil {
			return nil, err
		}
		for _, id := range users {
			if peers[id] == nil {
				peers[id] = map[string]bool{}
			}
			for _, other := range users {
				if id != other {
					peers[id][other] = true
				}
			}
		}
	}
	result := map[string][]string{}
	for id, other := range peers {
		for peer := range other {
			result[id] = append(result[id], peer)
		}
		sort.Strings(result[id])
	}
	return result, rows.Err()
}

func retryAccountOperation[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	var value T
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		value, err = operation()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "40001" {
			return value, err
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return value, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 10 * time.Millisecond):
			}
		}
	}
	return value, err
}
func (r *UserAccountMergeRepository) Merge(ctx context.Context, tenant, source, target, actor string, in AccountMergeInput) (*AccountMergePreview, error) {
	return retryAccountOperation(ctx, func() (*AccountMergePreview, error) { return r.mergeOnce(ctx, tenant, source, target, actor, in) })
}
func (r *UserAccountMergeRepository) RebindIdentity(ctx context.Context, tenant, source, target, actor, linkID, version string) error {
	_, err := retryAccountOperation(ctx, func() (bool, error) {
		err := r.rebindOnce(ctx, tenant, source, target, actor, linkID, version)
		return err == nil, err
	})
	return err
}

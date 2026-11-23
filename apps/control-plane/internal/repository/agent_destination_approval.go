package repository

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/probereports"
)

// T07/T08: this is the server-side half of the approval basis contract.
// aiprobe declares approval_status/approval_basis/approval_rule_id per
// destination against its own local catalog (see docs/11-model-destination-approval.md
// and contracts/model-destination-approval.v1.schema.json), but the control
// plane must not simply trust that claim — a compromised or misconfigured
// endpoint could declare "approved" for anything. AgentDestinationApprovalRepository
// owns the tenant's actual catalog (admin-managed) and re-derives the real
// verdict for every reported destination, official and relay alike.
var (
	ErrDestinationApprovalRuleInvalid  = errors.New("invalid destination approval rule")
	ErrDestinationApprovalRuleNotFound = errors.New("destination approval rule not found")
	ErrDestinationApprovalRuleConflict = errors.New("destination approval rule already exists for this match")
)

type AgentDestinationApprovalRepository struct{ db *pgxpool.Pool }

func NewAgentDestinationApprovalRepository(db *pgxpool.Pool) *AgentDestinationApprovalRepository {
	return &AgentDestinationApprovalRepository{db: db}
}

type DestinationApprovalRule struct {
	ID          string     `json:"id"`
	RuleID      string     `json:"rule_id"`
	MatchType   string     `json:"match_type"`
	MatchValue  string     `json:"match_value"`
	Category    string     `json:"category"`
	Enabled     bool       `json:"enabled"`
	Description string     `json:"description"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty"`
	DisabledBy  string     `json:"disabled_by,omitempty"`
}

type DestinationApprovalRuleFilter struct {
	Enabled        *bool
	Category       string
	Page, PageSize int
}

type DestinationApprovalRulePage struct {
	Items []DestinationApprovalRule `json:"items"`
	AgentAdminPage
}

type DestinationApprovalRuleCreate struct {
	RuleID      string
	MatchType   string
	MatchValue  string
	Category    string
	Description string
	CreatedBy   string
}

func validDestinationApprovalRuleID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for i, r := range value {
		alnum := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if i == 0 {
			if !alnum {
				return false
			}
			continue
		}
		if !alnum && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// normalizeDestinationOrigin mirrors the probe contract's own normalization
// (docs/11-model-destination-approval.md): lowercase scheme/host, strip a
// default port for the scheme, drop a trailing slash. The path is never part
// of this value because probereports.Destination.Origin carries no path.
func normalizeDestinationOrigin(raw string) (scheme, host string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", "", false
	}
	scheme = strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		hostname = hostname + ":" + port
	}
	return scheme, hostname, true
}

func normalizedDestinationOriginString(raw string) (string, bool) {
	scheme, host, ok := normalizeDestinationOrigin(raw)
	if !ok {
		return "", false
	}
	return scheme + "://" + host, true
}

func validDestinationApprovalRuleCreate(input DestinationApprovalRuleCreate) bool {
	if !validDestinationApprovalRuleID(input.RuleID) {
		return false
	}
	if input.MatchType != "host" && input.MatchType != "base_url_prefix" {
		return false
	}
	if input.Category != "official" && input.Category != "relay" {
		return false
	}
	value := strings.TrimSpace(input.MatchValue)
	if value == "" || len(value) > 512 {
		return false
	}
	switch input.MatchType {
	case "host":
		// A bare hostname: reject anything that parses as a URL (scheme,
		// path, query) so "host" rules cannot smuggle in path/query scope.
		if strings.ContainsAny(value, "/ \t\r\n") || strings.Contains(value, "://") {
			return false
		}
	case "base_url_prefix":
		if _, ok := normalizedDestinationOriginString(value); !ok {
			return false
		}
	}
	if len(input.Description) > 1024 {
		return false
	}
	return true
}

func (r *AgentDestinationApprovalRepository) List(ctx context.Context, tenant string, f DestinationApprovalRuleFilter) (*DestinationApprovalRulePage, error) {
	clauses, args := []string{"tenant_id=$1"}, []any{tenant}
	if f.Enabled != nil {
		args = append(args, *f.Enabled)
		clauses = append(clauses, fmt.Sprintf("enabled=$%d", len(args)))
	}
	if f.Category != "" {
		if f.Category != "official" && f.Category != "relay" {
			return nil, ErrDestinationApprovalRuleInvalid
		}
		args = append(args, f.Category)
		clauses = append(clauses, fmt.Sprintf("category=$%d", len(args)))
	}
	where := " WHERE " + strings.Join(clauses, " AND ")
	page, size, offset := normalizeAgentPage(f.Page, f.PageSize)
	var total int
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM agent_destination_approval_rules"+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	queryArgs := append(append([]any{}, args...), size, offset)
	query := `SELECT id,rule_id,match_type,match_value,category,enabled,description,created_by,created_at,updated_at,disabled_at,disabled_by
		FROM agent_destination_approval_rules` + where +
		fmt.Sprintf(" ORDER BY created_at DESC,id LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	rows, err := r.db.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DestinationApprovalRule{}
	for rows.Next() {
		var item DestinationApprovalRule
		if err = rows.Scan(&item.ID, &item.RuleID, &item.MatchType, &item.MatchValue, &item.Category,
			&item.Enabled, &item.Description, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt,
			&item.DisabledAt, &item.DisabledBy); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return &DestinationApprovalRulePage{Items: items, AgentAdminPage: AgentAdminPage{Page: page, PageSize: size, Total: total}}, nil
}

func (r *AgentDestinationApprovalRepository) Create(ctx context.Context, tenant string, input DestinationApprovalRuleCreate) (*DestinationApprovalRule, error) {
	if !validDestinationApprovalRuleCreate(input) {
		return nil, ErrDestinationApprovalRuleInvalid
	}
	id := stableUnifiedAssetID("dar_", tenant, input.RuleID, fmt.Sprintf("%d", time.Now().UnixNano()))
	matchValue := strings.TrimSpace(input.MatchValue)
	if input.MatchType == "base_url_prefix" {
		normalized, _ := normalizedDestinationOriginString(matchValue)
		matchValue = normalized
	} else {
		matchValue = strings.ToLower(matchValue)
	}
	var created DestinationApprovalRule
	err := r.db.QueryRow(ctx, `INSERT INTO agent_destination_approval_rules
		(id,tenant_id,rule_id,match_type,match_value,category,enabled,description,created_by)
		VALUES($1,$2,$3,$4,$5,$6,true,$7,$8)
		RETURNING id,rule_id,match_type,match_value,category,enabled,description,created_by,created_at,updated_at,disabled_at,disabled_by`,
		id, tenant, input.RuleID, input.MatchType, matchValue, input.Category, strings.TrimSpace(input.Description), input.CreatedBy,
	).Scan(&created.ID, &created.RuleID, &created.MatchType, &created.MatchValue, &created.Category,
		&created.Enabled, &created.Description, &created.CreatedBy, &created.CreatedAt, &created.UpdatedAt,
		&created.DisabledAt, &created.DisabledBy)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDestinationApprovalRuleConflict
		}
		return nil, err
	}
	return &created, nil
}

// Deactivate disables a rule. It never deletes the row: history and prior
// observations that reference this rule id must stay intact and auditable.
func (r *AgentDestinationApprovalRepository) Deactivate(ctx context.Context, tenant, id, actor string) (bool, error) {
	tag, err := r.db.Exec(ctx, `UPDATE agent_destination_approval_rules
		SET enabled=false, disabled_at=now(), disabled_by=$3, updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND enabled`, tenant, id, actor)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() != 0 {
		return true, nil
	}
	var exists bool
	if err = r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_destination_approval_rules WHERE tenant_id=$1 AND id=$2)`, tenant, id).Scan(&exists); err != nil {
		return false, err
	}
	if !exists {
		return false, ErrDestinationApprovalRuleNotFound
	}
	// Already disabled: idempotent no-op, not an error.
	return true, nil
}

// DestinationApprovalVerification is the server's own verdict for one
// reported destination, kept separate from whatever the client declared.
type DestinationApprovalVerification struct {
	Status        string // approved | not_listed | unreviewed | invalid_claim
	MatchedRuleID string
	MatchedRowID  string
}

// destinationApprovalQueryer is satisfied by both *pgxpool.Pool and pgx.Tx,
// so verification can run standalone or inside an existing report-ingestion
// transaction with one code path — the two must never diverge.
type destinationApprovalQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (r *AgentDestinationApprovalRepository) VerifyDestinationApproval(ctx context.Context, tenant string, destination probereports.Destination) (DestinationApprovalVerification, error) {
	return verifyDestinationApprovalTx(ctx, r.db, tenant, destination)
}

// verifyDestinationApprovalTx re-derives approval for one destination against
// the tenant's own catalog. It never trusts probereports.Destination's
// ApprovalStatus/ApprovalBasis/ApprovalRuleID as truth — those are recorded
// separately as the client's claim. A forged, disabled, or non-matching
// rule_id must resolve to something other than approved; classification
// (official vs relay) never changes how this function decides.
func verifyDestinationApprovalTx(ctx context.Context, q destinationApprovalQueryer, tenant string, destination probereports.Destination) (DestinationApprovalVerification, error) {
	scheme, host, ok := normalizeDestinationOrigin(destination.Origin)
	if !ok {
		return DestinationApprovalVerification{Status: "invalid_claim"}, nil
	}
	hostOnly := host
	if idx := strings.IndexByte(hostOnly, ':'); idx >= 0 {
		hostOnly = hostOnly[:idx]
	}
	origin := scheme + "://" + host
	rows, err := q.Query(ctx, `SELECT id,rule_id,match_type,match_value FROM agent_destination_approval_rules
		WHERE tenant_id=$1 AND enabled AND (
			(match_type='host' AND match_value=$2) OR
			(match_type='base_url_prefix' AND match_value=$3)
		) ORDER BY match_type, id LIMIT 1`, tenant, hostOnly, origin)
	if err != nil {
		return DestinationApprovalVerification{}, err
	}
	defer rows.Close()
	if rows.Next() {
		var rowID, ruleID, matchType, matchValue string
		if err = rows.Scan(&rowID, &ruleID, &matchType, &matchValue); err != nil {
			return DestinationApprovalVerification{}, err
		}
		if err = rows.Err(); err != nil {
			return DestinationApprovalVerification{}, err
		}
		return DestinationApprovalVerification{Status: "approved", MatchedRuleID: ruleID, MatchedRowID: rowID}, nil
	}
	if err = rows.Err(); err != nil {
		return DestinationApprovalVerification{}, err
	}
	// A catalog exists for this tenant (it has at least one rule, active or
	// not) but nothing matched: not_listed. An empty catalog means no basis
	// was ever configured, matching the probe's own "unreviewed" semantics —
	// we must not manufacture a not_listed shadow finding out of an admin
	// simply never having populated the catalog yet.
	var hasCatalog bool
	if err = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_destination_approval_rules WHERE tenant_id=$1)`, tenant).Scan(&hasCatalog); err != nil {
		return DestinationApprovalVerification{}, err
	}
	if hasCatalog {
		return DestinationApprovalVerification{Status: "not_listed"}, nil
	}
	return DestinationApprovalVerification{Status: "unreviewed"}, nil
}

// AgentDestinationApprovalObservation is what gets persisted per destination
// on report acceptance: the client's claim and the server's independent
// verdict, kept in separate columns so neither can silently overwrite the
// other for audit/recheck purposes.
type AgentDestinationApprovalObservation struct {
	EndpointID             string
	ReportID               string
	AssetSourceID          string
	DestinationIndex       int
	Origin                 string
	Classification         string
	ClientClaimedStatus    string
	ClientClaimedBasis     string
	ClientClaimedRuleID    string
	ServerVerifiedStatus   string
	ServerVerifiedRuleID   string
	ServerMatchedRuleRowID *string
	ObservedAt             time.Time
}

func insertDestinationApprovalObservation(ctx context.Context, tx unifiedAssetExecTx, tenant string, obs AgentDestinationApprovalObservation) error {
	id := stableUnifiedAssetID("dao_", tenant, obs.ReportID, obs.AssetSourceID, fmt.Sprintf("%d", obs.DestinationIndex))
	_, err := tx.Exec(ctx, `INSERT INTO agent_destination_approval_observations(
		id,tenant_id,endpoint_id,report_id,asset_source_id,destination_index,origin,classification,
		client_claimed_status,client_claimed_basis,client_claimed_rule_id,
		server_verified_status,server_verified_rule_id,server_matched_rule_row_id,observed_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
	ON CONFLICT (tenant_id,report_id,asset_source_id,destination_index) DO NOTHING`,
		id, tenant, obs.EndpointID, obs.ReportID, obs.AssetSourceID, obs.DestinationIndex, obs.Origin, obs.Classification,
		obs.ClientClaimedStatus, obs.ClientClaimedBasis, obs.ClientClaimedRuleID,
		obs.ServerVerifiedStatus, obs.ServerVerifiedRuleID, obs.ServerMatchedRuleRowID, obs.ObservedAt)
	if err != nil {
		return fmt.Errorf("insert destination approval observation: %w", err)
	}
	return nil
}

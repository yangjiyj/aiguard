package billing

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	DefaultCustomerGroup     = "default"
	CustomerGroupActive      = "active"
	CustomerGroupDisabled    = "disabled"
	MaxCustomerGroupRatioPPM = 1_000_000_000
)

var (
	ErrCustomerGroupNotFound = errors.New("billing customer group not found")
	ErrInvalidCustomerGroup  = errors.New("invalid billing customer group")
	customerGroupCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

type CustomerGroup struct {
	ID          string
	TenantID    string
	Code        string
	Name        string
	Description string
	Status      string
	IsDefault   bool
	RatioPPM    int64
	MemberCount int64
	PriceCount  int64
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type NewCustomerGroup struct {
	TenantID    string
	Code        string
	Name        string
	Description string
	RatioPPM    int64
	CreatedBy   string
}

type CustomerGroupUpdate struct {
	Name        string
	Description string
	Status      string
	RatioPPM    int64
}

func normalizeCustomerGroupCode(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (s *Store) EnsureDefaultCustomerGroup(ctx context.Context, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ErrInvalidCustomerGroup
	}
	_, err := s.db.Exec(ctx, `
        INSERT INTO billing_customer_groups
            (id, tenant_id, code, name, description, status, is_default, ratio_ppm)
        VALUES ($1, $2, 'default', 'Default customer group', '', 'active', TRUE, 1000000)
        ON CONFLICT (tenant_id, code) DO UPDATE
        SET is_default = TRUE, status = 'active'
    `, "group_"+uuid.NewString(), tenantID)
	if err != nil {
		return fmt.Errorf("ensure default billing customer group: %w", err)
	}
	return nil
}

func (s *Store) ListCustomerGroups(ctx context.Context, tenantID string) ([]CustomerGroup, error) {
	if err := s.EnsureDefaultCustomerGroup(ctx, tenantID); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `
        SELECT g.id, g.tenant_id, g.code, g.name, g.description, g.status,
               g.is_default, g.ratio_ppm, COUNT(DISTINCT m.user_id), COUNT(DISTINCT p.id),
               COALESCE(g.created_by, ''), g.created_at, g.updated_at
        FROM billing_customer_groups g
        LEFT JOIN billing_customer_group_memberships m
          ON m.tenant_id = g.tenant_id AND m.customer_group = g.code
        LEFT JOIN billing_model_prices p
          ON p.tenant_id = g.tenant_id AND p.customer_group = g.code
        WHERE g.tenant_id = $1
        GROUP BY g.id
        ORDER BY g.is_default DESC, g.name ASC, g.code ASC
    `, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, fmt.Errorf("list billing customer groups: %w", err)
	}
	defer rows.Close()
	groups := make([]CustomerGroup, 0)
	for rows.Next() {
		var group CustomerGroup
		if err := rows.Scan(&group.ID, &group.TenantID, &group.Code, &group.Name,
			&group.Description, &group.Status, &group.IsDefault, &group.RatioPPM, &group.MemberCount,
			&group.PriceCount, &group.CreatedBy, &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan billing customer group: %w", err)
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func (s *Store) CreateCustomerGroup(ctx context.Context, input NewCustomerGroup) (*CustomerGroup, error) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.Code = normalizeCustomerGroupCode(input.Code)
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	input.CreatedBy = strings.TrimSpace(input.CreatedBy)
	if input.RatioPPM == 0 {
		input.RatioPPM = ratioScale
	}
	if input.TenantID == "" || !customerGroupCodePattern.MatchString(input.Code) ||
		input.Code == DefaultCustomerGroup || input.Name == "" || len([]rune(input.Name)) > 120 ||
		len([]rune(input.Description)) > 255 || input.RatioPPM < 0 || input.RatioPPM > MaxCustomerGroupRatioPPM {
		return nil, ErrInvalidCustomerGroup
	}
	if err := s.EnsureDefaultCustomerGroup(ctx, input.TenantID); err != nil {
		return nil, err
	}
	group := &CustomerGroup{
		ID: "group_" + uuid.NewString(), TenantID: input.TenantID, Code: input.Code,
		Name: input.Name, Description: input.Description, Status: CustomerGroupActive,
		RatioPPM: input.RatioPPM, CreatedBy: input.CreatedBy,
	}
	err := s.db.QueryRow(ctx, `
        INSERT INTO billing_customer_groups
            (id, tenant_id, code, name, description, status, is_default, ratio_ppm, created_by)
        VALUES ($1,$2,$3,$4,$5,'active',FALSE,$6,NULLIF($7,''))
        RETURNING created_at, updated_at
    `, group.ID, group.TenantID, group.Code, group.Name, group.Description, group.RatioPPM, group.CreatedBy).
		Scan(&group.CreatedAt, &group.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrInvalidCustomerGroup
		}
		return nil, fmt.Errorf("create billing customer group: %w", err)
	}
	return group, nil
}

func (s *Store) UpdateCustomerGroup(ctx context.Context, tenantID, groupID string, update CustomerGroupUpdate) (*CustomerGroup, error) {
	tenantID, groupID = strings.TrimSpace(tenantID), strings.TrimSpace(groupID)
	update.Name = strings.TrimSpace(update.Name)
	update.Description = strings.TrimSpace(update.Description)
	update.Status = strings.TrimSpace(update.Status)
	if tenantID == "" || groupID == "" || update.Name == "" || len([]rune(update.Name)) > 120 ||
		len([]rune(update.Description)) > 255 ||
		(update.Status != CustomerGroupActive && update.Status != CustomerGroupDisabled) ||
		update.RatioPPM < 0 || update.RatioPPM > MaxCustomerGroupRatioPPM {
		return nil, ErrInvalidCustomerGroup
	}
	group := &CustomerGroup{}
	err := s.db.QueryRow(ctx, `
        UPDATE billing_customer_groups
        SET name=$1, description=$2,
            status=CASE WHEN is_default THEN 'active' ELSE $3 END,
            ratio_ppm=CASE WHEN $4=0 THEN ratio_ppm ELSE $4 END,
            updated_at=NOW()
        WHERE tenant_id=$5 AND id=$6
        RETURNING id, tenant_id, code, name, description, status, is_default,
                  ratio_ppm, COALESCE(created_by, ''), created_at, updated_at
    `, update.Name, update.Description, update.Status, update.RatioPPM, tenantID, groupID).Scan(
		&group.ID, &group.TenantID, &group.Code, &group.Name, &group.Description,
		&group.Status, &group.IsDefault, &group.RatioPPM, &group.CreatedBy, &group.CreatedAt, &group.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCustomerGroupNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update billing customer group: %w", err)
	}
	return group, nil
}

func (s *Store) AssignCustomerGroup(ctx context.Context, tenantID, userID, groupCode, actorID string) (*CustomerGroup, error) {
	tenantID, userID = strings.TrimSpace(tenantID), strings.TrimSpace(userID)
	groupCode, actorID = normalizeCustomerGroupCode(groupCode), strings.TrimSpace(actorID)
	if tenantID == "" || userID == "" || !customerGroupCodePattern.MatchString(groupCode) {
		return nil, ErrInvalidCustomerGroup
	}
	if err := s.EnsureDefaultCustomerGroup(ctx, tenantID); err != nil {
		return nil, err
	}
	group := &CustomerGroup{}
	err := s.db.QueryRow(ctx, `
        SELECT id, tenant_id, code, name, description, status, is_default,
               ratio_ppm, COALESCE(created_by, ''), created_at, updated_at
        FROM billing_customer_groups
        WHERE tenant_id=$1 AND code=$2 AND status='active'
    `, tenantID, groupCode).Scan(&group.ID, &group.TenantID, &group.Code, &group.Name,
		&group.Description, &group.Status, &group.IsDefault, &group.RatioPPM, &group.CreatedBy,
		&group.CreatedAt, &group.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCustomerGroupNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolve assignable billing customer group: %w", err)
	}
	result, err := s.db.Exec(ctx, `
        INSERT INTO billing_customer_group_memberships
            (tenant_id, user_id, customer_group, updated_by)
        VALUES ($1,$2,$3,NULLIF($4,''))
        ON CONFLICT (tenant_id, user_id) DO UPDATE
        SET customer_group=EXCLUDED.customer_group,
            updated_by=EXCLUDED.updated_by, updated_at=NOW()
    `, tenantID, userID, groupCode, actorID)
	if err != nil {
		return nil, fmt.Errorf("assign billing customer group: %w", err)
	}
	if result.RowsAffected() != 1 {
		return nil, ErrInvalidCustomerGroup
	}
	return group, nil
}

// ResolveCustomerGroupDetails returns the active group and its current billing
// ratio. A missing or disabled assignment safely falls back to the default.
func (s *Store) ResolveCustomerGroupDetails(ctx context.Context, tenantID, userID string) (*CustomerGroup, error) {
	tenantID, userID = strings.TrimSpace(tenantID), strings.TrimSpace(userID)
	if tenantID == "" || userID == "" {
		return nil, ErrInvalidCustomerGroup
	}
	if err := s.EnsureDefaultCustomerGroup(ctx, tenantID); err != nil {
		return nil, err
	}
	group := &CustomerGroup{}
	err := s.db.QueryRow(ctx, `
        SELECT g.id, g.tenant_id, g.code, g.name, g.description, g.status,
               g.is_default, g.ratio_ppm, COALESCE(g.created_by, ''), g.created_at, g.updated_at
        FROM billing_customer_groups g
        WHERE g.tenant_id=$1 AND g.code=COALESCE(
            (SELECT g.code
             FROM billing_customer_group_memberships m
             JOIN billing_customer_groups g
               ON g.tenant_id=m.tenant_id AND g.code=m.customer_group
             WHERE m.tenant_id=$1 AND m.user_id=$2 AND g.status='active'),
            (SELECT g.code FROM billing_customer_groups g
             WHERE g.tenant_id=$1 AND g.is_default AND g.status='active'
             LIMIT 1),
            'default'
        )
        LIMIT 1
    `, tenantID, userID).Scan(
		&group.ID, &group.TenantID, &group.Code, &group.Name, &group.Description,
		&group.Status, &group.IsDefault, &group.RatioPPM, &group.CreatedBy,
		&group.CreatedAt, &group.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve billing customer group: %w", err)
	}
	return group, nil
}

// ResolveCustomerGroup is retained for callers that only need the code.
func (s *Store) ResolveCustomerGroup(ctx context.Context, tenantID, userID string) (string, error) {
	group, err := s.ResolveCustomerGroupDetails(ctx, tenantID, userID)
	if err != nil {
		return "", err
	}
	return group.Code, nil
}

func (s *Store) CustomerGroupIsActive(ctx context.Context, tenantID, groupCode string) (bool, error) {
	if err := s.EnsureDefaultCustomerGroup(ctx, tenantID); err != nil {
		return false, err
	}
	var active bool
	err := s.db.QueryRow(ctx, `
        SELECT EXISTS(
            SELECT 1 FROM billing_customer_groups
            WHERE tenant_id=$1 AND code=$2 AND status='active'
        )
    `, strings.TrimSpace(tenantID), normalizeCustomerGroupCode(groupCode)).Scan(&active)
	if err != nil {
		return false, fmt.Errorf("validate billing customer group: %w", err)
	}
	return active, nil
}

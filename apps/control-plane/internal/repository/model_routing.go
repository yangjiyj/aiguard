package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrVersionConflict = errors.New("model routing config version conflict")
var ErrCurrentRouteConfirmationRequired = errors.New("current model route confirmation required")
var ErrInvalidBaselineProvider = errors.New("baseline provider is not an active tenant model route")
var ErrModelRouteUnavailable = errors.New("model routing candidate is unavailable")

type ModelRoutingRepository struct {
	db *pgxpool.Pool
}

type ModelRoutingPolicy struct {
	ID            string
	TenantID      string
	ScopeType     string
	ScopeRef      string
	Config        modelrouting.Config
	ConfigVersion int64
	Enabled       bool
}

type ModelRouteCount struct {
	ModelName     string
	RouteCount    int
	ProviderNames []string
}

type ModelRoutingOverview struct {
	Default                *ModelRoutingPolicy
	Overrides              []ModelRoutingPolicy
	MultiRouteModelCount   int
	OutboundRouteAvailable bool
}

type LegacyPolicyReport struct {
	ID          string
	ScopeType   string
	ScopeRef    string
	Layer       string
	Strategy    string
	Convertible bool
	Reason      string
}

func NewModelRoutingRepository(db *pgxpool.Pool) *ModelRoutingRepository {
	return &ModelRoutingRepository{db: db}
}

func (r *ModelRoutingRepository) GetDefault(ctx context.Context, tenantID string) (*ModelRoutingPolicy, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, scope_type, scope_ref, strategy, config_json, config_version, enabled
		FROM routing_policies
		WHERE tenant_id=$1 AND schema_version=2 AND scope_type='tenant'
		  AND scope_ref=$1 AND layer='provider'
	`, tenantID)
	policy, err := scanModelRoutingPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get model routing default: %w", err)
	}
	return policy, nil
}

func (r *ModelRoutingRepository) ListOverrides(ctx context.Context, tenantID string) ([]ModelRoutingPolicy, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, scope_type, scope_ref, strategy, config_json, config_version, enabled
		FROM routing_policies
		WHERE tenant_id=$1 AND schema_version=2 AND scope_type='model'
		  AND scope_ref IS NOT NULL AND layer='provider'
		ORDER BY scope_ref, id
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list model routing overrides: %w", err)
	}
	defer rows.Close()
	result := make([]ModelRoutingPolicy, 0)
	for rows.Next() {
		policy, err := scanModelRoutingPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("list model routing overrides: %w", err)
		}
		result = append(result, *policy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list model routing overrides: %w", err)
	}
	return result, nil
}

func (r *ModelRoutingRepository) UpsertDefault(ctx context.Context, tenantID string, expectedVersion int64, cfg modelrouting.Config) (*ModelRoutingPolicy, error) {
	return r.upsert(ctx, tenantID, "tenant", tenantID, expectedVersion, modelrouting.ScopeDefault, cfg)
}

func (r *ModelRoutingRepository) UpsertOverride(ctx context.Context, tenantID, modelName string, expectedVersion int64, cfg modelrouting.Config) (*ModelRoutingPolicy, error) {
	modelName = strings.TrimSpace(modelName)
	if modelName == "" {
		return nil, fmt.Errorf("model routing override requires model name")
	}
	return r.upsert(ctx, tenantID, "model", modelName, expectedVersion, modelrouting.ScopeOverride, cfg)
}

func (r *ModelRoutingRepository) upsert(ctx context.Context, tenantID, scopeType, scopeRef string, expectedVersion int64, validationScope modelrouting.Scope, cfg modelrouting.Config) (*ModelRoutingPolicy, error) {
	if err := cfg.Validate(validationScope); err != nil {
		return nil, fmt.Errorf("validate model routing config: %w", err)
	}
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal model routing config_json: %w", err)
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin model routing upsert: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('model-routing-provider-lifecycle:' || $1, 0))`, tenantID); err != nil {
		return nil, fmt.Errorf("lock model routing provider lifecycle: %w", err)
	}
	providerIDs := enabledModelRoutingProviderIDs(cfg)
	validationModelName := ""
	if scopeType == "model" {
		validationModelName = scopeRef
	}

	var currentID string
	var currentVersion int64
	err = tx.QueryRow(ctx, `
		SELECT id, config_version
		FROM routing_policies
		WHERE tenant_id=$1 AND schema_version=2 AND scope_type=$2
		  AND scope_ref=$3 AND layer='provider'
		FOR UPDATE
	`, tenantID, scopeType, scopeRef).Scan(&currentID, &currentVersion)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if expectedVersion != 0 {
			return nil, ErrVersionConflict
		}
		if err := validateProviderCandidatesWith(ctx, tx, tenantID, validationModelName, "", providerIDs); err != nil {
			return nil, err
		}
		currentID = "rpv2_" + uuid.NewString()
		currentVersion = 1
		_, err = tx.Exec(ctx, `
			INSERT INTO routing_policies
				(id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version, config_version)
			VALUES ($1,$2,$3,$4,'provider',$5,$6,TRUE,2,1)
		`, currentID, tenantID, scopeType, scopeRef, string(cfg.Strategy), configJSON)
		if isUniqueViolation(err) {
			return nil, ErrVersionConflict
		}
		if err != nil {
			return nil, fmt.Errorf("insert model routing policy: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("lock model routing policy: %w", err)
	default:
		if expectedVersion == 0 || currentVersion != expectedVersion {
			return nil, ErrVersionConflict
		}
		if err := validateProviderCandidatesWith(ctx, tx, tenantID, validationModelName, "", providerIDs); err != nil {
			return nil, err
		}
		currentVersion++
		tag, err := tx.Exec(ctx, `
			UPDATE routing_policies
			SET strategy=$4, config_json=$5, enabled=TRUE,
			    config_version=config_version+1, updated_at=NOW()
			WHERE tenant_id=$1 AND schema_version=2 AND scope_type=$2
			  AND scope_ref=$3 AND layer='provider' AND config_version=$6
		`, tenantID, scopeType, scopeRef, string(cfg.Strategy), configJSON, expectedVersion)
		if err != nil {
			return nil, fmt.Errorf("update model routing policy: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrVersionConflict
		}
	}
	if err := tx.Commit(ctx); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrVersionConflict
		}
		return nil, fmt.Errorf("commit model routing upsert: %w", err)
	}
	return &ModelRoutingPolicy{ID: currentID, TenantID: tenantID, ScopeType: scopeType, ScopeRef: scopeRef, Config: cfg, ConfigVersion: currentVersion, Enabled: true}, nil
}

func (r *ModelRoutingRepository) DeleteOverride(ctx context.Context, tenantID, modelName string) error {
	modelName = strings.TrimSpace(modelName)
	if modelName == "" {
		return nil
	}
	_, err := r.db.Exec(ctx, `
		DELETE FROM routing_policies
		WHERE tenant_id=$1 AND schema_version=2 AND scope_type='model'
		  AND scope_ref=$2 AND layer='provider'
	`, tenantID, modelName)
	if err != nil {
		return fmt.Errorf("delete model routing override: %w", err)
	}
	return nil
}

// DeleteDefault removes the tenant-level v2 default routing policy. It is
// idempotent and never touches model overrides, legacy rows, or other tenants.
func (r *ModelRoutingRepository) DeleteDefault(ctx context.Context, tenantID string) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM routing_policies
		WHERE tenant_id=$1 AND schema_version=2 AND scope_type='tenant'
		  AND scope_ref=$1 AND layer='provider'
	`, tenantID)
	if err != nil {
		return fmt.Errorf("delete model routing default: %w", err)
	}
	return nil
}

// convergeRoutingPoliciesForProvider keeps routing policies consistent when an
// upstream leaves the active pool (deleted or disabled). Enabled v2 policies
// that reference the provider are pruned in place: the provider is removed
// from the candidate list, priorities are renumbered, and a fixed strategy
// loses its fixed_provider_id (falling back to priority). A model override
// with fewer than two enabled candidates no longer represents redundancy and
// is deleted; a tenant default with no enabled candidate is deleted. The
// caller must hold the model-routing-provider-lifecycle advisory lock and run
// this inside the same transaction as the provider lifecycle change.
func convergeRoutingPoliciesForProvider(ctx context.Context, tx pgx.Tx, tenantID, providerID string) error {
	rows, err := tx.Query(ctx, `
		SELECT id, scope_type, strategy, config_json
		FROM routing_policies
		WHERE tenant_id=$1 AND schema_version=2 AND layer='provider'
		  AND scope_type IN ('tenant','model') AND enabled=TRUE
		  AND (
			COALESCE(config_json->>'fixed_provider_id','')=$2
			OR EXISTS (
				SELECT 1
				FROM jsonb_array_elements(
					CASE WHEN jsonb_typeof(config_json->'providers')='array'
						THEN config_json->'providers'
						ELSE '[]'::jsonb
					END
				) candidate
				WHERE candidate->>'provider_id'=$2
			)
		  )
		FOR UPDATE
	`, tenantID, providerID)
	if err != nil {
		return fmt.Errorf("lock routing policies for provider convergence: %w", err)
	}
	type convergedPolicy struct {
		id        string
		scopeType string
		strategy  string
		config    map[string]any
	}
	pending := make([]convergedPolicy, 0)
	for rows.Next() {
		var item convergedPolicy
		var configJSON []byte
		if err := rows.Scan(&item.id, &item.scopeType, &item.strategy, &configJSON); err != nil {
			rows.Close()
			return fmt.Errorf("scan routing policy for provider convergence: %w", err)
		}
		if err := json.Unmarshal(configJSON, &item.config); err != nil {
			rows.Close()
			return fmt.Errorf("decode routing policy %s: %w", item.id, err)
		}
		pending = append(pending, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate routing policies for provider convergence: %w", err)
	}
	rows.Close()

	for _, item := range pending {
		cfg := item.config
		providers, _ := cfg["providers"].([]any)
		remaining := make([]any, 0, len(providers))
		for _, entryAny := range providers {
			entry, ok := entryAny.(map[string]any)
			if !ok {
				continue
			}
			if entryID, _ := entry["provider_id"].(string); entryID == providerID {
				continue
			}
			remaining = append(remaining, entry)
		}
		for index, entryAny := range remaining {
			if entry, ok := entryAny.(map[string]any); ok {
				entry["priority"] = index + 1
			}
		}
		strategy := item.strategy
		if fixed, _ := cfg["fixed_provider_id"].(string); fixed != "" && fixed == providerID {
			delete(cfg, "fixed_provider_id")
			if strategy == "fixed" {
				strategy = "priority"
			}
		}
		// 冗余口径与页面展示一致：按剩余上游条目数（含停用条目，可随时重新启用），
		// 而非 enabled 标志。模型级规则少于 2 个上游即退化为直连；默认路由没有可用线路时清空。
		shouldDelete := len(remaining) == 0 || (item.scopeType == "model" && len(remaining) < 2)
		if shouldDelete {
			if _, err := tx.Exec(ctx, `DELETE FROM routing_policies WHERE id=$1`, item.id); err != nil {
				return fmt.Errorf("delete dangling routing policy %s: %w", item.id, err)
			}
			continue
		}
		cfg["providers"] = remaining
		configJSON, err := json.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("encode routing policy %s: %w", item.id, err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE routing_policies
			SET config_json=$2, strategy=$3, config_version=config_version+1, updated_at=NOW()
			WHERE id=$1
		`, item.id, configJSON, strategy); err != nil {
			return fmt.Errorf("converge routing policy %s: %w", item.id, err)
		}
	}
	return nil
}

func (r *ModelRoutingRepository) Overview(ctx context.Context, tenantID string) (*ModelRoutingOverview, error) {
	defaultPolicy, err := r.GetDefault(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	overrides, err := r.ListOverrides(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var count int
	err = r.db.QueryRow(ctx, `
		SELECT count(*) FROM (
			SELECT m.model_name
			FROM models m
			JOIN providers p ON p.id=m.provider_id
			WHERE p.tenant_id=$1 AND p.status='active' AND m.status='active'
			  AND EXISTS (SELECT 1 FROM provider_credentials pc WHERE pc.provider_id=p.id AND pc.status='active')
			GROUP BY m.model_name
			HAVING count(DISTINCT p.id) >= 2
		) multi_route_models
	`, tenantID).Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("count multi-route models: %w", err)
	}
	var outboundRouteAvailable bool
	if err := r.db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM models m
			JOIN providers p ON p.id=m.provider_id
			JOIN model_endpoint_capability_effective ec ON ec.model_id=m.id
			WHERE p.tenant_id=$1 AND p.status='active' AND m.status='active' AND ec.state='supported'
			  AND EXISTS (
				SELECT 1 FROM provider_credentials pc
				WHERE pc.provider_id=p.id AND pc.status='active'
				  AND COALESCE(pc.secret_ciphertext, '') <> ''
			  )
		)
	`, tenantID).Scan(&outboundRouteAvailable); err != nil {
		return nil, fmt.Errorf("check outbound model route availability: %w", err)
	}
	return &ModelRoutingOverview{Default: defaultPolicy, Overrides: overrides, MultiRouteModelCount: count, OutboundRouteAvailable: outboundRouteAvailable}, nil
}

// ValidateProviderCandidates applies the same persistent eligibility facts as
// the gateway hot path before a routing policy can be saved or re-enabled.
// An empty endpoint validates endpoint-independent control-plane policies:
// at least one supported endpoint is required. A concrete endpoint still
// requires that exact capability; runtime admission remains endpoint-specific.
func (r *ModelRoutingRepository) ValidateProviderCandidates(ctx context.Context, tenantID, modelName, endpoint string, providerIDs []string) error {
	return validateProviderCandidatesWith(ctx, r.db, tenantID, modelName, endpoint, providerIDs)
}

type modelRoutingRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func validateProviderCandidatesWith(ctx context.Context, querier modelRoutingRowQuerier, tenantID, modelName, endpoint string, providerIDs []string) error {
	if len(providerIDs) == 0 {
		return ErrModelRouteUnavailable
	}
	var eligible int
	if err := querier.QueryRow(ctx, `
		SELECT count(DISTINCT requested.provider_id)::int
		FROM unnest($3::text[]) requested(provider_id)
		JOIN providers p ON p.id=requested.provider_id AND p.tenant_id=$1 AND p.status='active'
		WHERE EXISTS (
			SELECT 1 FROM provider_credentials pc
			WHERE pc.provider_id=p.id AND pc.status='active'
			  AND COALESCE(pc.secret_ciphertext, '') <> ''
		) AND EXISTS (
			SELECT 1 FROM models m
			JOIN model_endpoint_capability_effective ec ON ec.model_id=m.id AND ($4='' OR ec.endpoint_type=$4) AND ec.state='supported'
			WHERE m.provider_id=p.id AND m.status='active'
			  AND ($2='' OR m.model_name=$2)
		)
	`, tenantID, strings.TrimSpace(modelName), providerIDs, endpoint).Scan(&eligible); err != nil {
		return fmt.Errorf("validate model routing candidates: %w", err)
	}
	if eligible != len(providerIDs) {
		return ErrModelRouteUnavailable
	}
	return nil
}

func enabledModelRoutingProviderIDs(cfg modelrouting.Config) []string {
	ids := make(map[string]struct{}, len(cfg.Providers)+1)
	for _, rule := range cfg.Providers {
		if rule.Enabled {
			ids[rule.ProviderID] = struct{}{}
		}
	}
	if cfg.FixedProviderID != "" {
		ids[cfg.FixedProviderID] = struct{}{}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func (r *ModelRoutingRepository) SearchModels(ctx context.Context, tenantID, query string, limit int) ([]ModelRouteCount, error) {
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}
	rows, err := r.db.Query(ctx, `
		SELECT m.model_name, count(DISTINCT p.id)::int,
		       array_agg(DISTINCT p.name ORDER BY p.name)
		FROM models m
		JOIN providers p ON p.id=m.provider_id
		WHERE p.tenant_id=$1 AND p.status='active' AND m.status='active'
		  AND m.model_name ILIKE '%' || $2 || '%'
		  AND EXISTS (SELECT 1 FROM provider_credentials pc WHERE pc.provider_id=p.id AND pc.status='active')
		GROUP BY m.model_name
		HAVING count(DISTINCT p.id) >= 2
		ORDER BY m.model_name
		LIMIT $3
	`, tenantID, strings.TrimSpace(query), limit)
	if err != nil {
		return nil, fmt.Errorf("search multi-route models: %w", err)
	}
	defer rows.Close()
	result := make([]ModelRouteCount, 0)
	for rows.Next() {
		var item ModelRouteCount
		if err := rows.Scan(&item.ModelName, &item.RouteCount, &item.ProviderNames); err != nil {
			return nil, fmt.Errorf("scan multi-route model: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("search multi-route models: %w", err)
	}
	return result, nil
}

func (r *ModelRoutingRepository) LegacyInventory(ctx context.Context, tenantID string) ([]LegacyPolicyReport, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, scope_type, COALESCE(scope_ref,''), layer, strategy, config_json
		FROM routing_policies
		WHERE tenant_id=$1 AND schema_version=1
		ORDER BY id
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list legacy routing policies: %w", err)
	}
	defer rows.Close()
	type legacyRow struct {
		report LegacyPolicyReport
		config []byte
	}
	legacyRows := make([]legacyRow, 0)
	for rows.Next() {
		var item legacyRow
		if err := rows.Scan(&item.report.ID, &item.report.ScopeType, &item.report.ScopeRef, &item.report.Layer, &item.report.Strategy, &item.config); err != nil {
			return nil, fmt.Errorf("scan legacy routing policy: %w", err)
		}
		legacyRows = append(legacyRows, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list legacy routing policies: %w", err)
	}

	reports := make([]LegacyPolicyReport, 0, len(legacyRows))
	for _, item := range legacyRows {
		report := item.report
		switch {
		case report.ScopeType != "model" || report.Layer != "provider":
			report.Reason = "only model-scoped provider-layer policies can be converted"
		case report.Strategy == "canary":
			report.Reason = "canary routing requires manual migration"
		case report.Strategy != "fallback" && report.Strategy != "lb":
			report.Reason = "strategy requires manual migration"
		default:
			providerIDs, extractErr := legacyProviderIDs(report.Strategy, item.config)
			if extractErr != nil {
				report.Reason = extractErr.Error()
			} else if len(providerIDs) == 0 {
				report.Reason = "policy has no explicit provider candidates"
			} else {
				valid, validateErr := r.legacyProvidersSupportModel(ctx, tenantID, report.ScopeRef, providerIDs)
				if validateErr != nil {
					return nil, validateErr
				}
				if valid {
					report.Convertible = true
					report.Reason = "all explicit providers are active and support this model"
				} else {
					report.Reason = "one or more providers are unavailable or do not support this model"
				}
			}
		}
		reports = append(reports, report)
	}
	return reports, nil
}

func scanModelRoutingPolicy(row pgx.Row) (*ModelRoutingPolicy, error) {
	var policy ModelRoutingPolicy
	var persistedStrategy string
	var configJSON []byte
	if err := row.Scan(&policy.ID, &policy.TenantID, &policy.ScopeType, &policy.ScopeRef, &persistedStrategy, &configJSON, &policy.ConfigVersion, &policy.Enabled); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(configJSON, &policy.Config); err != nil {
		return nil, fmt.Errorf("decode model routing config_json: %w", err)
	}
	var scope modelrouting.Scope
	switch policy.ScopeType {
	case "tenant":
		scope = modelrouting.ScopeDefault
	case "model":
		scope = modelrouting.ScopeOverride
	default:
		return nil, fmt.Errorf("validate model routing config_json: unknown scope_type %q", policy.ScopeType)
	}
	if err := policy.Config.Validate(scope); err != nil {
		return nil, fmt.Errorf("validate model routing config_json: %w", err)
	}
	if persistedStrategy != string(policy.Config.Strategy) {
		return nil, fmt.Errorf("strategy column does not match config_json")
	}
	return &policy, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func legacyProviderIDs(strategy string, raw []byte) ([]string, error) {
	var config map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("invalid legacy config_json")
	}
	switch strategy {
	case "fallback":
		return legacyFallbackProviderIDs(config)
	case "lb":
		return legacyLoadBalancingProviderIDs(config)
	default:
		return nil, fmt.Errorf("unsupported legacy strategy")
	}
}

func legacyFallbackProviderIDs(config map[string]any) ([]string, error) {
	values, ok := config["provider_chain"].([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("fallback provider_chain must be a non-empty array of provider ids")
	}
	providerIDs := make([]string, 0, len(values))
	for _, value := range values {
		providerID, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("fallback provider_chain must contain only non-empty strings")
		}
		providerIDs = append(providerIDs, providerID)
	}
	return validateUniqueProviderIDs("fallback provider_chain", providerIDs)
}

func legacyLoadBalancingProviderIDs(config map[string]any) ([]string, error) {
	values, ok := config["weighted_providers"].([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("lb weighted_providers must be a non-empty array")
	}
	providerIDs := make([]string, 0, len(values))
	for _, value := range values {
		entry, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("lb weighted_providers entries must be objects")
		}
		providerID, ok := entry["id"].(string)
		if !ok {
			return nil, fmt.Errorf("lb weighted_providers entries require a non-empty string id")
		}
		weight, ok := entry["weight"].(json.Number)
		if !ok || !validLegacyWeight(weight) {
			return nil, fmt.Errorf("lb weighted_providers entries require a positive integer weight within exact float64 and Go int range")
		}
		providerIDs = append(providerIDs, providerID)
	}
	return validateUniqueProviderIDs("lb weighted_providers", providerIDs)
}

func validLegacyWeight(weight json.Number) bool {
	value, ok := new(big.Rat).SetString(weight.String())
	if !ok || !value.IsInt() || value.Sign() <= 0 {
		return false
	}
	maxInt := new(big.Int).SetUint64(uint64(^uint(0) >> 1))
	maxExactFloat64Integer := big.NewInt(9007199254740991)
	return value.Num().Cmp(maxInt) <= 0 && value.Num().Cmp(maxExactFloat64Integer) <= 0
}

func validateUniqueProviderIDs(field string, values []string) ([]string, error) {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, providerID := range values {
		if providerID == "" || providerID != strings.TrimSpace(providerID) {
			return nil, fmt.Errorf("%s contains an empty or whitespace-padded provider id", field)
		}
		if _, ok := seen[providerID]; ok {
			return nil, fmt.Errorf("%s contains duplicate provider id %q", field, providerID)
		}
		seen[providerID] = struct{}{}
		result = append(result, providerID)
	}
	return result, nil
}

func (r *ModelRoutingRepository) legacyProvidersSupportModel(ctx context.Context, tenantID, modelName string, providerIDs []string) (bool, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT count(DISTINCT p.id)
		FROM providers p
		WHERE p.tenant_id=$1 AND p.id=ANY($2) AND p.status='active'
		  AND EXISTS (
			SELECT 1 FROM models m
			WHERE m.provider_id=p.id AND m.model_name=$3 AND m.status='active'
		  )
	`, tenantID, providerIDs, modelName).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("validate legacy provider candidates: %w", err)
	}
	return count == len(providerIDs), nil
}

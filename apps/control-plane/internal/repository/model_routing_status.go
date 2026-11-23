package repository

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

const (
	defaultRoutingStatusLimit = 50
	maxRoutingStatusLimit     = 100
)

type RoutingStatusFilter struct {
	State, Query, ProviderRef, Cursor, Endpoint string
	RouteCount, MinRouteCount, Limit            int
}

type ModelRouteStatus struct {
	ProviderID      string
	ProviderName    string
	CapabilityState string
	HealthState     string
}

type LogicalModelRoutingStatus struct {
	ModelName                string
	State                    string
	RouteCount               int
	ConfiguredCandidateCount int
	EligibleCandidateCount   int
	CurrentProviderID        string
	ConfigVersion            int64
	Routes                   []ModelRouteStatus
}

func (r *ModelRoutingRepository) ListRoutingStatus(ctx context.Context, tenantID string, filter RoutingStatusFilter) ([]LogicalModelRoutingStatus, string, error) {
	filter.State = strings.TrimSpace(filter.State)
	filter.Endpoint = strings.ToLower(strings.TrimSpace(filter.Endpoint))
	if filter.Endpoint == "" {
		filter.Endpoint = "chat"
	}
	if filter.Endpoint != "chat" && filter.Endpoint != "responses" && filter.Endpoint != "messages" && filter.Endpoint != "images" && filter.Endpoint != "embeddings" && filter.Endpoint != "files" {
		return nil, "", fmt.Errorf("invalid routing status endpoint %q", filter.Endpoint)
	}
	if filter.State != "" && filter.State != "single" && filter.State != "pending" && filter.State != "configured" && filter.State != "unavailable" {
		return nil, "", fmt.Errorf("invalid routing status state %q", filter.State)
	}
	if filter.RouteCount < 0 || filter.MinRouteCount < 0 {
		return nil, "", fmt.Errorf("route count must not be negative")
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = defaultRoutingStatusLimit
	} else if limit > maxRoutingStatusLimit {
		limit = maxRoutingStatusLimit
	}
	cursorModel := ""
	if filter.Cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(filter.Cursor)
		if err != nil || len(decoded) == 0 || len(decoded) > 255 || !utf8.Valid(decoded) || strings.ContainsRune(string(decoded), 0) || strings.TrimSpace(string(decoded)) != string(decoded) {
			return nil, "", fmt.Errorf("invalid routing status cursor")
		}
		cursorModel = string(decoded)
	}

	args := []any{tenantID, filter.Endpoint}
	where := make([]string, 0, 5)
	add := func(format string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(format, len(args)))
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		add("s.model_name ILIKE '%%' || $%d || '%%'", query)
	}
	if filter.State != "" {
		add("s.state = $%d", filter.State)
	}
	if providerRef := strings.TrimSpace(filter.ProviderRef); providerRef != "" {
		add("EXISTS (SELECT 1 FROM valid_routes vf WHERE vf.model_name=s.model_name AND vf.provider_id=$%d)", providerRef)
	}
	if filter.RouteCount > 0 {
		add("s.route_count = $%d", filter.RouteCount)
	}
	if filter.MinRouteCount > 0 {
		add("s.route_count >= $%d", filter.MinRouteCount)
	}
	if cursorModel != "" {
		add("s.model_name > $%d", cursorModel)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit+1)
	limitArg := len(args)

	query := fmt.Sprintf(`
		WITH catalog AS (
			SELECT DISTINCT m.model_name
			FROM models m
			JOIN providers p ON p.id=m.provider_id AND p.tenant_id=$1
			WHERE m.status='active'
		), configured_routes AS (
			SELECT DISTINCT m.model_name, p.id AS provider_id, p.name AS provider_name
			FROM models m
			JOIN providers p ON p.id=m.provider_id AND p.tenant_id=$1
			WHERE p.status='active' AND m.status='active'
			  AND EXISTS (
				SELECT 1 FROM provider_credentials pc
				WHERE pc.provider_id=p.id AND pc.status='active'
			  )
		), valid_routes AS (
			SELECT cr.model_name, cr.provider_id, cr.provider_name,
			       COALESCE(ec.state,'unknown') AS capability_state,
			       COALESCE(health.state,'unknown') AS health_state
			FROM configured_routes cr
			JOIN models m ON m.model_name=cr.model_name AND m.provider_id=cr.provider_id AND m.status='active'
			LEFT JOIN model_endpoint_capability_effective ec ON ec.model_id=m.id AND ec.endpoint_type=$2
			LEFT JOIN model_route_health_snapshots health
			  ON health.tenant_id=$1 AND health.model_name=cr.model_name AND health.provider_id=cr.provider_id
			 AND health.expires_at>NOW()
		), v3 AS (
			SELECT rp.scope_ref AS model_name, rp.config_version
			FROM routing_policies rp
			WHERE rp.tenant_id=$1 AND rp.schema_version IN (2,3)
			  AND rp.scope_type='model' AND rp.layer='provider' AND rp.enabled
		), statuses AS (
			SELECT c.model_name,
				count(vr.provider_id)::int AS configured_count,
				count(vr.provider_id)::int AS route_count,
				CASE
					WHEN count(vr.provider_id)=0 THEN 'unavailable'
					WHEN count(vr.provider_id)=1 THEN 'single'
					WHEN max(v3.model_name) IS NOT NULL THEN 'configured'
					ELSE 'pending'
				END AS state,
				COALESCE(max(v3.config_version),0)::bigint AS config_version,
				COALESCE(max(b.provider_id),'') AS current_provider_id
			FROM catalog c
			LEFT JOIN valid_routes vr ON vr.model_name=c.model_name
			LEFT JOIN v3 ON v3.model_name=c.model_name
			LEFT JOIN model_route_baselines b ON b.tenant_id=$1 AND b.model_name=c.model_name
			GROUP BY c.model_name
		), selected AS (
			SELECT s.* FROM statuses s
			%s
			ORDER BY s.model_name
			LIMIT $%d
		)
		SELECT s.model_name,s.state,s.configured_count,s.route_count,s.current_provider_id,s.config_version,
		       COALESCE(vr.provider_id,''),COALESCE(vr.provider_name,''),COALESCE(vr.capability_state,'unknown'),COALESCE(vr.health_state,'unknown')
		FROM selected s
		LEFT JOIN valid_routes vr ON vr.model_name=s.model_name
		ORDER BY s.model_name,vr.provider_id`, whereSQL, limitArg)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("list model routing status: %w", err)
	}
	defer rows.Close()
	items := make([]LogicalModelRoutingStatus, 0, limit+1)
	for rows.Next() {
		var modelName, state, currentProviderID, providerID, providerName, capabilityState, healthState string
		var configuredCount, routeCount int
		var configVersion int64
		if err := rows.Scan(&modelName, &state, &configuredCount, &routeCount, &currentProviderID, &configVersion, &providerID, &providerName, &capabilityState, &healthState); err != nil {
			return nil, "", fmt.Errorf("scan model routing status: %w", err)
		}
		if len(items) == 0 || items[len(items)-1].ModelName != modelName {
			items = append(items, LogicalModelRoutingStatus{ModelName: modelName, State: state, RouteCount: routeCount, ConfiguredCandidateCount: configuredCount, EligibleCandidateCount: 0, CurrentProviderID: currentProviderID, ConfigVersion: configVersion, Routes: make([]ModelRouteStatus, 0, routeCount)})
		}
		if providerID != "" {
			last := &items[len(items)-1]
			if capabilityState == "supported" && healthState != "unhealthy" {
				last.EligibleCandidateCount++
			}
			last.Routes = append(last.Routes, ModelRouteStatus{ProviderID: providerID, ProviderName: providerName, CapabilityState: capabilityState, HealthState: healthState})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate model routing status: %w", err)
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = base64.RawURLEncoding.EncodeToString([]byte(items[len(items)-1].ModelName))
	}
	return items, next, nil
}

func (r *ModelRoutingRepository) CaptureBaseline(ctx context.Context, tx pgx.Tx, tenantID, modelName, confirmedProviderID string) error {
	modelName = strings.TrimSpace(modelName)
	if modelName == "" {
		return fmt.Errorf("baseline model name is required")
	}
	var existing string
	err := tx.QueryRow(ctx, `
		SELECT provider_id FROM model_route_baselines
		WHERE tenant_id=$1 AND model_name=$2
		FOR UPDATE`, tenantID, modelName).Scan(&existing)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("lock model route baseline: %w", err)
	}

	providerID := ""
	capturedFrom := "runtime"
	err = tx.QueryRow(ctx, `
		SELECT rl.provider_id
		FROM request_logs rl
		JOIN models logged_model
		  ON logged_model.id=rl.model_id AND logged_model.model_name=$2
		JOIN providers logged_provider
		  ON logged_provider.id=logged_model.provider_id AND logged_provider.tenant_id=$1
		WHERE rl.tenant_id=$1 AND rl.request_status='success' AND rl.provider_id IS NOT NULL
		  AND EXISTS (
			SELECT 1
			FROM providers p
			JOIN models m ON m.provider_id=p.id AND m.model_name=$2 AND m.status='active'
			WHERE p.tenant_id=$1 AND p.id=rl.provider_id AND p.status='active'
			  AND EXISTS (
				SELECT 1 FROM provider_credentials pc
				WHERE pc.provider_id=p.id AND pc.status='active'
			  )
		  )
		ORDER BY rl.created_at DESC,rl.id DESC
		LIMIT 1`, tenantID, modelName).Scan(&providerID)
	if errors.Is(err, pgx.ErrNoRows) {
		providerID = strings.TrimSpace(confirmedProviderID)
		if providerID == "" {
			return ErrCurrentRouteConfirmationRequired
		}
		capturedFrom = "confirmed"
		var valid bool
		err = tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM providers p
				JOIN models m ON m.provider_id=p.id AND m.model_name=$3 AND m.status='active'
				WHERE p.tenant_id=$1 AND p.id=$2 AND p.status='active'
				  AND EXISTS (
					SELECT 1 FROM provider_credentials pc
					WHERE pc.provider_id=p.id AND pc.status='active'
				  )
			)`, tenantID, providerID, modelName).Scan(&valid)
		if err != nil {
			return fmt.Errorf("validate confirmed baseline route: %w", err)
		}
		if !valid {
			return ErrInvalidBaselineProvider
		}
	} else if err != nil {
		return fmt.Errorf("find latest successful model route: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO model_route_baselines(tenant_id,model_name,provider_id,captured_from)
		VALUES($1,$2,$3,$4)
		ON CONFLICT(tenant_id,model_name) DO NOTHING`, tenantID, modelName, providerID, capturedFrom)
	if err != nil {
		return fmt.Errorf("insert model route baseline: %w", err)
	}
	return nil
}

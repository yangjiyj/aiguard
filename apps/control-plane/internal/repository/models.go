package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Model represents a model record
type Model struct {
	ID              string
	ProviderID      string
	ModelName       string
	ModelLabel      string
	UpstreamModelID string
	Capabilities    map[string]interface{}
	Pricing         map[string]interface{}
	ProxyConfig     map[string]interface{}
	ContextWindow   int
	Status          string
	CreatedAt       time.Time
	// NativeMessagesProbed is request-scoped evidence from catalog sync. It is
	// intentionally not persisted in models.capabilities_json: only a real
	// probe may create the lower-precedence automatic capability fact.
	NativeMessagesProbed bool
}

type VerifiedProviderModel struct {
	CatalogID      string
	DeploymentName string
	ModelLabel     string
	Capabilities   map[string]interface{}
	Protocols      []string
	SourceVersion  string
	VerifiedAt     time.Time
	ExpiresAt      time.Time
}

// ModelEndpointProbeResult is the sanitized outcome of probing one upstream
// protocol endpoint. ErrorKind is intentionally categorical so provider
// response bodies and credentials never enter capability evidence.
type ModelEndpointProbeResult struct {
	EndpointType string
	State        string
	ErrorKind    string
}

// ModelProtocolProbeRecord carries the verified protocol facts produced while
// onboarding a model through the generic create flow.
type ModelProtocolProbeRecord struct {
	// Optional identity snapshot for native admission; never serialized or logged.
	CredentialID         string `json:"-"`
	SecretCiphertext     string `json:"-"`
	SourceVersion        string
	ProviderConfigDigest string
	VerifiedAt           time.Time
	ExpiresAt            time.Time
	Endpoints            []ModelEndpointProbeResult
}

var ErrVerifiedModelSyncConflict = errors.New("verified model sync conflict")

type VerifiedModelSyncResult struct {
	Created     int
	Updated     int
	Reactivated int
	Deactivated int
}

func parseJSONMap(data []byte) map[string]interface{} {
	result := map[string]interface{}{}
	if len(data) == 0 {
		return result
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return map[string]interface{}{}
	}

	return result
}

// mergeVerifiedModelCapabilities only fills capability keys that do not
// already exist. A verified sync is an inventory refresh; it is not allowed
// to overwrite an administrator's route, protocol, or previously verified
// capability decision.
func mergeVerifiedModelCapabilities(existing, desired map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(existing)+len(desired))
	for key, value := range existing {
		result[key] = value
	}
	for key, value := range desired {
		if key != "protocols" {
			if _, exists := result[key]; !exists {
				result[key] = value
			}
			continue
		}
		desiredProtocols, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		existingProtocols, ok := result[key].(map[string]interface{})
		if !ok {
			existingProtocols = make(map[string]interface{}, len(desiredProtocols))
			result[key] = existingProtocols
		}
		for protocol, capability := range desiredProtocols {
			if _, exists := existingProtocols[protocol]; !exists {
				existingProtocols[protocol] = capability
			}
		}
	}
	return result
}

// ModelRepository handles model database operations
type ModelRepository struct {
	db *pgxpool.Pool
}

var ErrModelsUnavailable = errors.New("one or more models unavailable")

type ModelBatchDeleteResult struct {
	Requested int `json:"requested"`
	Deleted   int `json:"deleted"`
	Disabled  int `json:"disabled"`
	Failed    int `json:"failed"`
}

func (r *ModelRepository) DeleteBatch(ctx context.Context, tenantID string, modelIDs []string) (ModelBatchDeleteResult, error) {
	ids := append([]string(nil), modelIDs...)
	sort.Strings(ids)
	result := ModelBatchDeleteResult{Requested: len(ids)}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("failed to begin model batch delete: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT m.id
		FROM models m
		JOIN providers p ON p.id = m.provider_id
		WHERE p.tenant_id = $1 AND m.id = ANY($2)
		ORDER BY m.id
		FOR UPDATE OF m
	`, tenantID, ids)
	if err != nil {
		return result, fmt.Errorf("failed to validate models for batch delete: %w", err)
	}

	available := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return result, fmt.Errorf("failed to scan model for batch delete: %w", err)
		}
		available++
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return result, fmt.Errorf("failed to validate models for batch delete: %w", rowsErr)
	}
	if available != len(ids) {
		return result, ErrModelsUnavailable
	}

	for i, id := range ids {
		savepoint := fmt.Sprintf("model_delete_%d", i)
		if _, err := tx.Exec(ctx, "SAVEPOINT "+savepoint); err != nil {
			return result, fmt.Errorf("failed to create model delete savepoint: %w", err)
		}

		commandTag, err := tx.Exec(ctx, `DELETE FROM models WHERE id = $1`, id)
		if err == nil {
			if commandTag.RowsAffected() != 1 {
				return result, fmt.Errorf("model %s disappeared during batch delete", id)
			}
			if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT "+savepoint); err != nil {
				return result, fmt.Errorf("failed to release model delete savepoint: %w", err)
			}
			result.Deleted++
			continue
		}

		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			return result, fmt.Errorf("failed to delete model %s: %w", id, err)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); err != nil {
			return result, fmt.Errorf("failed to roll back model delete savepoint: %w", err)
		}
		commandTag, err = tx.Exec(ctx, `UPDATE models SET status = 'disabled' WHERE id = $1`, id)
		if err != nil {
			return result, fmt.Errorf("failed to disable referenced model %s: %w", id, err)
		}
		if commandTag.RowsAffected() != 1 {
			return result, fmt.Errorf("model %s disappeared while disabling", id)
		}
		if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT "+savepoint); err != nil {
			return result, fmt.Errorf("failed to release model delete savepoint: %w", err)
		}
		result.Disabled++
	}

	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("failed to commit model batch delete: %w", err)
	}
	return result, nil
}

// NewModelRepository creates a new model repository
func NewModelRepository(db *pgxpool.Pool) *ModelRepository {
	return &ModelRepository{db: db}
}

// GetByID retrieves a model by ID
func (r *ModelRepository) GetByID(ctx context.Context, id string) (*Model, error) {
	query := `
		SELECT id, provider_id, model_name, COALESCE(model_label, ''), COALESCE(upstream_model_id, ''), capabilities_json, pricing_json, proxy_config, COALESCE(context_window, 0), status, created_at
		FROM models
		WHERE id = $1
	`

	row := r.db.QueryRow(ctx, query, id)
	var model Model
	var capabilitiesJSON, pricingJSON, proxyConfigJSON []byte
	err := row.Scan(
		&model.ID,
		&model.ProviderID,
		&model.ModelName,
		&model.ModelLabel,
		&model.UpstreamModelID,
		&capabilitiesJSON,
		&pricingJSON,
		&proxyConfigJSON,
		&model.ContextWindow,
		&model.Status,
		&model.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get model: %w", err)
	}

	model.Capabilities = parseJSONMap(capabilitiesJSON)
	model.Pricing = parseJSONMap(pricingJSON)
	model.ProxyConfig = parseJSONMap(proxyConfigJSON)

	return &model, nil
}

// GetByName retrieves a model by name
func (r *ModelRepository) GetByName(ctx context.Context, modelName string) (*Model, error) {
	query := `
		SELECT id, provider_id, model_name, COALESCE(model_label, ''), COALESCE(upstream_model_id, ''), capabilities_json, pricing_json, proxy_config, COALESCE(context_window, 0), status, created_at
		FROM models
		WHERE model_name = $1 AND status = 'active'
	`

	row := r.db.QueryRow(ctx, query, modelName)
	var model Model
	var capabilitiesJSON, pricingJSON, proxyConfigJSON []byte
	err := row.Scan(
		&model.ID,
		&model.ProviderID,
		&model.ModelName,
		&model.ModelLabel,
		&model.UpstreamModelID,
		&capabilitiesJSON,
		&pricingJSON,
		&proxyConfigJSON,
		&model.ContextWindow,
		&model.Status,
		&model.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get model: %w", err)
	}

	model.Capabilities = parseJSONMap(capabilitiesJSON)
	model.Pricing = parseJSONMap(pricingJSON)
	model.ProxyConfig = parseJSONMap(proxyConfigJSON)

	return &model, nil
}

// GetByProviderAndName retrieves a model by provider_id and model_name.
func (r *ModelRepository) GetByProviderAndName(ctx context.Context, providerID, modelName string) (*Model, error) {
	return r.getByProviderAndName(ctx, providerID, modelName)
}

// List retrieves all models visible to a tenant (including disabled ones for management)
func (r *ModelRepository) List(ctx context.Context, tenantID string) ([]*Model, error) {
	query := `
		SELECT id, provider_id, model_name, COALESCE(model_label, ''), COALESCE(upstream_model_id, ''), capabilities_json, pricing_json, proxy_config, COALESCE(context_window, 0), status, created_at
		FROM models
		WHERE provider_id IN (
			SELECT id FROM providers WHERE tenant_id = $1 AND status <> 'deleted'
		)
		ORDER BY model_name
	`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list models: %w", err)
	}
	defer rows.Close()

	models := []*Model{}
	for rows.Next() {
		var model Model
		var capabilitiesJSON, pricingJSON, proxyConfigJSON []byte
		err := rows.Scan(
			&model.ID,
			&model.ProviderID,
			&model.ModelName,
			&model.ModelLabel,
			&model.UpstreamModelID,
			&capabilitiesJSON,
			&pricingJSON,
			&proxyConfigJSON,
			&model.ContextWindow,
			&model.Status,
			&model.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		model.Capabilities = parseJSONMap(capabilitiesJSON)
		model.Pricing = parseJSONMap(pricingJSON)
		model.ProxyConfig = parseJSONMap(proxyConfigJSON)
		models = append(models, &model)
	}
	return models, nil
}

// Create creates a new model
func (r *ModelRepository) Create(ctx context.Context, model *Model) error {
	if model.ID == "" {
		model.ID = "model_" + uuid.New().String()[:8]
	}

	query := `
		INSERT INTO models (id, provider_id, model_name, model_label, upstream_model_id, capabilities_json, pricing_json, context_window, status)
		VALUES ($1, $2, $3, $4, $5, '{}', '{}', $6, $7)
	`

	_, err := r.db.Exec(ctx, query,
		model.ID,
		model.ProviderID,
		model.ModelName,
		model.ModelLabel,
		nullableString(model.UpstreamModelID),
		model.ContextWindow,
		model.Status,
	)

	if err != nil {
		return fmt.Errorf("failed to create model: %w", err)
	}
	return nil
}

// Update updates a model
func (r *ModelRepository) Update(ctx context.Context, model *Model) error {
	query := `
		UPDATE models
		SET model_label = $2, upstream_model_id = $3, context_window = $4, status = $5
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query,
		model.ID,
		model.ModelLabel,
		nullableString(model.UpstreamModelID),
		model.ContextWindow,
		model.Status,
	)

	if err != nil {
		return fmt.Errorf("failed to update model: %w", err)
	}
	return nil
}

// UpdatePricing updates the pricing_json for a model
func (r *ModelRepository) UpdatePricing(ctx context.Context, modelID string, pricingJSON string) error {
	query := `UPDATE models SET pricing_json = $1::jsonb, updated_at = NOW() WHERE id = $2`
	_, err := r.db.Exec(ctx, query, pricingJSON, modelID)
	if err != nil {
		return fmt.Errorf("failed to update model pricing: %w", err)
	}
	return nil
}

// UpdateCapabilities updates the capabilities_json for a model.
func (r *ModelRepository) UpdateCapabilities(ctx context.Context, modelID string, capabilitiesJSON string) error {
	query := `UPDATE models SET capabilities_json = $1::jsonb, updated_at = NOW() WHERE id = $2`
	result, err := r.db.Exec(ctx, query, capabilitiesJSON, modelID)
	if err != nil {
		return fmt.Errorf("failed to update model capabilities: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("model not found")
	}
	return nil
}

// RecordProtocolProbe merges verified protocol capabilities without
// overwriting unrelated model routing/features and records endpoint facts in
// the same transaction. This closes the gap where a newly created model had a
// JSON hint but no effective capability fact (or vice versa).
func (r *ModelRepository) RecordProtocolProbe(ctx context.Context, tenantID, providerID, modelID string, capabilities map[string]interface{}, record ModelProtocolProbeRecord) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(providerID) == "" || strings.TrimSpace(modelID) == "" {
		return fmt.Errorf("invalid model protocol probe identity")
	}
	if strings.TrimSpace(record.SourceVersion) == "" || strings.TrimSpace(record.ProviderConfigDigest) == "" || record.VerifiedAt.IsZero() || record.ExpiresAt.IsZero() || !record.ExpiresAt.After(record.VerifiedAt) || len(record.Endpoints) == 0 {
		return fmt.Errorf("invalid model protocol probe record")
	}
	seenEndpoints := make(map[string]struct{}, len(record.Endpoints))
	for _, endpoint := range record.Endpoints {
		if endpoint.EndpointType != "chat" && endpoint.EndpointType != "responses" && endpoint.EndpointType != "messages" {
			return fmt.Errorf("invalid probed endpoint %q", endpoint.EndpointType)
		}
		if endpoint.State != "supported" && endpoint.State != "unsupported" && endpoint.State != "unknown" {
			return fmt.Errorf("invalid probed endpoint state %q", endpoint.State)
		}
		if _, duplicate := seenEndpoints[endpoint.EndpointType]; duplicate {
			return fmt.Errorf("duplicate probed endpoint %q", endpoint.EndpointType)
		}
		seenEndpoints[endpoint.EndpointType] = struct{}{}
	}

	capabilitiesJSON, err := json.Marshal(mapOrEmpty(capabilities))
	if err != nil {
		return fmt.Errorf("marshal probed model capabilities: %w", err)
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin model protocol probe record: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := recordModelProtocolProbeTx(ctx, tx, tenantID, providerID, modelID, capabilitiesJSON, record); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit model protocol probe record: %w", err)
	}
	return nil
}

func recordModelProtocolProbeTx(ctx context.Context, tx pgx.Tx, tenantID, providerID, modelID string, capabilitiesJSON []byte, record ModelProtocolProbeRecord) error {
	if record.CredentialID != "" || record.SecretCiphertext != "" {
		var typ, base, auth, credentialID, ciphertext string
		err := tx.QueryRow(ctx, `SELECT p.provider_type,COALESCE(p.base_url,''),COALESCE(p.auth_mode,'api_key'),c.id,c.secret_ciphertext FROM providers p JOIN provider_credentials c ON c.provider_id=p.id AND c.status='active' WHERE p.id=$1 AND p.tenant_id=$2 AND p.status='active' FOR SHARE OF p,c`, providerID, tenantID).Scan(&typ, &base, &auth, &credentialID, &ciphertext)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrVerifiedModelSyncConflict
			}
			return err
		}
		if credentialID != record.CredentialID || ciphertext != record.SecretCiphertext || VerifiedModelSyncProviderConfigDigest(typ, base, auth) != record.ProviderConfigDigest {
			return ErrVerifiedModelSyncConflict
		}
	}

	commandTag, err := tx.Exec(ctx, `
UPDATE models AS m
SET capabilities_json = jsonb_set(
        COALESCE(m.capabilities_json, '{}'::jsonb) || ($1::jsonb - 'protocols'),
        '{protocols}',
        COALESCE(m.capabilities_json->'protocols', '{}'::jsonb)
          || COALESCE($1::jsonb->'protocols', '{}'::jsonb),
        true
    ),
    updated_at = NOW()
FROM providers AS p
WHERE m.id=$2 AND m.provider_id=$3 AND p.id=m.provider_id AND p.tenant_id=$4
`, string(capabilitiesJSON), modelID, providerID, tenantID)
	if err != nil {
		return fmt.Errorf("merge probed model capabilities: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf("model not found for tenant provider")
	}

	for _, endpoint := range record.Endpoints {
		evidenceJSON, marshalErr := json.Marshal(map[string]interface{}{
			"probe":      true,
			"error_kind": strings.TrimSpace(endpoint.ErrorKind),
		})
		if marshalErr != nil {
			return fmt.Errorf("marshal endpoint probe evidence: %w", marshalErr)
		}
		_, err = tx.Exec(ctx, `
INSERT INTO model_endpoint_capability_facts (
    id, tenant_id, provider_id, model_id, endpoint_type, state, source,
    source_version, provider_config_digest, generation, verified_at, expires_at,
    evidence_summary_json, created_at, updated_at
)
VALUES ($1,$2,$3,$4,$5,$6,'probe',$7,$8,1,$9,$10,$11::jsonb,NOW(),NOW())
ON CONFLICT (model_id, endpoint_type, source) DO UPDATE
SET state=EXCLUDED.state,
    source_version=EXCLUDED.source_version,
    provider_config_digest=EXCLUDED.provider_config_digest,
    generation=model_endpoint_capability_facts.generation + 1,
    verified_at=EXCLUDED.verified_at,
    expires_at=EXCLUDED.expires_at,
    evidence_summary_json=EXCLUDED.evidence_summary_json,
    updated_at=NOW()
WHERE EXCLUDED.verified_at >= model_endpoint_capability_facts.verified_at
`, "mecf_"+uuid.New().String(), tenantID, providerID, modelID, endpoint.EndpointType, endpoint.State,
			record.SourceVersion, record.ProviderConfigDigest, record.VerifiedAt, record.ExpiresAt, string(evidenceJSON))
		if err != nil {
			return fmt.Errorf("record %s protocol probe: %w", endpoint.EndpointType, err)
		}
	}
	return nil
}

func (r *ModelRepository) GetByIDForTenant(ctx context.Context, tenantID, modelID string) (*Model, error) {
	model, err := r.GetByID(ctx, modelID)
	if err != nil || model == nil {
		return model, err
	}
	var allowed bool
	if err := r.db.QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1 FROM models m JOIN providers p ON p.id=m.provider_id
  WHERE m.id=$1 AND p.tenant_id=$2
)
`, modelID, tenantID).Scan(&allowed); err != nil {
		return nil, fmt.Errorf("verify model tenant ownership: %w", err)
	}
	if !allowed {
		return nil, nil
	}
	return model, nil
}

func (r *ModelRepository) UpdateCapabilitiesAndOverrides(ctx context.Context, tenantID, actorUserID, modelID, capabilitiesJSON, reason string, protocols map[string]interface{}, clear []string) error {
	reason = strings.TrimSpace(reason)
	if len(protocols)+len(clear) == 0 {
		return r.UpdateCapabilities(ctx, modelID, capabilitiesJSON)
	}
	if reason == "" || len(reason) > 500 || strings.TrimSpace(actorUserID) == "" {
		return fmt.Errorf("capability override requires actor and reason")
	}
	endpointForProtocol := map[string]string{
		"chat_completions": "chat", "responses_native": "responses",
		"anthropic_messages": "messages", "images": "images",
		"gemini": "chat", "embeddings": "embeddings", "files": "files",
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin capability override: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var providerID string
	if err := tx.QueryRow(ctx, `
SELECT m.provider_id
FROM models m JOIN providers p ON p.id=m.provider_id
WHERE m.id=$1 AND p.tenant_id=$2
FOR UPDATE OF m
`, modelID, tenantID).Scan(&providerID); err != nil {
		return fmt.Errorf("lock tenant model for capability override: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE models SET capabilities_json=$1::jsonb, updated_at=NOW() WHERE id=$2`, capabilitiesJSON, modelID); err != nil {
		return fmt.Errorf("update model capability document: %w", err)
	}
	for protocol, raw := range protocols {
		endpoint, ok := endpointForProtocol[protocol]
		value, boolean := raw.(bool)
		if !ok || !boolean {
			return fmt.Errorf("invalid protocol capability override %q", protocol)
		}
		state := "unsupported"
		if value {
			state = "supported"
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO model_endpoint_capability_overrides
  (id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id,config_version,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,1,NOW(),NOW())
ON CONFLICT (model_id,endpoint_type) DO UPDATE
SET state=EXCLUDED.state, reason=EXCLUDED.reason, actor_user_id=EXCLUDED.actor_user_id,
    config_version=model_endpoint_capability_overrides.config_version+1, updated_at=NOW()
`, "meco_"+uuid.New().String(), tenantID, modelID, endpoint, state, reason, actorUserID); err != nil {
			return fmt.Errorf("upsert endpoint capability override: %w", err)
		}
	}
	for _, protocol := range clear {
		endpoint, ok := endpointForProtocol[strings.TrimSpace(protocol)]
		if !ok {
			return fmt.Errorf("invalid protocol capability override %q", protocol)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM model_endpoint_capability_overrides WHERE tenant_id=$1 AND model_id=$2 AND endpoint_type=$3`, tenantID, modelID, endpoint); err != nil {
			return fmt.Errorf("clear endpoint capability override: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit capability override: %w", err)
	}
	return nil
}

// UpdateStatus updates the status for a model
func (r *ModelRepository) UpdateStatus(ctx context.Context, modelID string, status string) error {
	query := `UPDATE models SET status = $1, updated_at = NOW() WHERE id = $2`
	result, err := r.db.Exec(ctx, query, status, modelID)
	if err != nil {
		return fmt.Errorf("failed to update model status: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("model not found")
	}
	return nil
}

// UpdateProxyConfig updates the proxy_config JSON field for a model.
func (r *ModelRepository) UpdateProxyConfig(ctx context.Context, modelID string, proxyConfigJSON string) error {
	query := `UPDATE models SET proxy_config = $1::jsonb WHERE id = $2`
	result, err := r.db.Exec(ctx, query, proxyConfigJSON, modelID)
	if err != nil {
		return fmt.Errorf("failed to update model proxy config: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("model not found")
	}
	return nil
}

// UpsertByProviderAndName creates or updates a model by provider_id and model_name.
// Returns true if created, false if updated.
func (r *ModelRepository) UpsertByProviderAndName(ctx context.Context, model *Model) (created bool, err error) {
	// First check if model exists
	existing, err := r.getByProviderAndName(ctx, model.ProviderID, model.ModelName)
	if err != nil {
		return false, err
	}

	if existing != nil {
		// Update existing model
		model.ID = existing.ID
		query := `
			UPDATE models
			SET model_label = $2, upstream_model_id = $3, context_window = $4, status = $5
			WHERE id = $1
		`
		_, err := r.db.Exec(ctx, query,
			model.ID,
			model.ModelLabel,
			nullableString(model.UpstreamModelID),
			model.ContextWindow,
			model.Status,
		)
		if err != nil {
			return false, fmt.Errorf("failed to update model: %w", err)
		}
		if err := r.upsertSyncedMessagesProbeFact(ctx, model); err != nil {
			return false, err
		}
		return false, nil
	}

	// Create new model
	if model.ID == "" {
		model.ID = "model_" + uuid.New().String()[:8]
	}

	// 把推断出的能力（modality）写进 capabilities_json；nil→{}（mapOrEmpty，向后兼容）。
	// 仅改 INSERT 新建路径；UPDATE 分支与 Create() 不动——避免再同步时覆盖 fallback handler
	// 写入的 routing 键（已存在行不回填，作为已知限制记录，非静默截断）。
	capJSON, _ := json.Marshal(mapOrEmpty(model.Capabilities))
	query := `
		INSERT INTO models (id, provider_id, model_name, model_label, upstream_model_id, capabilities_json, pricing_json, context_window, status)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, '{}', $7, $8)
	`

	_, err = r.db.Exec(ctx, query,
		model.ID,
		model.ProviderID,
		model.ModelName,
		model.ModelLabel,
		nullableString(model.UpstreamModelID),
		string(capJSON),
		model.ContextWindow,
		model.Status,
	)

	if err != nil {
		return false, fmt.Errorf("failed to create model: %w", err)
	}
	if err := r.upsertSyncedMessagesProbeFact(ctx, model); err != nil {
		return false, err
	}
	return true, nil
}

// upsertSyncedMessagesProbeFact records only a successful native Messages
// probe from catalog synchronization. It deliberately has lower precedence
// than administrator overrides and verified-sync facts, and expires if the
// upstream configuration later changes or the proof ages out.
func (r *ModelRepository) upsertSyncedMessagesProbeFact(ctx context.Context, model *Model) error {
	if !model.NativeMessagesProbed {
		return nil
	}
	protocols, _ := model.Capabilities["protocols"].(map[string]interface{})
	if protocols == nil || protocols["anthropic_messages"] != true {
		return nil
	}

	var tenantID, providerType, baseURL, authMode string
	if err := r.db.QueryRow(ctx, `
SELECT tenant_id, provider_type, COALESCE(base_url, ''), COALESCE(auth_mode, '')
FROM providers
WHERE id=$1
`, model.ProviderID).Scan(&tenantID, &providerType, &baseURL, &authMode); err != nil {
		return fmt.Errorf("load provider for Messages capability proof: %w", err)
	}
	digest := VerifiedModelSyncProviderConfigDigest(providerType, baseURL, authMode)
	_, err := r.db.Exec(ctx, `
INSERT INTO model_endpoint_capability_facts (
    id, tenant_id, provider_id, model_id, endpoint_type, state, source,
    source_version, provider_config_digest, generation, verified_at, expires_at,
    evidence_summary_json, created_at, updated_at
)
VALUES ($1,$2,$3,$4,'messages','supported','catalog_protocol_probe',
        'messages-v1',$5,1,NOW(),NOW()+INTERVAL '30 days',
        jsonb_build_object('protocol','anthropic_messages','probe','catalog_sync'),NOW(),NOW())
ON CONFLICT (model_id, endpoint_type, source) DO UPDATE
SET state='supported',
    source_version=EXCLUDED.source_version,
    provider_config_digest=EXCLUDED.provider_config_digest,
    generation=model_endpoint_capability_facts.generation + 1,
    verified_at=EXCLUDED.verified_at,
    expires_at=EXCLUDED.expires_at,
    evidence_summary_json=EXCLUDED.evidence_summary_json,
    updated_at=NOW()
`, "mecf_"+uuid.New().String(), tenantID, model.ProviderID, model.ID, digest)
	if err != nil {
		return fmt.Errorf("record native Messages capability proof: %w", err)
	}
	return nil
}

// MergeVerifiedProviderModels enables or refreshes the verified models of one
// Azure provider in a single transaction. It is additive: models that are not
// part of this batch keep their current status, so verifying deployments one by
// one (or a transient probe failure on an already enabled model) never disables
// anything. Disabling a model is an explicit action in model management.
// Existing capability keys are preserved unless desired explicitly overwrites them.
func (r *ModelRepository) MergeVerifiedProviderModels(ctx context.Context, tenantID, providerID, expectedCredentialID, expectedProviderConfigDigest string, desired []VerifiedProviderModel) (VerifiedModelSyncResult, error) {
	var result VerifiedModelSyncResult
	if expectedCredentialID == "" {
		return result, fmt.Errorf("%w: expected credential id must not be empty", ErrVerifiedModelSyncConflict)
	}
	if !validVerifiedModelSyncDigest(expectedProviderConfigDigest) {
		return result, fmt.Errorf("%w: invalid verified-model snapshot digest", ErrVerifiedModelSyncConflict)
	}
	if len(desired) == 0 {
		return result, fmt.Errorf("%w: verified model set must not be empty", ErrVerifiedModelSyncConflict)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("begin verified model replacement: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	var lockedProviderID, providerType, baseURL, authMode, providerStatus string
	err = tx.QueryRow(ctx, `
        SELECT id, provider_type, COALESCE(base_url, ''), COALESCE(auth_mode, ''), status
        FROM providers
        WHERE id=$1 AND tenant_id=$2
        FOR UPDATE
    `, providerID, tenantID).Scan(&lockedProviderID, &providerType, &baseURL, &authMode, &providerStatus)
	if err != nil {
		if err == pgx.ErrNoRows {
			return VerifiedModelSyncResult{}, fmt.Errorf("%w: provider does not belong to tenant", ErrVerifiedModelSyncConflict)
		}
		return VerifiedModelSyncResult{}, fmt.Errorf("lock provider for verified model replacement: %w", err)
	}
	if providerType != "azure" || providerStatus != "active" {
		return VerifiedModelSyncResult{}, fmt.Errorf("%w: provider must be an active azure provider", ErrVerifiedModelSyncConflict)
	}
	if VerifiedModelSyncProviderConfigDigest(providerType, baseURL, authMode) != expectedProviderConfigDigest {
		return VerifiedModelSyncResult{}, fmt.Errorf("%w: provider connection configuration changed", ErrVerifiedModelSyncConflict)
	}

	var currentCredentialID string
	err = tx.QueryRow(ctx, `
        SELECT id
        FROM provider_credentials
        WHERE provider_id=$1 AND status='active'
        ORDER BY created_at DESC
        LIMIT 1
        FOR UPDATE
    `, providerID).Scan(&currentCredentialID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return VerifiedModelSyncResult{}, fmt.Errorf("%w: provider has no active credential", ErrVerifiedModelSyncConflict)
		}
		return VerifiedModelSyncResult{}, fmt.Errorf("lock current provider credential: %w", err)
	}
	if currentCredentialID != expectedCredentialID {
		return VerifiedModelSyncResult{}, fmt.Errorf("%w: provider credential changed", ErrVerifiedModelSyncConflict)
	}

	canonical, err := canonicalVerifiedProviderModels(desired)
	if err != nil {
		return VerifiedModelSyncResult{}, err
	}
	// Lock every model row of the provider in id order before touching any of
	// them; provider soft delete takes the same locks in the same order.
	lockedModels, err := tx.Query(ctx, `
SELECT id
FROM models
WHERE provider_id=$1
ORDER BY id
FOR UPDATE
`, providerID)
	if err != nil {
		return VerifiedModelSyncResult{}, fmt.Errorf("lock provider models for duplicate check: %w", err)
	}
	lockedModels.Close()
	if lockedModelsErr := lockedModels.Err(); lockedModelsErr != nil {
		return VerifiedModelSyncResult{}, fmt.Errorf("iterate provider model locks: %w", lockedModelsErr)
	}
	var duplicateModelName string
	duplicateErr := tx.QueryRow(ctx, `
        SELECT model_name
        FROM models
        WHERE provider_id=$1
        GROUP BY model_name
        HAVING count(*) > 1
        LIMIT 1
    `, providerID).Scan(&duplicateModelName)
	if duplicateErr == nil {
		return VerifiedModelSyncResult{}, fmt.Errorf("%w: duplicate existing provider model rows", ErrVerifiedModelSyncConflict)
	}
	if duplicateErr != pgx.ErrNoRows {
		return VerifiedModelSyncResult{}, fmt.Errorf("check duplicate provider models: %w", duplicateErr)
	}

	for _, item := range canonical {
		modelID := ""

		rows, queryErr := tx.Query(ctx, `
SELECT id, status, capabilities_json
FROM models
WHERE provider_id = $1 AND model_name = $2
FOR UPDATE
`, providerID, item.CatalogID)
		if queryErr != nil {
			return VerifiedModelSyncResult{}, fmt.Errorf("lock existing verified model: %w", queryErr)
		}
		type existingModel struct {
			id           string
			status       string
			capabilities []byte
		}
		existing := make([]existingModel, 0, 2)
		for rows.Next() {
			var model existingModel
			if scanErr := rows.Scan(&model.id, &model.status, &model.capabilities); scanErr != nil {
				rows.Close()
				return VerifiedModelSyncResult{}, fmt.Errorf("scan existing verified model: %w", scanErr)
			}
			existing = append(existing, model)
		}
		rowsErr := rows.Err()
		rows.Close()
		if rowsErr != nil {
			return VerifiedModelSyncResult{}, fmt.Errorf("iterate existing verified models: %w", rowsErr)
		}
		if len(existing) > 1 {
			return VerifiedModelSyncResult{}, fmt.Errorf("%w: duplicate existing provider model rows", ErrVerifiedModelSyncConflict)
		}

		if len(existing) == 0 {
			capabilities := item.Capabilities
			if capabilities == nil {
				capabilities = map[string]interface{}{}
			}
			capabilitiesJSON, marshalErr := json.Marshal(capabilities)
			if marshalErr != nil {
				return VerifiedModelSyncResult{}, fmt.Errorf("encode verified model capabilities: %w", marshalErr)
			}
			modelID = "model_" + uuid.New().String()
			_, insertErr := tx.Exec(ctx, `
INSERT INTO models (
id, provider_id, model_name, model_label, upstream_model_id,
capabilities_json, pricing_json, status, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, '{}'::jsonb, 'active', NOW())
`, modelID, providerID, item.CatalogID, item.ModelLabel,
				nullableString(item.DeploymentName), string(capabilitiesJSON))
			if insertErr != nil {
				return VerifiedModelSyncResult{}, fmt.Errorf("create verified provider model: %w", insertErr)
			}
			result.Created++
		} else {
			modelID = existing[0].id
			capabilities := map[string]interface{}{}
			if len(existing[0].capabilities) > 0 {
				if decodeErr := json.Unmarshal(existing[0].capabilities, &capabilities); decodeErr != nil {
					return VerifiedModelSyncResult{}, fmt.Errorf("decode existing model capabilities: %w", decodeErr)
				}
				if capabilities == nil {
					capabilities = map[string]interface{}{}
				}
			}
			capabilities = mergeVerifiedModelCapabilities(capabilities, item.Capabilities)
			capabilitiesJSON, marshalErr := json.Marshal(capabilities)
			if marshalErr != nil {
				return VerifiedModelSyncResult{}, fmt.Errorf("encode verified model capabilities: %w", marshalErr)
			}
			if existing[0].status != "active" && existing[0].status != "disabled" {
				return VerifiedModelSyncResult{}, fmt.Errorf("%w: existing provider model has unsupported status", ErrVerifiedModelSyncConflict)
			}
			_, updateErr := tx.Exec(ctx, `
UPDATE models
SET model_label = $2,
upstream_model_id = $3,
capabilities_json = $4::jsonb,
status = 'active',
updated_at = NOW()
WHERE id = $1
`, existing[0].id, item.ModelLabel, nullableString(item.DeploymentName), string(capabilitiesJSON))
			if updateErr != nil {
				return VerifiedModelSyncResult{}, fmt.Errorf("update verified provider model: %w", updateErr)
			}
			if existing[0].status == "disabled" {
				result.Reactivated++
			} else {
				result.Updated++
			}
		}
		if err := upsertVerifiedEndpointFacts(ctx, tx, tenantID, providerID, modelID, expectedProviderConfigDigest, item); err != nil {
			return VerifiedModelSyncResult{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return VerifiedModelSyncResult{}, fmt.Errorf("commit verified model replacement: %w", err)
	}
	committed = true
	return result, nil
}

func canonicalVerifiedProviderModels(desired []VerifiedProviderModel) ([]VerifiedProviderModel, error) {
	byCatalogID := make(map[string]VerifiedProviderModel, len(desired))
	for _, item := range desired {
		if item.CatalogID == "" {
			return nil, fmt.Errorf("%w: verified model catalog id must not be empty", ErrVerifiedModelSyncConflict)
		}
		if existing, ok := byCatalogID[item.CatalogID]; ok {
			if existing.DeploymentName != item.DeploymentName ||
				existing.ModelLabel != item.ModelLabel ||
				!reflect.DeepEqual(existing.Capabilities, item.Capabilities) ||
				!reflect.DeepEqual(existing.Protocols, item.Protocols) ||
				existing.SourceVersion != item.SourceVersion ||
				!existing.VerifiedAt.Equal(item.VerifiedAt) || !existing.ExpiresAt.Equal(item.ExpiresAt) {
				return nil, fmt.Errorf("%w: conflicting duplicate verified model", ErrVerifiedModelSyncConflict)
			}
			continue
		}
		byCatalogID[item.CatalogID] = item
	}
	canonical := make([]VerifiedProviderModel, 0, len(byCatalogID))
	for _, item := range byCatalogID {
		canonical = append(canonical, item)
	}
	sort.Slice(canonical, func(i, j int) bool {
		return canonical[i].CatalogID < canonical[j].CatalogID
	})
	return canonical, nil
}

func upsertVerifiedEndpointFacts(ctx context.Context, tx pgx.Tx, tenantID, providerID, modelID, providerConfigDigest string, item VerifiedProviderModel) error {
	supported := make(map[string]bool, len(item.Protocols))
	for _, protocol := range item.Protocols {
		switch protocol {
		case "chat_completions":
			supported["chat"] = true
		case "responses_native":
			supported["responses"] = true
		case "anthropic_messages":
			supported["messages"] = true
		case "images", "embeddings", "files":
			supported[protocol] = true
		}
	}
	for _, endpoint := range []string{"chat", "responses", "messages", "images", "embeddings", "files"} {
		state := "unknown"
		if supported[endpoint] {
			state = "supported"
		}
		_, err := tx.Exec(ctx, `
INSERT INTO model_endpoint_capability_facts (
    id, tenant_id, provider_id, model_id, endpoint_type, state, source,
    source_version, provider_config_digest, generation, verified_at, expires_at,
    evidence_summary_json, created_at, updated_at
)
VALUES ($1,$2,$3,$4,$5,$6,'verified_sync',$7,$8,1,$9,$10,
        jsonb_build_object('verified', true),NOW(),NOW())
ON CONFLICT (model_id, endpoint_type, source) DO UPDATE
SET state=EXCLUDED.state,
    source_version=EXCLUDED.source_version,
    provider_config_digest=EXCLUDED.provider_config_digest,
    generation=model_endpoint_capability_facts.generation + 1,
    verified_at=EXCLUDED.verified_at,
    expires_at=EXCLUDED.expires_at,
    evidence_summary_json=EXCLUDED.evidence_summary_json,
    updated_at=NOW()
WHERE EXCLUDED.verified_at >= model_endpoint_capability_facts.verified_at
  AND (EXCLUDED.source_version <> model_endpoint_capability_facts.source_version
       OR EXCLUDED.provider_config_digest <> model_endpoint_capability_facts.provider_config_digest
       OR EXCLUDED.state <> model_endpoint_capability_facts.state)
`, "mecf_"+uuid.New().String(), tenantID, providerID, modelID, endpoint, state,
			item.SourceVersion, providerConfigDigest, item.VerifiedAt, item.ExpiresAt)
		if err != nil {
			return fmt.Errorf("upsert verified endpoint capability %s: %w", endpoint, err)
		}
	}
	return nil
}

// getByProviderAndName retrieves a model by provider_id and model_name
func (r *ModelRepository) getByProviderAndName(ctx context.Context, providerID, modelName string) (*Model, error) {
	query := `
		SELECT id, provider_id, model_name, COALESCE(model_label, ''), COALESCE(upstream_model_id, ''), capabilities_json, pricing_json, proxy_config, COALESCE(context_window, 0), status, created_at
		FROM models
		WHERE provider_id = $1 AND model_name = $2
	`

	row := r.db.QueryRow(ctx, query, providerID, modelName)
	var model Model
	var capabilitiesJSON, pricingJSON, proxyConfigJSON []byte
	err := row.Scan(
		&model.ID,
		&model.ProviderID,
		&model.ModelName,
		&model.ModelLabel,
		&model.UpstreamModelID,
		&capabilitiesJSON,
		&pricingJSON,
		&proxyConfigJSON,
		&model.ContextWindow,
		&model.Status,
		&model.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get model: %w", err)
	}

	model.Capabilities = parseJSONMap(capabilitiesJSON)
	model.Pricing = parseJSONMap(pricingJSON)
	model.ProxyConfig = parseJSONMap(proxyConfigJSON)

	return &model, nil
}

// Delete removes a model by ID
func (r *ModelRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM models WHERE id = $1`
	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete model: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("model not found")
	}
	return nil
}

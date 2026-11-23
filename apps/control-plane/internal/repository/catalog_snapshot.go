package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelcatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrCatalogSyncConflict = errors.New("catalog sync is in progress or snapshot changed")

type CatalogSnapshotModel struct {
	ID, Name, Description string
	Capabilities          map[string]interface{}
	Approved              bool
	// Reused 表示勾选了但没有重新探测：模型已纳入，库里的探测证据在有效期内且渠道配置未变。
	Reused           bool
	Probe            *ModelProtocolProbeRecord
	ProbeFailure     string
	HealthObservedAt time.Time
}
type CatalogSnapshotInput struct {
	TenantID, CredentialID, LeaseToken, Source string
	Provider                                   *Provider
	Models                                     []CatalogSnapshotModel
	SelectedIDs                                []string
}
type CatalogProbeFailure struct {
	ModelID         string `json:"model_id"`
	UpstreamModelID string `json:"upstream_model_id"`
	Reason          string `json:"reason"`
}
type CatalogSnapshotResult struct {
	Created              int                   `json:"created"`
	Updated              int                   `json:"updated"`
	Deactivated          int                   `json:"deactivated"`
	Reappeared           int                   `json:"reappeared"`
	Skipped              int                   `json:"skipped"`
	Verified             int                   `json:"verified"`
	VerificationFailed   int                   `json:"verification_failed"`
	TotalSeen            int                   `json:"total_seen"`
	Pending              int                   `json:"pending"`
	Reused               int                   `json:"reused"`
	SelectedMatched      int                   `json:"selected_matched"`
	NotFoundModelIDs     []string              `json:"not_found_model_ids,omitempty"`
	VerificationFailures []CatalogProbeFailure `json:"verification_failures"`
	RemovedIDs           []string              `json:"removed_model_ids"`
	SyncedAt             time.Time             `json:"synced_at"`
}

// Catalog discovery alone remains a preview candidate. Only selected
// models with current successful endpoint evidence enter managed inventory.
func catalogSnapshotAdmissionVerified(item CatalogSnapshotModel) bool {
	if !item.Approved || item.Probe == nil || !item.Probe.ExpiresAt.After(time.Now()) {
		return false
	}
	for _, endpoint := range item.Probe.Endpoints {
		if endpoint.EndpointType != "" && endpoint.State == "supported" {
			return true
		}
	}
	return false
}

type CatalogSyncState struct {
	IntervalSeconds int             `json:"interval_seconds"`
	Status          string          `json:"status"`
	Error           string          `json:"error"`
	StartedAt       *time.Time      `json:"started_at"`
	FinishedAt      *time.Time      `json:"finished_at"`
	SuccessAt       *time.Time      `json:"success_at"`
	Result          json.RawMessage `json:"result"`
}

func (r *ModelRepository) BeginCatalogSync(ctx context.Context, tenantID, providerID string) (string, error) {
	_, err := r.db.Exec(ctx, `INSERT INTO model_catalog_sync_state(provider_id,tenant_id)
 SELECT id,tenant_id FROM providers WHERE id=$1 AND tenant_id=$2 AND status='active' ON CONFLICT DO NOTHING`, providerID, tenantID)
	if err != nil {
		return "", err
	}
	token := uuid.New().String()
	tag, err := r.db.Exec(ctx, `WITH claimed AS (
 UPDATE model_catalog_sync_state SET lease_token=$3,lease_expires_at=NOW()+INTERVAL '15 minutes',last_started_at=NOW(),last_status='running',last_error=''
 WHERE provider_id=$1 AND tenant_id=$2 AND (lease_token IS NULL OR lease_expires_at<NOW()) RETURNING last_started_at
 ), expired AS (
 UPDATE model_catalog_sync_runs SET status='failed',error_code='lease_expired',finished_at=NOW(),result=jsonb_build_object('failed',1)
 WHERE provider_id=$1 AND tenant_id=$2 AND status='running' AND id<>$3 AND EXISTS(SELECT 1 FROM claimed)
 ) INSERT INTO model_catalog_sync_runs(id,tenant_id,provider_id,source,started_at,status)
 SELECT $3,$2,$1,'catalog',last_started_at,'running' FROM claimed`, providerID, tenantID, token)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", ErrCatalogSyncConflict
	}
	return token, nil
}
func (r *ModelRepository) FailCatalogSync(ctx context.Context, tenantID, providerID, token, code string) error {
	tag, err := r.db.Exec(ctx, `WITH released AS (
 UPDATE model_catalog_sync_state SET lease_token=NULL,lease_expires_at=NULL,last_finished_at=NOW(),last_status='failed',last_error=$4,next_sync_at=NOW()+make_interval(secs=>interval_seconds)
 WHERE provider_id=$1 AND tenant_id=$2 AND lease_token=$3 RETURNING last_started_at)
 INSERT INTO model_catalog_sync_runs(id,tenant_id,provider_id,source,started_at,status,error_code)
 SELECT $3,$2,$1,'catalog',last_started_at,'failed',$4 FROM released ON CONFLICT(id) DO UPDATE SET status='failed',error_code=EXCLUDED.error_code,finished_at=NOW(),result=jsonb_build_object('failed',1)`, providerID, tenantID, token, code)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrCatalogSyncConflict
	}
	return nil
}
func (r *ModelRepository) CatalogSyncState(ctx context.Context, tenantID, providerID string) (CatalogSyncState, error) {
	state := CatalogSyncState{IntervalSeconds: 3600, Status: "never", Result: json.RawMessage(`{}`)}
	err := r.db.QueryRow(ctx, `SELECT interval_seconds,last_status,last_error,last_started_at,last_finished_at,last_success_at,last_result FROM model_catalog_sync_state WHERE provider_id=$1 AND tenant_id=$2`, providerID, tenantID).Scan(&state.IntervalSeconds, &state.Status, &state.Error, &state.StartedAt, &state.FinishedAt, &state.SuccessAt, &state.Result)
	if err == pgx.ErrNoRows {
		return state, nil
	}
	return state, err
}
func (r *ModelRepository) SetCatalogSyncInterval(ctx context.Context, tenantID, providerID string, seconds int) error {
	if seconds != 0 && (seconds < 300 || seconds > 86400) {
		return fmt.Errorf("interval must be 0 or 300..86400 seconds")
	}
	tag, err := r.db.Exec(ctx, `INSERT INTO model_catalog_sync_state(provider_id,tenant_id,interval_seconds)
 SELECT id,tenant_id,$3 FROM providers WHERE id=$1 AND tenant_id=$2 ON CONFLICT(provider_id) DO UPDATE SET interval_seconds=$3`, providerID, tenantID, seconds)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrCatalogSyncConflict
	}
	return nil
}
func (r *ModelRepository) ApplyCatalogSnapshot(ctx context.Context, input CatalogSnapshotInput) (CatalogSnapshotResult, error) {
	result := CatalogSnapshotResult{TotalSeen: len(input.Models), RemovedIDs: []string{}, VerificationFailures: []CatalogProbeFailure{}}
	if input.Provider == nil || input.TenantID == "" || input.LeaseToken == "" || input.CredentialID == "" {
		return result, ErrCatalogSyncConflict
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	var token string
	var alive bool
	var started time.Time
	err = tx.QueryRow(ctx, `SELECT COALESCE(lease_token,''),lease_expires_at>NOW(),last_started_at FROM model_catalog_sync_state WHERE provider_id=$1 AND tenant_id=$2 FOR UPDATE`, input.Provider.ID, input.TenantID).Scan(&token, &alive, &started)
	if err != nil || !alive || token != input.LeaseToken {
		return result, ErrCatalogSyncConflict
	}
	var pt, base, mode, status string
	err = tx.QueryRow(ctx, `SELECT provider_type,COALESCE(base_url,''),COALESCE(auth_mode,''),status FROM providers WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, input.Provider.ID, input.TenantID).Scan(&pt, &base, &mode, &status)
	if err != nil || status != "active" || VerifiedModelSyncProviderConfigDigest(pt, base, mode) != VerifiedModelSyncProviderConfigDigest(input.Provider.ProviderType, input.Provider.BaseURL, input.Provider.AuthMode) {
		return result, ErrCatalogSyncConflict
	}
	var credential string
	err = tx.QueryRow(ctx, `SELECT id FROM provider_credentials WHERE provider_id=$1 AND status='active' ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, input.Provider.ID).Scan(&credential)
	if err != nil || credential != input.CredentialID {
		return result, ErrCatalogSyncConflict
	}
	seen := make([]string, 0, len(input.Models))
	unique := map[string]bool{}
	for _, item := range input.Models {
		if item.ID == "" || unique[item.ID] {
			return result, fmt.Errorf("invalid snapshot identity")
		}
		unique[item.ID] = true
		seen = append(seen, item.ID)
		admitted := catalogSnapshotAdmissionVerified(item)
		createdModel := false
		var modelID string
		var present bool
		var restore string
		err = tx.QueryRow(ctx, `SELECT COALESCE(model_id,''),present,restore_status FROM model_catalog_entries WHERE provider_id=$1 AND upstream_model_id=$2 FOR UPDATE`, input.Provider.ID, item.ID).Scan(&modelID, &present, &restore)
		if err != nil && err != pgx.ErrNoRows {
			return result, err
		}
		isNew := err == pgx.ErrNoRows
		if !isNew && !present {
			result.Reappeared++
		}
		if !isNew && !present && modelID != "" {
			if _, err = tx.Exec(ctx, `UPDATE models SET status='active',updated_at=NOW() WHERE provider_id=$1 AND COALESCE(NULLIF(upstream_model_id,''),model_name)=$2 AND id<>$3 AND status='upstream_removed'`, input.Provider.ID, item.ID, modelID); err != nil {
				return result, err
			}
		}
		if modelID == "" {
			var manual bool
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM models WHERE provider_id=$1 AND (COALESCE(NULLIF(upstream_model_id,''),model_name)=$2 OR model_name=$3))`, input.Provider.ID, item.ID, item.Name).Scan(&manual)
			if err != nil {
				return result, err
			}
			if manual {
				result.Skipped++
			} else if !admitted {
				if item.Approved {
					result.VerificationFailed++
					reason := item.ProbeFailure
					if reason == "" {
						reason = "not_verified"
					}
					result.VerificationFailures = append(result.VerificationFailures, CatalogProbeFailure{UpstreamModelID: item.ID, Reason: reason})
				} else {
					result.Skipped++
				}
			} else {
				modelID = "model_" + uuid.New().String()
				caps, err := json.Marshal(mapOrEmpty(item.Capabilities))
				if err != nil {
					return result, err
				}
				name := item.Name
				if name == "" {
					name = item.ID
				}
				_, err = tx.Exec(ctx, `INSERT INTO models(id,provider_id,model_name,model_label,upstream_model_id,capabilities_json,pricing_json,status,updated_at) VALUES($1,$2,$3::text,$3::text,$4,$5::jsonb,'{}','pending',NOW())`, modelID, input.Provider.ID, name, item.ID, string(caps))
				if err != nil {
					return result, err
				}
				result.Created++
				createdModel = true
				restore = "pending"
			}
		}
		if modelID != "" {
			var oldStatus string
			var oldCaps []byte
			err = tx.QueryRow(ctx, `SELECT status,capabilities_json FROM models WHERE id=$1 AND provider_id=$2 FOR UPDATE`, modelID, input.Provider.ID).Scan(&oldStatus, &oldCaps)
			if err != nil {
				return result, err
			}
			nextStatus := oldStatus
			if oldStatus == "upstream_removed" {
				nextStatus = restore
			}
			caps := mergeVerifiedModelCapabilities(parseJSONMap(oldCaps), item.Capabilities)
			if admitted {
				if nextStatus == "pending" {
					nextStatus = "active"
				}
				encoded, err := json.Marshal(caps)
				if err != nil {
					return result, err
				}
				if err = recordModelProtocolProbeTx(ctx, tx, input.TenantID, input.Provider.ID, modelID, encoded, *item.Probe); err != nil {
					return result, err
				}
				result.Verified++
			} else if item.Reused {
				// 已纳入且证据仍有效：本次没有新探测，沿用库里的端点证据和健康快照。
				result.Reused++
			} else if item.Approved {
				result.VerificationFailed++
				reason := item.ProbeFailure
				if reason == "" {
					reason = "not_verified"
				}
				result.VerificationFailures = append(result.VerificationFailures, CatalogProbeFailure{ModelID: modelID, UpstreamModelID: item.ID, Reason: reason})
			}
			if item.Probe != nil || item.ProbeFailure != "" {
				health := "healthy"
				if item.ProbeFailure != "" {
					health = "unknown"
					for _, reason := range strings.Split(item.ProbeFailure, "/") {
						if reason == "unauthorized" || reason == "rate_limited" || reason == "timeout" || reason == "upstream_error" || reason == "not_deployed" {
							health = "unhealthy"
						}
					}
				}
				_, err = tx.Exec(ctx, `INSERT INTO model_route_health_snapshots(tenant_id,model_name,provider_id,state,version,observed_at,expires_at,source_instance,failure_category)
 SELECT DISTINCT $1,m.model_name,$2,$4,1,$7::timestamptz,$7::timestamptz+INTERVAL '15 minutes',$5,$6 FROM models m WHERE m.provider_id=$2 AND COALESCE(NULLIF(m.upstream_model_id,''),m.model_name)=$3 AND m.status<>'deleted'
 ON CONFLICT(tenant_id,model_name,provider_id) DO UPDATE SET state=EXCLUDED.state,version=model_route_health_snapshots.version+1,observed_at=EXCLUDED.observed_at,expires_at=EXCLUDED.expires_at,source_instance=EXCLUDED.source_instance,failure_category=EXCLUDED.failure_category,updated_at=NOW() WHERE EXCLUDED.observed_at>=model_route_health_snapshots.observed_at`, input.TenantID, input.Provider.ID, item.ID, health, "catalog-sync:"+input.LeaseToken, item.ProbeFailure, item.HealthObservedAt)
				if err != nil {
					return result, err
				}
			}
			if nextStatus == "pending" {
				result.Pending++
			}
			if item.Name != "" {
				_, err = tx.Exec(ctx, `UPDATE models SET model_label=$2,status=$3,updated_at=NOW() WHERE id=$1`, modelID, item.Name, nextStatus)
			} else {
				_, err = tx.Exec(ctx, `UPDATE models SET status=$2,updated_at=NOW() WHERE id=$1`, modelID, nextStatus)
			}
			if err != nil {
				return result, err
			}
			if !createdModel {
				result.Updated++
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO model_catalog_entries(provider_id,upstream_model_id,model_id,display_name,description,present,restore_status)
 VALUES($1,$2,NULLIF($3,''),$4,$5,true,$6) ON CONFLICT(provider_id,upstream_model_id) DO UPDATE SET model_id=EXCLUDED.model_id,display_name=EXCLUDED.display_name,description=EXCLUDED.description,present=true,last_seen_at=NOW(),removed_at=NULL`, input.Provider.ID, item.ID, modelID, item.Name, item.Description, restore)
		if err != nil {
			return result, err
		}
	}
	for _, id := range input.SelectedIDs {
		if unique[id] {
			result.SelectedMatched++
		} else {
			result.NotFoundModelIDs = append(result.NotFoundModelIDs, id)
		}
	}
	rows, err := tx.Query(ctx, `SELECT upstream_model_id,COALESCE(model_id,'') FROM model_catalog_entries WHERE provider_id=$1 AND present AND NOT(upstream_model_id=ANY($2::text[])) ORDER BY upstream_model_id FOR UPDATE`, input.Provider.ID, seen)
	if err != nil {
		return result, err
	}
	type removed struct{ id, model string }
	removedItems := []removed{}
	for rows.Next() {
		var x removed
		if err = rows.Scan(&x.id, &x.model); err != nil {
			rows.Close()
			return result, err
		}
		removedItems = append(removedItems, x)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	for _, x := range removedItems {
		restore := "pending"
		if x.model != "" {
			if err = tx.QueryRow(ctx, `SELECT status FROM models WHERE id=$1 FOR UPDATE`, x.model).Scan(&restore); err != nil {
				return result, err
			}
			aliasRows, queryErr := tx.Query(ctx, `SELECT id,status FROM models WHERE provider_id=$1 AND COALESCE(NULLIF(upstream_model_id,''),model_name)=$2 AND status<>'deleted' ORDER BY id FOR UPDATE`, input.Provider.ID, x.id)
			if queryErr != nil {
				return result, queryErr
			}
			type alias struct{ id, status string }
			aliases := []alias{}
			for aliasRows.Next() {
				var item alias
				if err = aliasRows.Scan(&item.id, &item.status); err != nil {
					aliasRows.Close()
					return result, err
				}
				aliases = append(aliases, item)
			}
			err = aliasRows.Err()
			aliasRows.Close()
			if err != nil {
				return result, err
			}
			for _, item := range aliases {
				if item.status == "active" {
					if _, err = tx.Exec(ctx, `UPDATE models SET status='upstream_removed',updated_at=NOW() WHERE id=$1`, item.id); err != nil {
						return result, err
					}
				}
				result.Deactivated++
				result.RemovedIDs = append(result.RemovedIDs, item.id)
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE model_catalog_entries SET present=false,restore_status=$3,removed_at=NOW() WHERE provider_id=$1 AND upstream_model_id=$2`, input.Provider.ID, x.id, restore); err != nil {
			return result, err
		}
	}
	result.SyncedAt = time.Now().UTC()
	encoded, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	if input.Source == "" {
		input.Source = "manual"
	}
	_, err = tx.Exec(ctx, `INSERT INTO model_catalog_sync_runs(id,tenant_id,provider_id,source,started_at,status,result) VALUES($1,$2,$3,$4,$5,'success',$6::jsonb) ON CONFLICT(id) DO UPDATE SET source=EXCLUDED.source,status='success',error_code='',result=EXCLUDED.result,finished_at=NOW()`, input.LeaseToken, input.TenantID, input.Provider.ID, input.Source, started, string(encoded))
	if err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `UPDATE model_catalog_sync_state SET lease_token=NULL,lease_expires_at=NULL,last_finished_at=NOW(),last_success_at=NOW(),next_sync_at=NOW()+make_interval(secs=>interval_seconds),last_status='success',last_error='',last_result=$2::jsonb WHERE provider_id=$1`, input.Provider.ID, string(encoded))
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return CatalogSnapshotResult{}, err
	}
	return result, nil
}
func (r *ModelRepository) CatalogModelPresent(ctx context.Context, modelID string) (bool, error) {
	var present bool
	err := r.db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM model_catalog_entries c JOIN models m ON m.provider_id=c.provider_id AND COALESCE(NULLIF(m.upstream_model_id,''),m.model_name)=c.upstream_model_id WHERE m.id=$1 AND c.model_id IS NOT NULL AND NOT c.present)`, modelID).Scan(&present)
	return present, err
}

func (r *ModelRepository) ModelAvailability(ctx context.Context, tenantID string) (map[string]modelcatalog.Availability, error) {
	return modelcatalog.Load(ctx, r.db, tenantID)
}

// CatalogModelsWithValidProbe 返回该渠道目录里已纳入、且探测证据仍可沿用的上游模型标识：
// 至少一个端点由探测判定为 supported、未过期（留 1 天余量），并且是在当前渠道配置
// （类型、地址、鉴权方式）下取得的；当前健康快照为 unhealthy 的不沿用（之后探测失败过，要重验）。
// 目录同步据此跳过这些模型的重复推理调用。
func (r *ModelRepository) CatalogModelsWithValidProbe(ctx context.Context, tenantID string, provider *Provider) (map[string]bool, error) {
	digest := VerifiedModelSyncProviderConfigDigest(provider.ProviderType, provider.BaseURL, provider.AuthMode)
	rows, err := r.db.Query(ctx, `SELECT DISTINCT c.upstream_model_id
 FROM model_catalog_entries c
 JOIN models m ON m.id=c.model_id AND m.provider_id=c.provider_id AND m.status<>'deleted'
 JOIN providers p ON p.id=c.provider_id AND p.tenant_id=$1
 JOIN model_endpoint_capability_facts f ON f.model_id=m.id AND f.source='probe' AND f.state='supported'
 LEFT JOIN model_route_health_snapshots h ON h.tenant_id=p.tenant_id AND h.provider_id=p.id AND h.model_name=m.model_name AND h.expires_at>NOW()
 WHERE c.provider_id=$2 AND c.present AND f.provider_config_digest=$3 AND f.expires_at > NOW() + INTERVAL '1 day'
   AND COALESCE(h.state,'unknown')<>'unhealthy'`, tenantID, provider.ID, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

var ErrCatalogModelUnavailable = errors.New("model was removed upstream and cannot be enabled")

// Manual status changes serialize with snapshot commits through the same
// provider row; a stale presence check cannot reopen a just-removed route.
func (r *ModelRepository) UpdateCatalogModelStatus(ctx context.Context, tenantID, modelID, status string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var providerID string
	if err = tx.QueryRow(ctx, `SELECT p.id FROM providers p JOIN models m ON m.provider_id=p.id WHERE m.id=$1 AND p.tenant_id=$2 FOR UPDATE OF p`, modelID, tenantID).Scan(&providerID); err != nil {
		return err
	}
	var current string
	var present bool
	var proved bool
	if err = tx.QueryRow(ctx, `SELECT m.status,NOT EXISTS(SELECT 1 FROM model_catalog_entries c WHERE c.provider_id=m.provider_id AND c.upstream_model_id=COALESCE(NULLIF(m.upstream_model_id,''),m.model_name) AND c.model_id IS NOT NULL AND NOT c.present),EXISTS(SELECT 1 FROM model_endpoint_capability_effective ec WHERE ec.model_id=m.id AND ec.state='supported') FROM models m WHERE m.id=$1 FOR UPDATE`, modelID).Scan(&current, &present, &proved); err != nil {
		return err
	}
	// 启用由管理员决定；探测是否通过只作建议（proved 仅用于展示），上游已下架才拒绝。
	_ = proved
	if status == "active" && !present {
		return ErrCatalogModelUnavailable
	}
	if _, err = tx.Exec(ctx, `UPDATE models SET status=$2,updated_at=NOW() WHERE id=$1`, modelID, status); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

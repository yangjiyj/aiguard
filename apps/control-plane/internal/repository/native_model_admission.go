package repository

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// NativeModelAdmissionSnapshot binds the pre-probe model mapping and the exact
// logical/deployment names that produced the generation evidence.
type NativeModelAdmissionSnapshot struct {
	ModelName          string
	ProbedDeployment   string
	ExistingModelID    string
	ExistingDeployment string
	ExistingStatus     string
}

// UpsertNativeVerifiedModel publishes one model mapping and its proof together.
// Concurrent provider credential/configuration changes or model edits make the
// entire operation fail without modifying an existing routable model.
func (r *ModelRepository) UpsertNativeVerifiedModel(ctx context.Context, tenant string, model *Model, record ModelProtocolProbeRecord, snapshot NativeModelAdmissionSnapshot) (bool, error) {
	if model == nil || tenant == "" || model.ProviderID == "" || model.ModelName == "" || snapshot.ModelName != model.ModelName || snapshot.ProbedDeployment != model.UpstreamModelID || record.CredentialID == "" || record.SecretCiphertext == "" || record.SourceVersion == "" || record.ProviderConfigDigest == "" || record.VerifiedAt.IsZero() || !record.ExpiresAt.After(record.VerifiedAt) || len(record.Endpoints) != 1 || record.Endpoints[0].EndpointType != "chat" || record.Endpoints[0].State != "supported" {
		return false, ErrVerifiedModelSyncConflict
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	// Serialize admissions for this provider, including the absent-model case.
	var providerID string
	if err = tx.QueryRow(ctx, `SELECT id FROM providers WHERE id=$1 AND tenant_id=$2 AND status='active' FOR UPDATE`, model.ProviderID, tenant).Scan(&providerID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrVerifiedModelSyncConflict
		}
		return false, err
	}
	rows, err := tx.Query(ctx, `SELECT id,COALESCE(upstream_model_id,''),status FROM models WHERE provider_id=$1 AND model_name=$2 FOR UPDATE`, model.ProviderID, model.ModelName)
	if err != nil {
		return false, err
	}
	var id, deployment, status string
	count := 0
	for rows.Next() {
		count++
		if err = rows.Scan(&id, &deployment, &status); err != nil {
			rows.Close()
			return false, err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	if count > 1 || (count == 0 && snapshot.ExistingModelID != "") || (count == 1 && (snapshot.ExistingModelID != id || snapshot.ExistingDeployment != deployment || snapshot.ExistingStatus != status)) {
		return false, ErrVerifiedModelSyncConflict
	}
	capabilities, err := json.Marshal(mapOrEmpty(model.Capabilities))
	if err != nil {
		return false, err
	}
	created := count == 0
	if created {
		id = "model_" + uuid.NewString()
		_, err = tx.Exec(ctx, `INSERT INTO models(id,provider_id,model_name,model_label,upstream_model_id,capabilities_json,pricing_json,context_window,status) VALUES($1,$2,$3,$4,$5,$6::jsonb,'{}'::jsonb,$7,$8)`, id, model.ProviderID, model.ModelName, model.ModelLabel, model.UpstreamModelID, string(capabilities), model.ContextWindow, model.Status)
	} else {
		_, err = tx.Exec(ctx, `UPDATE models SET model_label=$2,upstream_model_id=$3,context_window=$4,status=$5,updated_at=NOW() WHERE id=$1`, id, model.ModelLabel, model.UpstreamModelID, model.ContextWindow, model.Status)
		if err == nil && deployment != model.UpstreamModelID {
			_, err = tx.Exec(ctx, `DELETE FROM model_endpoint_capability_facts WHERE model_id=$1`, id)
			if err == nil {
				_, err = tx.Exec(ctx, `DELETE FROM model_endpoint_capability_overrides WHERE model_id=$1`, id)
			}
			if err == nil {
				_, err = tx.Exec(ctx, `UPDATE models SET capabilities_json=COALESCE(capabilities_json,'{}'::jsonb)-'protocols' WHERE id=$1`, id)
			}
		}
	}
	if err != nil {
		return false, err
	}
	if err = recordModelProtocolProbeTx(ctx, tx, tenant, model.ProviderID, id, capabilities, record); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	model.ID = id
	return created, nil
}

package repository

import (
	"context"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/jackc/pgx/v5"
)

func validateIntegrationModels(ctx context.Context, tx pgx.Tx, tenant string, names []string) error {
	for _, name := range names {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM models m JOIN providers p ON p.id=m.provider_id WHERE p.tenant_id=$1 AND m.model_name=$2)`, tenant, name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ai.ErrInvalid
		}
	}
	return nil
}

func (r *IntegrationRepository) GetCredential(ctx context.Context, tenant, id string) (*ai.Credential, error) {
	return scanIntegrationCredential(r.db.QueryRow(ctx, `SELECT `+credentialColumns+` FROM internal_keys WHERE tenant_id=$1 AND id=$2 AND agent_instance_id IS NOT NULL`, tenant, id))
}

func (r *IntegrationRepository) UpdateCredential(ctx context.Context, tenant, id string, update ai.CredentialUpdate) (*ai.Credential, error) {
	if update.ModelAllowlist == nil && update.Enforcement == nil && update.DLPEnforcement == nil {
		return nil, ai.ErrInvalid
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	key, err := scanIntegrationCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM internal_keys WHERE tenant_id=$1 AND id=$2 AND agent_instance_id IS NOT NULL FOR UPDATE`, tenant, id))
	if err != nil {
		return nil, err
	}
	if update.ModelAllowlist != nil {
		key.ModelRestriction = "allowlist"
		key.ModelAllowlist = *update.ModelAllowlist
	}
	if update.Enforcement != nil {
		key.Enforcement = *update.Enforcement
		if key.Enforcement == "" {
			return nil, ai.ErrInvalid
		}
	}
	if update.DLPEnforcement != nil {
		key.DLPEnforcement = *update.DLPEnforcement
		if key.DLPEnforcement == "" {
			return nil, ai.ErrInvalid
		}
	}
	if err = ai.ValidateCredentialControls(*key); err != nil {
		return nil, err
	}
	if err = validateIntegrationModels(ctx, tx, tenant, key.ModelAllowlist); err != nil {
		return nil, err
	}
	out, err := scanIntegrationCredential(tx.QueryRow(ctx, `UPDATE internal_keys SET model_restriction=$3,model_allowlist=$4,model_enforcement=$5,dlp_enforcement=$6 WHERE tenant_id=$1 AND id=$2 RETURNING `+credentialColumns, tenant, id, key.ModelRestriction, key.ModelAllowlist, key.Enforcement, key.DLPEnforcement))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

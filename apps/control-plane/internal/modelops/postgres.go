package modelops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

const configColumns = `version,enabled,interval_seconds,concurrency,timeout_seconds,max_targets,max_output_tokens,protocols,failure_threshold,updated_at,updated_by,cost_confirmed_at,cost_confirmed_by`

type scanner interface{ Scan(...any) error }

func scanConfig(r scanner) (Config, error) {
	var c Config
	err := r.Scan(&c.Version, &c.Enabled, &c.IntervalSeconds, &c.Concurrency, &c.TimeoutSeconds, &c.MaxTargets, &c.MaxOutputTokens, &c.Protocols, &c.FailureThreshold, &c.UpdatedAt, &c.UpdatedBy, &c.CostConfirmedAt, &c.CostConfirmedBy)
	return c, err
}
func (s *PostgresStore) GetConfig(ctx context.Context, tenant string) (Config, error) {
	if tenant == "" {
		return Config{}, ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO model_ops_configs(tenant_id) VALUES($1) ON CONFLICT DO NOTHING`, tenant)
	if err != nil {
		return Config{}, err
	}
	return scanConfig(s.pool.QueryRow(ctx, `SELECT `+configColumns+` FROM model_ops_configs WHERE tenant_id=$1`, tenant))
}
func (s *PostgresStore) UpdateConfig(ctx context.Context, tenant, actor string, version int64, c Config, confirm bool) (Config, error) {
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	if tenant == "" || actor == "" || version < 1 {
		return Config{}, ErrInvalid
	}
	if c.Enabled && !confirm {
		return Config{}, ErrCostConfirmation
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Config{}, err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `INSERT INTO model_ops_configs(tenant_id) VALUES($1) ON CONFLICT DO NOTHING`, tenant); err != nil {
		return Config{}, err
	}
	old, err := scanConfig(tx.QueryRow(ctx, `SELECT `+configColumns+` FROM model_ops_configs WHERE tenant_id=$1 FOR UPDATE`, tenant))
	if err != nil {
		return Config{}, err
	}
	if old.Version != version {
		return Config{}, ErrConflict
	}
	c.Version = version + 1
	newCfg, err := scanConfig(tx.QueryRow(ctx, `UPDATE model_ops_configs SET version=version+1,enabled=$2,interval_seconds=$3,concurrency=$4,timeout_seconds=$5,max_targets=$6,max_output_tokens=$7,protocols=$8,failure_threshold=$9,updated_at=clock_timestamp(),updated_by=$10,cost_confirmed_at=CASE WHEN $11 THEN clock_timestamp() ELSE cost_confirmed_at END,cost_confirmed_by=CASE WHEN $11 THEN $10 ELSE cost_confirmed_by END,next_batch_at=clock_timestamp() WHERE tenant_id=$1 RETURNING `+configColumns, tenant, c.Enabled, c.IntervalSeconds, c.Concurrency, c.TimeoutSeconds, c.MaxTargets, c.MaxOutputTokens, c.Protocols, c.FailureThreshold, actor, confirm))
	if err != nil {
		return Config{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE model_ops_leases SET epoch=epoch+1,token='',expires_at='-infinity' WHERE tenant_id=$1`, tenant); err != nil {
		return Config{}, err
	}
	b, _ := json.Marshal(newCfg)
	if _, err = tx.Exec(ctx, `INSERT INTO model_ops_config_audit(id,tenant_id,previous_version,version,actor,config_json,cost_confirmed) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.NewString(), tenant, version, newCfg.Version, actor, b, confirm); err != nil {
		return Config{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Config{}, err
	}
	return newCfg, nil
}

const targetSelect = `SELECT m.id,m.model_name,p.id,p.name,COALESCE(m.upstream_model_id,''),p.provider_type,COALESCE(p.base_url,''),COALESCE(p.auth_mode,'api_key'),pc.id,COALESCE(pc.secret_ciphertext,''),m.status,p.status,COALESCE((SELECT e.endpoint_type FROM model_endpoint_capability_effective e WHERE e.model_id=m.id AND e.state='supported' AND e.endpoint_type IN ('chat','responses','messages') ORDER BY CASE e.endpoint_type WHEN 'chat' THEN 1 WHEN 'responses' THEN 2 ELSE 3 END LIMIT 1),'')
FROM models m JOIN providers p ON p.id=m.provider_id JOIN provider_credentials pc ON pc.provider_id=p.id AND pc.status='active'
AND pc.id=(SELECT c.id FROM provider_credentials c WHERE c.provider_id=p.id AND c.status='active' ORDER BY c.created_at DESC,c.id DESC LIMIT 1)
WHERE p.tenant_id=$1 AND m.status='active' AND p.status='active'`

func scanTarget(row scanner) (Target, string, error) {
	var t Target
	var typ, base, auth, cipher string
	err := row.Scan(&t.ModelID, &t.ModelName, &t.ProviderID, &t.ProviderName, &t.UpstreamModelID, &typ, &base, &auth, &t.CredentialID, &cipher, &t.ModelStatus, &t.ProviderStatus, &t.PreferredProtocol)
	if err != nil {
		return t, "", err
	}
	t.ProviderType = typ
	t.ConfigDigest = repository.VerifiedModelSyncProviderConfigDigest(typ, base, auth)
	t.IdentityDigest = DigestTargetIdentity(typ, base, auth, t.CredentialID, cipher, t.ModelID, t.ProviderID, t.ModelName, t.UpstreamModelID, t.ModelStatus, t.ProviderStatus)
	if strings.EqualFold(strings.TrimSpace(typ), "anthropic") {
		t.PreferredProtocol = "messages"
	}
	if t.PreferredProtocol == "" || strings.EqualFold(strings.TrimSpace(typ), "gemini") || strings.EqualFold(strings.TrimSpace(typ), "vertex") || strings.EqualFold(strings.TrimSpace(typ), "bedrock") {
		t.PreferredProtocol = "chat"
	}
	return t, typ, nil
}
func compatibleProtocol(typ, protocol string) bool {
	if strings.EqualFold(strings.TrimSpace(typ), "anthropic") {
		return protocol == "messages"
	}
	if native := strings.ToLower(strings.TrimSpace(typ)); native == "gemini" || native == "vertex" || native == "bedrock" {
		return protocol == "chat"
	}
	return true
}

// Periodic probes remain restricted to admitted models. Pending models are
// selectable only for explicit, tenant-authorized manual verification.
func (s *PostgresStore) ListTargets(ctx context.Context, tenant string, protocols []string) ([]Target, error) {
	return s.listTargets(ctx, tenant, protocols, false)
}
func (s *PostgresStore) ListManualTargets(ctx context.Context, tenant string, protocols []string) ([]Target, error) {
	return s.listTargets(ctx, tenant, protocols, true)
}
func targetSelection(manual bool) string {
	if manual {
		return strings.Replace(targetSelect, "m.status='active'", "m.status IN ('active','pending')", 1)
	}
	return targetSelect
}
func (s *PostgresStore) listTargets(ctx context.Context, tenant string, protocols []string, manual bool) ([]Target, error) {
	if tenant == "" {
		return nil, ErrInvalid
	}
	if len(protocols) > 0 {
		if err := ValidateProtocols(protocols); err != nil {
			return nil, err
		}
	}
	rows, err := s.pool.Query(ctx, targetSelection(manual)+` ORDER BY m.id,p.id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	targets := []Target{}
	for rows.Next() {
		t, typ, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		selected := protocols
		if len(selected) == 0 {
			selected = []string{t.PreferredProtocol}
		}
		for _, protocol := range selected {
			if compatibleProtocol(typ, protocol) {
				t.ManualProbe = manual
				t.Protocol = protocol
				t.Supported = ProtocolSupported(typ, protocol)
				targets = append(targets, t)
			}
		}
	}
	return targets, rows.Err()
}
func verifyTarget(ctx context.Context, tx pgx.Tx, tenant string, want Target) error {
	return verifyTargetSelection(ctx, tx, tenant, want, false)
}
func verifyTargetSelection(ctx context.Context, tx pgx.Tx, tenant string, want Target, manual bool) error {
	got, typ, err := scanTarget(tx.QueryRow(ctx, targetSelection(manual)+` AND m.id=$2 AND p.id=$3 FOR SHARE OF m,p,pc`, tenant, want.ModelID, want.ProviderID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnavailable
	}
	if err != nil {
		return err
	}
	if got.IdentityDigest != want.IdentityDigest || got.ConfigDigest != want.ConfigDigest || !compatibleProtocol(typ, want.Protocol) {
		return ErrIdentityChanged
	}
	return nil
}
func (s *PostgresStore) ListEnabledTenants(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT tenant_id FROM model_ops_configs WHERE enabled AND next_batch_at<=clock_timestamp() ORDER BY next_batch_at,tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func leaseSeconds(c Config) int { return c.TimeoutSeconds + 15 }
func (s *PostgresStore) AcquireLease(ctx context.Context, tenant, owner string) (*Lease, error) {
	if tenant == "" || owner == "" {
		return nil, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	c, err := scanConfig(tx.QueryRow(ctx, `SELECT `+configColumns+` FROM model_ops_configs WHERE tenant_id=$1 AND enabled AND next_batch_at<=clock_timestamp() AND NOT EXISTS(SELECT 1 FROM model_operations_jobs j WHERE j.tenant_id=$1 AND j.state IN ('queued','running')) FOR UPDATE`, tenant))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Recheck after taking the config lock: the initial snapshot may predate a queued job.
	var manualActive bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM model_operations_jobs WHERE tenant_id=$1 AND state IN ('queued','running'))`, tenant).Scan(&manualActive); err != nil {
		return nil, err
	}
	if manualActive {
		return nil, nil
	}
	if _, err = tx.Exec(ctx, `INSERT INTO model_ops_leases(tenant_id) VALUES($1) ON CONFLICT DO NOTHING`, tenant); err != nil {
		return nil, err
	}
	l := &Lease{TenantID: tenant, Owner: owner, Token: uuid.NewString(), Config: c}
	err = tx.QueryRow(ctx, `UPDATE model_ops_leases SET epoch=epoch+1,token=$2,owner=$3,config_version=$4,expires_at=clock_timestamp()+make_interval(secs=>$5) WHERE tenant_id=$1 AND expires_at<=clock_timestamp() RETURNING epoch,expires_at`, tenant, l.Token, owner, c.Version, leaseSeconds(c)).Scan(&l.Epoch, &l.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRow(ctx, `SELECT cursor_key FROM model_ops_configs WHERE tenant_id=$1`, tenant).Scan(&l.Cursor); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return l, nil
}
func checkLease(ctx context.Context, tx pgx.Tx, l *Lease) error {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT c.enabled AND c.version=$4 AND l.config_version=$4 AND l.token=$2 AND l.epoch=$3 AND l.expires_at>clock_timestamp() FROM model_ops_configs c JOIN model_ops_leases l USING(tenant_id) WHERE c.tenant_id=$1 FOR UPDATE OF c,l`, l.TenantID, l.Token, l.Epoch, l.Config.Version).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if !valid {
		return ErrLeaseLost
	}
	return nil
}
func (s *PostgresStore) RenewLease(ctx context.Context, l *Lease) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if err = checkLease(ctx, tx, l); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE model_ops_leases SET expires_at=clock_timestamp()+make_interval(secs=>$2) WHERE tenant_id=$1`, l.TenantID, leaseSeconds(l.Config)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *PostgresStore) ReleaseLease(ctx context.Context, l *Lease, cursor string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if err = checkLease(ctx, tx, l); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE model_ops_configs SET cursor_key=$2,next_batch_at=clock_timestamp()+make_interval(secs=>$3) WHERE tenant_id=$1`, l.TenantID, cursor, l.Config.IntervalSeconds); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE model_ops_leases SET token='',expires_at='-infinity' WHERE tenant_id=$1`, l.TenantID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *PostgresStore) ClaimTarget(ctx context.Context, l *Lease, t Target) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.Background())
	if err = checkLease(ctx, tx, l); err != nil {
		return false, err
	}
	if err = verifyTarget(ctx, tx, l.TenantID, t); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO model_ops_target_schedule(tenant_id,target_key,identity_digest) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, l.TenantID, t.Key(), t.IdentityDigest); err != nil {
		return false, err
	}
	var due, hasBusiness bool
	err = tx.QueryRow(ctx, `SELECT next_probe_at<=clock_timestamp(), EXISTS(SELECT 1 FROM request_logs r JOIN models requested ON requested.id=r.model_id WHERE r.tenant_id=$1 AND requested.model_name=$4 AND r.provider_id=$5 AND r.endpoint_type=$6 AND r.request_status='success' AND r.created_at>clock_timestamp()-make_interval(secs=>$7) AND last_probe_at IS NOT NULL AND r.created_at>last_probe_at) AND last_probe_at>clock_timestamp()-make_interval(secs=>$7*4) FROM model_ops_target_schedule WHERE tenant_id=$1 AND target_key=$2 AND identity_digest=$3 FOR UPDATE`, l.TenantID, t.Key(), t.IdentityDigest, t.ModelName, t.ProviderID, t.Protocol, l.Config.IntervalSeconds).Scan(&due, &hasBusiness)
	if errors.Is(err, pgx.ErrNoRows) {
		// Keep the durable next-due bound after config changes: an old request may still be cancelling.
		if _, err = tx.Exec(ctx, `UPDATE model_ops_target_schedule SET identity_digest=$3,last_probe_at=NULL WHERE tenant_id=$1 AND target_key=$2`, l.TenantID, t.Key(), t.IdentityDigest); err != nil {
			return false, err
		}
		err = tx.QueryRow(ctx, `SELECT next_probe_at<=clock_timestamp() FROM model_ops_target_schedule WHERE tenant_id=$1 AND target_key=$2`, l.TenantID, t.Key()).Scan(&due)
		hasBusiness = false
	}
	if err != nil {
		return false, err
	}
	if !due || hasBusiness {
		return false, tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `UPDATE model_ops_target_schedule SET next_probe_at=clock_timestamp()+make_interval(secs=>$3),claim_epoch=$4,claim_token=$5 WHERE tenant_id=$1 AND target_key=$2`, l.TenantID, t.Key(), l.Config.IntervalSeconds, l.Epoch, l.Token); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
func (s *PostgresStore) Complete(ctx context.Context, l *Lease, t Target, o Outcome) (ProbeRecord, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProbeRecord{}, err
	}
	defer tx.Rollback(context.Background())
	if err = checkLease(ctx, tx, l); err != nil {
		return ProbeRecord{}, err
	}
	if err = verifyTarget(ctx, tx, l.TenantID, t); err != nil {
		return ProbeRecord{}, err
	}
	var claimed bool
	err = tx.QueryRow(ctx, `SELECT claim_epoch=$3 AND claim_token=$4 AND identity_digest=$5 FROM model_ops_target_schedule WHERE tenant_id=$1 AND target_key=$2 FOR UPDATE`, l.TenantID, t.Key(), l.Epoch, l.Token, t.IdentityDigest).Scan(&claimed)
	if err != nil {
		return ProbeRecord{}, err
	}
	if !claimed {
		return ProbeRecord{}, ErrLeaseLost
	}
	r, err := insertOutcome(ctx, tx, l.TenantID, l.Owner, t, o, "scheduled", l.Config.Version, l.Epoch, l.Config.FailureThreshold)
	if err != nil {
		return ProbeRecord{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE model_ops_target_schedule SET last_probe_at=clock_timestamp(),claim_token='' WHERE tenant_id=$1 AND target_key=$2`, l.TenantID, t.Key()); err != nil {
		return ProbeRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ProbeRecord{}, err
	}
	return r, nil
}
func (s *PostgresStore) BeginScheduledDispatch(ctx context.Context, l *Lease, t Target) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if err = checkLease(ctx, tx, l); err != nil {
		return err
	}
	if err = verifyTarget(ctx, tx, l.TenantID, t); err != nil {
		return err
	}
	var manualPending bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM model_ops_manual_claims WHERE tenant_id=$1 AND target_key=$2 AND NOT completed AND dispatch_deadline>clock_timestamp())`, l.TenantID, t.Key()).Scan(&manualPending); err != nil {
		return err
	}
	if manualPending {
		return ErrLeaseLost
	}
	result, err := tx.Exec(ctx, `UPDATE model_ops_target_schedule SET dispatch_deadline=clock_timestamp()+make_interval(secs=>$6) WHERE tenant_id=$1 AND target_key=$2 AND claim_epoch=$3 AND claim_token=$4 AND identity_digest=$5`, l.TenantID, t.Key(), l.Epoch, l.Token, t.IdentityDigest, l.Config.TimeoutSeconds)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return tx.Commit(ctx)
}
func (s *PostgresStore) RecordManual(ctx context.Context, tenant, actor string, t Target, o Outcome) (ProbeRecord, error) {
	if actor == "" || tenant == "" {
		return ProbeRecord{}, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProbeRecord{}, err
	}
	defer tx.Rollback(context.Background())
	c, err := authenticateManual(ctx, tx, tenant, actor, t)
	if err != nil {
		return ProbeRecord{}, err
	}
	if invocationID(ctx) != "" {
		var valid bool
		err = tx.QueryRow(ctx, `SELECT NOT completed AND identity_digest=$4 AND config_version=$5 AND owner_token=$6 FROM model_ops_manual_claims WHERE tenant_id=$1 AND invocation_id=$2 AND target_key=$3 FOR UPDATE`, tenant, invocationID(ctx), t.Key(), t.IdentityDigest, c.Version, jobOwner(ctx)).Scan(&valid)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !valid {
			return ProbeRecord{}, ErrConflict
		}
		if err != nil {
			return ProbeRecord{}, err
		}
	}
	r, err := insertOutcome(ctx, tx, tenant, actor, t, o, "manual", c.Version, 0, c.FailureThreshold)
	if err != nil {
		return ProbeRecord{}, err
	}
	if invocationID(ctx) != "" {
		if _, err = tx.Exec(ctx, `UPDATE model_ops_manual_claims SET completed=true WHERE tenant_id=$1 AND invocation_id=$2 AND target_key=$3`, tenant, invocationID(ctx), t.Key()); err != nil {
			return ProbeRecord{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return ProbeRecord{}, err
	}
	return r, nil
}
func authenticateManual(ctx context.Context, tx pgx.Tx, tenant, actor string, t Target) (Config, error) {
	c, err := scanConfig(tx.QueryRow(ctx, `SELECT `+configColumns+` FROM model_ops_configs WHERE tenant_id=$1 FOR UPDATE`, tenant))
	if err != nil {
		return c, err
	}
	if t.ConfigVersion > 0 && t.ConfigVersion != c.Version {
		return c, ErrConflict
	}
	if token := jobOwner(ctx); token != "" {
		var valid bool
		err = tx.QueryRow(ctx, `SELECT state='running' AND NOT cancel_requested AND lease_until>clock_timestamp() AND actor=$3 AND owner_token=$4 FROM model_operations_jobs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, invocationID(ctx), actor, token).Scan(&valid)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !valid {
			return c, ErrLeaseLost
		}
		if err != nil {
			return c, err
		}
	}
	return c, verifyTargetSelection(ctx, tx, tenant, t, true)
}
func (s *PostgresStore) BeginManualTarget(ctx context.Context, tenant, actor string, t Target) (bool, error) {
	if tenant == "" || actor == "" || invocationID(ctx) == "" {
		return false, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.Background())
	c, err := authenticateManual(ctx, tx, tenant, actor, t)
	if err != nil {
		return false, err
	}
	var pending bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM model_ops_manual_claims WHERE tenant_id=$1 AND target_key=$2 AND invocation_id<>$3 AND NOT completed AND dispatch_deadline>clock_timestamp()) OR EXISTS(SELECT 1 FROM model_ops_target_schedule WHERE tenant_id=$1 AND target_key=$2 AND claim_token<>'' AND dispatch_deadline>clock_timestamp())`, tenant, t.Key(), invocationID(ctx)).Scan(&pending)
	if err != nil {
		return false, err
	}
	if pending {
		return false, ErrLeaseLost
	}
	result, err := tx.Exec(ctx, `INSERT INTO model_ops_manual_claims(tenant_id,invocation_id,target_key,identity_digest,config_version,owner_token,dispatch_deadline) VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+make_interval(secs=>$7)) ON CONFLICT DO NOTHING`, tenant, invocationID(ctx), t.Key(), t.IdentityDigest, c.Version, jobOwner(ctx), c.TimeoutSeconds)
	if err != nil {
		return false, err
	}
	return result.RowsAffected() == 1, tx.Commit(ctx)
}
func insertOutcome(ctx context.Context, tx pgx.Tx, tenant, actor string, t Target, o Outcome, source string, version, epoch int64, threshold int) (ProbeRecord, error) {
	if !ProtocolSupported(t.ProviderType, t.Protocol) || o.ErrorKind == "unsupported" {
		return ProbeRecord{}, ErrUnavailable
	}
	o = o.sanitized()
	if o.ErrorKind == "config_changed" {
		return ProbeRecord{}, ErrIdentityChanged
	}
	r := ProbeRecord{ID: uuid.NewString(), Target: t, Outcome: o, Source: source, Actor: actor, ConfigVersion: version, Epoch: epoch, InvocationID: invocationID(ctx)}
	err := tx.QueryRow(ctx, `INSERT INTO model_ops_probe_history(id,tenant_id,model_id,model_name,provider_id,provider_name,upstream_model_id,protocol,config_digest,identity_digest,source,actor,config_version,epoch,success,http_status,body_validated,latency_ms,error_kind,invocation_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) RETURNING created_at`, r.ID, tenant, t.ModelID, t.ModelName, t.ProviderID, t.ProviderName, t.UpstreamModelID, t.Protocol, t.ConfigDigest, t.IdentityDigest, source, actor, version, epoch, o.Success, o.HTTPStatus, o.BodyValidated, o.LatencyMS, o.ErrorKind, r.InvocationID).Scan(&r.CreatedAt)
	if err != nil {
		return ProbeRecord{}, err
	}
	if o.Success {
		_, err = tx.Exec(ctx, `UPDATE model_ops_alerts SET state='resolved',resolved_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND model_id=$2 AND provider_id=$3 AND protocol=$4 AND identity_digest=$5 AND state='open'`, tenant, t.ModelID, t.ProviderID, t.Protocol, t.IdentityDigest)
	} else if o.ErrorKind != "cancelled" {
		var count int
		err = tx.QueryRow(ctx, `SELECT count(*)::int FROM model_ops_probe_history WHERE tenant_id=$1 AND model_id=$2 AND provider_id=$3 AND protocol=$4 AND identity_digest=$5 AND NOT success AND error_kind<>'cancelled' AND (created_at,id) > COALESCE((SELECT (created_at,id) FROM model_ops_probe_history WHERE tenant_id=$1 AND model_id=$2 AND provider_id=$3 AND protocol=$4 AND identity_digest=$5 AND success ORDER BY created_at DESC,id DESC LIMIT 1),('-infinity'::timestamptz,''::text))`, tenant, t.ModelID, t.ProviderID, t.Protocol, t.IdentityDigest).Scan(&count)
		if err == nil && count >= threshold {
			_, err = tx.Exec(ctx, `INSERT INTO model_ops_alerts(id,tenant_id,model_id,model_name,provider_id,provider_name,upstream_model_id,protocol,config_digest,identity_digest,state,failure_count,last_error) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'open',$11,$12) ON CONFLICT(tenant_id,model_id,provider_id,protocol,identity_digest) WHERE state='open' DO UPDATE SET failure_count=EXCLUDED.failure_count,last_error=EXCLUDED.last_error,updated_at=clock_timestamp()`, uuid.NewString(), tenant, t.ModelID, t.ModelName, t.ProviderID, t.ProviderName, t.UpstreamModelID, t.Protocol, t.ConfigDigest, t.IdentityDigest, count, o.ErrorKind)
		}
	}
	if err != nil {
		return ProbeRecord{}, fmt.Errorf("record probe alert: %w", err)
	}
	return r, nil
}

var _ Store = (*PostgresStore)(nil)

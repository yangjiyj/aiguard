package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/agentidentity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNativeEventInvalid      = errors.New("invalid native event batch")
	ErrNativeEventConflict     = errors.New("native event identity has different content")
	ErrNativeEventUnauthorized = errors.New("native event transport identity is no longer authorized")
)

type NativeEventLedger struct {
	db    *pgxpool.Pool
	begin func(context.Context) (pgx.Tx, error)
}

func NewNativeEventLedger(db *pgxpool.Pool) *NativeEventLedger {
	return &NativeEventLedger{db: db, begin: db.Begin}
}

// NativeEventTransport is populated only from authenticated server context.
// CredentialHash is rechecked under lock and is never stored in the event.
type NativeEventTransport struct{ TenantID, EndpointID, CredentialHash string }
type NativeEventReceipt struct {
	SchemaVersion string   `json:"schema_version"`
	Accepted      []string `json:"accepted"`
	Duplicates    []string `json:"duplicates"`
}

func nativeDigest(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic("native identity contains non-JSON value")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func nativeSourceID(endpoint string, p agentidentity.Producer) string {
	return nativeDigest([]string{endpoint, p.Kind, p.NativeID})
}
func nativeRefHash(ref agentidentity.NativeRef) string {
	return nativeDigest([]string{ref.Kind, ref.Namespace, ref.NativeID, ref.Revision})
}

type nativePreparedEvent struct {
	event agentidentity.Event
	hash  string
}

func prepareNativeEvents(env *agentidentity.Envelope) ([]nativePreparedEvent, error) {
	result := make([]nativePreparedEvent, 0, len(env.Events))
	seen := make(map[string]string)
	for _, event := range env.Events {
		// Raw has passed duplicate-key, UTF-8 and exact-contract validation.
		hash := nativeDigest(struct {
			Schema   string                 `json:"schema_version"`
			Producer agentidentity.Producer `json:"producer"`
			Event    json.RawMessage        `json:"event"`
		}{env.SchemaVersion, env.Producer, event.Raw})
		id := strings.ToLower(event.EventID)
		if old, ok := seen[id]; ok {
			if old != hash {
				return nil, ErrNativeEventConflict
			}
			continue
		}
		seen[id] = hash
		result = append(result, nativePreparedEvent{event: event, hash: hash})
	}
	return result, nil
}

// Ingest validates the raw envelope itself so callers cannot bypass the contract
// by constructing a partially initialized Envelope. A successful ACK means the
// whole transaction committed; no ACK is returned for partial/conflicting data.
func (r *NativeEventLedger) Ingest(ctx context.Context, auth NativeEventTransport, raw []byte) (*NativeEventReceipt, error) {
	if auth.TenantID == "" || auth.EndpointID == "" || len(auth.CredentialHash) != 64 {
		return nil, ErrNativeEventUnauthorized
	}
	if _, err := hex.DecodeString(auth.CredentialHash); err != nil {
		return nil, ErrNativeEventUnauthorized
	}
	env, err := agentidentity.ParseEnvelope(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNativeEventInvalid, err)
	}
	events, err := prepareNativeEvents(env)
	if err != nil {
		return nil, err
	}
	tx, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Serializes batches and rotation/revocation on this authenticated registration.
	// The caller-supplied producer cannot select this row.
	var currentEndpoint string
	err = tx.QueryRow(ctx, `SELECT id FROM agent_endpoints
  WHERE tenant_id=$1 AND id=$2 AND token_hash=$3 AND status IN ('active','stale')
  FOR UPDATE`, auth.TenantID, auth.EndpointID, auth.CredentialHash).Scan(&currentEndpoint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNativeEventUnauthorized
	}
	if err != nil {
		return nil, err
	}
	source := nativeSourceID(auth.EndpointID, env.Producer)
	producer, err := json.Marshal(env.Producer)
	if err != nil {
		return nil, err
	}
	receipt := &NativeEventReceipt{SchemaVersion: "identity-events.ack.v1", Accepted: []string{}, Duplicates: []string{}}
	for _, item := range events {
		event := item.event
		tag, err := tx.Exec(ctx, `INSERT INTO agent_native_events
   (tenant_id,endpoint_id,event_id,source_id,schema_version,producer,event_type,source_occurred_at,payload_hash,payload)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
   ON CONFLICT(tenant_id,endpoint_id,event_id) DO NOTHING`,
			auth.TenantID, auth.EndpointID, event.EventID, source, env.SchemaVersion, producer, event.EventType, event.OccurredAt, item.hash, []byte(event.Raw))
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			var oldHash string
			if err = tx.QueryRow(ctx, `SELECT payload_hash FROM agent_native_events
    WHERE tenant_id=$1 AND endpoint_id=$2 AND event_id=$3`,
				auth.TenantID, auth.EndpointID, event.EventID).Scan(&oldHash); err != nil {
				return nil, err
			}
			if oldHash != item.hash {
				return nil, ErrNativeEventConflict
			}
			receipt.Duplicates = append(receipt.Duplicates, event.EventID)
			continue
		}
		for _, ref := range event.References {
			refJSON, err := json.Marshal(ref.Ref)
			if err != nil {
				return nil, err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO agent_native_event_refs
    (tenant_id,endpoint_id,event_id,source_id,role,ref_hash,native_ref)
    VALUES($1,$2,$3,$4,$5,$6,$7)`,
				auth.TenantID, auth.EndpointID, event.EventID, source, ref.Role, nativeRefHash(ref.Ref), refJSON); err != nil {
				return nil, err
			}
		}
		receipt.Accepted = append(receipt.Accepted, event.EventID)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return receipt, nil
}

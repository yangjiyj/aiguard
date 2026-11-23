// Package modelcatalog projects the same current inventory for administration
// and caller-visible model discovery. It never reads or deletes request history.
package modelcatalog

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Availability struct {
	ID             string   `json:"id"`
	Name           string   `json:"model_name"`
	ProviderType   string   `json:"provider_type"`
	Callable       bool     `json:"callable"`
	State          string   `json:"availability_state"`
	InventoryState string   `json:"inventory_state"`
	Endpoints      []string `json:"callable_endpoints"`
	Health         string   `json:"health_state"`
	ProofState     string   `json:"proof_state"`
	// Advice 只是给管理员的建议（expired/unverified/unsupported/unhealthy），从不影响 Callable。
	Advice string `json:"advice"`
}

func ProviderConfigDigest(providerType, baseURL, authMode string) string {
	h := sha256.New()
	for _, value := range []string{"jjdguard:verified-model-sync:provider-config:v1", providerType, baseURL, authMode} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(value)))
		h.Write(n[:])
		h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func LegacyProviderConfigDigest(providerType, baseURL, authMode string) string {
	sum := md5.Sum([]byte(providerType + "\x1f" + baseURL + "\x1f" + authMode)) // compatibility fingerprint, not authentication
	return "legacy-md5:" + hex.EncodeToString(sum[:])
}
func State(modelStatus, providerStatus string, credential, present bool, supported int, health string) string {
	if !present || modelStatus == "upstream_removed" {
		return "upstream_removed"
	}
	if modelStatus == "pending" {
		return "pending_admission"
	}
	if modelStatus != "active" {
		return "disabled"
	}
	if providerStatus != "active" {
		return "provider_disabled"
	}
	if !credential {
		return "credential_unavailable"
	}
	// 探测结果（是否验证、是否过期、健康快照）只作建议，见 Advice。
	return "callable"
}

// Advice 把探测结果翻译成给管理员的建议；空字符串表示无需处理。
func Advice(supported int, health string, sawExpired, sawUnsupported bool) string {
	if health == "unhealthy" {
		return "unhealthy"
	}
	if supported > 0 {
		return ""
	}
	if sawExpired {
		return "expired"
	}
	if sawUnsupported {
		return "unsupported"
	}
	return "unverified"
}
func Load(ctx context.Context, db *pgxpool.Pool, tenantID string) (map[string]Availability, error) {
	rows, err := db.Query(ctx, `SELECT m.id,m.model_name,p.provider_type,COALESCE(p.base_url,''),COALESCE(p.auth_mode,''),m.status,p.status,
 EXISTS(SELECT 1 FROM provider_credentials pc WHERE pc.provider_id=p.id AND pc.status='active'),
 COALESCE(c.present,true),CASE WHEN c.model_id IS NULL THEN 'manual_or_legacy' WHEN c.present THEN 'present' ELSE 'upstream_removed' END,
 COALESCE(ec.endpoint_type,''),COALESCE(ec.state,'unknown'),COALESCE(ec.provider_config_digest,''),COALESCE(ec.is_override,false),COALESCE(health.state,'unknown')
 FROM models m JOIN providers p ON p.id=m.provider_id LEFT JOIN model_catalog_entries c ON c.provider_id=m.provider_id AND c.upstream_model_id=COALESCE(NULLIF(m.upstream_model_id,''),m.model_name) AND c.model_id IS NOT NULL
 LEFT JOIN model_endpoint_capability_effective ec ON ec.model_id=m.id
 LEFT JOIN model_route_health_snapshots health ON health.tenant_id=p.tenant_id AND health.provider_id=p.id AND health.model_name=m.model_name AND health.expires_at>NOW()
 WHERE p.tenant_id=$1 AND p.status<>'deleted' AND m.status<>'deleted' ORDER BY m.id,ec.endpoint_type`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]Availability{}
	expired, unsupported := map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var id, name, pt, base, auth, ms, ps, inventory, endpoint, state, digest, health string
		var credential, present, override bool
		if err = rows.Scan(&id, &name, &pt, &base, &auth, &ms, &ps, &credential, &present, &inventory, &endpoint, &state, &digest, &override, &health); err != nil {
			return nil, err
		}
		item, ok := result[id]
		if !ok {
			item = Availability{ID: id, Name: name, ProviderType: pt, InventoryState: inventory, Health: health, Endpoints: []string{}}
		}
		valid := override || digest == ProviderConfigDigest(pt, base, auth) || digest == LegacyProviderConfigDigest(pt, base, auth)
		if valid && endpoint != "" {
			switch state {
			case "expired":
				expired[id] = true
			case "unsupported":
				unsupported[id] = true
			}
		}
		if valid && state == "supported" && endpoint != "" {
			item.Endpoints = append(item.Endpoints, endpoint)
			if !override {
				item.ProofState = "verified"
			} else if item.ProofState != "verified" {
				item.ProofState = "manual"
			}
		}
		item.State = State(ms, ps, credential, present, len(item.Endpoints), health)
		item.Callable = item.State == "callable"
		item.Advice = Advice(len(item.Endpoints), health, expired[id], unsupported[id])
		result[id] = item
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for id, item := range result {
		sort.Strings(item.Endpoints)
		result[id] = item
	}
	return result, nil
}

// CallablePredicate is the database equivalent of Load's callable projection.
// It expects model alias m and provider alias p. Only administrative facts
// block: model/provider switches, an active credential and upstream removal.
// Probe proofs and health snapshots are advisory and deliberately absent.
const CallablePredicate = `p.status='active' AND m.status='active'
 AND EXISTS(SELECT 1 FROM provider_credentials pc WHERE pc.provider_id=p.id AND pc.status='active')
 AND NOT EXISTS(SELECT 1 FROM model_catalog_entries c WHERE c.provider_id=p.id
   AND c.upstream_model_id=COALESCE(NULLIF(m.upstream_model_id,''),m.model_name)
   AND c.model_id IS NOT NULL AND NOT c.present)`

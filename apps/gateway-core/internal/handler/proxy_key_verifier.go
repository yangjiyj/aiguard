package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DBProxyKeyVerifier verifies 免Token代理 access keys against proxy_access_keys (阶段二 2.5, 承接任务 1.7).
type DBProxyKeyVerifier struct {
	db *pgxpool.Pool
}

// NewDBProxyKeyVerifier constructs a DB-backed proxy key verifier.
func NewDBProxyKeyVerifier(db *pgxpool.Pool) *DBProxyKeyVerifier {
	return &DBProxyKeyVerifier{db: db}
}

// VerifyProxyKey checks the raw X-Proxy-Key against proxy_access_keys.
// Returns an error when the key is missing/invalid/expired/inactive or not authorized for modelID.
func (v *DBProxyKeyVerifier) VerifyProxyKey(ctx context.Context, rawKey, modelID string) (*ProxyKeyInfo, error) {
	if v == nil || v.db == nil {
		return nil, fmt.Errorf("proxy key verifier not configured")
	}
	if rawKey == "" {
		return nil, fmt.Errorf("proxy key missing")
	}

	sum := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(sum[:])

	var keyID string
	var modelIDsRaw []byte
	err := v.db.QueryRow(ctx,
		`SELECT id, model_ids FROM proxy_access_keys
         WHERE proxy_key_hash = $1 AND status = 'active'
           AND (expires_at IS NULL OR expires_at > now())`,
		keyHash,
	).Scan(&keyID, &modelIDsRaw)
	if err != nil {
		return nil, fmt.Errorf("proxy key not found or inactive: %w", err)
	}

	var modelIDs []string
	if len(modelIDsRaw) > 0 {
		if uerr := json.Unmarshal(modelIDsRaw, &modelIDs); uerr != nil {
			return nil, fmt.Errorf("invalid model_ids for proxy key: %w", uerr)
		}
	}

	// Empty model_ids => authorized for all models.
	if len(modelIDs) > 0 && modelID != "" {
		authorized := false
		for _, m := range modelIDs {
			if m == modelID {
				authorized = true
				break
			}
		}
		if !authorized {
			return nil, fmt.Errorf("proxy key not authorized for model %s", modelID)
		}
	}

	return &ProxyKeyInfo{KeyID: keyID, ModelIDs: modelIDs}, nil
}

package repository

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelcatalog"
	"hash"
	"sort"
)

const (
	verifiedModelSyncConfigDigestDomain    = "jjdguard:verified-model-sync:provider-config:v1"
	verifiedModelSyncActiveSetDigestDomain = "jjdguard:verified-model-sync:active-set:v1"
)

type verifiedModelSyncActiveItem struct {
	ID              string
	ModelName       string
	UpstreamModelID string
}

// VerifiedModelSyncProviderConfigDigest binds a proof to the exact persisted
// connection settings without placing the URL or any credential in the proof.
func VerifiedModelSyncProviderConfigDigest(providerType, baseURL, authMode string) string {
	return modelcatalog.ProviderConfigDigest(providerType, baseURL, authMode)
}

// VerifiedModelSyncActiveSetDigest binds a proof to active membership and the
// upstream deployment mapping. Input order and unrelated provider rows do not
// affect the digest.
func VerifiedModelSyncActiveSetDigest(models []*Model, providerID string) string {
	items := make([]verifiedModelSyncActiveItem, 0, len(models))
	for _, model := range models {
		if model == nil || model.ProviderID != providerID || model.Status != "active" {
			continue
		}
		items = append(items, verifiedModelSyncActiveItem{
			ID:              model.ID,
			ModelName:       model.ModelName,
			UpstreamModelID: model.UpstreamModelID,
		})
	}
	return verifiedModelSyncActiveItemsDigest(providerID, items)
}

func verifiedModelSyncActiveItemsDigest(providerID string, items []verifiedModelSyncActiveItem) string {
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		if items[i].ModelName != items[j].ModelName {
			return items[i].ModelName < items[j].ModelName
		}
		return items[i].UpstreamModelID < items[j].UpstreamModelID
	})
	h := sha256.New()
	writeVerifiedModelSyncDigestString(h, verifiedModelSyncActiveSetDigestDomain)
	writeVerifiedModelSyncDigestString(h, providerID)
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(items)))
	_, _ = h.Write(count[:])
	for _, item := range items {
		writeVerifiedModelSyncDigestString(h, item.ID)
		writeVerifiedModelSyncDigestString(h, item.ModelName)
		writeVerifiedModelSyncDigestString(h, item.UpstreamModelID)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func validVerifiedModelSyncDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func writeVerifiedModelSyncDigestString(h hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(value))
}

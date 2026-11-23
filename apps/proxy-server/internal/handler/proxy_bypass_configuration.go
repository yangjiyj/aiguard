package handler

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/proxywhitelist"
	"github.com/google/uuid"
)

func mitmBypassEnvironmentSuffixes() []string {
	var suffixes []string
	seen := make(map[string]bool)
	for _, entry := range strings.Split(os.Getenv("PROXY_MITM_BYPASS_SUFFIXES"), ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry != "" && !seen[entry] {
			suffixes = append(suffixes, entry)
			seen[entry] = true
		}
	}
	return suffixes
}

func (h *ProxyHandler) recordMITMBypassEnvironmentConfiguration() {
	suffixes := mitmBypassEnvironmentSuffixes()
	if len(suffixes) == 0 {
		return
	}
	tenantID := proxywhitelist.Tenant("")
	if h.whitelistChecker != nil {
		tenantID = proxywhitelist.Tenant(h.whitelistChecker.tenantID)
	}
	log.Printf("PROXY_MITM_BYPASS_SUFFIXES appended tenant=%q suffixes=%q coverage_gap=true", tenantID, suffixes)
	if h.auditWriter == nil || h.auditWriter.db == nil {
		return
	}
	detail, err := json.Marshal(map[string]interface{}{
		"source": "PROXY_MITM_BYPASS_SUFFIXES", "tenant_id": tenantID,
		"suffixes": suffixes, "coverage_gap": true,
	})
	if err != nil {
		log.Printf("MITM bypass configuration audit unavailable: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = h.auditWriter.db.Exec(ctx, `INSERT INTO audit_operations
		(id, user_id, action_type, action_detail, target_type, target_id)
		VALUES ($1, NULL, 'proxy_mitm_bypass.env', $2::jsonb, 'forward_proxy', $3)`, uuid.NewString(), detail, tenantID)
	if err != nil {
		log.Printf("MITM bypass configuration audit unavailable: %v", err)
	}
}

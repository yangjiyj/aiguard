package handler

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// Domain exceptions use the existing tenant proxy whitelist. Only a host that
// matches this call's URL and port is passed to DLP; wildcard patterns are not
// copied into DLP's suffix allowlist.
func toolAllowedDomains(ctx context.Context, db *pgxpool.Pool, tenantID string, arguments map[string]any) ([]string, []agentguard.Evidence) {
	urls := toolArgumentURLs(arguments)
	if len(urls) == 0 {
		return nil, nil
	}
	gap := []agentguard.Evidence{{RuleID: "agentguard_allowed_domains_unavailable", Category: "coverage_gap"}}
	if db == nil || tenantID == "" {
		return nil, gap
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := db.Query(queryCtx, `SELECT host_pattern, port FROM proxy_whitelist WHERE tenant_id=$1`, tenantID)
	if err != nil {
		return nil, gap
	}
	defer rows.Close()
	allowed := map[string]bool{}
	allowedTargets := map[string]bool{}
	for rows.Next() {
		var pattern string
		var port int
		if err := rows.Scan(&pattern, &port); err != nil {
			return nil, gap
		}
		pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
		for _, target := range urls {
			host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
			targetPort := 443
			if target.Scheme == "http" {
				targetPort = 80
			}
			if target.Port() != "" {
				value, err := strconv.Atoi(target.Port())
				if err != nil || value < 1 || value > 65535 {
					continue
				}
				targetPort = value
			}
			if port != 0 && port != targetPort {
				continue
			}
			matches := host == pattern
			if strings.HasPrefix(pattern, "*.") {
				matches = strings.HasSuffix(host, strings.TrimPrefix(pattern, "*"))
			}
			if matches {
				allowed[host] = true
				allowedTargets[target.String()] = true
			}
		}
	}
	if rows.Err() != nil {
		return nil, gap
	}
	// DLP allows subdomains of each entry. A mixed call with any unlisted URL
	// keeps the empty allowlist so an approved host cannot exempt that target.
	for _, target := range urls {
		if !allowedTargets[target.String()] {
			return nil, nil
		}
	}
	domains := make([]string, 0, len(allowed))
	for host := range allowed {
		domains = append(domains, host)
	}
	sort.Strings(domains)
	return domains, nil
}

func toolArgumentURLs(arguments map[string]any) []*url.URL {
	var urls []*url.URL
	var collect func(any, int)
	collect = func(value any, depth int) {
		if depth > 16 || len(urls) >= 128 {
			return
		}
		switch item := value.(type) {
		case string:
			parsed, err := url.Parse(strings.TrimSpace(item))
			if err == nil && parsed.Hostname() != "" && (parsed.Scheme == "https" || parsed.Scheme == "http") {
				urls = append(urls, parsed)
			}
		case map[string]any:
			for _, child := range item {
				collect(child, depth+1)
			}
		case []any:
			for _, child := range item {
				collect(child, depth+1)
			}
		}
	}
	collect(arguments, 0)
	return urls
}

func appendToolAnalysisGap(decision agentguard.Decision, ruleID string) agentguard.Decision {
	decision.Evidence = append(decision.Evidence, agentguard.Evidence{RuleID: ruleID, Category: "coverage_gap"})
	return decision
}

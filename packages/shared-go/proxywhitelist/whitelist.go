// Package proxywhitelist provides the tenant-scoped policy shared by forward proxies.
package proxywhitelist

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Rule struct {
	HostPattern  string
	Port         int
	AuditEnabled bool
	TenantID     string
}

// Tenant selects deployment configuration, never a client-supplied header.
func Tenant(value string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return "tenant_default"
}

func Host(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(value), "[]")), ".")
}

// Target accepts DNS names and IPv6 literals, retaining the target's actual port.
func Target(value string, defaultPort int) (string, int) {
	if host, port, err := net.SplitHostPort(value); err == nil {
		if parsed, err := strconv.Atoi(port); err == nil {
			return Host(host), parsed
		}
	}
	return Host(value), defaultPort
}

func Matches(rule Rule, host string, port int) bool {
	if rule.Port <= 0 || rule.Port > 65535 || rule.Port != port {
		return false
	}
	return MatchesHost(rule.HostPattern, host)
}

func MatchesHost(pattern, host string) bool {
	host, pattern = Host(host), Host(pattern)
	if strings.HasPrefix(pattern, "*.") {
		domain := strings.TrimPrefix(pattern, "*.")
		return domain != "" && (host == domain || strings.HasSuffix(host, "."+domain))
	}
	return pattern != "" && pattern == host
}

func Match(rules []Rule, tenantID, host string, port int) (matched *Rule, count int) {
	tenantID = Tenant(tenantID)
	for i := range rules {
		if rules[i].TenantID != tenantID {
			continue
		}
		count++
		if matched == nil && Matches(rules[i], host, port) {
			matched = &rules[i]
		}
	}
	return matched, count
}

type Store struct{ DB *pgxpool.Pool }

func (s Store) ListRules(ctx context.Context, tenantID string) ([]Rule, error) {
	if s.DB == nil {
		return nil, errors.New("proxy whitelist store unavailable")
	}
	rows, err := s.DB.Query(ctx, `SELECT host_pattern, port, audit_enabled, tenant_id FROM proxy_whitelist WHERE tenant_id = $1`, Tenant(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []Rule
	for rows.Next() {
		var rule Rule
		if err := rows.Scan(&rule.HostPattern, &rule.Port, &rule.AuditEnabled, &rule.TenantID); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

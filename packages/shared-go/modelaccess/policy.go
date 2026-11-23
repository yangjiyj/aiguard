// Package modelaccess computes department, personal narrowing and extra model grants.
package modelaccess

import (
	"errors"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	Inherit   = "inherit"
	Allowlist = "allowlist"
)

var ErrInvalidPolicy = errors.New("invalid user model policy")

type Policy struct {
	Mode       string   `json:"mode"`
	ModelNames []string `json:"model_names"`
}

func Normalize(policy Policy) (Policy, error) {
	if policy.Mode == "" {
		policy.Mode = Inherit
	}
	if policy.Mode != Inherit && policy.Mode != Allowlist {
		return Policy{}, ErrInvalidPolicy
	}
	if len(policy.ModelNames) > 500 || (policy.Mode == Inherit && len(policy.ModelNames) != 0) {
		return Policy{}, ErrInvalidPolicy
	}
	names := make(map[string]bool, len(policy.ModelNames))
	for _, raw := range policy.ModelNames {
		name := strings.TrimSpace(raw)
		if name == "" || len(name) > 256 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return Policy{}, ErrInvalidPolicy
		}
		names[name] = true
	}
	policy.ModelNames = make([]string, 0, len(names))
	for name := range names {
		policy.ModelNames = append(policy.ModelNames, name)
	}
	sort.Strings(policy.ModelNames)
	return policy, nil
}

// Resolve always returns a subset of the department models. An empty explicit
// allowlist denies every model; inheritance contributes no additional grants.
func Resolve(department []string, policy Policy) ([]string, error) {
	policy, err := Normalize(policy)
	if err != nil {
		return nil, err
	}
	personal := make(map[string]bool, len(policy.ModelNames))
	for _, name := range policy.ModelNames {
		personal[name] = true
	}
	resultSet := make(map[string]bool, len(department))
	for _, name := range department {
		if policy.Mode == Inherit || personal[name] {
			resultSet[name] = true
		}
	}
	result := make([]string, 0, len(resultSet))
	for name := range resultSet {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

const (
	SourceDepartment       = "department"
	SourcePersonalExtra    = "personal_extra"
	SourcePersonalNarrowed = "personal_narrowed"
)

type ExtraGrant struct {
	ID        string     `json:"id"`
	Model     string     `json:"model"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

func NormalizeExtraGrant(grant ExtraGrant, now time.Time) (ExtraGrant, error) {
	policy, err := Normalize(Policy{Mode: Allowlist, ModelNames: []string{grant.Model}})
	grant.Reason = strings.TrimSpace(grant.Reason)
	if err != nil || grant.Reason == "" || len(grant.Reason) > 2000 || strings.IndexFunc(grant.Reason, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) >= 0 || (grant.ExpiresAt != nil && !grant.ExpiresAt.After(now)) {
		return ExtraGrant{}, ErrInvalidPolicy
	}
	grant.Model = policy.ModelNames[0]
	return grant, nil
}

// ResolveWithExtras keeps narrowing within the current department; only explicit,
// current extra grants can add authorized models outside it. Base provenance wins
// when a model is also covered by an extra grant.
func ResolveWithExtras(department []string, policy Policy, grants []ExtraGrant, _ []string, now time.Time) ([]string, map[string]string, []string, error) {
	policy, err := Normalize(policy)
	if err != nil {
		return nil, nil, nil, err
	}
	base, err := Resolve(department, policy)
	if err != nil {
		return nil, nil, nil, err
	}
	sources := map[string]string{}
	for _, name := range base {
		source := SourceDepartment
		if policy.Mode == Allowlist {
			source = SourcePersonalNarrowed
		}
		sources[name] = source
	}
	for _, grant := range grants {
		if grant.RevokedAt == nil && (grant.ExpiresAt == nil || grant.ExpiresAt.After(now)) && sources[grant.Model] == "" {
			sources[grant.Model] = SourcePersonalExtra
		}
	}
	result := make([]string, 0, len(sources))
	for name := range sources {
		result = append(result, name)
	}
	sort.Strings(result)
	dept := map[string]bool{}
	for _, name := range department {
		dept[name] = true
	}
	stale := []string{}
	for _, name := range policy.ModelNames {
		if !dept[name] {
			stale = append(stale, name)
		}
	}
	return result, sources, stale, nil
}

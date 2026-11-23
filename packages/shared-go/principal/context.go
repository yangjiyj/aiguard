// Package principal defines the trusted, versioned identity context shared by
// gateway, proxy, and security policy evaluation.
package principal

import (
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const CurrentSchemaVersion = 1

type TrustLevel string
type IdentitySource string

const (
	TrustUnknown       TrustLevel = "unknown"
	TrustKeyBound      TrustLevel = "key_bound"
	TrustAuthenticated TrustLevel = "authenticated"

	SourceUnknown      IdentitySource = "unknown"
	SourceAPIKey       IdentitySource = "api_key"
	SourceForwardProxy IdentitySource = "forward_proxy"
	SourceReverseProxy IdentitySource = "reverse_proxy"
	SourceSession      IdentitySource = "session"
)

var ErrInvalidContext = errors.New("principal context is invalid")

type Context struct {
	SchemaVersion                 int            `json:"schema_version"`
	TenantID                      string         `json:"tenant_id"`
	ActorUserID                   string         `json:"actor_user_id,omitempty"`
	KeyOwnerUserID                string         `json:"key_owner_user_id,omitempty"`
	ActorDepartmentIDs            []string       `json:"actor_department_ids,omitempty"`
	ActorDepartmentAncestorIDs    []string       `json:"actor_department_ancestor_ids,omitempty"`
	KeyOwnerDepartmentIDs         []string       `json:"key_owner_department_ids,omitempty"`
	KeyOwnerDepartmentAncestorIDs []string       `json:"key_owner_department_ancestor_ids,omitempty"`
	ProjectID                     string         `json:"project_id,omitempty"`
	ApplicationID                 string         `json:"application_id,omitempty"`
	ApplicationDepartmentID       string         `json:"application_department_id,omitempty"`
	KeyID                         string         `json:"key_id,omitempty"`
	Protocol                      string         `json:"protocol,omitempty"`
	EntryPoint                    string         `json:"entry_point,omitempty"`
	ModelID                       string         `json:"model_id,omitempty"`
	IdentitySource                IdentitySource `json:"identity_source"`
	TrustLevel                    TrustLevel     `json:"trust_level"`
	IdentityVersion               string         `json:"identity_version,omitempty"`
}

func Normalize(in Context) (Context, error) {
	out := in
	if out.SchemaVersion == 0 {
		out.SchemaVersion = CurrentSchemaVersion
	}
	trim := func(value string) string { return strings.TrimSpace(value) }
	out.TenantID = trim(out.TenantID)
	out.ActorUserID = trim(out.ActorUserID)
	out.KeyOwnerUserID = trim(out.KeyOwnerUserID)
	out.ProjectID = trim(out.ProjectID)
	out.ApplicationID = trim(out.ApplicationID)
	out.ApplicationDepartmentID = trim(out.ApplicationDepartmentID)
	out.KeyID = trim(out.KeyID)
	out.Protocol = strings.ToLower(trim(out.Protocol))
	out.EntryPoint = strings.ToLower(trim(out.EntryPoint))
	out.IdentityVersion = trim(out.IdentityVersion)
	out.ModelID = trim(out.ModelID)
	if out.IdentitySource == "" {
		out.IdentitySource = SourceUnknown
	}
	if out.TrustLevel == "" {
		out.TrustLevel = TrustUnknown
	}
	if out.ProjectID == "" {
		out.ProjectID = out.ApplicationID
	}
	if out.ApplicationID == "" {
		out.ApplicationID = out.ProjectID
	}
	out.ActorDepartmentIDs = normalizeIDs(out.ActorDepartmentIDs)
	out.ActorDepartmentAncestorIDs = normalizeIDs(out.ActorDepartmentAncestorIDs)
	out.KeyOwnerDepartmentIDs = normalizeIDs(out.KeyOwnerDepartmentIDs)
	out.KeyOwnerDepartmentAncestorIDs = normalizeIDs(out.KeyOwnerDepartmentAncestorIDs)
	if err := out.Validate(); err != nil {
		return Context{}, err
	}
	return out, nil
}

// WithModel returns a copy of the context stamped with the requested model so
// model-scoped policy bindings can evaluate per model. Empty or whitespace-only
// models leave the context untouched.
func WithModel(c Context, model string) Context {
	model = strings.TrimSpace(model)
	if model == "" || c.ModelID == model {
		return c
	}
	c.ModelID = model
	return c
}

func (c Context) Validate() error {
	if c.SchemaVersion != CurrentSchemaVersion || !validID(c.TenantID) {
		return ErrInvalidContext
	}
	if c.ProjectID != c.ApplicationID {
		return ErrInvalidContext
	}
	for _, value := range []string{
		c.ActorUserID, c.KeyOwnerUserID, c.ProjectID, c.ApplicationID,
		c.ApplicationDepartmentID, c.KeyID, c.Protocol, c.EntryPoint, c.IdentityVersion, c.ModelID,
	} {
		if value != "" && !validID(value) {
			return ErrInvalidContext
		}
	}
	if (c.Protocol != "" && !validSelector(c.Protocol)) || (c.EntryPoint != "" && !validSelector(c.EntryPoint)) {
		return ErrInvalidContext
	}
	for _, values := range [][]string{
		c.ActorDepartmentIDs, c.ActorDepartmentAncestorIDs,
		c.KeyOwnerDepartmentIDs, c.KeyOwnerDepartmentAncestorIDs,
	} {
		for _, value := range values {
			if !validID(value) {
				return ErrInvalidContext
			}
		}
	}
	switch c.IdentitySource {
	case SourceUnknown, SourceAPIKey, SourceForwardProxy, SourceReverseProxy, SourceSession:
	default:
		return ErrInvalidContext
	}
	switch c.TrustLevel {
	case TrustUnknown:
		if c.ActorUserID != "" || c.KeyOwnerUserID != "" || len(c.ActorDepartmentIDs) > 0 || len(c.ActorDepartmentAncestorIDs) > 0 || len(c.KeyOwnerDepartmentIDs) > 0 || len(c.KeyOwnerDepartmentAncestorIDs) > 0 {
			return ErrInvalidContext
		}
	case TrustKeyBound:
		if c.KeyID == "" || c.ActorUserID != "" || len(c.ActorDepartmentIDs) > 0 || len(c.ActorDepartmentAncestorIDs) > 0 {
			return ErrInvalidContext
		}
	case TrustAuthenticated:
		if c.ActorUserID == "" {
			return ErrInvalidContext
		}
	default:
		return ErrInvalidContext
	}
	if (len(c.ActorDepartmentIDs) > 0 || len(c.ActorDepartmentAncestorIDs) > 0) && c.ActorUserID == "" {
		return ErrInvalidContext
	}
	if (len(c.KeyOwnerDepartmentIDs) > 0 || len(c.KeyOwnerDepartmentAncestorIDs) > 0) && c.KeyOwnerUserID == "" {
		return ErrInvalidContext
	}
	if c.KeyOwnerUserID != "" && c.KeyID == "" {
		return ErrInvalidContext
	}
	if c.ApplicationDepartmentID != "" && c.ApplicationID == "" {
		return ErrInvalidContext
	}
	return nil
}

func normalizeIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func validID(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || utf8.RuneCountInString(value) > 256 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validSelector(value string) bool {
	for i, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || i > 0 && (r == '_' || r == '-' || r == '.' || r == ':') {
			continue
		}
		return false
	}
	return value != ""
}

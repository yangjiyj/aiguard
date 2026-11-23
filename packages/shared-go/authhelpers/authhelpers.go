package authhelpers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
)

// HashKey computes SHA256 hash of a key for storage comparison
func HashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// GenerateKey creates a new internal API key
func GenerateKey() string {
	// Format: jjd_<uuid>; existing keys remain valid through full-key SHA-256 lookup.
	return "jjd_" + uuid.New().String()
}

// GetKeyPrefix extracts the prefix from a key for display purposes
func GetKeyPrefix(key string) string {
	if len(key) > 8 {
		return key[:8] + "..."
	}
	return key
}

// ExtractBearerToken extracts the token from Authorization header
func ExtractBearerToken(authHeader string) string {
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return ""
	}

	if strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// ContextKey types for auth values
type ContextKey string

const (
	TenantKey    ContextKey = "tenant_id"
	ProjectKey   ContextKey = "project_id"
	UserKey      ContextKey = "user_id"
	KeyIDKey     ContextKey = "key_id"
	SessionKey   ContextKey = "session_id"
	AgentTypeKey ContextKey = "agent_type"
)

// GetTenantID retrieves tenant ID from context
func GetTenantID(ctx context.Context) string {
	if v := ctx.Value(TenantKey); v != nil {
		return v.(string)
	}
	return ""
}

// GetProjectID retrieves project ID from context
func GetProjectID(ctx context.Context) string {
	if v := ctx.Value(ProjectKey); v != nil {
		return v.(string)
	}
	return ""
}

// GetUserID retrieves user ID from context
func GetUserID(ctx context.Context) string {
	if v := ctx.Value(UserKey); v != nil {
		return v.(string)
	}
	return ""
}

// GetKeyID retrieves key ID from context
func GetKeyID(ctx context.Context) string {
	if v := ctx.Value(KeyIDKey); v != nil {
		return v.(string)
	}
	return ""
}

// SetAuthContext sets all auth values in context
func SetAuthContext(ctx context.Context, tenantID, projectID, userID, keyID string) context.Context {
	ctx = context.WithValue(ctx, TenantKey, tenantID)
	ctx = context.WithValue(ctx, ProjectKey, projectID)
	ctx = context.WithValue(ctx, UserKey, userID)
	ctx = context.WithValue(ctx, KeyIDKey, keyID)
	return ctx
}

// SetAgentMetadata sets agent metadata in context
func SetAgentMetadata(ctx context.Context, sessionID, agentType, workspaceID string) context.Context {
	if sessionID != "" {
		ctx = context.WithValue(ctx, SessionKey, sessionID)
	}
	if agentType != "" {
		ctx = context.WithValue(ctx, AgentTypeKey, agentType)
	}
	return ctx
}

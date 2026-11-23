package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/google/uuid"
)

// HeaderName is the HTTP header for request ID
const HeaderName = "X-Request-ID"

// Generate creates a new unique request ID
func Generate() string {
	// Use UUID v4 for request IDs
	return "req_" + uuid.New().String()
}

// GenerateShort creates a shorter request ID using random bytes
func GenerateShort() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to UUID if random read fails
		return "req_" + uuid.New().String()[:16]
	}
	return "req_" + hex.EncodeToString(b)
}

// ContextKey is the context key for request ID
type ContextKey string

const Key ContextKey = "request_id"

// FromContext retrieves request ID from context
func FromContext(ctx context.Context) string {
	if id := ctx.Value(Key); id != nil {
		return id.(string)
	}
	return ""
}

// ToContext adds request ID to context
func ToContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, Key, id)
}

// Middleware is an HTTP middleware that ensures every request has an ID
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request already has an ID in header
		id := r.Header.Get(HeaderName)
		if id == "" {
			id = Generate()
		}

		// Add to context
		ctx := ToContext(r.Context(), id)

		// Add to response header for tracing
		w.Header().Set(HeaderName, id)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
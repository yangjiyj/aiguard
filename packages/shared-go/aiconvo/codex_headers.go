package aiconvo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
)

// CodexThreadKey uses the native thread identity, which survives changes to the
// process session and prompt. Old clients sent the thread in session_id.
// These client declarations are grouping hints only, never authorization.
func CodexThreadKey(headers http.Header, tenantID, caller string) string {
	if strings.TrimSpace(tenantID) == "" {
		return ""
	}
	var identity string
	for _, aliases := range [][]string{{"thread-id", "thread_id"}, {"session-id", "session_id"}} {
		found := false
		for name, values := range headers {
			if !strings.EqualFold(name, aliases[0]) && !strings.EqualFold(name, aliases[1]) {
				continue
			}
			found = true
			if len(values) != 1 {
				return ""
			}
			value := strings.TrimSpace(values[0])
			if len(value) == 0 || len(value) > 256 {
				return ""
			}
			for _, c := range value {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("-_.:", c)) {
					return ""
				}
			}
			if identity != "" && identity != value {
				return ""
			}
			identity = value
		}
		if found {
			break
		}
	}
	if identity == "" {
		return ""
	}
	tuple, _ := json.Marshal([]string{"codex_thread_v1", tenantID, caller, identity})
	sum := sha256.Sum256(tuple)
	return "codex_" + hex.EncodeToString(sum[:])[:48]
}

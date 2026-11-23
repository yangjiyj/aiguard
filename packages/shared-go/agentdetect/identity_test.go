package agentdetect

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestIdentityHeadersPreserveDeclarationWithoutSecrets(t *testing.T) {
	h := http.Header{"User-Agent": {"codex_exec/1.0"}, "X-Agent-Type": {"main"}, "X-Jjdguard-Agent-Name": {"团队助手"}, "Authorization": {"Bearer SECRET"}, "X-Api-Key": {"SECRET"}}
	raw := IdentityHeaders(h)
	var got map[string]string
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got["declared_type"] != "main" || got["declared_name"] != "团队助手" || got["user_agent"] != "codex_exec/1.0" {
		t.Fatalf("missing observations: %s", raw)
	}
	if strings.Contains(raw, "SECRET") || len(got) != 6 {
		t.Fatal("unexpected header retained")
	}
	if BoundedIdentityValue(" 你\n好世界 ", 2) != "你好" {
		t.Fatal("bounds/control filtering")
	}
}

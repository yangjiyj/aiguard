package handler

import (
	"bytes"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
)

func TestRequestPrincipalAuditNeverPersistsKeyOwnerAsActor(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{
		UserID: "owner-a",
		Principal: &principal.Context{
			SchemaVersion: 1, TenantID: "tenant-a", ProjectID: "app-a", ApplicationID: "app-a",
			KeyID: "key-a", KeyOwnerUserID: "owner-a", IdentitySource: principal.SourceAPIKey, TrustLevel: principal.TrustKeyBound,
		},
	}
	actor, encoded := requestPrincipalAudit(envelope)
	if actor != "" {
		t.Fatalf("key owner persisted as actor: %q", actor)
	}
	if !bytes.Contains(encoded, []byte(`"key_owner_user_id":"owner-a"`)) || bytes.Contains(encoded, []byte(`"actor_user_id":"owner-a"`)) {
		t.Fatalf("principal audit boundary lost: %s", encoded)
	}
}

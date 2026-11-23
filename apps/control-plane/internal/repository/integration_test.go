package repository

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
)

func TestAgentCredentialRotationIsAtomicAndRetainsAuditIdentity(t *testing.T) {
	db, tenant, project, _ := setupInternalKeysTestDB(t)
	ctx := context.Background()
	repo := NewIntegrationRepository(db)
	agent := fmt.Sprintf("agent_%d", time.Now().UnixNano())
	oldRaw := "credential-fixture-original-" + agent
	old, err := repo.IssueCredential(ctx, tenant, ai.Credential{AgentInstanceID: agent, ProjectID: project, Scopes: []string{"chat", "models"}}, oldRaw, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.IssueCredential(ctx, tenant, ai.Credential{AgentInstanceID: agent}, oldRaw, old.KeyID)
	if !errors.Is(err, ai.ErrConflict) {
		t.Fatalf("duplicate hash rotation must fail with conflict: %v", err)
	}
	var status string
	if err = db.QueryRow(ctx, `SELECT status FROM internal_keys WHERE id=$1`, old.KeyID).Scan(&status); err != nil || status != "active" {
		t.Fatalf("failed rotation invalidated predecessor: %q %v", status, err)
	}
	var count int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM internal_keys WHERE tenant_id=$1 AND agent_instance_id=$2`, tenant, agent).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed rotation left a successor: count=%d err=%v", count, err)
	}
	successor, err := repo.IssueCredential(ctx, tenant, ai.Credential{AgentInstanceID: agent}, "credential-fixture-successor-"+agent, old.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if successor.AgentInstanceID != agent || successor.KeyID == old.KeyID {
		t.Fatal("rotation binding changed")
	}
	if err = db.QueryRow(ctx, `SELECT status FROM internal_keys WHERE id=$1`, old.KeyID).Scan(&status); err != nil || status != "revoked" {
		t.Fatalf("predecessor not revoked: %q %v", status, err)
	}
	if _, err = repo.RevokeCredential(ctx, "foreign-tenant", successor.KeyID); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("cross-tenant revoke err=%v", err)
	}
	requestID := "tri_identity_" + agent
	if _, err = db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,project_id,client_id) VALUES($1,$1,$2,$3,$4)`, requestID, tenant, project, old.KeyID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM request_logs WHERE request_id=$1`, requestID)
	})
	var materialized string
	if err = db.QueryRow(ctx, `SELECT agent_instance_id FROM request_logs WHERE request_id=$1`, requestID).Scan(&materialized); err != nil || materialized != agent {
		t.Fatalf("historical attribution=%q err=%v", materialized, err)
	}
	if _, err = db.Exec(ctx, `UPDATE internal_keys SET agent_instance_id='other-agent' WHERE id=$1`, old.KeyID); err == nil {
		t.Fatal("binding reassignment must be rejected")
	}
}

func TestAgentPolicyVersionCASAndTenantScope(t *testing.T) {
	db, tenant, project, _ := setupInternalKeysTestDB(t)
	repo := NewIntegrationRepository(db)
	ctx := context.Background()
	agent := fmt.Sprintf("agent_%d", time.Now().UnixNano())
	_, err := repo.IssueCredential(ctx, tenant, ai.Credential{AgentInstanceID: agent, ProjectID: project, Scopes: []string{"chat"}}, "credential-fixture-policy-"+agent, "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := repo.WritePolicy(ctx, tenant, "", "", ai.Policy{AgentInstanceID: agent, Action: "block_model_egress", Enabled: true, Mode: "protect"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM integration_agent_policies WHERE id=$1`, p.ID)
	})
	if p.Version != "1" {
		t.Fatal(p.Version)
	}
	if _, err = repo.WritePolicy(ctx, tenant, p.ID, "999", *p); !errors.Is(err, ai.ErrConflict) {
		t.Fatalf("CAS err=%v", err)
	}
	next, err := repo.WritePolicy(ctx, tenant, p.ID, "1", *p)
	if err != nil || next.Version != "2" {
		t.Fatalf("next=%+v err=%v", next, err)
	}
	if _, err = repo.GetPolicy(ctx, "foreign-tenant", p.ID); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("cross-tenant read err=%v", err)
	}
}

func TestAgentCredentialDuplicateHashConcurrentIssue(t *testing.T) {
	db, tenant, project, _ := setupInternalKeysTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	repo := NewIntegrationRepository(db)
	agent := fmt.Sprintf("agent_concurrent_%d", time.Now().UnixNano())
	raw := "credential-fixture-concurrent-" + agent
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, err := repo.IssueCredential(ctx, tenant, ai.Credential{AgentInstanceID: agent, ProjectID: project, Scopes: []string{"chat"}}, raw, "")
			results <- err
		}()
	}
	close(start)
	success, conflicts := 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, ai.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected issue error: %v", err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("concurrent duplicate results: success=%d conflicts=%d", success, conflicts)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM internal_keys WHERE tenant_id=$1 AND agent_instance_id=$2`, tenant, agent).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate rows persisted: count=%d err=%v", count, err)
	}
}

func TestAgentMCPPolicyRequiresRegisteredTenantTarget(t *testing.T) {
	db, tenant, project, _ := setupInternalKeysTestDB(t)
	ctx := context.Background()
	repo := NewIntegrationRepository(db)
	agent := fmt.Sprintf("agent_mcp_%d", time.Now().UnixNano())
	_, err := repo.IssueCredential(ctx, tenant, ai.Credential{AgentInstanceID: agent, ProjectID: project, Scopes: []string{"mcp"}}, "credential-fixture-mcp-"+agent, "")
	if err != nil {
		t.Fatal(err)
	}
	server := "mcp_" + agent
	foreign := "foreign_" + agent
	if _, err = db.Exec(ctx, `INSERT INTO mcp_servers(id,tenant_id,name,server_url,status) VALUES($1,$2,'display-name','http://127.0.0.1:9/mcp','active'),($3,'tenant_default','foreign','http://127.0.0.1:9/mcp','active')`, server, tenant, foreign); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM integration_agent_policies WHERE tenant_id=$1 AND agent_instance_id=$2`, tenant, agent)
		_, _ = db.Exec(context.Background(), `DELETE FROM mcp_servers WHERE id=$1 OR id=$2`, server, foreign)
	})
	input := ai.Policy{AgentInstanceID: agent, Action: "disable_mcp", Enabled: true, Mode: "protect"}
	for _, bad := range []string{"missing_" + agent, foreign, "display-name"} {
		input.MCPServerID = bad
		if _, err = repo.WritePolicy(ctx, tenant, "", "", input); !errors.Is(err, ai.ErrNotFound) {
			t.Fatalf("unregistered or foreign target %q err=%v", bad, err)
		}
	}
	input.MCPServerID = server
	p, err := repo.WritePolicy(ctx, tenant, "", "", input)
	if err != nil {
		t.Fatal(err)
	}
	input.Enabled = false
	next, err := repo.WritePolicy(ctx, tenant, p.ID, p.Version, input)
	if err != nil || next.Version != "2" {
		t.Fatalf("valid target update=%+v err=%v", next, err)
	}
	if _, err = db.Exec(ctx, `DELETE FROM mcp_servers WHERE id=$1 AND tenant_id=$2`, server, tenant); err != nil {
		t.Fatal(err)
	}
	input.Enabled = true
	if _, err = repo.WritePolicy(ctx, tenant, p.ID, next.Version, input); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("deleted target CAS update err=%v", err)
	}
	if _, err = repo.WritePolicy(ctx, tenant, "", "", input); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("deleted target create err=%v", err)
	}
	retained, err := repo.GetPolicy(ctx, tenant, p.ID)
	if err != nil || retained.Enabled || retained.Version != "2" {
		t.Fatalf("rejected write changed policy=%+v err=%v", retained, err)
	}
	input.MCPServerID = ""
	if _, err = repo.WritePolicy(ctx, tenant, "", "", input); err != nil {
		t.Fatalf("all MCP empty reference err=%v", err)
	}
}

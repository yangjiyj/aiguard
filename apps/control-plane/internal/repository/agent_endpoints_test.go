package repository

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestProductAllowedRequiresExactArrayMember(t *testing.T) {
	allowed := []string{"claude-code-pro"}
	if productAllowed(allowed, "claude-code") {
		t.Fatal("substring product unexpectedly allowed")
	}
	if !productAllowed(allowed, "claude-code-pro") {
		t.Fatal("exact product unexpectedly rejected")
	}
	if !productAllowed(nil, "any-product") {
		t.Fatal("empty allowlist must allow any product")
	}
}

func agentEndpointTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENT_ENDPOINT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENT_ENDPOINT_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var name string
	if err = db.QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "jjdguard_dev" {
		t.Fatalf("refusing non-development database %q", name)
	}
	return db
}

func insertEnrollmentToken(t *testing.T, db *pgxpool.Pool, maxEndpoints int, allowed string) (string, string, string) {
	t.Helper()
	suffix := uuid.NewString()
	tenantID := "agent-endpoint-test-tenant-" + suffix
	enrollmentID := "agent-endpoint-test-enrollment-" + suffix
	token := "agent-endpoint-test-token-" + suffix
	_, err := db.Exec(context.Background(), `INSERT INTO agent_enrollment_tokens
		(id,tenant_id,name,token_hash,token_prefix,default_mode,allowed_products,max_endpoints)
		VALUES($1,$2,'test',$3,'test','monitor',$4::jsonb,$5)`, enrollmentID, tenantID, HashAgentToken(token), allowed, maxEndpoints)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.Exec(ctx, `DELETE FROM agent_endpoints WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM agent_enrollment_tokens WHERE id=$1`, enrollmentID)
	})
	return tenantID, enrollmentID, token
}

func endpointRegisterRequest(machineID string) AgentEndpointRegisterRequest {
	return AgentEndpointRegisterRequest{
		MachineID: machineID, Hostname: "host-a", OS: "linux", OSVersion: "1",
		Arch: "amd64", OSUser: "user-a", AgentProduct: "claude-code", AgentVersion: "1",
		AdapterName: "adapter", AdapterVersion: "1", HookdVersion: "1",
		Capabilities: []string{"tool-hooks"},
	}
}

func TestAgentEndpointRegisterReturnsOriginalIDAndRotatesToken(t *testing.T) {
	db := agentEndpointTestDB(t)
	tenantID, enrollmentID, enrollmentToken := insertEnrollmentToken(t, db, 1, `["claude-code"]`)
	repo := NewAgentEndpointRepository(db)
	ctx := context.Background()
	first, err := repo.Register(ctx, HashAgentToken(enrollmentToken), endpointRegisterRequest("machine-a"))
	if err != nil {
		t.Fatal(err)
	}
	firstID := first["endpoint_id"].(string)
	firstToken := first["endpoint_token"].(string)
	request := endpointRegisterRequest("machine-a")
	request.Hostname = "renamed-host"
	request.OSVersion = "2"
	request.AgentVersion = "2"
	second, err := repo.Register(ctx, HashAgentToken(enrollmentToken), request)
	if err != nil {
		t.Fatal(err)
	}
	if second["endpoint_id"] != firstID {
		t.Fatalf("endpoint id changed: first=%v second=%v", firstID, second["endpoint_id"])
	}
	secondToken := second["endpoint_token"].(string)
	if secondToken == firstToken {
		t.Fatal("endpoint token was not rotated")
	}
	if resolved, err := repo.Resolve(ctx, HashAgentToken(firstToken)); err != nil || resolved != nil {
		t.Fatalf("old token still resolves: value=%+v err=%v", resolved, err)
	}
	resolved, err := repo.Resolve(ctx, HashAgentToken(secondToken))
	if err != nil || resolved == nil || resolved.EndpointID != firstID {
		t.Fatalf("new token resolution=%+v err=%v", resolved, err)
	}
	var count int
	var hostname, osVersion, agentVersion string
	var lastUsed *time.Time
	if err = db.QueryRow(ctx, `SELECT count(*),max(hostname),max(os_version),max(agent_version)
		FROM agent_endpoints WHERE tenant_id=$1 AND enrollment_token_id=$2`, tenantID, enrollmentID).
		Scan(&count, &hostname, &osVersion, &agentVersion); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT last_used_at FROM agent_enrollment_tokens WHERE id=$1`, enrollmentID).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if count != 1 || hostname != request.Hostname || osVersion != request.OSVersion || agentVersion != request.AgentVersion || lastUsed == nil {
		t.Fatalf("count=%d hostname=%q os=%q agent=%q last_used=%v", count, hostname, osVersion, agentVersion, lastUsed)
	}
}

func TestAgentEndpointRegisterSerializesMaxEndpointQuota(t *testing.T) {
	db := agentEndpointTestDB(t)
	tenantID, enrollmentID, enrollmentToken := insertEnrollmentToken(t, db, 1, `["claude-code"]`)
	repo := NewAgentEndpointRepository(db)
	ctx := context.Background()
	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for i := 0; i < 2; i++ {
		machineID := fmt.Sprintf("machine-%d", i)
		go func() {
			ready.Done()
			<-start
			_, err := repo.Register(ctx, HashAgentToken(enrollmentToken), endpointRegisterRequest(machineID))
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	successes := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful registrations=%d, want 1", successes)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_endpoints WHERE tenant_id=$1 AND enrollment_token_id=$2 AND status<>'revoked'`, tenantID, enrollmentID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("active endpoints=%d, want 1", count)
	}
}

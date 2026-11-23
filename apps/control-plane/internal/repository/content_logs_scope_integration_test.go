package repository

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This test exercises the repository INSERT, not just scope normalization. Each
// run uses a separate schema so it cannot change pre-existing application rows.
func TestContentLogCreatePersistsDeploymentEnvironmentScope(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "content_scope_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("clean isolated scope fixture: %v", err)
		}
		admin.Close()
	})

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if _, err := db.Exec(ctx, `
        CREATE TABLE content_logs (
            id varchar(64) PRIMARY KEY,
            request_id varchar(64) NOT NULL,
            tenant_id varchar(64) NOT NULL,
            user_id varchar(64),
            session_id varchar(64),
            role varchar(32) NOT NULL,
            content text NOT NULL,
            tokens integer NOT NULL,
            message_index integer,
            environment_scope text NOT NULL DEFAULT 'legacy-unclassified'
                CHECK (environment_scope IN ('home', 'customer', 'legacy-unclassified'))
        )
    `); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, deployment, explicit, want string
	}{
		{"customer fallback", "customer", "", "customer"},
		{"customer confines home", "customer", "home", "customer"},
		{"customer confines invalid", "customer", "untrusted-header", "customer"},
		{"home confines customer", "home", "customer", "home"},
		{"legacy accepts explicit", "legacy-unclassified", "customer", "customer"},
		{"legacy keeps unknown", "legacy-unclassified", "", "legacy-unclassified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			index := 2
			record := &ContentLog{
				RequestID: uuid.NewString(), TenantID: "isolated-test-tenant",
				UserID: "isolated-test-user", SessionID: "isolated-test-session",
				Role: "user", Content: "synthetic audit evidence", Tokens: 3,
				MessageIndex: &index, EnvironmentScope: tc.explicit,
			}
			if err := NewContentLogRepository(db, tc.deployment).Create(ctx, record); err != nil {
				t.Fatalf("persist content log: %v", err)
			}
			var storedScope, storedContent string
			var storedIndex int
			if err := db.QueryRow(ctx,
				"SELECT environment_scope, content, message_index FROM content_logs WHERE id=$1",
				record.ID).Scan(&storedScope, &storedContent, &storedIndex); err != nil {
				t.Fatal(err)
			}
			if storedScope != tc.want || record.EnvironmentScope != tc.want {
				t.Fatalf("stored=%q returned=%q want=%q", storedScope, record.EnvironmentScope, tc.want)
			}
			if storedContent != record.Content || storedIndex != index {
				t.Fatalf("scope persistence changed evidence: content=%q index=%d", storedContent, storedIndex)
			}
		})
	}
}

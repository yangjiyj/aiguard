package repository

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func rawProviderFactDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TRI_RAW_FACTS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TRI_RAW_FACTS_TEST_DATABASE_URL requires dedicated tri_rawfacts_ database")
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid private test database configuration")
	}
	if config.ConnConfig.Host != "127.0.0.1" || !strings.HasPrefix(config.ConnConfig.Database, "tri_rawfacts_") {
		t.Fatal("refusing non-dedicated database")
	}
	db, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	t.Cleanup(db.Close)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `DROP SCHEMA public CASCADE;CREATE SCHEMA public;
CREATE TABLE tenants(id VARCHAR(64) PRIMARY KEY,name TEXT);
CREATE TABLE providers(id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) REFERENCES tenants(id),name TEXT,provider_type TEXT,base_url TEXT,auth_mode TEXT,is_default BOOLEAN,status TEXT,created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE provider_credentials(id VARCHAR(64) PRIMARY KEY,provider_id VARCHAR(64) REFERENCES providers(id),credential_name TEXT,secret_ciphertext TEXT,kms_key_ref TEXT,status TEXT,rotated_at TIMESTAMPTZ,created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE models(id VARCHAR(64) PRIMARY KEY,provider_id VARCHAR(64) REFERENCES providers(id),model_name TEXT,model_label TEXT,upstream_model_id TEXT,capabilities_json JSONB DEFAULT '{}',pricing_json JSONB DEFAULT '{}',context_window INT,status TEXT,created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE request_logs(id TEXT PRIMARY KEY,model_id TEXT,provider_id TEXT,endpoint_type TEXT,request_status TEXT,created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE routing_policies(id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64),scope_type TEXT,scope_ref TEXT,layer TEXT,strategy TEXT,config_json JSONB DEFAULT '{}',enabled BOOLEAN,schema_version INT DEFAULT 1,config_version BIGINT DEFAULT 1);`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../../../deploy/migrations/149_model_endpoint_capability_facts.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	return db
}

func rawProviderFactSeed(t *testing.T, db *pgxpool.Pool) (*Provider, ProviderProtocolProbeSnapshot, ModelProtocolProbeRecord) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO tenants VALUES('tenant-a','owned-test');INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,is_default,status) VALUES('provider-a','tenant-a','raw','openai','http://10.20.30.1:28991/v1/chat/completions','authorization_raw',false,'active');INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES('credential-a','provider-a','original','old-test-ciphertext','synthetic-key','active');INSERT INTO models(id,provider_id,model_name,model_label,upstream_model_id,capabilities_json,status) VALUES('model-a','provider-a','actual-model','actual-model','actual-upstream','{"routing":{"keep":true},"protocols":{"tools":false}}','active');`); err != nil {
		t.Fatal(err)
	}
	repo := NewProviderRepository(db)
	p, err := repo.GetByID(ctx, "tenant-a", "provider-a")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	snapshot := ProviderProtocolProbeSnapshot{ProviderConfigDigest: VerifiedModelSyncProviderConfigDigest(p.ProviderType, p.BaseURL, p.AuthMode), ProviderUpdatedAt: p.UpdatedAt, CredentialID: "credential-a", SecretCiphertext: "old-test-ciphertext", ModelID: "model-a", ModelName: "actual-model", UpstreamModelID: "actual-upstream", ModelStatus: "active"}
	p.BaseURL = "http://10.20.30.1:28991/verified/chat"
	record := ModelProtocolProbeRecord{SourceVersion: "actual-probe-test", ProviderConfigDigest: VerifiedModelSyncProviderConfigDigest(p.ProviderType, p.BaseURL, p.AuthMode), VerifiedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour), Endpoints: []ModelEndpointProbeResult{{EndpointType: "chat", State: "supported"}}}
	return p, snapshot, record
}

func TestRawProviderProtocolProbeAtomicUpdatePersistsOnlyVerifiedChat(t *testing.T) {
	db := rawProviderFactDB(t)
	p, snapshot, record := rawProviderFactSeed(t, db)
	cred := &ProviderCredential{CredentialName: "verified", SecretCiphertext: "new-test-ciphertext", KMSKeyRef: "synthetic-key", Status: "active"}
	caps := map[string]interface{}{"protocols": map[string]interface{}{"chat_completions": true}}
	if err := NewProviderRepository(db).UpdateWithCredentialAndProtocolProbe(context.Background(), p, cred, snapshot, caps, record); err != nil {
		t.Fatal(err)
	}
	var state, source, digest string
	var override bool
	if err := db.QueryRow(context.Background(), `SELECT state,source,provider_config_digest,is_override FROM model_endpoint_capability_effective WHERE model_id='model-a' AND endpoint_type='chat'`).Scan(&state, &source, &digest, &override); err != nil {
		t.Fatal(err)
	}
	if state != "supported" || source != "probe" || digest != record.ProviderConfigDigest || override {
		t.Fatal("actual chat fact differs")
	}
	var extra int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM model_endpoint_capability_facts WHERE model_id='model-a' AND endpoint_type<>'chat'`).Scan(&extra); err != nil || extra != 0 {
		t.Fatal("unprobed endpoint fact created")
	}
	var payload []byte
	if err := db.QueryRow(context.Background(), `SELECT capabilities_json FROM models WHERE id='model-a'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var stored map[string]interface{}
	if err := json.Unmarshal(payload, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["routing"].(map[string]interface{})["keep"] != true || stored["protocols"].(map[string]interface{})["tools"] != false {
		t.Fatal("unrelated capability overwritten")
	}
}

func TestRawProviderProtocolProbeFactFailureRollsBackCompleteUpdate(t *testing.T) {
	db := rawProviderFactDB(t)
	p, snapshot, record := rawProviderFactSeed(t, db)
	if _, err := db.Exec(context.Background(), `ALTER TABLE model_endpoint_capability_facts ADD CONSTRAINT refuse_fixture_write CHECK(source_version<>'fail-write')`); err != nil {
		t.Fatal(err)
	}
	record.SourceVersion = "fail-write"
	err := NewProviderRepository(db).UpdateWithCredentialAndProtocolProbe(context.Background(), p, &ProviderCredential{CredentialName: "updated", SecretCiphertext: "new-test-ciphertext", Status: "active"}, snapshot, map[string]interface{}{"protocols": map[string]interface{}{"chat_completions": true}}, record)
	if err == nil {
		t.Fatal("fact failure committed provider update")
	}
	var url, ciphertext, status string
	var credentialCount, factCount int
	if err := db.QueryRow(context.Background(), `SELECT p.base_url,c.secret_ciphertext,c.status,(SELECT count(*) FROM provider_credentials),(SELECT count(*) FROM model_endpoint_capability_facts) FROM providers p JOIN provider_credentials c ON c.provider_id=p.id WHERE p.id='provider-a'`).Scan(&url, &ciphertext, &status, &credentialCount, &factCount); err != nil {
		t.Fatal(err)
	}
	if url != "http://10.20.30.1:28991/v1/chat/completions" || ciphertext != "old-test-ciphertext" || status != "active" || credentialCount != 1 || factCount != 0 {
		t.Fatal("provider/credential/fact rollback incomplete")
	}
}

func TestRawProviderProtocolProbeRejectsConcurrentIdentityChanges(t *testing.T) {
	for _, kind := range []string{"config", "credential", "ciphertext", "mapping", "model_status"} {
		t.Run(kind, func(t *testing.T) {
			db := rawProviderFactDB(t)
			p, snapshot, record := rawProviderFactSeed(t, db)
			statements := map[string]string{
				"config":       `UPDATE providers SET base_url='http://concurrent.invalid/chat',updated_at=clock_timestamp() WHERE id='provider-a'`,
				"credential":   `UPDATE provider_credentials SET status='rotated' WHERE id='credential-a';INSERT INTO provider_credentials(id,provider_id,secret_ciphertext,status,created_at) VALUES('credential-b','provider-a','other-test-cipher','active',clock_timestamp())`,
				"ciphertext":   `UPDATE provider_credentials SET secret_ciphertext='other-test-cipher' WHERE id='credential-a'`,
				"mapping":      `UPDATE models SET upstream_model_id='concurrent-upstream' WHERE id='model-a'`,
				"model_status": `UPDATE models SET status='disabled' WHERE id='model-a'`,
			}
			if _, err := db.Exec(context.Background(), statements[kind]); err != nil {
				t.Fatal(err)
			}
			err := NewProviderRepository(db).UpdateWithCredentialAndProtocolProbe(context.Background(), p, nil, snapshot, map[string]interface{}{"protocols": map[string]interface{}{"chat_completions": true}}, record)
			if !errors.Is(err, ErrProviderProtocolProbeConflict) {
				t.Fatalf("stale %s proof accepted: %v", kind, err)
			}
			var facts int
			if err := db.QueryRow(context.Background(), `SELECT count(*) FROM model_endpoint_capability_facts`).Scan(&facts); err != nil || facts != 0 {
				t.Fatal("stale proof created fact")
			}
		})
	}
}

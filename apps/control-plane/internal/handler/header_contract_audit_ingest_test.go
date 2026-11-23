package handler

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

func TestHeaderContractConflictIngestRequiresStrictEventAndTwoAcks(t *testing.T) {
	sys, chain := &headerContractSystemRepo{}, &headerContractChain{}
	deps := newHeaderContractDeps(sys, chain, false)
	body := `{"occurrence_id":"be0e16c4-ac4a-4d1c-8f93-5bb20b4af755","service":"gateway-core.api","header_kind":"session_id","request_id":"req-1","source_ip":"203.0.113.9"}`
	h := InternalAPIMiddleware("secret", deps)(CreateHeaderContractConflictIngest(deps))
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/header-contract-conflicts", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || sys.count != 0 || chain.count != 0 {
		t.Fatalf("unauthenticated status=%d durable=(%d,%d)", w.Code, sys.count, chain.count)
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/v1/header-contract-conflicts", strings.NewReader(body))
	req.Header.Set(InternalAPISecretHeader, "secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent || sys.count != 1 || chain.count != 1 || sys.eventID != chain.eventID {
		t.Fatalf("status=%d durable=(%d,%d) ids=(%q,%q) body=%s", w.Code, sys.count, chain.count, sys.eventID, chain.eventID, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/v1/header-contract-conflicts", strings.NewReader(strings.TrimSuffix(body, "}")+`,"extra":"rejected"}`))
	req.Header.Set(InternalAPISecretHeader, "secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/v1/header-contract-conflicts", strings.NewReader(body+" trailing-garbage"))
	req.Header.Set(InternalAPISecretHeader, "secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trailing garbage status=%d", w.Code)
	}
	if sys.count != 1 || chain.count != 1 {
		t.Fatalf("trailing garbage wrote durable evidence: (%d,%d)", sys.count, chain.count)
	}
}

func TestHeaderContractConflictThreeBoundariesPersistCentralWORMWithoutValues(t *testing.T) {
	url := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	systemRepo := repository.NewSystemRepository(db)
	chainRepo := repository.NewAuditChainRepository(db, []byte("header-contract-integration-key"))
	deps := &Dependencies{SystemRepo: systemRepo, AuditAppender: audit_chain.NewAppender(chainRepo, false)}
	h := InternalAPIMiddleware("secret", deps)(CreateHeaderContractConflictIngest(deps))
	srv := httptest.NewServer(h)
	defer srv.Close()
	client := headeraudit.NewClient(srv.URL, "secret")

	type boundary struct{ service, kind string }
	boundaries := []boundary{
		{"gateway-core.api", "session_id"},
		{"gateway-core.reverse-proxy", "workspace_id"},
		{"proxy-server.mitm", "agent_type"},
	}
	ids := make([]string, 0, len(boundaries))
	for _, b := range boundaries {
		hdr := http.Header{
			"X-JJDGuard-Agent-Type": []string{"new-value-canary"},
			"X-NewAPI-Agent-Type":   []string{"legacy-value-canary"},
			"X-Request-Id":          []string{"req-" + uuid.NewString()},
		}
		event, err := headeraudit.NewEvent(b.service, b.kind, hdr, "203.0.113.9:443")
		if err != nil {
			t.Fatal(err)
		}
		if err := client.AppendCritical(ctx, event); err != nil {
			t.Fatalf("%s append: %v", b.service, err)
		}
		ids = append(ids, "header-contract-conflict:"+event.OccurrenceID)
	}

	var firstSeq, lastSeq int64
	for _, id := range ids {
		var action, detail, userID, targetType, targetID, ipAddress string
		if err := db.QueryRow(ctx, `SELECT action_type,action_detail::text,COALESCE(user_id,''),target_type,target_id,ip_address FROM audit_operations WHERE id=$1`, id).
			Scan(&action, &detail, &userID, &targetType, &targetID, &ipAddress); err != nil {
			t.Fatal(err)
		}
		if action != "header_contract_conflict" || userID != "" || targetType != "header_contract" || targetID != "" || ipAddress != "" {
			t.Fatalf("unexpected fixed identity for %s: %q %q %q %q %q", id, action, userID, targetType, targetID, ipAddress)
		}
		var chainPayload string
		if err := db.QueryRow(ctx, `SELECT payload_json::text FROM audit_chain WHERE event_type='header_contract_conflict' AND event_id=$1`, id).Scan(&chainPayload); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail+chainPayload, "value-canary") {
			t.Fatalf("conflicting header value leaked for %s", id)
		}
		var seq int64
		if err := db.QueryRow(ctx, `SELECT seq FROM audit_chain WHERE event_type='header_contract_conflict' AND event_id=$1`, id).Scan(&seq); err != nil {
			t.Fatal(err)
		}
		if firstSeq == 0 || seq < firstSeq {
			firstSeq = seq
		}
		if seq > lastSeq {
			lastSeq = seq
		}
	}
	verified, err := chainRepo.Verify(ctx, firstSeq, lastSeq)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.OK {
		t.Fatalf("central WORM verification failed at %d: %s", verified.FirstBreakAtSeq, verified.Detail)
	}
}

type headerContractFixtureEvidence struct {
	OK             bool `json:"ok"`
	OperationCount int  `json:"operation_count"`
	ChainCount     int  `json:"chain_count"`
	IdentityOK     bool `json:"identity_ok"`
	PayloadOK      bool `json:"payload_ok"`
	NoCanary       bool `json:"no_canary"`
	WORMVerified   bool `json:"worm_verified"`
}

func exactHeaderContractPayload(raw []byte, requestID, service, kind string) bool {
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil || len(payload) != 4 {
		return false
	}
	if payload["request_id"] != requestID || payload["service"] != service || payload["header_kind"] != kind {
		return false
	}
	sourceIP, ok := payload["source_ip"].(string)
	return ok && net.ParseIP(sourceIP) != nil
}

// TestHeaderContractCentralFixtureServer is launched by the live PostgreSQL
// acceptance gate. It exposes the real authenticated ingest handler while
// gateway/proxy package tests drive their actual outer boundaries.
func TestHeaderContractCentralFixtureServer(t *testing.T) {
	addr := os.Getenv("HEADER_CONTRACT_CENTRAL_FIXTURE_ADDR")
	readyFile := os.Getenv("HEADER_CONTRACT_CENTRAL_FIXTURE_READY_FILE")
	nonce := os.Getenv("HEADER_CONTRACT_CENTRAL_FIXTURE_NONCE")
	url := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if addr == "" || readyFile == "" || nonce == "" || url == "" {
		t.Skip("central fixture is only started by the live acceptance gate")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	systemRepo := repository.NewSystemRepository(db)
	chainRepo := repository.NewAuditChainRepository(db, []byte("header-contract-integration-key"))
	deps := &Dependencies{SystemRepo: systemRepo, AuditAppender: audit_chain.NewAppender(chainRepo, false)}
	mux := http.NewServeMux()
	mux.Handle("/internal/v1/header-contract-conflicts", InternalAPIMiddleware("secret", deps)(CreateHeaderContractConflictIngest(deps)))
	mux.HandleFunc("/__fixture/health", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("nonce") != nonce {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/__fixture/evidence", func(w http.ResponseWriter, r *http.Request) {
		requestID, service, kind := r.URL.Query().Get("request_id"), r.URL.Query().Get("service"), r.URL.Query().Get("kind")
		evidence := headerContractFixtureEvidence{NoCanary: true}
		if requestID == "" || service == "" || kind == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(evidence)
			return
		}
		if err := db.QueryRow(r.Context(), `SELECT count(*) FROM audit_operations WHERE action_type='header_contract_conflict' AND action_detail->>'request_id'=$1`, requestID).Scan(&evidence.OperationCount); err != nil {
			t.Errorf("operation count: %v", err)
		}
		if err := db.QueryRow(r.Context(), `SELECT count(*) FROM audit_chain WHERE event_type='header_contract_conflict' AND payload_json->>'request_id'=$1`, requestID).Scan(&evidence.ChainCount); err != nil {
			t.Errorf("chain count: %v", err)
		}
		if evidence.OperationCount == 1 && evidence.ChainCount == 1 {
			var action, userID, targetType, targetID, ipAddress string
			var operationPayload, chainPayload []byte
			var seq int64
			opErr := db.QueryRow(r.Context(), `SELECT action_type,COALESCE(user_id,''),COALESCE(target_type,''),COALESCE(target_id,''),COALESCE(ip_address,''),action_detail FROM audit_operations WHERE action_type='header_contract_conflict' AND action_detail->>'request_id'=$1`, requestID).
				Scan(&action, &userID, &targetType, &targetID, &ipAddress, &operationPayload)
			chainErr := db.QueryRow(r.Context(), `SELECT seq,payload_json FROM audit_chain WHERE event_type='header_contract_conflict' AND payload_json->>'request_id'=$1`, requestID).
				Scan(&seq, &chainPayload)
			evidence.IdentityOK = opErr == nil && action == "header_contract_conflict" && userID == "" && targetType == "header_contract" && targetID == "" && ipAddress == ""
			evidence.PayloadOK = opErr == nil && chainErr == nil && exactHeaderContractPayload(operationPayload, requestID, service, kind) && exactHeaderContractPayload(chainPayload, requestID, service, kind)
			evidence.NoCanary = !strings.Contains(strings.ToLower(string(operationPayload)+string(chainPayload)), "canary")
			if verified, verifyErr := chainRepo.Verify(r.Context(), seq, seq); verifyErr == nil {
				evidence.WORMVerified = verified.OK
			}
		}
		evidence.OK = evidence.OperationCount == 1 && evidence.ChainCount == 1 && evidence.IdentityOK && evidence.PayloadOK && evidence.NoCanary && evidence.WORMVerified
		w.Header().Set("Content-Type", "application/json")
		if !evidence.OK {
			w.WriteHeader(http.StatusConflict)
		}
		_ = json.NewEncoder(w).Encode(evidence)
	})
	shutdown := make(chan struct{})
	var shutdownOnce sync.Once
	mux.HandleFunc("/__fixture/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("nonce") != nonce {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		shutdownOnce.Do(func() { close(shutdown) })
		w.WriteHeader(http.StatusNoContent)
	})
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(readyFile, []byte("http://"+listener.Addr().String()), 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Errorf("central fixture serve: %v", err)
		}
	}()
	<-shutdown
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(stopCtx); err != nil {
		t.Fatal(err)
	}
}

package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

// --- Mock CACertificateRepo ---

type MockCACertificateRepo struct {
	certs            map[string]*repository.CACertificate
	nextID           int
	lastValidityDays int
}

func newMockCACertificateRepo() *MockCACertificateRepo {
	return &MockCACertificateRepo{
		certs:  make(map[string]*repository.CACertificate),
		nextID: 1,
	}
}

func (m *MockCACertificateRepo) GenerateCA(ctx context.Context, tenantID string, validityDays int) (*repository.CACertificate, error) {
	m.lastValidityDays = validityDays
	m.nextID++
	id := fmt.Sprintf("ca_test_%d", m.nextID)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(m.nextID)),
		Subject:      pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, validityDays),
		IsCA:         true,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	status := "active"
	for _, existing := range m.certs {
		if existing.TenantID == tenantID && existing.Status == "active" {
			status = "pending"
			break
		}
	}
	ca := &repository.CACertificate{
		ID:                  id,
		TenantID:            tenantID,
		CAType:              "root",
		PrivateKeyEncrypted: string(keyPEM),
		CertificatePEM:      string(certPEM),
		Status:              status,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().AddDate(0, 0, validityDays),
	}
	m.certs[ca.ID] = ca
	return ca, nil
}

func (m *MockCACertificateRepo) GetByID(_ context.Context, tenantID, id string) (*repository.CACertificate, error) {
	cert := m.certs[id]
	if cert == nil || cert.TenantID != tenantID {
		return nil, nil
	}
	return cert, nil
}

func (m *MockCACertificateRepo) GetActive(ctx context.Context, tenantID string) (*repository.CACertificate, error) {
	for _, c := range m.certs {
		if c.TenantID == tenantID && c.Status == "active" {
			return c, nil
		}
	}
	return nil, nil
}

func (m *MockCACertificateRepo) List(ctx context.Context, tenantID string) ([]repository.CACertificate, error) {
	var result []repository.CACertificate
	for _, c := range m.certs {
		if c.TenantID == tenantID {
			result = append(result, *c)
		}
	}
	return result, nil
}

func (m *MockCACertificateRepo) Activate(_ context.Context, tenantID, id string) (*repository.CACertificate, error) {
	target := m.certs[id]
	if target == nil || target.TenantID != tenantID {
		return nil, repository.ErrCANotFound
	}
	if target.Status != "pending" || !target.ExpiresAt.After(time.Now()) {
		return nil, repository.ErrCAInvalidState
	}
	for _, cert := range m.certs {
		if cert.TenantID == tenantID && cert.Status == "active" {
			cert.Status = "deprecated"
		}
	}
	target.Status = "active"
	return target, nil
}

func (m *MockCACertificateRepo) Delete(_ context.Context, tenantID, id string) error {
	target := m.certs[id]
	if target == nil || target.TenantID != tenantID {
		return repository.ErrCANotFound
	}
	if target.Status == "active" {
		return repository.ErrCAActive
	}
	delete(m.certs, id)
	return nil
}

func requestWithCAID(req *http.Request, id string) *http.Request {
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))
}

// --- Tests ---

func TestMapCACertificateToInfo(t *testing.T) {
	now := time.Now()
	cert := &repository.CACertificate{
		ID:             "ca_001",
		TenantID:       "tenant_demo",
		CAType:         "root",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		Status:         "active",
		CreatedAt:      now,
		ExpiresAt:      now.AddDate(1, 0, 0),
	}

	info := mapCACertificateToInfo(cert)

	if info.ID != "ca_001" {
		t.Errorf("expected ID=ca_001, got %s", info.ID)
	}
	if info.Status != "active" {
		t.Errorf("expected status=active, got %s", info.Status)
	}
	if info.CAType != "root" {
		t.Errorf("expected ca_type=root, got %s", info.CAType)
	}
}

func TestGenerateCA_Unauthorized(t *testing.T) {
	deps := &Dependencies{
		CACertificatesRepo: newMockCACertificateRepo(),
	}
	handler := GenerateCA(deps)

	req := httptest.NewRequest("POST", "/admin/v1/ca/generate", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestGenerateCA_ForbiddenForNonAdmin(t *testing.T) {
	deps := &Dependencies{
		CACertificatesRepo: newMockCACertificateRepo(),
	}
	handler := GenerateCA(deps)

	req := httptest.NewRequest("POST", "/admin/v1/ca/generate?validity_days=365", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_dev",
		TenantID: "tenant_demo",
		Role:     "developer",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestGenerateCA_Success(t *testing.T) {
	mockRepo := newMockCACertificateRepo()
	mockSystemRepo := &MockSystemRepo{}
	deps := &Dependencies{
		CACertificatesRepo: mockRepo,
		SystemRepo:         mockSystemRepo,
	}
	handler := GenerateCA(deps)

	req := httptest.NewRequest("POST", "/admin/v1/ca/generate?validity_days=365", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp CACertificateInfo
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.ID == "" {
		t.Error("expected CA to have ID")
	}
	if resp.Status != "active" {
		t.Errorf("expected status=active, got %s", resp.Status)
	}
	if !strings.Contains(resp.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Error("expected certificate PEM in response")
	}
	if strings.Contains(w.Body.String(), "private_key_encrypted") {
		t.Fatal("CA generation response must never expose the private key")
	}
}

func TestGenerateCA_StagesReplacementAsPending(t *testing.T) {
	mockRepo := newMockCACertificateRepo()
	mockRepo.GenerateCA(context.Background(), "tenant_demo", 365)
	deps := &Dependencies{CACertificatesRepo: mockRepo, SystemRepo: &MockSystemRepo{}}
	handler := GenerateCA(deps)

	req := httptest.NewRequest("POST", "/admin/v1/ca/generate", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", TenantID: "tenant_demo", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()
	handler(w, req)

	var resp CACertificateInfo
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != "pending" {
		t.Fatalf("replacement CA status = %q, want pending", resp.Status)
	}
}

func TestActivateCACertificate_SwitchesPendingCA(t *testing.T) {
	mockRepo := newMockCACertificateRepo()
	oldCA, _ := mockRepo.GenerateCA(context.Background(), "tenant_demo", 365)
	newCA, _ := mockRepo.GenerateCA(context.Background(), "tenant_demo", 365)
	deps := &Dependencies{CACertificatesRepo: mockRepo, SystemRepo: &MockSystemRepo{}}
	handler := ActivateCACertificate(deps)

	req := httptest.NewRequest("POST", "/admin/v1/ca/"+newCA.ID+"/activate", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", TenantID: "tenant_demo", Role: "platform_admin",
	}))
	req = requestWithCAID(req, newCA.ID)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if oldCA.Status != "deprecated" || newCA.Status != "active" {
		t.Fatalf("old=%s new=%s, want deprecated/active", oldCA.Status, newCA.Status)
	}
}

func TestDeleteCACertificate_RejectsCurrentCA(t *testing.T) {
	mockRepo := newMockCACertificateRepo()
	active, _ := mockRepo.GenerateCA(context.Background(), "tenant_demo", 365)
	deps := &Dependencies{CACertificatesRepo: mockRepo}
	handler := DeleteCACertificate(deps)

	req := httptest.NewRequest("DELETE", "/admin/v1/ca/"+active.ID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", TenantID: "tenant_demo", Role: "platform_admin",
	}))
	req = requestWithCAID(req, active.ID)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGenerateCA_DefaultValidity(t *testing.T) {
	mockRepo := newMockCACertificateRepo()
	mockSystemRepo := &MockSystemRepo{}
	deps := &Dependencies{
		CACertificatesRepo: mockRepo,
		SystemRepo:         mockSystemRepo,
	}
	handler := GenerateCA(deps)

	req := httptest.NewRequest("POST", "/admin/v1/ca/generate", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}

	if mockRepo.lastValidityDays != 3650 {
		t.Fatalf("default validity days = %d, want 3650", mockRepo.lastValidityDays)
	}
}

func TestListCACertificates_Success(t *testing.T) {
	mockRepo := newMockCACertificateRepo()
	// Pre-populate
	mockRepo.GenerateCA(context.Background(), "tenant_demo", 365)

	deps := &Dependencies{
		CACertificatesRepo: mockRepo,
	}
	handler := ListCACertificates(deps)

	req := httptest.NewRequest("GET", "/admin/v1/ca/list", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	data, _ := resp["data"].([]interface{})
	if len(data) != 1 {
		t.Errorf("expected 1 CA certificate, got %d", len(data))
	}
}

func TestListCACertificates_EmptyList(t *testing.T) {
	deps := &Dependencies{
		CACertificatesRepo: newMockCACertificateRepo(),
	}
	handler := ListCACertificates(deps)

	req := httptest.NewRequest("GET", "/admin/v1/ca/list", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	data, _ := resp["data"].([]interface{})
	if len(data) != 0 {
		t.Errorf("expected empty list, got %d items", len(data))
	}
}

func TestGetCACertificate_Success(t *testing.T) {
	mockRepo := newMockCACertificateRepo()
	mockRepo.GenerateCA(context.Background(), "tenant_demo", 365)

	deps := &Dependencies{
		CACertificatesRepo: mockRepo,
	}
	handler := GetCACertificate(deps)

	req := httptest.NewRequest("GET", "/admin/v1/ca/certificate", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetCACertificate_NotFound(t *testing.T) {
	deps := &Dependencies{
		CACertificatesRepo: newMockCACertificateRepo(),
	}
	handler := GetCACertificate(deps)

	req := httptest.NewRequest("GET", "/admin/v1/ca/certificate", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for not found, got %d", w.Code)
	}
}

func TestDownloadCACertificate_Success(t *testing.T) {
	mockRepo := newMockCACertificateRepo()
	mockRepo.GenerateCA(context.Background(), "tenant_demo", 365)

	deps := &Dependencies{
		CACertificatesRepo: mockRepo,
	}
	handler := DownloadCACertificate(deps)

	req := httptest.NewRequest("GET", "/admin/v1/ca/download", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Check content type
	if w.Header().Get("Content-Type") != "application/x-x509-ca-cert" {
		t.Errorf("expected Content-Type=application/x-x509-ca-cert, got %s", w.Header().Get("Content-Type"))
	}

	// Check filename in Content-Disposition
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "jjdguard_proxy_ca_") {
		t.Errorf("expected CA-specific filename in Content-Disposition, got %s", cd)
	}
	if !strings.HasSuffix(cd, ".crt") {
		t.Errorf("expected Windows-installable .crt filename, got %s", cd)
	}
}

func TestDownloadCACertificate_NotFound(t *testing.T) {
	deps := &Dependencies{
		CACertificatesRepo: newMockCACertificateRepo(),
	}
	handler := DownloadCACertificate(deps)

	req := httptest.NewRequest("GET", "/admin/v1/ca/download", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for not found, got %d", w.Code)
	}
}

func TestCACertificate_TenantIsolation(t *testing.T) {
	mockRepo := newMockCACertificateRepo()
	mockRepo.GenerateCA(context.Background(), "tenant_demo", 365)
	mockRepo.GenerateCA(context.Background(), "tenant_other", 365)

	deps := &Dependencies{
		CACertificatesRepo: mockRepo,
	}
	handler := ListCACertificates(deps)

	req := httptest.NewRequest("GET", "/admin/v1/ca/list", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	data, _ := resp["data"].([]interface{})
	if len(data) != 1 {
		t.Errorf("expected 1 CA (tenant isolation), got %d", len(data))
	}

	// Verify it's tenant_demo's CA
	first := data[0].(map[string]interface{})
	if first["tenant_id"] != "tenant_demo" {
		t.Errorf("expected tenant_id=tenant_demo, got %s", first["tenant_id"])
	}
}

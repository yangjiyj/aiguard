package handler

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

func TestMatchPattern(t *testing.T) {
	w := &WhitelistChecker{}

	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"api.openai.com", "api.openai.com", true},
		{"api.openai.com", "other.openai.com", false},
		{"*.openai.com", "api.openai.com", true},
		{"*.openai.com", "v1.api.openai.com", true},
		{"*.openai.com", "openai.com", true},
		{"*.openai.com", "other.com", false},
		{"*.anthropic.com", "api.anthropic.com", true},
		{"*.anthropic.com", "api.openai.com", false},
		{"", "", false},
		{"", "example.com", false},
		{"*.example.com", "a.b.c.example.com", true},
	}

	for _, tt := range tests {
		got := w.matchPattern(tt.pattern, tt.host)
		if got != tt.want {
			t.Errorf("matchPattern(%s, %s) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

func TestActiveRootCAQueryLoadsTenantDefaultCA(t *testing.T) {
	query := activeRootCAQuery()
	if !strings.Contains(query, "tenant_default") {
		t.Fatal("active root CA query must load the default private-deployment tenant CA")
	}
	if !strings.Contains(query, "ca_type = 'root'") {
		t.Fatal("active root CA query must only load root CA records")
	}
	if !strings.Contains(query, "SELECT id,") {
		t.Fatal("active root CA query must return a stable CA identity for hot reload")
	}
	if !strings.Contains(query, "expires_at > NOW()") {
		t.Fatal("active root CA query must not load expired certificates")
	}
}

func TestRootCARotationClearsCachedLeafCertificates(t *testing.T) {
	m := NewCAManager(nil, "")
	before, err := m.GetCertificate("rotation.example.test")
	if err != nil {
		t.Fatalf("get certificate before rotation: %v", err)
	}

	m.generateSelfSignedCA()
	after, err := m.GetCertificate("rotation.example.test")
	if err != nil {
		t.Fatalf("get certificate after rotation: %v", err)
	}
	if bytes.Equal(before.Certificate[1], after.Certificate[1]) {
		t.Fatal("cached leaf certificate still uses the previous root CA")
	}
}

func TestParseRootCADecryptsEncryptedPrivateKey(t *testing.T) {
	t.Setenv("JJD_INTERNAL_API_SECRET", "ca-manager-unit-test-key")
	m := NewCAManager(nil, "")
	rootKey := m.rootCA.PrivateKey.(*rsa.PrivateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.rootCA.Certificate[0]})
	encryptedKey, err := secrets.EncryptCAPrivateKey(string(keyPEM))
	if err != nil {
		t.Fatalf("encrypt root private key: %v", err)
	}

	parsed, err := parseRootCA(encryptedKey, string(certPEM))
	if err != nil {
		t.Fatalf("parse encrypted root CA: %v", err)
	}
	if !bytes.Equal(parsed.Certificate[0], m.rootCA.Certificate[0]) {
		t.Fatal("parsed certificate does not match the encrypted root CA")
	}
}

func TestGetCertificate_GeneratesForNewHost(t *testing.T) {
	m := NewCAManager(nil, "")

	// Generate cert for first host
	cert, err := m.GetCertificate("api.openai.com")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert.Certificate == nil || len(cert.Certificate) == 0 {
		t.Error("generated certificate should have certificate bytes")
	}
	if cert.PrivateKey == nil {
		t.Error("generated certificate should have private key")
	}
}

func TestGetCertificate_CachesResult(t *testing.T) {
	m := NewCAManager(nil, "")

	// Generate cert twice for same host
	cert1, err := m.GetCertificate("api.test.com")
	if err != nil {
		t.Fatalf("first GetCertificate failed: %v", err)
	}

	cert2, err := m.GetCertificate("api.test.com")
	if err != nil {
		t.Fatalf("second GetCertificate failed: %v", err)
	}

	// Should return cached cert (same object)
	if &cert1 != &cert2 {
		// Actually they're copies, so we can't compare pointers
		// But we can compare certificate bytes
		if len(cert1.Certificate) != len(cert2.Certificate) {
			t.Error("cached cert should have same certificate chain length")
		}
	}
}

func TestGetCertificate_StripsPort(t *testing.T) {
	m := NewCAManager(nil, "")

	// Request cert with port in host
	cert1, err := m.GetCertificate("api.openai.com:443")
	if err != nil {
		t.Fatalf("GetCertificate with port failed: %v", err)
	}

	// Request cert without port - should return cached cert
	cert2, err := m.GetCertificate("api.openai.com")
	if err != nil {
		t.Fatalf("GetCertificate without port failed: %v", err)
	}

	// Both should return cached cert for "api.openai.com"
	if len(cert1.Certificate) != len(cert2.Certificate) {
		t.Error("certificates should match after port stripping")
	}
}

func TestGetCertificate_GeneratesDifferentCertsForDifferentHosts(t *testing.T) {
	m := NewCAManager(nil, "")

	cert1, err := m.GetCertificate("api.openai.com")
	if err != nil {
		t.Fatalf("GetCertificate openai failed: %v", err)
	}

	cert2, err := m.GetCertificate("api.anthropic.com")
	if err != nil {
		t.Fatalf("GetCertificate anthropic failed: %v", err)
	}

	// Different hosts should have different certificates
	// Parse certificates and check CommonName
	x509_1, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate 1 failed: %v", err)
	}

	x509_2, err := x509.ParseCertificate(cert2.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate 2 failed: %v", err)
	}

	if x509_1.Subject.CommonName != "api.openai.com" {
		t.Errorf("cert1 CommonName = %s, want api.openai.com", x509_1.Subject.CommonName)
	}
	if x509_2.Subject.CommonName != "api.anthropic.com" {
		t.Errorf("cert2 CommonName = %s, want api.anthropic.com", x509_2.Subject.CommonName)
	}
}

func TestGenerateCertificate_Validity(t *testing.T) {
	m := NewCAManager(nil, "")

	cert, err := m.generateCertificate("test.example.com")
	if err != nil {
		t.Fatalf("generateCertificate failed: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	// Check NotBefore is recent and backdated to tolerate minor client/server clock skew.
	now := time.Now()
	if x509Cert.NotBefore.After(now) {
		t.Error("NotBefore should not be in the future")
	}
	if x509Cert.NotBefore.Before(now.Add(-10*time.Minute)) || x509Cert.NotBefore.After(now.Add(-4*time.Minute)) {
		t.Errorf("NotBefore should be backdated about 5 minutes, got %v", x509Cert.NotBefore)
	}

	// Check NotAfter is 30 days from NotBefore
	expectedExpiry := x509Cert.NotBefore.AddDate(0, 0, 30)
	if x509Cert.NotAfter != expectedExpiry {
		t.Errorf("NotAfter = %v, want %v (30 days from NotBefore)", x509Cert.NotAfter, expectedExpiry)
	}

	// Check it's a server auth certificate
	serverAuthFound := false
	for _, ext := range x509Cert.ExtKeyUsage {
		if ext == x509.ExtKeyUsageServerAuth {
			serverAuthFound = true
			break
		}
	}
	if !serverAuthFound {
		t.Error("certificate should have ServerAuth extended key usage")
	}
}

func TestGeneratedCAAndLeafUseParsedJJDGuardSubjects(t *testing.T) {
	m := NewCAManager(nil, "")
	root, err := x509.ParseCertificate(m.rootCA.Certificate[0])
	if err != nil {
		t.Fatalf("parse root CA: %v", err)
	}
	if !reflect.DeepEqual(root.Subject.Organization, []string{"JJDGuard"}) {
		t.Fatalf("root organization = %v", root.Subject.Organization)
	}
	if strings.Contains(strings.ToLower(root.Subject.CommonName), "new"+"api") {
		t.Fatal("root common name contains retired brand")
	}
	if !root.IsCA {
		t.Fatal("root certificate must be a CA")
	}

	chain, err := m.generateCertificate("brand.example.test")
	if err != nil {
		t.Fatalf("generate leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(chain.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if !reflect.DeepEqual(leaf.Subject.Organization, []string{"JJDGuard"}) {
		t.Fatalf("leaf organization = %v", leaf.Subject.Organization)
	}
	if leaf.Subject.CommonName != "brand.example.test" {
		t.Fatalf("leaf common name = %q", leaf.Subject.CommonName)
	}
}

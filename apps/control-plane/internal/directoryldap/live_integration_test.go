package directoryldap

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

// TestLiveLDAPSIntegration is opt-in: it verifies a real private-CA LDAPS
// endpoint without weakening certificate verification in normal test runs.
func TestLiveLDAPSIntegration(t *testing.T) {
	url := os.Getenv("DIRECTORY_LDAP_INTEGRATION_URL")
	if url == "" {
		t.Skip("DIRECTORY_LDAP_INTEGRATION_URL is not set")
	}
	caPath := os.Getenv("DIRECTORY_LDAP_INTEGRATION_CA_FILE")
	caCertPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read integration CA certificate: %v", err)
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		t.Fatal("integration CA is not PEM encoded")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("parse integration CA certificate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	policy, err := LoadTargetPolicyFromEnvironment()
	if err != nil {
		t.Fatalf("load integration target policy: %v", err)
	}
	client := Client{Policy: policy}
	request := TestRequest{
		ConnectionURL: url,
		BindDN:        os.Getenv("DIRECTORY_LDAP_INTEGRATION_BIND_DN"),
		BindPassword:  os.Getenv("DIRECTORY_LDAP_INTEGRATION_BIND_PASSWORD"),
		CACertPEM:     string(caCertPEM),
	}
	result, err := client.TestConnection(ctx, request)
	if err != nil {
		t.Fatalf("real LDAPS connection failed: %v", err)
	}
	if !result.Connected || !result.Bound || !result.RootDSE {
		t.Fatalf("unexpected live test result: %+v", result)
	}
	users, err := client.ListUsers(ctx, SyncRequest{
		TestRequest:       request,
		UsersDN:           os.Getenv("DIRECTORY_LDAP_INTEGRATION_USERS_DN"),
		UserFilter:        "(objectClass=user)",
		StableIDAttribute: "objectGUID",
		UsernameAttribute: "sAMAccountName",
		EmailAttribute:    "mail",
		NameAttribute:     "cn",
	})
	if err != nil {
		t.Fatalf("real LDAPS user query failed: %v", err)
	}
	if len(users) < 2 {
		t.Fatalf("expected at least two simulated AD users, got %d", len(users))
	}
}

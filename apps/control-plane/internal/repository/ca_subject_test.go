package repository

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNewJJDGuardCATemplateProducesParsedJJDGuardCertificate(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	template := newJJDGuardCATemplate(now, big.NewInt(42), 365)
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if !reflect.DeepEqual(cert.Subject.Organization, []string{"JJDGuard"}) {
		t.Fatalf("organization = %v, want JJDGuard", cert.Subject.Organization)
	}
	if strings.Contains(strings.ToLower(cert.Subject.CommonName), "new"+"api") {
		t.Fatalf("common name contains retired brand")
	}
	if cert.Subject.CommonName != "JJDGuard Proxy MITM Root CA" {
		t.Fatalf("common name = %q", cert.Subject.CommonName)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Fatalf("parsed certificate is not a valid CA")
	}
	if cert.SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("serial = %s", cert.SerialNumber)
	}
	if !cert.NotBefore.Equal(now) || !cert.NotAfter.Equal(now.AddDate(0, 0, 365)) {
		t.Fatalf("validity = %s..%s", cert.NotBefore, cert.NotAfter)
	}
}

func TestNewJJDGuardCATemplateTreatsDefaultAsTenCalendarYears(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	template := newJJDGuardCATemplate(now, big.NewInt(43), 3650)
	want := now.AddDate(10, 0, 0)
	if !template.NotAfter.Equal(want) {
		t.Fatalf("not after = %s, want %s", template.NotAfter, want)
	}
}

package directoryldap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func newSelfSignedCA(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	return newSelfSigned(t, true, "JJDGuard Directory Test Root")
}

func newSelfSignedLeaf(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	return newSelfSigned(t, false, "dc.example.test")
}

func newSelfSigned(t *testing.T, isCA bool, commonName string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// poolContains 用 Subjects 之外的方式判断：Go 1.18 起 CertPool.Subjects 已弃用，
// 这里直接用 pool 做一次链校验（自签 CA 自验必然成功）。
func poolContains(pool *x509.CertPool, certificate *x509.Certificate) bool {
	if pool == nil || certificate == nil {
		return false
	}
	if certificate.IsCA {
		_, err := certificate.Verify(x509.VerifyOptions{Roots: pool})
		return err == nil
	}
	// 叶子证书：自签叶子只有在自己进了信任池时才能验证通过。
	_, err := certificate.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

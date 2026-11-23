package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CAManager manages CA certificates for MITM
type CAManager struct {
	db              *pgxpool.Pool
	controlPlaneURL string
	rootMu          sync.RWMutex
	rootCA          *tls.Certificate
	rootCAID        string
	certCache       sync.Map
	refreshMu       sync.Mutex
	lastRefresh     time.Time
	refreshInterval time.Duration
}

func activeRootCAQuery() string {
	return `
		SELECT id, private_key_encrypted, certificate_pem
		FROM ca_certificates
		WHERE status = 'active'
		  AND ca_type = 'root'
		  AND expires_at > NOW()
		  AND (tenant_id IS NULL OR tenant_id IN ('tenant_default', 'default'))
		ORDER BY
		  CASE
		    WHEN tenant_id = 'tenant_default' THEN 0
		    WHEN tenant_id IS NULL THEN 1
		    ELSE 2
		  END,
		  created_at DESC
		LIMIT 1
	`
}

// NewCAManager creates a new CA manager
func NewCAManager(db *pgxpool.Pool, controlPlaneURL string) *CAManager {
	m := &CAManager{
		db:              db,
		controlPlaneURL: controlPlaneURL,
		refreshInterval: 5 * time.Second,
	}
	m.loadRootCA()
	return m
}

// loadRootCA loads the active root CA from database
func (m *CAManager) loadRootCA() {
	// If no database, generate self-signed CA
	if m.db == nil {
		m.generateSelfSignedCA()
		return
	}

	if err := m.refreshRootCA(context.Background(), true); err != nil {
		log.Printf("No active CA found, generating self-signed: %v", err)
		m.generateSelfSignedCA()
	}
}

func parseRootCA(privateKeyPEM, certPEM string) (*tls.Certificate, error) {
	decryptedKeyPEM, err := secrets.DecryptCAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CA private key: %w", err)
	}

	// Parse PEM blocks
	keyBlock, _ := pem.Decode([]byte(decryptedKeyPEM))
	certBlock, _ := pem.Decode([]byte(certPEM))

	if keyBlock == nil || certBlock == nil {
		return nil, fmt.Errorf("failed to parse CA PEM blocks")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
	}, nil
}

func (m *CAManager) clearCertificateCache() {
	m.certCache.Range(func(key, _ any) bool {
		m.certCache.Delete(key)
		return true
	})
}

func (m *CAManager) installRootCA(id string, cert *tls.Certificate) {
	m.rootMu.Lock()
	m.rootCA = cert
	m.rootCAID = id
	m.rootMu.Unlock()
	m.clearCertificateCache()
}

// refreshRootCA reloads a newly activated CA without restarting the proxy.
// Request-path checks are rate limited so normal traffic does not query PostgreSQL per host.
func (m *CAManager) refreshRootCA(ctx context.Context, force bool) error {
	if m.db == nil {
		return nil
	}

	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	if !force && time.Since(m.lastRefresh) < m.refreshInterval {
		return nil
	}
	m.lastRefresh = time.Now()

	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var id, privateKeyPEM, certPEM string
	if err := m.db.QueryRow(queryCtx, activeRootCAQuery()).Scan(&id, &privateKeyPEM, &certPEM); err != nil {
		return err
	}

	m.rootMu.RLock()
	currentID := m.rootCAID
	m.rootMu.RUnlock()
	if id == currentID {
		return nil
	}

	cert, err := parseRootCA(privateKeyPEM, certPEM)
	if err != nil {
		return err
	}
	m.installRootCA(id, cert)
	log.Printf("Activated MITM root CA id=%s", id)
	return nil
}

func newJJDGuardProxyRootTemplate(notBefore time.Time, serial *big.Int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "JJDGuard Proxy Root CA",
			Organization: []string{"JJDGuard"},
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func newJJDGuardProxyLeafTemplate(host string, notBefore time.Time, serial *big.Int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"JJDGuard"},
			CommonName:   host,
		},
		NotBefore:   notBefore,
		NotAfter:    notBefore.AddDate(0, 0, 30),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}
}

// generateSelfSignedCA generates a self-signed CA for testing
func (m *CAManager) generateSelfSignedCA() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	notBefore := time.Now().Add(-5 * time.Minute)

	template := newJJDGuardProxyRootTemplate(notBefore, big.NewInt(1))

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	m.installRootCA("self-signed", &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	})

	log.Println("Generated self-signed CA for testing")
}

// GetCertificate generates or retrieves a certificate for the given host
func (m *CAManager) GetCertificate(host string) (tls.Certificate, error) {
	if err := m.refreshRootCA(context.Background(), false); err != nil {
		// Keep serving with the last known-good CA during transient database errors.
		log.Printf("Failed to refresh active CA, retaining current CA: %v", err)
	}
	// Remove port from host
	hostWithoutPort := host
	if idx := strings.Index(host, ":"); idx > 0 {
		hostWithoutPort = host[:idx]
	}

	m.rootMu.RLock()
	rootID := m.rootCAID
	m.rootMu.RUnlock()
	cacheKey := rootID + "|" + hostWithoutPort

	// Cache entries are namespaced by root identity so an in-flight request
	// cannot repopulate an old leaf after a CA rotation.
	if cached, ok := m.certCache.Load(cacheKey); ok {
		return cached.(tls.Certificate), nil
	}

	// Generate certificate
	cert, signingRootID, err := m.generateCertificateWithRootID(hostWithoutPort)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Cache it
	m.certCache.Store(signingRootID+"|"+hostWithoutPort, cert)

	return cert, nil
}

// generateCertificate generates a certificate for the given host signed by the root CA
func (m *CAManager) generateCertificate(host string) (tls.Certificate, error) {
	cert, _, err := m.generateCertificateWithRootID(host)
	return cert, err
}

func (m *CAManager) generateCertificateWithRootID(host string) (tls.Certificate, string, error) {
	m.rootMu.RLock()
	defer m.rootMu.RUnlock()
	if m.rootCA == nil {
		return tls.Certificate{}, "", fmt.Errorf("no root CA available")
	}
	rootCA := *m.rootCA
	rootID := m.rootCAID

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to generate key: %w", err)
	}

	// Parse root CA certificate
	rootCert, err := x509.ParseCertificate(rootCA.Certificate[0])
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to parse root CA: %w", err)
	}

	notBefore := time.Now().Add(-5 * time.Minute)

	template := newJJDGuardProxyLeafTemplate(host, notBefore, big.NewInt(time.Now().Unix()))

	certBytes, err := x509.CreateCertificate(rand.Reader, template, rootCert, &key.PublicKey, rootCA.PrivateKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to create certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certBytes, rootCA.Certificate[0]},
		PrivateKey:  key,
	}, rootID, nil
}

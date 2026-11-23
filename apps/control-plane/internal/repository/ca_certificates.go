package repository

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrCANotFound     = errors.New("CA certificate not found")
	ErrCAInvalidState = errors.New("CA certificate state does not allow this operation")
	ErrCAActive       = errors.New("active CA certificate cannot be deleted")
)

type CACertificate struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	CAType              string    `json:"ca_type"`
	PrivateKeyEncrypted string    `json:"private_key_encrypted"`
	CertificatePEM      string    `json:"certificate_pem"`
	Status              string    `json:"status"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type CACertificateRepository struct {
	db *pgxpool.Pool
}

func NewCACertificateRepository(db *pgxpool.Pool) *CACertificateRepository {
	return &CACertificateRepository{db: db}
}

func (r *CACertificateRepository) GetByID(ctx context.Context, tenantID, id string) (*CACertificate, error) {
	query := `
		SELECT id, tenant_id, ca_type, private_key_encrypted, certificate_pem, status, created_at, expires_at
		FROM ca_certificates
		WHERE tenant_id = $1 AND id = $2
	`
	row := r.db.QueryRow(ctx, query, tenantID, id)
	var cert CACertificate
	err := row.Scan(&cert.ID, &cert.TenantID, &cert.CAType, &cert.PrivateKeyEncrypted, &cert.CertificatePEM, &cert.Status, &cert.CreatedAt, &cert.ExpiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}
	return &cert, nil
}

func (r *CACertificateRepository) GetActive(ctx context.Context, tenantID string) (*CACertificate, error) {
	query := `
		SELECT id, tenant_id, ca_type, private_key_encrypted, certificate_pem, status, created_at, expires_at
		FROM ca_certificates
		WHERE tenant_id = $1 AND status = 'active' AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1
	`
	row := r.db.QueryRow(ctx, query, tenantID)
	var cert CACertificate
	err := row.Scan(&cert.ID, &cert.TenantID, &cert.CAType, &cert.PrivateKeyEncrypted, &cert.CertificatePEM, &cert.Status, &cert.CreatedAt, &cert.ExpiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get active CA certificate: %w", err)
	}
	return &cert, nil
}

func (r *CACertificateRepository) List(ctx context.Context, tenantID string) ([]CACertificate, error) {
	query := `
		SELECT id, tenant_id, ca_type, private_key_encrypted, certificate_pem, status, created_at, expires_at
		FROM ca_certificates
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list CA certificates: %w", err)
	}
	defer rows.Close()

	var certs []CACertificate
	for rows.Next() {
		var cert CACertificate
		if err := rows.Scan(&cert.ID, &cert.TenantID, &cert.CAType, &cert.PrivateKeyEncrypted, &cert.CertificatePEM, &cert.Status, &cert.CreatedAt, &cert.ExpiresAt); err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (r *CACertificateRepository) Create(ctx context.Context, cert *CACertificate) error {
	if cert.ID == "" {
		cert.ID = "ca_" + uuid.New().String()[:8]
	}

	if cert.Status == "" {
		cert.Status = "active"
	}

	if cert.CAType == "" {
		cert.CAType = "root"
	}

	query := `
		INSERT INTO ca_certificates (id, tenant_id, ca_type, private_key_encrypted, certificate_pem, status, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at
	`
	err := r.db.QueryRow(ctx, query,
		cert.ID, cert.TenantID, cert.CAType, cert.PrivateKeyEncrypted, cert.CertificatePEM, cert.Status, cert.ExpiresAt,
	).Scan(&cert.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}
	return nil
}

func (r *CACertificateRepository) GenerateCA(ctx context.Context, tenantID string, validityDays int) (*CACertificate, error) {
	if _, err := r.db.Exec(ctx, `
		UPDATE ca_certificates
		SET status = 'expired'
		WHERE tenant_id = $1
		  AND status IN ('active', 'pending')
		  AND expires_at <= NOW()
	`, tenantID); err != nil {
		return nil, fmt.Errorf("failed to expire stale CA certificates: %w", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	template := newJJDGuardCATemplate(now, serialNumber, validityDays)

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	encryptedKeyPEM, err := secrets.EncryptCAPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt CA private key: %w", err)
	}

	cert := &CACertificate{
		TenantID:            tenantID,
		PrivateKeyEncrypted: encryptedKeyPEM,
		CertificatePEM:      certPEM,
		Status:              "pending",
		ExpiresAt:           template.NotAfter,
	}

	active, err := r.GetActive(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if active == nil {
		// A fresh deployment needs one usable CA immediately. Replacements are
		// deliberately staged as pending until an administrator activates them.
		cert.Status = "active"
	}

	if err := r.Create(ctx, cert); err != nil {
		return nil, err
	}

	return cert, nil
}

// Activate atomically switches the tenant to a pending, unexpired root CA.
// The old CA is retained as deprecated so clients can keep it during a grace period.
func (r *CACertificateRepository) Activate(ctx context.Context, tenantID, id string) (*CACertificate, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin CA activation: %w", err)
	}
	defer tx.Rollback(ctx)

	var status string
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT status, expires_at
		FROM ca_certificates
		WHERE tenant_id = $1 AND id = $2 AND ca_type = 'root'
		FOR UPDATE
	`, tenantID, id).Scan(&status, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCANotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load CA for activation: %w", err)
	}
	if status != "pending" || !expiresAt.After(time.Now()) {
		return nil, ErrCAInvalidState
	}

	if _, err := tx.Exec(ctx, `
		UPDATE ca_certificates
		SET status = 'deprecated'
		WHERE tenant_id = $1 AND ca_type = 'root' AND status = 'active'
	`, tenantID); err != nil {
		return nil, fmt.Errorf("deprecate current CA: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE ca_certificates SET status = 'active' WHERE tenant_id = $1 AND id = $2
	`, tenantID, id); err != nil {
		return nil, fmt.Errorf("activate CA: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit CA activation: %w", err)
	}

	return r.GetByID(ctx, tenantID, id)
}

func (r *CACertificateRepository) UpdateStatus(ctx context.Context, tenantID, id, status string) error {
	query := `
		UPDATE ca_certificates
		SET status = $3
		WHERE tenant_id = $1 AND id = $2
	`
	result, err := r.db.Exec(ctx, query, tenantID, id, status)
	if err != nil {
		return fmt.Errorf("failed to update CA certificate status: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("CA certificate not found")
	}
	return nil
}

func (r *CACertificateRepository) DeprecateAllActive(ctx context.Context, tenantID string) error {
	query := `
		UPDATE ca_certificates
		SET status = 'deprecated'
		WHERE tenant_id = $1 AND status = 'active'
	`
	_, err := r.db.Exec(ctx, query, tenantID)
	if err != nil {
		return fmt.Errorf("failed to deprecate active CA certificates: %w", err)
	}
	return nil
}

func (r *CACertificateRepository) Delete(ctx context.Context, tenantID, id string) error {
	result, err := r.db.Exec(ctx, `
		DELETE FROM ca_certificates
		WHERE tenant_id = $1 AND id = $2 AND status != 'active'
	`, tenantID, id)
	if err != nil {
		return fmt.Errorf("failed to delete CA certificate: %w", err)
	}
	if result.RowsAffected() > 0 {
		return nil
	}

	var status string
	err = r.db.QueryRow(ctx, `SELECT status FROM ca_certificates WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCANotFound
	}
	if err != nil {
		return fmt.Errorf("failed to load CA certificate after delete conflict: %w", err)
	}
	return ErrCAActive
}

package handler

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type CACertificateInfo struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	CAType            string `json:"ca_type"`
	CertificatePEM    string `json:"certificate_pem"`
	Status            string `json:"status"`
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
	CreatedAt         string `json:"created_at,omitempty"`
	ExpiresAt         string `json:"expires_at,omitempty"`
}

func certificateFingerprint(pemValue string) string {
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func mapCACertificateToInfo(c *repository.CACertificate) CACertificateInfo {
	return CACertificateInfo{
		ID:                c.ID,
		TenantID:          c.TenantID,
		CAType:            c.CAType,
		CertificatePEM:    c.CertificatePEM,
		Status:            c.Status,
		FingerprintSHA256: certificateFingerprint(c.CertificatePEM),
		CreatedAt:         c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		ExpiresAt:         c.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func GenerateCA(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can generate CA certificates")
			return
		}

		validityDays := 3650
		if d := r.URL.Query().Get("validity_days"); d != "" {
			v, err := strconv.Atoi(d)
			if err != nil || v < 30 || v > 3650 {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_validity", "validity_days must be between 30 and 3650")
				return
			}
			validityDays = v
		}

		cert, err := deps.CACertificatesRepo.GenerateCA(r.Context(), user.TenantID, validityDays)
		if err != nil {
			log.Printf("GenerateCA error: %v", err)
			writeError(w, "internal_error", "failed to generate CA certificate")
			return
		}

		detail := map[string]interface{}{
			"ca_id":         cert.ID,
			"validity_days": validityDays,
		}
		logAudit(r, deps, "generate_ca", detail, "ca_certificate", cert.ID)

		resp := mapCACertificateToInfo(cert)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

func ActivateCACertificate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can activate CA certificates")
			return
		}

		id := chi.URLParam(r, "id")
		cert, err := deps.CACertificatesRepo.Activate(r.Context(), user.TenantID, id)
		switch {
		case errors.Is(err, repository.ErrCANotFound):
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "CA certificate not found")
			return
		case errors.Is(err, repository.ErrCAInvalidState):
			writeErrorWithStatus(w, http.StatusConflict, "invalid_state", "only an unexpired pending CA can be activated")
			return
		case err != nil:
			log.Printf("ActivateCACertificate error: %v", err)
			writeError(w, "internal_error", "failed to activate CA certificate")
			return
		}

		logAudit(r, deps, "activate_ca", map[string]interface{}{"ca_id": cert.ID}, "ca_certificate", cert.ID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mapCACertificateToInfo(cert))
	}
}

func DeleteCACertificate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can delete CA certificates")
			return
		}

		id := chi.URLParam(r, "id")
		err := deps.CACertificatesRepo.Delete(r.Context(), user.TenantID, id)
		switch {
		case errors.Is(err, repository.ErrCANotFound):
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "CA certificate not found")
			return
		case errors.Is(err, repository.ErrCAActive):
			writeErrorWithStatus(w, http.StatusConflict, "active_ca", "the current CA cannot be deleted")
			return
		case err != nil:
			log.Printf("DeleteCACertificate error: %v", err)
			writeError(w, "internal_error", "failed to delete CA certificate")
			return
		}

		logAudit(r, deps, "delete_ca", map[string]interface{}{"ca_id": id}, "ca_certificate", id)
		w.WriteHeader(http.StatusNoContent)
	}
}

func GetCACertificate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		cert, err := deps.CACertificatesRepo.GetActive(r.Context(), user.TenantID)
		if err != nil {
			log.Printf("GetCACertificate error: %v", err)
			writeError(w, "internal_error", "failed to get CA certificate")
			return
		}

		if cert == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "no active CA certificate found")
			return
		}

		resp := mapCACertificateToInfo(cert)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func ListCACertificates(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		certs, err := deps.CACertificatesRepo.List(r.Context(), user.TenantID)
		if err != nil {
			log.Printf("ListCACertificates error: %v", err)
			writeError(w, "internal_error", "failed to list CA certificates")
			return
		}

		data := make([]CACertificateInfo, len(certs))
		for i, c := range certs {
			data[i] = mapCACertificateToInfo(&c)
		}

		resp := map[string]interface{}{
			"data":  data,
			"total": len(data),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func DownloadCACertificate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		id := chi.URLParam(r, "id")
		var cert *repository.CACertificate
		var err error
		if id == "" {
			cert, err = deps.CACertificatesRepo.GetActive(r.Context(), user.TenantID)
		} else {
			cert, err = deps.CACertificatesRepo.GetByID(r.Context(), user.TenantID, id)
		}
		if err != nil {
			log.Printf("DownloadCACertificate error: %v", err)
			writeError(w, "internal_error", "failed to get CA certificate")
			return
		}

		if cert == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "CA certificate not found")
			return
		}

		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=jjdguard_proxy_ca_"+cert.ID+".crt")
		_, _ = w.Write([]byte(cert.CertificatePEM)) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- PEM download is not rendered as HTML.
	}
}

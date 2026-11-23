package repository

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func newJJDGuardCATemplate(now time.Time, serial *big.Int, validityDays int) *x509.Certificate {
	notAfter := now.AddDate(0, 0, validityDays)
	if validityDays == 3650 {
		// The product default uses 3650 as the API value for a full ten
		// calendar years, including leap days.
		notAfter = now.AddDate(10, 0, 0)
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "JJDGuard Proxy MITM Root CA",
			Organization: []string{"JJDGuard"},
		},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

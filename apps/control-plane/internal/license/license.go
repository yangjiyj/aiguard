package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	Algorithm                 = "ed25519"
	SchemaVersionV1           = "license.v1"
	SchemaVersionV2           = "license.v2"
	SignatureAlgorithmV2      = "Ed25519-JCS-B64URL"
	ProductJJDGuardEnterprise = "jjdguard-enterprise"
	ProductLegacyEnterprise   = "newapi-enterprise"
	StatusActive              = "active"
	StatusMissing             = "missing"
	StatusExpired             = "expired"
	StatusPending             = "pending"
	StatusInvalid             = "invalid"
	StatusGrace               = "grace"
	StatusTrial               = "trial"
	StatusClockRollback       = "clock_rollback"
	TrialWindowDays           = 90
	TimeStateSchemaVersion    = "license-time-state.v1"
	RevocationListVersion     = "license-revocation-list.v1"
)

type Payload struct {
	LicenseID   string    `json:"license_id"`
	Customer    string    `json:"customer"`
	LicenseType string    `json:"license_type"`
	Edition     string    `json:"edition"`
	IssuedAt    time.Time `json:"issued_at"`
	NotBefore   time.Time `json:"not_before"`
	ExpiresAt   time.Time `json:"expires_at"`
	MaxUsers    int       `json:"max_users"`
	Features    []string  `json:"features"`
}

type File struct {
	Algorithm string  `json:"algorithm"`
	Payload   Payload `json:"payload"`
	Signature string  `json:"signature"`
}

type Status struct {
	Status       string            `json:"status"`
	Valid        bool              `json:"valid"`
	Reason       string            `json:"reason,omitempty"`
	DaysLeft     int               `json:"days_left,omitempty"`
	TrialDays    int               `json:"trial_days,omitempty"`
	PublicKeySet bool              `json:"public_key_set"`
	ImportedAt   string            `json:"imported_at,omitempty"`
	Version      string            `json:"version,omitempty"`
	KeyID        string            `json:"key_id,omitempty"`
	Products     []string          `json:"products,omitempty"`
	Features     []string          `json:"features,omitempty"`
	Binding      *BindingStatus    `json:"binding,omitempty"`
	Clock        *ClockStatus      `json:"clock,omitempty"`
	Revocation   *RevocationStatus `json:"revocation,omitempty"`
	Grace        *GraceStatus      `json:"grace,omitempty"`
	Payload      *Payload          `json:"payload,omitempty"`
	PayloadV2    *PayloadV2        `json:"payload_v2,omitempty"`
}

type BindingStatus struct {
	Mode    string `json:"mode"`
	Matched bool   `json:"matched"`
}

type ClockStatus struct {
	RollbackDetected bool   `json:"rollback_detected"`
	EffectiveNow     string `json:"effective_now,omitempty"`
	MaxSeenWallTime  string `json:"max_seen_wall_time,omitempty"`
}

type RevocationStatus struct {
	Checked bool   `json:"checked"`
	Revoked bool   `json:"revoked"`
	Reason  string `json:"reason,omitempty"`
}

type GraceStatus struct {
	Reason string `json:"reason"`
	Until  string `json:"until"`
	Days   int    `json:"days"`
}

type FileV2 struct {
	SchemaVersion      string    `json:"schemaVersion"`
	Payload            PayloadV2 `json:"payload"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	KeyID              string    `json:"keyId"`
	Signature          string    `json:"signature"`
}

type PayloadV2 struct {
	SchemaVersion     string            `json:"schemaVersion"`
	LicenseID         string            `json:"licenseId"`
	Customer          CustomerV2        `json:"customer"`
	Subject           SubjectV2         `json:"subject"`
	Edition           string            `json:"edition"`
	IssuedAt          string            `json:"issuedAt"`
	NotBefore         string            `json:"notBefore"`
	ExpiresAt         string            `json:"expiresAt"`
	MaxUsers          int               `json:"maxUsers"`
	Features          []string          `json:"features"`
	DeploymentBinding DeploymentBinding `json:"deploymentBinding"`
	GracePolicy       GracePolicy       `json:"gracePolicy"`
	RevocationInfo    RevocationInfo    `json:"revocationInfo"`
	Issuer            string            `json:"issuer"`
}

type CustomerV2 struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type SubjectV2 struct {
	DisplayName string   `json:"displayName"`
	Products    []string `json:"products"`
}

type DeploymentBinding struct {
	Mode         string        `json:"mode"`
	BindingID    string        `json:"bindingId,omitempty"`
	Fingerprints []Fingerprint `json:"fingerprints,omitempty"`
}

type Fingerprint struct {
	Scope     string `json:"scope"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type GracePolicy struct {
	ExpiryGraceDays            int `json:"expiryGraceDays"`
	ClockRollbackGraceHours    int `json:"clockRollbackGraceHours"`
	OfflineRevocationStaleDays int `json:"offlineRevocationStaleDays"`
}

type RevocationInfo struct {
	Mode   string `json:"mode"`
	ListID string `json:"listId,omitempty"`
	URL    string `json:"url,omitempty"`
}

type TimeState struct {
	SchemaVersion           string `json:"schemaVersion"`
	LicenseID               string `json:"licenseId"`
	LastSeenWallTime        string `json:"lastSeenWallTime"`
	MaxSeenWallTime         string `json:"maxSeenWallTime"`
	FirstSeenAt             string `json:"firstSeenAt"`
	ClockRollbackDetectedAt string `json:"clockRollbackDetectedAt,omitempty"`
}

type RevocationList struct {
	SchemaVersion      string            `json:"schemaVersion,omitempty"`
	Payload            RevocationPayload `json:"payload"`
	SignatureAlgorithm string            `json:"signatureAlgorithm,omitempty"`
	KeyID              string            `json:"keyId,omitempty"`
	Signature          string            `json:"signature,omitempty"`
}

type RevocationPayload struct {
	SchemaVersion   string           `json:"schemaVersion,omitempty"`
	ListID          string           `json:"listId,omitempty"`
	Issuer          string           `json:"issuer,omitempty"`
	IssuedAt        string           `json:"issuedAt,omitempty"`
	ValidUntil      string           `json:"validUntil,omitempty"`
	RevokedLicenses []RevokedLicense `json:"revokedLicenses,omitempty"`
	RevokedKeyIDs   []string         `json:"revokedKeyIds,omitempty"`
}

type RevokedLicense struct {
	LicenseID string `json:"licenseId"`
	RevokedAt string `json:"revokedAt,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type VerificationOptions struct {
	PublicKeyV1            string
	PublicKeysV2           map[string]string
	AcceptedProducts       []string
	Product                string
	TrustedIssuers         map[string]struct{}
	DeploymentFingerprints []Fingerprint
	TimeState              *TimeState
	RevocationList         *RevocationList
	RevocationListError    string
	Now                    time.Time
}

var (
	ErrMissingPublicKey          = errors.New("license public key is not configured")
	ErrInvalidPublicKey          = errors.New("license public key is invalid")
	ErrInvalidToken              = errors.New("license file is invalid")
	ErrInvalidSignature          = errors.New("license signature is invalid")
	ErrNotYetValid               = errors.New("license is not yet valid")
	ErrExpired                   = errors.New("license is expired")
	ErrProductMismatch           = errors.New("license product is not authorized")
	ErrDeploymentBindingMismatch = errors.New("license deployment binding mismatch")
	ErrClockRollback             = errors.New("system clock rollback detected")
	ErrLicenseRevoked            = errors.New("license is revoked")
	ErrRevocationListUnavailable = errors.New("license revocation list unavailable")
)

func Sign(payload Payload, privateKey ed25519.PrivateKey) (*File, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}
	payload.Features = normalizeFeatures(payload.Features)
	data, err := canonicalPayload(payload)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, data)
	return &File{
		Algorithm: Algorithm,
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func SignV2(payload PayloadV2, keyID string, privateKey ed25519.PrivateKey) (*FileV2, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}
	payload.SchemaVersion = SchemaVersionV2
	data, err := CanonicalPayloadV2(payload)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, data)
	return &FileV2{
		SchemaVersion:      SchemaVersionV2,
		Payload:            payload,
		SignatureAlgorithm: SignatureAlgorithmV2,
		KeyID:              keyID,
		Signature:          base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

func SignRevocationList(payload RevocationPayload, keyID string, privateKey ed25519.PrivateKey) (*RevocationList, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}
	payload.SchemaVersion = RevocationListVersion
	data, err := CanonicalRevocationPayload(payload)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, data)
	return &RevocationList{
		SchemaVersion:      RevocationListVersion,
		Payload:            payload,
		SignatureAlgorithm: SignatureAlgorithmV2,
		KeyID:              keyID,
		Signature:          base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

func Verify(raw string, publicKeyBase64 string, now time.Time) (*File, *Status, error) {
	publicKeySet := strings.TrimSpace(publicKeyBase64) != ""
	if !publicKeySet {
		return nil, invalidStatus(ErrMissingPublicKey, publicKeySet), ErrMissingPublicKey
	}

	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyBase64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, invalidStatus(ErrInvalidPublicKey, publicKeySet), ErrInvalidPublicKey
	}

	var file File
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &file); err != nil {
		return nil, invalidStatus(ErrInvalidToken, publicKeySet), ErrInvalidToken
	}
	if strings.ToLower(file.Algorithm) != Algorithm || strings.TrimSpace(file.Signature) == "" {
		return nil, invalidStatus(ErrInvalidToken, publicKeySet), ErrInvalidToken
	}
	if err := validatePayload(file.Payload); err != nil {
		return nil, invalidStatus(err, publicKeySet), err
	}

	sig, err := base64.StdEncoding.DecodeString(file.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, invalidStatus(ErrInvalidSignature, publicKeySet), ErrInvalidSignature
	}
	payloadBytes, err := canonicalPayload(file.Payload)
	if err != nil {
		return nil, invalidStatus(err, publicKeySet), err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payloadBytes, sig) {
		return nil, invalidStatus(ErrInvalidSignature, publicKeySet), ErrInvalidSignature
	}

	status := Evaluate(file.Payload, now, publicKeySet)
	if !status.Valid {
		if status.Status == StatusExpired {
			return &file, status, ErrExpired
		}
		if status.Status == StatusPending {
			return &file, status, ErrNotYetValid
		}
		return &file, status, ErrInvalidToken
	}
	return &file, status, nil
}

func VerifyAny(raw string, opts VerificationOptions) (interface{}, *Status, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if isV2Envelope(raw) {
		return verifyV2(raw, opts, now)
	}
	file, status, err := Verify(raw, opts.PublicKeyV1, now)
	if status != nil {
		status.Version = SchemaVersionV1
	}
	return file, status, err
}

func MarshalFileV2(file FileV2) (string, error) {
	data, err := json.Marshal(file)
	return string(data), err
}

func CanonicalPayloadV2(payload PayloadV2) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return canonicalJSON(v)
}

func CanonicalRevocationPayload(payload RevocationPayload) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return canonicalJSON(v)
}

func VerifyRevocationList(list RevocationList, publicKeys map[string]string, trustedIssuers map[string]struct{}, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if list.SchemaVersion != RevocationListVersion ||
		list.Payload.SchemaVersion != RevocationListVersion ||
		list.SignatureAlgorithm != SignatureAlgorithmV2 ||
		strings.TrimSpace(list.KeyID) == "" ||
		strings.TrimSpace(list.Signature) == "" ||
		strings.TrimSpace(list.Payload.ListID) == "" ||
		strings.TrimSpace(list.Payload.Issuer) == "" {
		return ErrInvalidToken
	}
	if len(trustedIssuers) > 0 {
		if _, ok := trustedIssuers[list.Payload.Issuer]; !ok {
			return ErrInvalidToken
		}
	}
	for _, raw := range []string{list.Payload.IssuedAt, list.Payload.ValidUntil} {
		if !isStrictRFC3339UTC(raw) {
			return ErrInvalidToken
		}
	}
	validUntil, err := time.Parse(time.RFC3339, list.Payload.ValidUntil)
	if err != nil {
		return ErrInvalidToken
	}
	if now.UTC().After(validUntil) {
		return ErrExpired
	}
	pubText := strings.TrimSpace(publicKeys[list.KeyID])
	if pubText == "" {
		return ErrMissingPublicKey
	}
	pub, err := base64.RawURLEncoding.DecodeString(pubText)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ErrInvalidPublicKey
	}
	sig, err := base64.RawURLEncoding.DecodeString(list.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	payloadBytes, err := CanonicalRevocationPayload(list.Payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payloadBytes, sig) {
		return ErrInvalidSignature
	}
	return nil
}

func verifyV2(raw string, opts VerificationOptions, now time.Time) (*FileV2, *Status, error) {
	publicKeySet := len(opts.PublicKeysV2) > 0
	var file FileV2
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &file); err != nil {
		return nil, invalidStatus(ErrInvalidToken, publicKeySet), ErrInvalidToken
	}
	if file.SchemaVersion != SchemaVersionV2 ||
		file.Payload.SchemaVersion != SchemaVersionV2 ||
		file.SignatureAlgorithm != SignatureAlgorithmV2 ||
		strings.TrimSpace(file.KeyID) == "" ||
		strings.TrimSpace(file.Signature) == "" {
		return nil, invalidStatus(ErrInvalidToken, publicKeySet), ErrInvalidToken
	}
	pubText := strings.TrimSpace(opts.PublicKeysV2[file.KeyID])
	if pubText == "" {
		return nil, invalidStatus(ErrMissingPublicKey, publicKeySet), ErrMissingPublicKey
	}
	pub, err := base64.RawURLEncoding.DecodeString(pubText)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, invalidStatus(ErrInvalidPublicKey, publicKeySet), ErrInvalidPublicKey
	}
	sig, err := base64.RawURLEncoding.DecodeString(file.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, invalidStatus(ErrInvalidSignature, publicKeySet), ErrInvalidSignature
	}
	payloadBytes, err := CanonicalPayloadV2(file.Payload)
	if err != nil {
		return nil, invalidStatus(err, publicKeySet), err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payloadBytes, sig) {
		return nil, invalidStatus(ErrInvalidSignature, publicKeySet), ErrInvalidSignature
	}
	if err := validatePayloadV2(file.Payload, opts); err != nil {
		return nil, invalidStatus(err, publicKeySet), err
	}
	if err := validateProductV2(file.Payload, opts); err != nil {
		return nil, invalidStatus(err, publicKeySet), err
	}

	status, err := evaluateV2(file, opts, now, publicKeySet)
	if err != nil {
		return &file, status, err
	}
	if !status.Valid {
		if status.Status == StatusExpired {
			return &file, status, ErrExpired
		}
		if status.Status == StatusPending {
			return &file, status, ErrNotYetValid
		}
		return &file, status, ErrInvalidToken
	}
	return &file, status, nil
}

func StatusFromStored(raw string, publicKeyBase64 string, importedAt string, now time.Time) Status {
	if strings.TrimSpace(raw) == "" {
		return Status{
			Status:       StatusMissing,
			Valid:        false,
			Reason:       "license not imported",
			TrialDays:    TrialWindowDays,
			PublicKeySet: strings.TrimSpace(publicKeyBase64) != "",
			ImportedAt:   importedAt,
		}
	}
	_, status, err := Verify(raw, publicKeyBase64, now)
	if status == nil {
		status = invalidStatus(err, strings.TrimSpace(publicKeyBase64) != "")
	}
	status.ImportedAt = importedAt
	return *status
}

func Evaluate(payload Payload, now time.Time, publicKeySet bool) *Status {
	status := &Status{
		Status:       StatusActive,
		Valid:        true,
		TrialDays:    TrialWindowDays,
		PublicKeySet: publicKeySet,
		Version:      SchemaVersionV1,
		Payload:      &payload,
		Features:     payload.Features,
	}
	if !payload.NotBefore.IsZero() && now.Before(payload.NotBefore) {
		status.Status = StatusPending
		status.Valid = false
		status.Reason = "license is not yet valid"
		return status
	}
	if !payload.ExpiresAt.IsZero() && now.After(payload.ExpiresAt) {
		status.Status = StatusExpired
		status.Valid = false
		status.Reason = "license expired"
		return status
	}
	status.DaysLeft = daysLeft(now, payload.ExpiresAt)
	if strings.EqualFold(payload.LicenseType, "trial") {
		status.TrialDays = TrialWindowDays
	}
	return status
}

func evaluateV2(file FileV2, opts VerificationOptions, now time.Time, publicKeySet bool) (*Status, error) {
	payload := file.Payload
	var revocationList *RevocationList
	revocationReason := opts.RevocationListError
	if opts.RevocationList != nil {
		if err := VerifyRevocationList(*opts.RevocationList, opts.PublicKeysV2, opts.TrustedIssuers, now); err != nil {
			revocationReason = err.Error()
		} else {
			revocationList = opts.RevocationList
		}
	}
	status := &Status{
		Status:       StatusActive,
		Valid:        true,
		TrialDays:    TrialWindowDays,
		PublicKeySet: publicKeySet,
		Version:      SchemaVersionV2,
		KeyID:        file.KeyID,
		Products:     append([]string(nil), payload.Subject.Products...),
		Features:     append([]string(nil), payload.Features...),
		Binding:      &BindingStatus{Mode: payload.DeploymentBinding.Mode, Matched: payload.DeploymentBinding.Mode == "none" || fingerprintsMatch(payload.DeploymentBinding.Fingerprints, opts.DeploymentFingerprints)},
		Revocation:   &RevocationStatus{Checked: opts.RevocationList != nil || revocationReason != "", Reason: revocationReason},
		PayloadV2:    &payload,
	}
	notBefore, _ := time.Parse(time.RFC3339, payload.NotBefore)
	expiresAt, _ := time.Parse(time.RFC3339, payload.ExpiresAt)
	effectiveNow, rollback, maxSeen := effectiveLicenseTime(now, opts.TimeState)
	status.Clock = &ClockStatus{
		RollbackDetected: rollback,
		EffectiveNow:     effectiveNow.UTC().Format(time.RFC3339),
		MaxSeenWallTime:  maxSeen,
	}
	if rollback {
		status.Status = StatusClockRollback
		status.Valid = false
		status.Reason = ErrClockRollback.Error()
		return status, ErrClockRollback
	}
	if opts.RevocationListError != "" {
		// 已配置的吊销列表不可用（读取/解析/校验失败）：无法确认未被吊销，fail-closed。
		reason := opts.RevocationListError
		if !strings.HasPrefix(reason, ErrRevocationListUnavailable.Error()) {
			reason = ErrRevocationListUnavailable.Error() + ": " + reason
		}
		status.Status = StatusInvalid
		status.Valid = false
		status.Reason = reason
		status.Revocation.Reason = reason
		return status, ErrRevocationListUnavailable
	}
	if isRevoked(file, revocationList) {
		status.Status = StatusInvalid
		status.Valid = false
		status.Reason = ErrLicenseRevoked.Error()
		status.Revocation.Revoked = true
		status.Revocation.Reason = ErrLicenseRevoked.Error()
		return status, ErrLicenseRevoked
	}
	if effectiveNow.Before(notBefore) {
		status.Status = StatusPending
		status.Valid = false
		status.Reason = "license is not yet valid"
		return status, nil
	}
	if effectiveNow.After(expiresAt) {
		if payload.GracePolicy.ExpiryGraceDays > 0 {
			graceUntil := expiresAt.Add(time.Duration(payload.GracePolicy.ExpiryGraceDays) * 24 * time.Hour)
			if !effectiveNow.After(graceUntil) {
				status.Status = StatusGrace
				status.Valid = true
				status.Reason = "license expired; running in grace period"
				status.Grace = &GraceStatus{
					Reason: "expired",
					Until:  graceUntil.UTC().Format(time.RFC3339),
					Days:   daysLeft(effectiveNow, graceUntil),
				}
				status.DaysLeft = 0
				return status, nil
			}
		}
		status.Status = StatusExpired
		status.Valid = false
		status.Reason = "license expired"
		return status, nil
	}
	status.DaysLeft = daysLeft(effectiveNow, expiresAt)
	return status, nil
}

func canonicalPayload(payload Payload) ([]byte, error) {
	payload.Features = normalizeFeatures(payload.Features)
	return json.Marshal(payload)
}

func normalizeFeatures(features []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(features))
	for _, feature := range features {
		feature = strings.TrimSpace(feature)
		if feature == "" {
			continue
		}
		if _, ok := seen[feature]; ok {
			continue
		}
		seen[feature] = struct{}{}
		out = append(out, feature)
	}
	sort.Strings(out)
	return out
}

func validatePayload(payload Payload) error {
	if strings.TrimSpace(payload.LicenseID) == "" ||
		strings.TrimSpace(payload.Customer) == "" ||
		strings.TrimSpace(payload.LicenseType) == "" ||
		strings.TrimSpace(payload.Edition) == "" ||
		payload.IssuedAt.IsZero() ||
		payload.ExpiresAt.IsZero() {
		return ErrInvalidToken
	}
	if payload.MaxUsers < 0 {
		return ErrInvalidToken
	}
	return nil
}

func validatePayloadV2(payload PayloadV2, opts VerificationOptions) error {
	if strings.TrimSpace(payload.LicenseID) == "" ||
		strings.TrimSpace(payload.Customer.ID) == "" ||
		strings.TrimSpace(payload.Customer.DisplayName) == "" ||
		strings.TrimSpace(payload.Subject.DisplayName) == "" ||
		strings.TrimSpace(payload.Edition) == "" ||
		strings.TrimSpace(payload.Issuer) == "" ||
		len(payload.Subject.Products) == 0 ||
		len(payload.Features) == 0 ||
		payload.MaxUsers < 0 {
		return ErrInvalidToken
	}
	for _, raw := range []string{payload.IssuedAt, payload.NotBefore, payload.ExpiresAt} {
		if !isStrictRFC3339UTC(raw) {
			return ErrInvalidToken
		}
	}
	if len(opts.TrustedIssuers) > 0 {
		if _, ok := opts.TrustedIssuers[payload.Issuer]; !ok {
			return ErrInvalidToken
		}
	}
	switch payload.DeploymentBinding.Mode {
	case "none":
		return nil
	case "optional", "required":
		if payload.DeploymentBinding.BindingID == "" || len(payload.DeploymentBinding.Fingerprints) == 0 {
			return ErrInvalidToken
		}
		if len(opts.DeploymentFingerprints) == 0 {
			if payload.DeploymentBinding.Mode == "required" {
				return ErrDeploymentBindingMismatch
			}
			return nil
		}
		if !fingerprintsMatch(payload.DeploymentBinding.Fingerprints, opts.DeploymentFingerprints) {
			if payload.DeploymentBinding.Mode == "required" {
				return ErrDeploymentBindingMismatch
			}
		}
		return nil
	default:
		return ErrInvalidToken
	}
}

func effectiveAcceptedProducts(opts VerificationOptions) []string {
	if len(opts.AcceptedProducts) > 0 {
		return opts.AcceptedProducts
	}
	if opts.Product != "" {
		return []string{opts.Product}
	}
	return nil
}

func validateProductV2(payload PayloadV2, opts VerificationOptions) error {
	accepted := effectiveAcceptedProducts(opts)
	if len(accepted) == 0 {
		return nil
	}
	for _, product := range accepted {
		if containsString(payload.Subject.Products, product) {
			return nil
		}
	}
	return ErrProductMismatch
}

func effectiveLicenseTime(now time.Time, state *TimeState) (time.Time, bool, string) {
	now = now.UTC()
	if state == nil || strings.TrimSpace(state.MaxSeenWallTime) == "" {
		return now, false, ""
	}
	maxSeen, err := time.Parse(time.RFC3339, state.MaxSeenWallTime)
	if err != nil {
		return now, false, ""
	}
	if now.Before(maxSeen) {
		return maxSeen, true, maxSeen.UTC().Format(time.RFC3339)
	}
	return now, false, maxSeen.UTC().Format(time.RFC3339)
}

func isRevoked(file FileV2, list *RevocationList) bool {
	if list == nil {
		return false
	}
	for _, license := range list.Payload.RevokedLicenses {
		if license.LicenseID == file.Payload.LicenseID {
			return true
		}
	}
	for _, keyID := range list.Payload.RevokedKeyIDs {
		if keyID == file.KeyID {
			return true
		}
	}
	return false
}

func isV2Envelope(raw string) bool {
	var header struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	return json.Unmarshal([]byte(strings.TrimSpace(raw)), &header) == nil && header.SchemaVersion == SchemaVersionV2
}

func canonicalJSON(v interface{}) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonicalJSON(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonicalJSON(b *bytes.Buffer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		data, err := json.Marshal(x)
		if err != nil {
			return err
		}
		b.Write(data)
	case json.Number:
		if strings.ContainsAny(x.String(), ".eE") {
			return ErrInvalidToken
		}
		b.WriteString(x.String())
	case []interface{}:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonicalJSON(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			keyBytes, err := json.Marshal(key)
			if err != nil {
				return err
			}
			b.Write(keyBytes)
			b.WriteByte(':')
			if err := writeCanonicalJSON(b, x[key]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return ErrInvalidToken
	}
	return nil
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func fingerprintsMatch(licensed, local []Fingerprint) bool {
	for _, want := range licensed {
		for _, got := range local {
			if want.Scope == got.Scope && want.Algorithm == got.Algorithm && want.Value == got.Value {
				return true
			}
		}
	}
	return false
}

func isStrictRFC3339UTC(raw string) bool {
	if !strings.HasSuffix(raw, "Z") || strings.Contains(raw, ".") {
		return false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	return t.UTC().Format(time.RFC3339) == raw
}

func invalidStatus(err error, publicKeySet bool) *Status {
	reason := "invalid license"
	if err != nil {
		reason = err.Error()
	}
	return &Status{
		Status:       StatusInvalid,
		Valid:        false,
		Reason:       reason,
		TrialDays:    TrialWindowDays,
		PublicKeySet: publicKeySet,
	}
}

// TrialStatusFromAnchor 根据安装锚点判定零签名试用态。
// anchor 为首次安装时间；publicKeySet 透传；now 为当前时刻。
func TrialStatusFromAnchor(anchor time.Time, publicKeySet bool, now time.Time) Status {
	if anchor.IsZero() {
		return Status{Status: StatusMissing, Valid: false, Reason: "license not imported",
			TrialDays: TrialWindowDays, PublicKeySet: publicKeySet}
	}
	end := anchor.AddDate(0, 0, TrialWindowDays)
	if now.After(end) {
		return Status{Status: StatusExpired, Valid: false, Reason: "trial expired",
			TrialDays: TrialWindowDays, PublicKeySet: publicKeySet}
	}
	return Status{Status: StatusTrial, Valid: true, TrialDays: TrialWindowDays,
		DaysLeft: daysLeft(now, end), PublicKeySet: publicKeySet,
		Features: []string{
			"agent_audit", "content_retention", "ide_proxy", "sensitive_data_guard", "web_ai",
		}}
}

func daysLeft(now, expiresAt time.Time) int {
	if expiresAt.IsZero() || now.After(expiresAt) {
		return 0
	}
	seconds := expiresAt.Sub(now).Seconds()
	days := int(seconds / 86400)
	if seconds > float64(days*86400) {
		days++
	}
	return days
}

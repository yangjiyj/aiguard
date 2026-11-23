package retentionartifact

import (
	"fmt"
	"io"
	"strings"
)

type Direction string

const (
	DirectionInput  Direction = "input"
	DirectionOutput Direction = "output"
)

type Kind string

const (
	KindImage Kind = "image"
	KindFile  Kind = "file"
)

type Origin string

const (
	OriginInlineBytes     Origin = "inline_bytes"
	OriginMultipartUpload Origin = "multipart_upload"
	OriginBinaryUpload    Origin = "binary_upload"
	OriginUploadReference Origin = "upload_reference"
	OriginRemoteReference Origin = "remote_reference"
)

type RetentionStatus string

const (
	RetentionStatusRetained           RetentionStatus = "retained"
	RetentionStatusReferenceOnly      RetentionStatus = "reference_only"
	RetentionStatusFailed             RetentionStatus = "failed"
	RetentionStatusOversizeUnretained RetentionStatus = "oversize_unretained"
)

const LegacyEnvironmentScope = "legacy-unclassified"

func NormalizeEnvironmentScope(value string) string {
	switch normalized := strings.ToLower(strings.TrimSpace(value)); normalized {
	case "customer", "home", "claude", "codex", LegacyEnvironmentScope:
		return normalized
	default:
		return LegacyEnvironmentScope
	}
}

// ResolveEnvironmentScope keeps a classified deployment inside its trusted
// evidence boundary. An explicit record/key scope is considered only when the
// deployment itself is still unclassified.
func ResolveEnvironmentScope(explicit, deployment string) string {
	deployment = NormalizeEnvironmentScope(deployment)
	if deployment != LegacyEnvironmentScope {
		return deployment
	}
	if strings.TrimSpace(explicit) != "" {
		return NormalizeEnvironmentScope(explicit)
	}
	return LegacyEnvironmentScope
}

type Candidate struct {
	Direction            Direction `json:"direction"`
	Kind                 Kind      `json:"kind"`
	Origin               Origin    `json:"origin,omitempty"`
	DisplayName          string    `json:"display_name,omitempty"`
	DeclaredMIME         string    `json:"declared_mime,omitempty"`
	DeclaredSize         int64     `json:"declared_size,omitempty"`
	Ordinal              int       `json:"ordinal"`
	OriginalSHA256       string    `json:"-"`
	ReferenceFingerprint string    `json:"-"`
	ReferenceID          string    `json:"-"`
	RemoteURL            string    `json:"-"`
	Payload              io.Reader `json:"-"`
}

func (c Candidate) Validate() error {
	if c.Direction != DirectionInput && c.Direction != DirectionOutput {
		return fmt.Errorf("invalid artifact direction %q", c.Direction)
	}
	if c.Kind != KindImage && c.Kind != KindFile {
		return fmt.Errorf("invalid artifact kind %q", c.Kind)
	}
	return nil
}

func (c Candidate) StableKey() string {
	identity := strings.TrimSpace(c.OriginalSHA256)
	if identity == "" {
		identity = strings.TrimSpace(c.ReferenceFingerprint)
	}
	if identity == "" {
		return fmt.Sprintf("%s:%s:ordinal:%d", c.Direction, c.Kind, c.Ordinal)
	}
	return fmt.Sprintf("%s:%s:%s", c.Direction, c.Kind, identity)
}

func Deduplicate(candidates []Candidate) []Candidate {
	seen := make(map[string]struct{}, len(candidates))
	result := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		key := candidate.StableKey()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

type Result struct {
	Status            RetentionStatus `json:"retention_status"`
	FailureCode       string          `json:"failure_code,omitempty"`
	OriginalSHA256    string          `json:"sha256,omitempty"`
	ByteSize          int64           `json:"byte_size,omitempty"`
	MediaType         string          `json:"media_type,omitempty"`
	DisplayName       string          `json:"display_name,omitempty"`
	OriginalObjectKey string          `json:"-"`
	PreviewObjectKey  string          `json:"-"`
	StorageBackend    string          `json:"storage_backend,omitempty"`
}

func (r Result) Validate() error {
	switch r.Status {
	case RetentionStatusRetained, RetentionStatusReferenceOnly,
		RetentionStatusFailed, RetentionStatusOversizeUnretained:
		return nil
	default:
		return fmt.Errorf("invalid retention status %q", r.Status)
	}
}

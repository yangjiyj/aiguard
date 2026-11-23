package retentionartifact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestArtifactRetentionStatusRejectsLegacyOrUnknownValues(t *testing.T) {
	for _, status := range []RetentionStatus{
		RetentionStatusRetained,
		RetentionStatusReferenceOnly,
		RetentionStatusFailed,
		RetentionStatusOversizeUnretained,
	} {
		if err := (Result{Status: status}).Validate(); err != nil {
			t.Fatalf("status %q should be valid: %v", status, err)
		}
	}
	if err := (Result{Status: "externalized"}).Validate(); err == nil {
		t.Fatal("legacy status must not be accepted for new writes")
	}
}

func TestArtifactDeduplicateUsesDirectionAndOriginalOrReferenceFingerprint(t *testing.T) {
	candidates := []Candidate{
		{Direction: DirectionInput, Kind: KindImage, OriginalSHA256: "same-bytes"},
		{Direction: DirectionInput, Kind: KindImage, OriginalSHA256: "same-bytes"},
		{Direction: DirectionOutput, Kind: KindImage, OriginalSHA256: "same-bytes"},
		{Direction: DirectionInput, Kind: KindFile, ReferenceFingerprint: "stable-reference"},
		{Direction: DirectionInput, Kind: KindFile, ReferenceFingerprint: "stable-reference"},
	}

	got := Deduplicate(candidates)
	if len(got) != 3 {
		t.Fatalf("Deduplicate() produced %d candidates, want 3: %#v", len(got), got)
	}
}

func TestArtifactCandidateDoesNotMarshalUnsafePayloadOrReference(t *testing.T) {
	candidate := Candidate{
		Direction:            DirectionInput,
		Kind:                 KindFile,
		Origin:               OriginRemoteReference,
		RemoteURL:            "https://signed.example.test/private?signature=secret",
		ReferenceID:          "/Users/person/secret.txt",
		ReferenceFingerprint: "safe-fingerprint",
		Payload:              strings.NewReader("raw bytes"),
	}

	encoded, err := json.Marshal(candidate)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	serialized := string(encoded)
	for _, forbidden := range []string{"signed.example", "secret.txt", "raw bytes", "reference_id", "remote_url", "payload"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("serialized candidate leaked %q: %s", forbidden, serialized)
		}
	}
}

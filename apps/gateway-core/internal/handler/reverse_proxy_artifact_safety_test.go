package handler

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

func TestReverseProxyArtifactMetadataDoesNotPersistSensitiveReferences(t *testing.T) {
	metadata := string(reverseProxyArtifactMetadataJSON([]retentionartifact.Candidate{{
		Direction: retentionartifact.DirectionInput, Kind: retentionartifact.KindFile,
		DisplayName: "report.txt", ReferenceID: "file-secret-reference",
		RemoteURL: "https://example.test/signed?token=secret", ReferenceFingerprint: "safe-hash",
	}}))
	for _, forbidden := range []string{"file-secret-reference", "signed?token", "safe-hash"} {
		if strings.Contains(metadata, forbidden) {
			t.Fatalf("metadata leaked %q: %s", forbidden, metadata)
		}
	}
	if !strings.Contains(metadata, "report.txt") {
		t.Fatalf("safe display metadata missing: %s", metadata)
	}
}

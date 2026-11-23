package handler

import (
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

func TestBuildProxyRetainedArtifactWritesBridgesExternalizedImages(t *testing.T) {
	until := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	item := retainedAttachmentMetadata{
		Source: "agent_artifact", Stage: "request", ContentType: "image/png",
		Size: 379525, SHA256: "b505ac334d5b", ObjectKey: "tenant/request/image",
		StorageBackend: "local", RetentionStatus: "externalized",
	}
	record := ProxyAuditRecord{RequestID: "req-1", TenantID: "tenant-a", Provider: "examplegw"}
	writes := buildProxyRetainedArtifactWrites(record, until, []retainedAttachmentMetadata{item})
	if len(writes) != 1 {
		t.Fatalf("writes=%#v", writes)
	}
	got := writes[0]
	if got.artifact.Status != retentionartifact.RetentionStatusRetained || got.artifact.Kind != retentionartifact.KindImage {
		t.Fatalf("artifact=%#v", got.artifact)
	}
	if got.artifact.OriginalObjectKey != item.ObjectKey || got.artifact.PreviewObjectKey != "" {
		t.Fatalf("image object linkage=%#v", got.artifact)
	}
	if got.link.RequestID != record.RequestID || got.link.Direction != retentionartifact.DirectionInput || got.link.Ordinal != 0 {
		t.Fatalf("link=%#v", got.link)
	}
}

func TestBuildProxyRetainedArtifactWritesUsesObjectSidecarExpiry(t *testing.T) {
	objectExpiry := time.Date(2026, 10, 3, 8, 24, 45, 0, time.UTC)
	callExpiry := objectExpiry.Add(12 * time.Hour)
	item := retainedAttachmentMetadata{
		Stage: "request", ContentType: "image/png", SHA256: "same-sha",
		ObjectKey: "donor/object", RetentionStatus: "externalized",
		RetentionUntil: objectExpiry.Format(time.RFC3339Nano),
	}
	writes := buildProxyRetainedArtifactWrites(
		ProxyAuditRecord{RequestID: "req-reference", TenantID: "tenant-a", Provider: "github"},
		callExpiry,
		[]retainedAttachmentMetadata{item},
	)
	if len(writes) != 1 || !writes[0].artifact.RetentionUntil.Equal(objectExpiry) {
		t.Fatalf("artifact expiry = %#v, want donor sidecar %s", writes, objectExpiry)
	}

	item.RetentionUntil = "invalid"
	writes = buildProxyRetainedArtifactWrites(
		ProxyAuditRecord{RequestID: "req-new-copy", TenantID: "tenant-a", Provider: "github"},
		callExpiry,
		[]retainedAttachmentMetadata{item},
	)
	if len(writes) != 1 || !writes[0].artifact.RetentionUntil.Equal(callExpiry) {
		t.Fatalf("invalid sidecar expiry must use call fallback: %#v", writes)
	}
}

func TestBuildProxyRetainedArtifactWritesDeduplicatesContentAcrossRequests(t *testing.T) {
	item := retainedAttachmentMetadata{Stage: "request", ContentType: "image/png", SHA256: "same-sha", ObjectKey: "one", RetentionStatus: "externalized"}
	first := buildProxyRetainedArtifactWrites(ProxyAuditRecord{RequestID: "req-1", TenantID: "tenant-a", Provider: "github"}, time.Now(), []retainedAttachmentMetadata{item})
	item.ObjectKey = "two"
	second := buildProxyRetainedArtifactWrites(ProxyAuditRecord{RequestID: "req-2", TenantID: "tenant-a", Provider: "github"}, time.Now(), []retainedAttachmentMetadata{item})
	if len(first) != 1 || len(second) != 1 || first[0].artifact.ID != second[0].artifact.ID {
		t.Fatalf("same retained bytes must share artifact identity: first=%#v second=%#v", first, second)
	}
	if first[0].link.ID == second[0].link.ID {
		t.Fatalf("different requests must retain distinct links: first=%#v second=%#v", first[0].link, second[0].link)
	}
}

func TestBuildProxyRetainedArtifactWritesSeparatesEnvironmentScopes(t *testing.T) {
	item := retainedAttachmentMetadata{
		Stage: "request", ContentType: "image/png", SHA256: "same-sha",
		ObjectKey: "retained/object", RetentionStatus: "externalized",
	}
	customer := buildProxyRetainedArtifactWrites(
		ProxyAuditRecord{RequestID: "req-z-random", TenantID: "tenant-a", Provider: "github", EnvironmentScope: "customer"},
		time.Now(),
		[]retainedAttachmentMetadata{item},
	)
	home := buildProxyRetainedArtifactWrites(
		ProxyAuditRecord{RequestID: "req-a-random", TenantID: "tenant-a", Provider: "github", EnvironmentScope: "home"},
		time.Now(),
		[]retainedAttachmentMetadata{item},
	)
	legacy := buildProxyRetainedArtifactWrites(
		ProxyAuditRecord{RequestID: "req-legacy", TenantID: "tenant-a", Provider: "github"},
		time.Now(),
		[]retainedAttachmentMetadata{item},
	)
	if customer[0].artifact.ID == home[0].artifact.ID {
		t.Fatalf("same bytes in different scopes reused one artifact: customer=%#v home=%#v", customer[0], home[0])
	}
	if customer[0].artifact.EnvironmentScope != "customer" || home[0].link.EnvironmentScope != "home" {
		t.Fatalf("scope was not propagated: customer=%#v home=%#v", customer[0], home[0])
	}
	if legacy[0].artifact.EnvironmentScope != retentionartifact.LegacyEnvironmentScope {
		t.Fatalf("blank scope = %q, want legacy", legacy[0].artifact.EnvironmentScope)
	}
}

func TestReconcileExistingProxyArtifactRefreshesRetainedCopyButPreservesLateReference(t *testing.T) {
	until := time.Now().UTC().Add(24 * time.Hour)
	record := ProxyAuditRecord{RequestID: "req-new", TenantID: "tenant-a", EnvironmentScope: "customer"}
	existing := retentionartifact.ArtifactRecord{
		ID: "artifact-existing", TenantID: "tenant-a", EnvironmentScope: "customer",
		Status: retentionartifact.RetentionStatusRetained, OriginalObjectKey: "old-original",
		PreviewObjectKey: "old-preview", RetentionUntil: until.Add(-time.Hour),
	}
	newCopy := proxyRetainedArtifactWrite{
		artifact: retentionartifact.ArtifactRecord{
			ID: "artifact-generated", TenantID: "tenant-a", EnvironmentScope: "customer",
			Status: retentionartifact.RetentionStatusRetained, OriginalObjectKey: "new-original",
			PreviewObjectKey: "new-preview", RetentionUntil: until,
		},
		link: retentionartifact.ArtifactLink{Direction: retentionartifact.DirectionInput},
	}
	refreshed := reconcileExistingProxyArtifact(record, newCopy, existing, until)
	if refreshed.artifact.ID != existing.ID || refreshed.artifact.OriginalObjectKey != "new-original" ||
		refreshed.artifact.PreviewObjectKey != "new-preview" {
		t.Fatalf("new retained copy was not kept for repository refresh: %#v", refreshed)
	}

	lateReference := newCopy
	lateReference.artifact.Status = retentionartifact.RetentionStatusReferenceOnly
	lateReference.artifact.OriginalObjectKey = ""
	lateReference.artifact.PreviewObjectKey = ""
	preserved := reconcileExistingProxyArtifact(record, lateReference, existing, until)
	if preserved.artifact.Status != retentionartifact.RetentionStatusRetained ||
		preserved.artifact.OriginalObjectKey != "old-original" ||
		preserved.artifact.PreviewObjectKey != "old-preview" ||
		!preserved.artifact.RetentionUntil.Equal(existing.RetentionUntil) {
		t.Fatalf("late reference downgraded retained bytes: %#v", preserved)
	}
}

func TestBuildProxyRetainedArtifactWritesKeepsUploadReferenceAcrossRestart(t *testing.T) {
	upload := retainedAttachmentMetadata{
		Stage: "request", ContentType: "image/png", ReferenceID: "copilot-attachment-1",
		SHA256: strings.Repeat("a", 64), ObjectKey: "upload/object", RetentionStatus: "externalized",
	}
	reference := retainedAttachmentMetadata{
		Stage: "request", ContentType: "image/png", ReferenceID: "copilot-attachment-1",
		RetentionStatus: "reference_only",
	}
	record := ProxyAuditRecord{RequestID: "req-upload", TenantID: "tenant-a", Provider: "github"}
	first := buildProxyRetainedArtifactWrites(record, time.Now(), []retainedAttachmentMetadata{upload})
	record.RequestID = "req-chat"
	second := buildProxyRetainedArtifactWrites(record, time.Now(), []retainedAttachmentMetadata{reference})
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("writes first=%#v second=%#v", first, second)
	}
	if first[0].artifact.ID != second[0].artifact.ID || first[0].artifact.SourceReferenceHash != second[0].artifact.SourceReferenceHash {
		t.Fatalf("reference identity changed across restart: first=%#v second=%#v", first[0].artifact, second[0].artifact)
	}
	if first[0].artifact.Status != retentionartifact.RetentionStatusRetained || second[0].artifact.Status != retentionartifact.RetentionStatusReferenceOnly {
		t.Fatalf("unexpected statuses: first=%q second=%q", first[0].artifact.Status, second[0].artifact.Status)
	}
}

func TestNormalizedProxyArtifactStatusFailsClosed(t *testing.T) {
	if status, _ := normalizedProxyArtifactStatus(retainedAttachmentMetadata{RetentionStatus: "url_only"}); status != retentionartifact.RetentionStatusReferenceOnly {
		t.Fatalf("url-only status=%q", status)
	}
	if status, _ := normalizedProxyArtifactStatus(retainedAttachmentMetadata{RetentionStatus: "oversize_unretained"}); status != retentionartifact.RetentionStatusOversizeUnretained {
		t.Fatalf("oversize status=%q", status)
	}
	if status, failure := normalizedProxyArtifactStatus(retainedAttachmentMetadata{RetentionStatus: "externalize_failed"}); status != retentionartifact.RetentionStatusFailed || failure == "" {
		t.Fatalf("failure status=%q code=%q", status, failure)
	}
}

func TestProxyArtifactDisplayNameDoesNotExposeLocalPath(t *testing.T) {
	if got := proxyArtifactDisplayName(`C:\Users\test\private\screen.png`, retentionartifact.KindImage); got != "screen.png" {
		t.Fatalf("display name=%q", got)
	}
	if got := proxyArtifactDisplayName("", retentionartifact.KindImage); got != "artifact-image" {
		t.Fatalf("empty image display name=%q", got)
	}
}

package handler

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

func TestReverseProxyArtifactIDIsStableAcrossUploadRequests(t *testing.T) {
	candidate := retentionartifact.Candidate{ReferenceFingerprint: "sha256-upload-bytes"}
	first := reverseProxyArtifactID("tenant-a", "customer", "openai", "request-1", candidate)
	second := reverseProxyArtifactID("tenant-a", "customer", "openai", "request-2", candidate)
	if first == "" || first != second {
		t.Fatalf("同一上传引用必须跨请求稳定关联: first=%q second=%q", first, second)
	}
	if strings.Contains(first, candidate.ReferenceFingerprint) || !strings.HasPrefix(first, "rta_") {
		t.Fatalf("artifact ID 不得暴露原始引用指纹: %q", first)
	}
}

func TestReverseProxyArtifactIDSeparatesEnvironmentScopesAndNormalizesBlank(t *testing.T) {
	candidate := retentionartifact.Candidate{ReferenceFingerprint: "same-upload"}
	customer := reverseProxyArtifactID("tenant-a", "customer", "openai", "request-z", candidate)
	home := reverseProxyArtifactID("tenant-a", "home", "openai", "request-a", candidate)
	legacy := reverseProxyArtifactID("tenant-a", "", "openai", "request-a", candidate)
	explicitLegacy := reverseProxyArtifactID("tenant-a", retentionartifact.LegacyEnvironmentScope, "openai", "request-b", candidate)
	if customer == home {
		t.Fatalf("artifact identity crossed environment scopes: customer=%q home=%q", customer, home)
	}
	if legacy != explicitLegacy {
		t.Fatalf("blank scope must normalize to legacy: blank=%q explicit=%q", legacy, explicitLegacy)
	}
}

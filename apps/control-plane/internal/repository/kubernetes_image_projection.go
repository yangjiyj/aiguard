package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	kubernetesRuntimeDigestEvidence          = regexp.MustCompile("^(?:containerd|docker|cri-o|crio)://sha256:([0-9a-f]{64})$")
	kubernetesRuntimeReferenceDigestEvidence = regexp.MustCompile("^(?:docker-pullable|containerd|docker|cri-o|crio)://[^@\\s]+@sha256:([0-9a-f]{64})$")
	kubernetesDeclaredDigestEvidence         = regexp.MustCompile("^[^@\\s]+@sha256:([0-9a-f]{64})$")
	kubernetesImageReferenceEvidence         = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:/+\\-]*$")
)

type kubernetesImageKey struct {
	key    string
	basis  string
	digest string
	ref    string
}

func containerKubernetesImageKey(container KubernetesContainer) (kubernetesImageKey, bool) {
	runtimeID := strings.ToLower(strings.TrimSpace(container.RuntimeImageID))
	declared := strings.TrimSpace(container.DeclaredImage)
	if match := kubernetesRuntimeDigestEvidence.FindStringSubmatch(runtimeID); match != nil {
		return kubernetesImageKey{key: "digest:sha256:" + match[1], basis: "runtime_digest", digest: "sha256:" + match[1]}, true
	}
	if match := kubernetesRuntimeReferenceDigestEvidence.FindStringSubmatch(runtimeID); match != nil {
		return kubernetesImageKey{key: "digest:sha256:" + match[1], basis: "runtime_digest", digest: "sha256:" + match[1]}, true
	}
	if match := kubernetesDeclaredDigestEvidence.FindStringSubmatch(strings.ToLower(declared)); match != nil {
		return kubernetesImageKey{key: "digest:sha256:" + match[1], basis: "declared_digest", digest: "sha256:" + match[1]}, true
	}
	if safeKubernetesImageReference(declared) {
		return kubernetesImageKey{key: "ref:" + declared, basis: "declared_reference_only", ref: declared}, true
	}
	return kubernetesImageKey{}, false
}

func safeKubernetesImageReference(value string) bool {
	return len(value) > 0 && len(value) <= 1024 && strings.TrimSpace(value) == value &&
		!strings.Contains(value, "://") && !strings.ContainsAny(value, "@?#\\ \t\r\n") &&
		kubernetesImageReferenceEvidence.MatchString(value) && !strings.HasPrefix(value, "/") && !strings.HasSuffix(value, "/")
}

func reportedKubernetesImageKeys(image KubernetesImage) ([]kubernetesImageKey, bool) {
	if image.IdentityBasis == "runtime_digest" || image.IdentityBasis == "declared_digest" {
		if image.Digest == "" || !kubernetesImageDigestPattern.MatchString(image.Digest) {
			return nil, false
		}
		return []kubernetesImageKey{{key: "digest:" + image.Digest, basis: image.IdentityBasis, digest: image.Digest}}, true
	}
	if image.IdentityBasis != "declared_reference_only" || image.Digest != "" || len(image.DeclaredReferences) == 0 {
		return nil, false
	}
	result := make([]kubernetesImageKey, 0, len(image.DeclaredReferences))
	seen := make(map[string]struct{}, len(image.DeclaredReferences))
	for _, ref := range image.DeclaredReferences {
		if !safeKubernetesImageReference(ref) {
			return nil, false
		}
		key := "ref:" + ref
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, kubernetesImageKey{key: key, basis: "declared_reference_only", ref: ref})
	}
	return result, true
}

func deriveKubernetesImageCoverage(snapshot KubernetesDiscoverySnapshot, podsComplete bool) (KubernetesResourceStatus, string) {
	status := KubernetesResourceStatus{Resource: "images", Status: "partial"}
	if !podsComplete {
		return status, "images_not_bound_to_pods"
	}
	expected := make(map[string][]KubernetesContainer)
	for _, pod := range snapshot.Pods {
		for _, container := range pod.Containers {
			key, ok := containerKubernetesImageKey(container)
			if !ok || container.ImageIdentityBasis != key.basis {
				return status, "image_identity_unavailable"
			}
			expected[key.key] = append(expected[key.key], container)
		}
	}
	reported := make(map[string]KubernetesImage)
	for _, image := range snapshot.Images {
		keys, ok := reportedKubernetesImageKeys(image)
		if !ok {
			return status, "image_reference_not_safe"
		}
		for _, key := range keys {
			if _, duplicate := reported[key.key]; duplicate {
				return status, "images_not_bound_to_pods"
			}
			reported[key.key] = image
		}
	}
	for key, containers := range expected {
		image, ok := reported[key]
		if !ok {
			return status, "images_not_bound_to_pods"
		}
		for _, container := range containers {
			if container.DeclaredImage != "" && !containsKubernetesString(image.DeclaredReferences, container.DeclaredImage) {
				return status, "images_not_bound_to_pods"
			}
			if container.RuntimeImageID != "" && !containsKubernetesString(image.RuntimeImageIDs, container.RuntimeImageID) {
				return status, "images_not_bound_to_pods"
			}
		}
	}
	for key := range reported {
		if _, ok := expected[key]; !ok {
			return status, "images_not_bound_to_pods"
		}
	}
	status.Status = "complete"
	status.Pages = 1
	status.ObjectsObserved = len(expected)
	return status, ""
}

func containsKubernetesString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func kubernetesImageIdentityNative(key kubernetesImageKey) (string, string) {
	if key.digest != "" {
		return "ImageDigest", key.digest
	}
	sum := sha256.Sum256([]byte(key.ref))
	return "DeclaredImageReference", "declared-sha256:" + hex.EncodeToString(sum[:])
}

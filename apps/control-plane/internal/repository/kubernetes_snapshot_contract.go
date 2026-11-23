package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	KubernetesSnapshotSchemaVersion = "kubernetes-discovery.v1"
	KubernetesReportSchemaVersion   = "kubernetes-observations.v1"
	KubernetesCollectorProduct      = "aiprobe-kubernetes"
	KubernetesMaxReportBytes        = 32 << 20
	KubernetesSnapshotRunTTL        = 15 * time.Minute
	maxKubernetesObjects            = 10000
)

const kubernetesCoverageNote = "Read-only snapshot of one explicitly requested namespace and the allowlisted resource types. It does not establish cluster-wide workload coverage, business ownership, policy authorization, or enforcement."

var (
	kubernetesReportIDPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	kubernetesObjectUIDPattern   = regexp.MustCompile(`^[^\x00-\x20\x7f]{1,128}$`)
	kubernetesNamespacePattern   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$|^[a-z0-9]$`)
	kubernetesDNSLabelPattern    = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	kubernetesOwnerAPIVersion    = regexp.MustCompile(`^(?:[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])*)*/)?v[0-9]+(?:(?:alpha|beta)[0-9]+)?$`)
	kubernetesOwnerKind          = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)
	kubernetesImageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	kubernetesReasonCodes        = stringSet(
		"request_failed", "unauthorized", "forbidden", "not_found", "rate_limited", "invalid_response",
		"namespace_type_mismatch", "namespace_name_mismatch", "namespace_uid_missing",
		"invalid_object", "duplicate_object_uid", "object_limit_reached", "byte_limit_reached",
		"malformed_list_envelope", "unexpected_list_type", "server_exceeded_page_limit",
		"continuation_token_too_large", "page_limit_reached", "container_image_identity_missing",
		"ambiguous_controller_owner", "owner_reference_incomplete", "owner_kind_outside_allowlist",
		"owner_cycle", "owner_reference_unresolved", "owner_reference_name_mismatch", "owner_chain_too_deep",
		"registered_namespace_uid_not_verified", "registered_namespace_uid_mismatch", "complete_list_object_count_mismatch",
		"complete_list_has_zero_pages", "object_namespace_uid_missing", "images_not_bound_to_pods",
		"image_identity_unavailable", "image_reference_not_safe", "resource_gap_prevents_complete_list",
	)
	kubernetesContainerReasons = stringSet(
		"ContainerCreating", "CrashLoopBackOff", "ErrImagePull", "ImagePullBackOff", "CreateContainerConfigError",
		"CreateContainerError", "InvalidImageName", "ErrImageNeverPull", "ContainerCannotRun", "RunContainerError",
		"Completed", "Error", "OOMKilled", "DeadlineExceeded", "Terminated", "Evicted", "other",
	)
	kubernetesIdentityStatuses  = stringSet("uid", "uid_unavailable", "uid_mismatch", "namespace_uid", "provisional_namespace_name")
	kubernetesOwnershipStatuses = stringSet(
		"root", "unowned", "no_controller_owner", "ambiguous_controller_owners", "owner_reference_incomplete",
		"owner_kind_not_collected", "owner_cycle", "owner_reference_unresolved", "owner_reference_name_mismatch",
		"resolved", "owner_chain_too_deep",
	)
	kubernetesImageIdentityBases = stringSet("runtime_digest", "declared_digest", "declared_reference_only", "unavailable")
)

type KubernetesObservationReport struct {
	SchemaVersion string                      `json:"schema_version"`
	RunID         string                      `json:"run_id"`
	ReportID      string                      `json:"report_id"`
	Snapshot      KubernetesDiscoverySnapshot `json:"snapshot"`
}

type KubernetesDiscoverySnapshot struct {
	SchemaVersion string                      `json:"schema_version"`
	ObservedAt    string                      `json:"observed_at"`
	ClusterID     string                      `json:"cluster_id"`
	Namespace     KubernetesNamespaceIdentity `json:"namespace"`
	Status        string                      `json:"collection_status"`
	CoverageNote  string                      `json:"coverage_note"`
	Resources     []KubernetesResourceStatus  `json:"resources"`
	Workloads     []KubernetesWorkload        `json:"workloads"`
	Pods          []KubernetesPod             `json:"pods"`
	Images        []KubernetesImage           `json:"images"`
	Gaps          []KubernetesObservationGap  `json:"observation_gaps"`
}

type KubernetesNamespaceIdentity struct {
	Name           string `json:"name"`
	UID            string `json:"uid,omitempty"`
	IdentityStatus string `json:"identity_status"`
}

type KubernetesResourceStatus struct {
	Resource        string `json:"resource"`
	Status          string `json:"status"`
	Pages           int    `json:"pages"`
	ObjectsObserved int    `json:"objects_observed"`
	ResourceVersion string `json:"resource_version,omitempty"`
}

type KubernetesObservationGap struct {
	Resource   string `json:"resource"`
	Reason     string `json:"reason"`
	StatusCode int    `json:"status_code,omitempty"`
	Kind       string `json:"kind,omitempty"`
	UID        string `json:"uid,omitempty"`
}

type KubernetesOwnerReference struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller,omitempty"`
}

type KubernetesObjectRef struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	ID         string `json:"id"`
}

type KubernetesWorkload struct {
	ID                 string                     `json:"id"`
	WorkloadID         string                     `json:"workload_id,omitempty"`
	APIVersion         string                     `json:"api_version"`
	Kind               string                     `json:"kind"`
	Name               string                     `json:"name"`
	UID                string                     `json:"uid"`
	Namespace          string                     `json:"namespace"`
	NamespaceUID       string                     `json:"namespace_uid,omitempty"`
	IdentityStatus     string                     `json:"identity_status"`
	OwnershipStatus    string                     `json:"ownership_status"`
	OwnerReferences    []KubernetesOwnerReference `json:"owner_references"`
	OwnerChain         []KubernetesObjectRef      `json:"owner_chain"`
	Generation         int64                      `json:"generation,omitempty"`
	ObservedGeneration int64                      `json:"observed_generation,omitempty"`
	DesiredReplicas    *int32                     `json:"desired_replicas,omitempty"`
	ReadyReplicas      int32                      `json:"ready_replicas,omitempty"`
	Active             int32                      `json:"active,omitempty"`
	ObservedPodCount   int                        `json:"observed_pod_count"`
	CreationTimestamp  string                     `json:"creation_timestamp,omitempty"`
	DeletionTimestamp  string                     `json:"deletion_timestamp,omitempty"`
}

type KubernetesPod struct {
	ID                string                     `json:"id"`
	WorkloadID        string                     `json:"workload_id,omitempty"`
	Name              string                     `json:"name"`
	UID               string                     `json:"uid"`
	Namespace         string                     `json:"namespace"`
	NamespaceUID      string                     `json:"namespace_uid,omitempty"`
	IdentityStatus    string                     `json:"identity_status"`
	OwnershipStatus   string                     `json:"ownership_status"`
	OwnerReferences   []KubernetesOwnerReference `json:"owner_references"`
	OwnerChain        []KubernetesObjectRef      `json:"owner_chain"`
	Phase             string                     `json:"phase,omitempty"`
	ServiceAccount    string                     `json:"service_account,omitempty"`
	CreationTimestamp string                     `json:"creation_timestamp,omitempty"`
	DeletionTimestamp string                     `json:"deletion_timestamp,omitempty"`
	Containers        []KubernetesContainer      `json:"containers"`
}

type KubernetesContainer struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Class              string `json:"class"`
	DeclaredImage      string `json:"declared_image"`
	RuntimeImageID     string `json:"runtime_image_id,omitempty"`
	ImageID            string `json:"image_id"`
	ImageIdentityBasis string `json:"image_identity_basis"`
	State              string `json:"state"`
	StateReason        string `json:"state_reason,omitempty"`
	Ready              bool   `json:"ready"`
	RestartCount       int32  `json:"restart_count"`
}

type KubernetesImage struct {
	ID                 string   `json:"id"`
	IdentityBasis      string   `json:"identity_basis"`
	Digest             string   `json:"digest,omitempty"`
	DeclaredReferences []string `json:"declared_references"`
	RuntimeImageIDs    []string `json:"runtime_image_ids"`
}

var kubernetesResourceGVK = map[string][2]string{
	"pods":         {"v1", "Pod"},
	"deployments":  {"apps/v1", "Deployment"},
	"replicasets":  {"apps/v1", "ReplicaSet"},
	"statefulsets": {"apps/v1", "StatefulSet"},
	"daemonsets":   {"apps/v1", "DaemonSet"},
	"jobs":         {"batch/v1", "Job"},
	"cronjobs":     {"batch/v1", "CronJob"},
}

func (r KubernetesObservationReport) Validate() error {
	if r.SchemaVersion != KubernetesReportSchemaVersion {
		return errors.New("unsupported Kubernetes report schema")
	}
	if _, err := uuid.Parse(r.RunID); err != nil {
		return errors.New("invalid Kubernetes snapshot run ID")
	}
	if !kubernetesReportIDPattern.MatchString(r.ReportID) {
		return errors.New("invalid Kubernetes report ID")
	}
	canonical, err := json.Marshal(r.Snapshot)
	if err != nil {
		return fmt.Errorf("encode Kubernetes snapshot: %w", err)
	}
	digest := sha256.Sum256(canonical)
	if r.ReportID != "sha256:"+hex.EncodeToString(digest[:]) {
		return errors.New("Kubernetes report ID does not match snapshot digest")
	}
	return r.Snapshot.Validate()
}

func (s KubernetesDiscoverySnapshot) Validate() error {
	if s.SchemaVersion != KubernetesSnapshotSchemaVersion {
		return errors.New("unsupported Kubernetes snapshot schema")
	}
	if len(s.ObservedAt) > 64 || !safeKubernetesText(s.ObservedAt, 64) {
		return errors.New("invalid Kubernetes source observation time")
	}
	observed, err := time.Parse(time.RFC3339Nano, s.ObservedAt)
	if err != nil || observed.IsZero() {
		return errors.New("invalid Kubernetes source observation time")
	}
	if len(s.ClusterID) < 1 || len(s.ClusterID) > 128 || strings.TrimSpace(s.ClusterID) != s.ClusterID || strings.ContainsAny(s.ClusterID, "\x00\r\n") {
		return errors.New("invalid Kubernetes cluster label")
	}
	if !kubernetesNamespacePattern.MatchString(s.Namespace.Name) {
		return errors.New("invalid Kubernetes namespace name")
	}
	if len(s.Namespace.UID) > 128 || (s.Namespace.UID != "" && !kubernetesObjectUIDPattern.MatchString(s.Namespace.UID)) {
		return errors.New("invalid Kubernetes namespace UID")
	}
	if s.Namespace.IdentityStatus != "uid" && s.Namespace.IdentityStatus != "uid_unavailable" && s.Namespace.IdentityStatus != "uid_mismatch" {
		return errors.New("invalid namespace identity status")
	}
	if s.CoverageNote != kubernetesCoverageNote {
		return errors.New("invalid coverage note")
	}
	if s.Status != "complete" && s.Status != "partial" {
		return errors.New("invalid collection status")
	}
	if len(s.Resources) > len(kubernetesResourceGVK) {
		return errors.New("too many Kubernetes resource statuses")
	}
	resourceStatus := make(map[string]string, len(s.Resources))
	for _, status := range s.Resources {
		if _, ok := kubernetesResourceGVK[status.Resource]; !ok {
			return errors.New("resource status outside Kubernetes allowlist")
		}
		if _, exists := resourceStatus[status.Resource]; exists {
			return errors.New("duplicate Kubernetes resource status")
		}
		switch status.Status {
		case "complete", "partial", "forbidden", "limited", "failed":
		default:
			return errors.New("invalid Kubernetes resource status")
		}
		if status.Pages < 0 || status.Pages > 20 || status.ObjectsObserved < 0 || status.ObjectsObserved > maxKubernetesObjects || len(status.ResourceVersion) > 256 || !safeKubernetesText(status.ResourceVersion, 256) {
			return errors.New("invalid Kubernetes resource counters")
		}
		resourceStatus[status.Resource] = status.Status
	}
	for resource := range kubernetesResourceGVK {
		if _, ok := resourceStatus[resource]; !ok {
			resourceStatus[resource] = "partial"
		}
	}
	if len(s.Gaps) > maxKubernetesObjects {
		return errors.New("too many Kubernetes observation gaps")
	}
	for _, gap := range s.Gaps {
		if !isKubernetesResourceName(gap.Resource) || !containsKubernetesContractString(kubernetesReasonCodes, gap.Reason) ||
			(gap.Kind != "" && !validKubernetesIdentifier(gap.Kind, 128)) ||
			(gap.UID != "" && !kubernetesObjectUIDPattern.MatchString(gap.UID)) || gap.StatusCode < 0 || gap.StatusCode > 599 {
			return errors.New("invalid Kubernetes observation gap")
		}
	}
	if len(s.Workloads)+len(s.Pods)+len(s.Images) > maxKubernetesObjects {
		return errors.New("Kubernetes snapshot object limit exceeded")
	}
	seen := make(map[string]struct{}, len(s.Workloads)+len(s.Pods))
	for _, workload := range s.Workloads {
		gvk, ok := kubernetesResourceGVK[resourceForKubernetesKind(workload.Kind)]
		if !ok || gvk[0] != workload.APIVersion || gvk[1] != workload.Kind || workload.Kind == "Pod" ||
			!validKubernetesObject(workload.APIVersion, workload.Kind, workload.Name, workload.UID, workload.Namespace, workload.NamespaceUID, s.Namespace.Name, s.Namespace.UID) ||
			!containsKubernetesContractString(kubernetesIdentityStatuses, workload.IdentityStatus) || !containsKubernetesContractString(kubernetesOwnershipStatuses, workload.OwnershipStatus) || !validOwnerClaims(workload.OwnerReferences, workload.OwnerChain) ||
			workload.Generation < 0 || workload.ObservedGeneration < 0 || !nonnegativeKubernetesInt32(workload.DesiredReplicas) || workload.ReadyReplicas < 0 || workload.Active < 0 || workload.ObservedPodCount < 0 || workload.ObservedPodCount > maxKubernetesObjects ||
			!validKubernetesTimestamp(workload.CreationTimestamp) || !validKubernetesTimestamp(workload.DeletionTimestamp) {
			return errors.New("invalid Kubernetes workload identity")
		}
		key := workload.APIVersion + "\x00" + workload.Kind + "\x00" + workload.UID
		if _, exists := seen[key]; exists {
			return errors.New("duplicate Kubernetes object UID")
		}
		seen[key] = struct{}{}
		if !kubernetesStatusCanContain(resourceStatus[resourceForKubernetesKind(workload.Kind)]) {
			return errors.New("Kubernetes workload included in failed or forbidden list")
		}
	}
	for _, pod := range s.Pods {
		if !validKubernetesObject("v1", "Pod", pod.Name, pod.UID, pod.Namespace, pod.NamespaceUID, s.Namespace.Name, s.Namespace.UID) ||
			!containsKubernetesContractString(kubernetesIdentityStatuses, pod.IdentityStatus) || !containsKubernetesContractString(kubernetesOwnershipStatuses, pod.OwnershipStatus) || !validOwnerClaims(pod.OwnerReferences, pod.OwnerChain) ||
			(len(pod.Phase) > 16 || (pod.Phase != "" && !containsKubernetesContractString(kubernetesPodPhases, pod.Phase))) || !validKubernetesServiceAccount(pod.ServiceAccount) ||
			!validKubernetesTimestamp(pod.CreationTimestamp) || !validKubernetesTimestamp(pod.DeletionTimestamp) {
			return errors.New("invalid Kubernetes pod identity")
		}
		key := "v1\x00Pod\x00" + pod.UID
		if _, exists := seen[key]; exists {
			return errors.New("duplicate Kubernetes object UID")
		}
		seen[key] = struct{}{}
		if !kubernetesStatusCanContain(resourceStatus["pods"]) {
			return errors.New("Kubernetes pod included in failed or forbidden list")
		}
		if len(pod.Containers) > 500 {
			return errors.New("too many containers in pod")
		}
		for _, container := range pod.Containers {
			if !validKubernetesIdentifier(container.Name, 256) || !validKubernetesIdentifier(container.Class, 64) ||
				!safeKubernetesText(container.DeclaredImage, 1024) || !safeKubernetesText(container.RuntimeImageID, 1024) ||
				!safeKubernetesText(container.ImageID, 256) || !containsKubernetesContractString(kubernetesImageIdentityBases, container.ImageIdentityBasis) ||
				!containsKubernetesContractString(kubernetesContainerStates, container.State) || (container.StateReason != "" && !containsKubernetesContractString(kubernetesContainerReasons, container.StateReason)) || container.RestartCount < 0 {
				return errors.New("invalid Kubernetes container observation")
			}
		}
	}
	for _, image := range s.Images {
		if len(image.ID) > 256 || !safeKubernetesText(image.ID, 256) || !containsKubernetesContractString(kubernetesImageIdentityBases, image.IdentityBasis) ||
			len(image.DeclaredReferences) > maxKubernetesObjects || len(image.RuntimeImageIDs) > maxKubernetesObjects {
			return errors.New("invalid Kubernetes image observation")
		}
		if image.Digest != "" && !kubernetesImageDigestPattern.MatchString(image.Digest) {
			return errors.New("invalid Kubernetes image digest")
		}
		if image.IdentityBasis == "runtime_digest" || image.IdentityBasis == "declared_digest" {
			if image.Digest == "" {
				return errors.New("digest-based Kubernetes image is missing its digest")
			}
		} else if image.IdentityBasis != "declared_reference_only" && image.IdentityBasis != "unavailable" {
			return errors.New("invalid Kubernetes image identity basis")
		}
		for _, value := range append(append([]string{}, image.DeclaredReferences...), image.RuntimeImageIDs...) {
			if len(value) > 1024 || !safeKubernetesText(value, 1024) {
				return errors.New("invalid Kubernetes image reference")
			}
		}
	}
	if s.Status == "complete" {
		if s.Namespace.UID == "" || s.Namespace.IdentityStatus != "uid" || len(s.Gaps) != 0 {
			return errors.New("complete Kubernetes snapshot lacks namespace identity or has observation gaps")
		}
		for _, status := range resourceStatus {
			if status != "complete" {
				return errors.New("complete Kubernetes snapshot includes an incomplete resource")
			}
		}
	}
	return nil
}

func stringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func containsKubernetesContractString(values map[string]struct{}, value string) bool {
	_, ok := values[value]
	return ok
}

var kubernetesContainerStates = stringSet("running", "waiting", "terminated", "unknown")

func isKubernetesResourceName(value string) bool {
	if value == "namespaces" || value == "images" {
		return true
	}
	_, ok := kubernetesResourceGVK[value]
	return ok
}

func resourceForKubernetesKind(kind string) string {
	for resource, gvk := range kubernetesResourceGVK {
		if gvk[1] == kind {
			return resource
		}
	}
	return ""
}

func kubernetesStatusCanContain(status string) bool {
	return status == "complete" || status == "partial" || status == "limited"
}

func validKubernetesObject(apiVersion, kind, name, uid, namespace, namespaceUID, expectedName, expectedUID string) bool {
	gvk := kubernetesResourceGVK[resourceForKubernetesKind(kind)]
	return gvk[0] == apiVersion && gvk[1] == kind && validKubernetesIdentifier(name, 253) &&
		kubernetesObjectUIDPattern.MatchString(uid) && namespace == expectedName &&
		(namespaceUID == "" || expectedUID == "" || namespaceUID == expectedUID)
}

func validOwnerClaims(references []KubernetesOwnerReference, chain []KubernetesObjectRef) bool {
	if len(references) > 32 || len(chain) > 8 {
		return false
	}
	for _, reference := range references {
		if (reference.APIVersion != "" && !validKubernetesOwnerAPIVersion(reference.APIVersion)) ||
			(reference.Kind != "" && !validKubernetesOwnerKind(reference.Kind)) ||
			(reference.Name != "" && !validKubernetesIdentifier(reference.Name, 253)) ||
			(reference.UID != "" && !kubernetesObjectUIDPattern.MatchString(reference.UID)) {
			return false
		}
	}
	for _, reference := range chain {
		if !validKubernetesOwnerAPIVersion(reference.APIVersion) || !validKubernetesOwnerKind(reference.Kind) || !validKubernetesIdentifier(reference.Name, 253) ||
			!kubernetesObjectUIDPattern.MatchString(reference.UID) || !validKubernetesIdentifier(reference.ID, 256) {
			return false
		}
	}
	return true
}

var kubernetesPodPhases = stringSet("Pending", "Running", "Succeeded", "Failed", "Unknown")

func validKubernetesOwnerAPIVersion(value string) bool {
	if len(value) > 128 || !kubernetesOwnerAPIVersion.MatchString(value) {
		return false
	}
	group, _, hasGroup := strings.Cut(value, "/")
	if !hasGroup {
		return true
	}
	for _, label := range strings.Split(group, ".") {
		if len(label) > 63 || !kubernetesDNSLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validKubernetesOwnerKind(value string) bool {
	return len(value) <= 128 && kubernetesOwnerKind.MatchString(value)
}

func validKubernetesTimestamp(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 64 || !safeKubernetesText(value, 64) {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !parsed.IsZero()
}

func validKubernetesServiceAccount(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 253 || strings.TrimSpace(value) != value {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 || !kubernetesDNSLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func nonnegativeKubernetesInt32(value *int32) bool {
	return value == nil || *value >= 0
}

func validKubernetesIdentifier(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && safeKubernetesText(value, max)
}

func safeKubernetesText(value string, max int) bool {
	if len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

package repository

import (
	"strings"
	"testing"
	"time"
)

func testKubernetesSnapshot() KubernetesDiscoverySnapshot {
	resources := make([]KubernetesResourceStatus, 0, len(kubernetesResourceGVK))
	for resource := range kubernetesResourceGVK {
		resources = append(resources, KubernetesResourceStatus{Resource: resource, Status: "complete", Pages: 1})
	}
	return KubernetesDiscoverySnapshot{
		SchemaVersion: KubernetesSnapshotSchemaVersion,
		ObservedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		ClusterID:     "cluster-a",
		Namespace:     KubernetesNamespaceIdentity{Name: "prod", UID: "namespace-uid", IdentityStatus: "uid"},
		Status:        "complete",
		CoverageNote:  kubernetesCoverageNote,
		Resources:     resources,
		Workloads:     []KubernetesWorkload{},
		Pods:          []KubernetesPod{},
		Images:        []KubernetesImage{},
		Gaps:          []KubernetesObservationGap{},
	}
}

func TestKubernetesCompleteKindWithZeroPagesCannotAdvanceCoverage(t *testing.T) {
	snapshot := testKubernetesSnapshot()
	for i := range snapshot.Resources {
		if snapshot.Resources[i].Resource == "pods" {
			snapshot.Resources[i].Pages = 0
		}
	}
	snapshot.Status = "partial"
	coverage, gaps, _, exactScope := normalizedKubernetesCoverage(snapshot, snapshot.Namespace.UID)
	if !exactScope {
		t.Fatal("exact registered namespace UID was not recognized")
	}
	for _, item := range coverage {
		if item.Resource == "pods" && (item.Status != "partial" || item.Pages != 0) {
			t.Fatalf("zero-page list advanced complete coverage: %#v", item)
		}
	}
	if !hasKubernetesGap(gaps, "complete_list_has_zero_pages") {
		t.Fatalf("zero-page downgrade did not produce a bounded gap: %#v", gaps)
	}
}

func TestKubernetesCompleteKindWithMissingObjectNamespaceUIDCannotAdvanceCoverage(t *testing.T) {
	snapshot := testKubernetesSnapshot()
	snapshot.Status = "partial"
	snapshot.Pods = []KubernetesPod{{UID: "pod-1", Namespace: "prod"}}
	for i := range snapshot.Resources {
		if snapshot.Resources[i].Resource == "pods" {
			snapshot.Resources[i].ObjectsObserved = 1
		}
	}
	coverage, gaps, _, _ := normalizedKubernetesCoverage(snapshot, snapshot.Namespace.UID)
	for _, item := range coverage {
		if item.Resource == "pods" && item.Status != "partial" {
			t.Fatalf("missing namespace UID remained complete: %#v", item)
		}
	}
	if !hasKubernetesGap(gaps, "object_namespace_uid_missing") {
		t.Fatalf("missing object scope did not produce a gap: %#v", gaps)
	}
}

func TestKubernetesImageCoverageBindsTypedImageRowsToPodContainers(t *testing.T) {
	snapshot := testKubernetesSnapshot()
	snapshot.Pods = []KubernetesPod{{Containers: []KubernetesContainer{{
		Name: "app", Class: "container", DeclaredImage: "registry.example/team/api:stable",
		ImageIdentityBasis: "declared_reference_only",
	}}}}
	snapshot.Images = []KubernetesImage{{IdentityBasis: "declared_reference_only", DeclaredReferences: []string{"registry.example/team/api:stable"}}}
	complete, gap := deriveKubernetesImageCoverage(snapshot, true)
	if complete.Status != "complete" || complete.Pages != 1 || gap != "" {
		t.Fatalf("bound mutable image reference was not represented: %#v gap=%q", complete, gap)
	}
	snapshot.Images = append(snapshot.Images, KubernetesImage{IdentityBasis: "declared_reference_only", DeclaredReferences: []string{"orphan.example/other:tag"}})
	partial, gap := deriveKubernetesImageCoverage(snapshot, true)
	if partial.Status != "partial" || gap != "images_not_bound_to_pods" {
		t.Fatalf("unbound image observation did not create a gap: %#v gap=%q", partial, gap)
	}
}

func TestKubernetesSnapshotRejectsFreeformCoverageAndGapText(t *testing.T) {
	snapshot := testKubernetesSnapshot()
	snapshot.CoverageNote = "tenant-private text"
	if err := snapshot.Validate(); err == nil {
		t.Fatal("freeform coverage note was accepted")
	}
	snapshot = testKubernetesSnapshot()
	snapshot.Gaps = []KubernetesObservationGap{{Resource: "pods", Reason: "secret-account-name"}}
	snapshot.Status = "partial"
	if err := snapshot.Validate(); err == nil {
		t.Fatal("freeform observation reason was accepted")
	}
	snapshot = testKubernetesSnapshot()
	snapshot.Pods = []KubernetesPod{{Name: "pod-1", UID: "pod-1", Namespace: "prod", NamespaceUID: "namespace-uid", IdentityStatus: "namespace_uid", OwnershipStatus: "unowned",
		OwnerReferences: []KubernetesOwnerReference{}, OwnerChain: []KubernetesObjectRef{},
		Containers: []KubernetesContainer{{Name: "app", Class: "container", ImageIdentityBasis: "unavailable", State: "waiting", StateReason: "secret-account-name"}}}}
	for i := range snapshot.Resources {
		if snapshot.Resources[i].Resource == "pods" {
			snapshot.Resources[i].ObjectsObserved = 1
		}
	}
	snapshot.Status = "partial"
	if err := snapshot.Validate(); err == nil || !strings.Contains(err.Error(), "container") {
		t.Fatalf("freeform container reason was not rejected: %v", err)
	}
}

func hasKubernetesGap(gaps []KubernetesObservationGap, reason string) bool {
	for _, gap := range gaps {
		if gap.Reason == reason {
			return true
		}
	}
	return false
}

func TestResourceScopedGapPreventsOnlyThatKindFromAdvancingCoverage(t *testing.T) {
	snapshot := testKubernetesSnapshot()
	snapshot.Status = "partial"
	snapshot.Gaps = []KubernetesObservationGap{{Resource: "pods", Reason: "invalid_object"}}
	coverage, gaps, _, _ := normalizedKubernetesCoverage(snapshot, snapshot.Namespace.UID)
	statuses := make(map[string]string, len(coverage))
	for _, status := range coverage {
		statuses[status.Resource] = status.Status
	}
	if statuses["pods"] != "partial" {
		t.Fatalf("pods gap did not block complete coverage: %#v", coverage)
	}
	if statuses["deployments"] != "complete" {
		t.Fatalf("unrelated complete kind was downgraded: %#v", coverage)
	}
	if !hasKubernetesGap(gaps, "resource_gap_prevents_complete_list") {
		t.Fatalf("normalized completeness gap was not retained for receipt: %#v", gaps)
	}
}

func TestKubernetesNamespaceIdentityUsesRegisteredUID(t *testing.T) {
	snapshot := testKubernetesSnapshot()
	scope := kubernetesRunScope{RegistrationID: "registration-a", ClusterLabel: "cluster-a", NamespaceName: "prod", NamespaceUID: snapshot.Namespace.UID}
	coverage, _, _, exactScope := normalizedKubernetesCoverage(snapshot, snapshot.Namespace.UID)
	if !exactScope {
		t.Fatal("registered UID did not establish exact namespace scope")
	}
	records := buildKubernetesAssetRecords(scope, snapshot, coverage)
	if len(records) != 1 || records[0].resource != "namespaces" || records[0].assetType != "kubernetes_namespace" ||
		records[0].uid != snapshot.Namespace.UID || records[0].name != snapshot.Namespace.Name {
		t.Fatalf("namespace projection did not use registered UID: %#v", records)
	}
	if got := kubernetesNativeID(records[0].apiVersion, records[0].kind, records[0].uid); got != "v1\x1eNamespace\x1enamespace-uid" {
		t.Fatalf("unexpected namespace native identity %q", got)
	}
	changed := snapshot
	changed.Namespace.UID = "recreated-uid"
	if records := buildKubernetesAssetRecords(scope, changed, coverage); len(records) != 0 {
		t.Fatalf("recreated namespace UID was projected into old scope: %#v", records)
	}
}

func TestKubernetesScaleAndRescheduleKeepOnlyStableUIDIdentity(t *testing.T) {
	snapshot := testKubernetesSnapshot()
	scope := kubernetesRunScope{RegistrationID: "registration-a", ClusterLabel: "cluster-a", NamespaceName: "prod", NamespaceUID: snapshot.Namespace.UID}
	snapshot.Workloads = []KubernetesWorkload{{
		APIVersion: "apps/v1", Kind: "Deployment", Name: "api", UID: "deployment-uid",
		Namespace: "prod", NamespaceUID: scope.NamespaceUID, Generation: 2,
	}}
	snapshot.Pods = []KubernetesPod{
		{UID: "pod-old", Name: "api-1", Namespace: "prod", NamespaceUID: scope.NamespaceUID, Containers: []KubernetesContainer{}},
		{UID: "pod-new", Name: "api-2", Namespace: "prod", NamespaceUID: scope.NamespaceUID, Containers: []KubernetesContainer{}},
	}
	coverage, _, _, _ := normalizedKubernetesCoverage(snapshot, scope.NamespaceUID)
	records := buildKubernetesAssetRecords(scope, snapshot, coverage)
	var deploymentNative string
	var podNatives []string
	for _, record := range records {
		switch record.kind {
		case "Deployment":
			deploymentNative = kubernetesNativeID(record.apiVersion, record.kind, record.uid)
		case "Pod":
			podNatives = append(podNatives, kubernetesNativeID(record.apiVersion, record.kind, record.uid))
		}
	}
	if deploymentNative == "" || len(podNatives) != 2 || podNatives[0] == podNatives[1] {
		t.Fatalf("scale/reschedule identity was not UID-based: deployment=%q pods=%#v", deploymentNative, podNatives)
	}
	snapshot.Workloads[0].Generation = 3
	updated := buildKubernetesAssetRecords(scope, snapshot, coverage)
	for _, record := range updated {
		if record.kind == "Deployment" && kubernetesNativeID(record.apiVersion, record.kind, record.uid) != deploymentNative {
			t.Fatalf("scale changed stable Deployment identity: %#v", record)
		}
	}
}

func TestKubernetesImageProjectionSkipsPodWithoutRegisteredNamespaceUID(t *testing.T) {
	snapshot := testKubernetesSnapshot()
	snapshot.Pods = []KubernetesPod{{
		Name: "pod-1", UID: "pod-1", Namespace: "prod", NamespaceUID: "",
		Containers: []KubernetesContainer{{
			Name: "app", Class: "container", DeclaredImage: "registry.example/team/api:stable",
			ImageIdentityBasis: "declared_reference_only",
		}},
	}}
	records := buildKubernetesImageAssetRecords(snapshot, snapshot.Namespace.UID)
	if len(records) != 0 {
		t.Fatalf("image from namespace-unverified Pod was projected: %#v", records)
	}
}

func TestKubernetesOwnerResolutionUsesUIDAndFlagsNameMismatch(t *testing.T) {
	apiVersion, kind, uid := "apps/v1", "ReplicaSet", "rs-uid"
	nativeID := kubernetesNativeID(apiVersion, kind, uid)
	ownerIndex := map[string]kubernetesOwnerTarget{
		kubernetesOwnerKey(apiVersion, kind, uid): {nativeID: nativeID, name: "actual-rs"},
	}
	controller := true
	evidence := kubernetesOwnerEvidence([]KubernetesOwnerReference{{
		APIVersion: apiVersion, Kind: kind, Name: "spoofed-display-name", UID: uid, Controller: &controller,
	}}, ownerIndex)
	if len(evidence) != 1 || evidence[0]["resolution"] != "uid_match_in_snapshot" ||
		evidence[0]["resolved_source_native_id"] != nativeID || evidence[0]["name_display_mismatch"] != true {
		t.Fatalf("owner name was used as identity or mismatch was hidden: %#v", evidence)
	}
}

func TestKubernetesSnapshotRejectsUnboundedOrMalformedProjectedFields(t *testing.T) {
	validSnapshot := func() KubernetesDiscoverySnapshot {
		snapshot := testKubernetesSnapshot()
		snapshot.Pods = []KubernetesPod{{
			Name: "pod-1", UID: "pod-1", Namespace: "prod", NamespaceUID: "namespace-uid",
			IdentityStatus: "namespace_uid", OwnershipStatus: "unowned", OwnerReferences: []KubernetesOwnerReference{}, OwnerChain: []KubernetesObjectRef{},
			Phase: "Running", ServiceAccount: "runtime", CreationTimestamp: "2026-09-26T12:00:00Z", Containers: []KubernetesContainer{},
		}}
		snapshot.Workloads = []KubernetesWorkload{{
			APIVersion: "apps/v1", Kind: "Deployment", Name: "api", UID: "deployment-1", Namespace: "prod", NamespaceUID: "namespace-uid",
			IdentityStatus: "uid", OwnershipStatus: "root", OwnerReferences: []KubernetesOwnerReference{}, OwnerChain: []KubernetesObjectRef{},
			Generation: 1, ObservedGeneration: 1, ObservedPodCount: 1, CreationTimestamp: "2026-09-26T12:00:00Z",
		}}
		for i := range snapshot.Resources {
			switch snapshot.Resources[i].Resource {
			case "pods":
				snapshot.Resources[i].ObjectsObserved = 1
			case "deployments":
				snapshot.Resources[i].ObjectsObserved = 1
			}
		}
		return snapshot
	}
	tests := []struct {
		name   string
		mutate func(*KubernetesDiscoverySnapshot)
	}{
		{name: "observed time length", mutate: func(s *KubernetesDiscoverySnapshot) { s.ObservedAt = strings.Repeat("1", 65) }},
		{name: "pod phase", mutate: func(s *KubernetesDiscoverySnapshot) { s.Pods[0].Phase = "private-value" }},
		{name: "pod phase length", mutate: func(s *KubernetesDiscoverySnapshot) { s.Pods[0].Phase = strings.Repeat("x", 17) }},
		{name: "service account syntax", mutate: func(s *KubernetesDiscoverySnapshot) { s.Pods[0].ServiceAccount = "runtime/name" }},
		{name: "service account length", mutate: func(s *KubernetesDiscoverySnapshot) { s.Pods[0].ServiceAccount = strings.Repeat("a", 254) }},
		{name: "pod creation timestamp", mutate: func(s *KubernetesDiscoverySnapshot) { s.Pods[0].CreationTimestamp = "secret-value" }},
		{name: "pod deletion timestamp length", mutate: func(s *KubernetesDiscoverySnapshot) { s.Pods[0].DeletionTimestamp = strings.Repeat("1", 65) }},
		{name: "workload timestamp", mutate: func(s *KubernetesDiscoverySnapshot) { s.Workloads[0].CreationTimestamp = "secret-value" }},
		{name: "negative generation", mutate: func(s *KubernetesDiscoverySnapshot) { s.Workloads[0].Generation = -1 }},
		{name: "negative observed generation", mutate: func(s *KubernetesDiscoverySnapshot) { s.Workloads[0].ObservedGeneration = -1 }},
		{name: "negative desired replicas", mutate: func(s *KubernetesDiscoverySnapshot) { value := int32(-1); s.Workloads[0].DesiredReplicas = &value }},
		{name: "negative ready replicas", mutate: func(s *KubernetesDiscoverySnapshot) { s.Workloads[0].ReadyReplicas = -1 }},
		{name: "negative active count", mutate: func(s *KubernetesDiscoverySnapshot) { s.Workloads[0].Active = -1 }},
		{name: "negative observed pod count", mutate: func(s *KubernetesDiscoverySnapshot) { s.Workloads[0].ObservedPodCount = -1 }},
		{name: "oversized observed pod count", mutate: func(s *KubernetesDiscoverySnapshot) { s.Workloads[0].ObservedPodCount = maxKubernetesObjects + 1 }},
		{name: "owner API version control", mutate: func(s *KubernetesDiscoverySnapshot) {
			s.Pods[0].OwnerReferences = []KubernetesOwnerReference{{APIVersion: "apps/v1\nsecret", Kind: "ReplicaSet", Name: "rs"}}
		}},
		{name: "owner kind control", mutate: func(s *KubernetesDiscoverySnapshot) {
			s.Pods[0].OwnerReferences = []KubernetesOwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet\nsecret", Name: "rs"}}
		}},
		{name: "owner kind syntax", mutate: func(s *KubernetesDiscoverySnapshot) {
			s.Pods[0].OwnerReferences = []KubernetesOwnerReference{{APIVersion: "apps/v1", Kind: "Replica-Set", Name: "rs"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := validSnapshot()
			test.mutate(&snapshot)
			if err := snapshot.Validate(); err == nil {
				t.Fatal("malformed projected value was accepted")
			}
		})
	}
}

func TestKubernetesOwnerClaimsAcceptSafeCustomAPIKinds(t *testing.T) {
	if !validOwnerClaims([]KubernetesOwnerReference{{APIVersion: "policy.example.com/v1alpha1", Kind: "WorkloadPolicy", Name: "policy-1"}}, []KubernetesObjectRef{{
		APIVersion: "policy.example.com/v1alpha1", Kind: "CustomWorkload", Name: "custom-1", UID: "owner-uid", ID: "k8sobj:v1:0123456789abcdef",
	}}) {
		t.Fatal("safe custom API group and kind were rejected")
	}
}


func TestKubernetesOwnerClaimsAllowSafeIncompleteReferences(t *testing.T) {
	if !validOwnerClaims([]KubernetesOwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet"}}, []KubernetesObjectRef{}) {
		t.Fatal("safe incomplete owner reference was rejected instead of remaining an explicit gap")
	}
	longGroup := strings.Repeat("a", 64) + ".example/v1"
	if validOwnerClaims([]KubernetesOwnerReference{{APIVersion: longGroup, Kind: "CustomWorkload", Name: "custom-1"}}, []KubernetesObjectRef{}) {
		t.Fatal("owner API group with an oversized DNS label was accepted")
	}
}

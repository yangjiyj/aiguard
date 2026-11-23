package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const kubernetesSourceType = "kubernetes_cluster"
const kubernetesInstanceKey = "__kubernetes_native_identity__"

type kubernetesAssetRecord struct {
	resource    string
	assetType   string
	apiVersion  string
	kind        string
	uid         string
	name        string
	version     string
	contentHash string
	evidence    map[string]any
}

func projectKubernetesSnapshot(ctx context.Context, tx kubernetesSnapshotTx, tenant string, scope kubernetesRunScope, report KubernetesObservationReport, coverage []KubernetesResourceStatus) error {
	if err := lockUnifiedAssetTenantWrite(ctx, tx, tenant); err != nil {
		return err
	}
	sourceNamespace := kubernetesSourceNamespace(scope.RegistrationID, scope.NamespaceUID)
	if sourceNamespace == "" || len(sourceNamespace) > 255 || strings.ContainsAny(sourceNamespace, "\x1e\x1f") {
		return ErrKubernetesInvalid
	}
	records := buildKubernetesAssetRecords(scope, report.Snapshot, coverage)
	ownerIndex := make(map[string]kubernetesOwnerTarget, len(records))
	for _, record := range records {
		if record.resource == "namespaces" || record.resource == "pods-derived" || record.resource == "images" {
			continue
		}
		nativeID := kubernetesNativeID(record.apiVersion, record.kind, record.uid)
		ownerIndex[kubernetesOwnerKey(record.apiVersion, record.kind, record.uid)] = kubernetesOwnerTarget{nativeID: nativeID, name: record.name}
	}
	for i := range records {
		if records[i].assetType == "kubernetes_workload" || records[i].assetType == "kubernetes_pod" {
			records[i].evidence["hierarchy_owner_refs"] = kubernetesOwnerEvidence(records[i].evidence["raw_owner_references"], ownerIndex)
			delete(records[i].evidence, "raw_owner_references")
			records[i].evidence["ownership_semantics"] = "Kubernetes object hierarchy claims only; not a business owner or execution-control signal"
		}
		records[i].evidence["kubernetes_registration_id"] = scope.RegistrationID
		records[i].evidence["kubernetes_namespace_uid"] = scope.NamespaceUID
		records[i].evidence["kubernetes_run_id"] = report.RunID
		records[i].evidence["kubernetes_run_sequence"] = scope.Sequence
		records[i].evidence["kubernetes_report_id"] = report.ReportID
	}
	seenByResource := make(map[string]map[string]struct{})
	for _, record := range records {
		nativeID := kubernetesNativeID(record.apiVersion, record.kind, record.uid)
		if len(nativeID) > 512 || strings.ContainsAny(nativeID, "\x1f") || record.assetType == "" || record.name == "" {
			return ErrKubernetesInvalid
		}
		if seenByResource[record.resource] == nil {
			seenByResource[record.resource] = make(map[string]struct{})
		}
		seenByResource[record.resource][nativeID] = struct{}{}
		if err := upsertKubernetesUnifiedAsset(ctx, tx, tenant, sourceNamespace, nativeID, record, report); err != nil {
			return err
		}
	}
	for _, status := range coverage {
		if status.Status != "complete" {
			continue
		}
		kinds := kubernetesKindsForResource(status.Resource)
		if len(kinds) == 0 {
			continue
		}
		seen := make(map[string]struct{})
		for nativeID := range seenByResource[status.Resource] {
			seen[nativeID] = struct{}{}
		}
		if status.Resource == "pods" {
			for nativeID := range seenByResource["pods-derived"] {
				seen[nativeID] = struct{}{}
			}
		}
		if err := tombstoneMissingKubernetesAssets(ctx, tx, tenant, sourceNamespace, scope, report, status.Resource, kinds, seen); err != nil {
			return err
		}
	}
	return nil
}

func buildKubernetesAssetRecords(scope kubernetesRunScope, snapshot KubernetesDiscoverySnapshot, coverage []KubernetesResourceStatus) []kubernetesAssetRecord {
	statusByResource := make(map[string]string, len(coverage))
	for _, status := range coverage {
		statusByResource[status.Resource] = status.Status
	}
	result := make([]kubernetesAssetRecord, 0, len(snapshot.Workloads)+len(snapshot.Pods)+len(snapshot.Images)+1)
	if snapshot.Namespace.UID == scope.NamespaceUID && snapshot.Namespace.IdentityStatus == "uid" {
		result = append(result, kubernetesAssetRecord{resource: "namespaces", assetType: "kubernetes_namespace", apiVersion: "v1", kind: "Namespace",
			uid: scope.NamespaceUID, name: snapshot.Namespace.Name, evidence: map[string]any{"identity_basis": "registered_namespace_uid", "namespace_name": snapshot.Namespace.Name}})
	}
	for _, workload := range snapshot.Workloads {
		resource := resourceForKubernetesKind(workload.Kind)
		if !kubernetesStatusCanContain(statusByResource[resource]) || workload.NamespaceUID == "" || workload.NamespaceUID != scope.NamespaceUID {
			continue
		}
		evidence := map[string]any{
			"identity_basis": "api_group_kind_object_uid", "api_version": workload.APIVersion, "kind": workload.Kind, "object_uid": workload.UID,
			"namespace_uid": scope.NamespaceUID, "reported_identity_status": workload.IdentityStatus, "reported_ownership_status": workload.OwnershipStatus,
			"raw_owner_references": workload.OwnerReferences, "reported_generation": workload.Generation, "observed_generation": workload.ObservedGeneration,
			"desired_replicas": workload.DesiredReplicas, "ready_replicas": workload.ReadyReplicas, "active": workload.Active, "observed_pod_count": workload.ObservedPodCount,
			"creation_timestamp": workload.CreationTimestamp, "deletion_timestamp": workload.DeletionTimestamp,
		}
		result = append(result, kubernetesAssetRecord{resource: resource, assetType: "kubernetes_workload", apiVersion: workload.APIVersion, kind: workload.Kind,
			uid: workload.UID, name: workload.Name, version: kubernetesGenerationVersion(workload.Generation), evidence: evidence})
	}
	for _, pod := range snapshot.Pods {
		if !kubernetesStatusCanContain(statusByResource["pods"]) || pod.NamespaceUID == "" || pod.NamespaceUID != scope.NamespaceUID {
			continue
		}
		evidence := map[string]any{
			"identity_basis": "api_group_kind_object_uid", "api_version": "v1", "kind": "Pod", "object_uid": pod.UID,
			"namespace_uid": scope.NamespaceUID, "reported_identity_status": pod.IdentityStatus, "reported_ownership_status": pod.OwnershipStatus,
			"raw_owner_references": pod.OwnerReferences, "phase": pod.Phase, "service_account": pod.ServiceAccount,
			"creation_timestamp": pod.CreationTimestamp, "deletion_timestamp": pod.DeletionTimestamp,
		}
		result = append(result, kubernetesAssetRecord{resource: "pods", assetType: "kubernetes_pod", apiVersion: "v1", kind: "Pod", uid: pod.UID, name: pod.Name, version: pod.Phase, evidence: evidence})
		for _, container := range pod.Containers {
			containerUID := pod.UID + "/" + container.Class + "/" + container.Name
			containerEvidence := map[string]any{
				"identity_basis": "pod_uid_container_class_name", "parent_pod_native_id": kubernetesNativeID("v1", "Pod", pod.UID),
				"pod_uid": pod.UID, "container_name": container.Name, "container_class": container.Class,
				"declared_image_observed": container.DeclaredImage != "", "runtime_image_id_observed": container.RuntimeImageID != "",
				"reported_image_identity_basis": container.ImageIdentityBasis, "state": container.State, "state_reason": container.StateReason,
				"ready": container.Ready, "restart_count": container.RestartCount,
			}
			if imageKey, ok := containerKubernetesImageKey(container); ok {
				kind, uid := kubernetesImageIdentityNative(imageKey)
				containerEvidence["image_identity_native_id"] = kubernetesNativeID("image/v1", kind, uid)
				containerEvidence["image_identity_basis"] = imageKey.basis
				if imageKey.digest != "" {
					containerEvidence["image_digest"] = imageKey.digest
				}
				if imageKey.ref != "" {
					containerEvidence["declared_image"] = imageKey.ref
				}
			}
			result = append(result, kubernetesAssetRecord{resource: "pods-derived", assetType: "kubernetes_container", apiVersion: "container/v1", kind: "Container",
				uid: containerUID, name: pod.Name + "/" + container.Name, version: container.State, evidence: containerEvidence})
		}
	}
	if kubernetesStatusCanContain(statusByResource["pods"]) {
		result = append(result, buildKubernetesImageAssetRecords(snapshot, scope.NamespaceUID)...)
	}
	return result
}

func buildKubernetesImageAssetRecords(snapshot KubernetesDiscoverySnapshot, registeredNamespaceUID string) []kubernetesAssetRecord {
	seen := make(map[string]struct{})
	result := make([]kubernetesAssetRecord, 0)
	for _, pod := range snapshot.Pods {
		if pod.NamespaceUID == "" || pod.NamespaceUID != registeredNamespaceUID {
			continue
		}
		for _, container := range pod.Containers {
			imageKey, ok := containerKubernetesImageKey(container)
			if !ok {
				continue
			}
			if _, exists := seen[imageKey.key]; exists {
				continue
			}
			seen[imageKey.key] = struct{}{}
			kind, uid := kubernetesImageIdentityNative(imageKey)
			evidence := map[string]any{
				"identity_basis":     imageKey.basis,
				"source_observation": "pod_container_image_reference",
				"digest_identity":    imageKey.digest != "",
			}
			assetType := "kubernetes_image"
			name := imageKey.digest
			version := imageKey.digest
			contentHash := imageKey.digest
			if imageKey.ref != "" {
				assetType = "kubernetes_image_reference"
				name = imageKey.ref
				version = ""
				contentHash = ""
				evidence["declared_reference"] = imageKey.ref
				evidence["reference_is_mutable"] = true
			}
			result = append(result, kubernetesAssetRecord{resource: "images", assetType: assetType, apiVersion: "image/v1", kind: kind,
				uid: uid, name: name, version: version, contentHash: contentHash, evidence: evidence})
		}
	}
	return result
}

type kubernetesOwnerTarget struct {
	nativeID string
	name     string
}

func kubernetesOwnerEvidence(raw any, ownerIndex map[string]kubernetesOwnerTarget) []map[string]any {
	refs, ok := raw.([]KubernetesOwnerReference)
	if !ok || len(refs) == 0 {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(refs))
	for _, ref := range refs {
		row := map[string]any{"api_version": ref.APIVersion, "kind": ref.Kind, "name": ref.Name, "uid": ref.UID, "resolution": "unresolved_or_out_of_scope"}
		if ref.Controller != nil {
			row["controller"] = *ref.Controller
		}
		if ref.UID != "" {
			if owner, found := ownerIndex[kubernetesOwnerKey(ref.APIVersion, ref.Kind, ref.UID)]; found {
				row["resolution"] = "uid_match_in_snapshot"
				row["resolved_source_native_id"] = owner.nativeID
				if ref.Name != owner.name {
					row["name_display_mismatch"] = true
				}
			}
		}
		out = append(out, row)
	}
	return out
}

func kubernetesOwnerKey(apiVersion, kind, uid string) string {
	return apiVersion + "\x00" + kind + "\x00" + uid
}

func kubernetesSourceNamespace(registrationID, namespaceUID string) string {
	if registrationID == "" || namespaceUID == "" {
		return ""
	}
	return "k8s:" + registrationID + ":" + namespaceUID
}

func kubernetesNativeID(apiVersion, kind, uid string) string {
	return apiVersion + "\x1e" + kind + "\x1e" + uid
}

func kubernetesGenerationVersion(value int64) string {
	if value <= 0 {
		return ""
	}
	return strconv.FormatInt(value, 10)
}

func kubernetesKindsForResource(resource string) []string {
	switch resource {
	case "pods":
		return []string{"Pod", "Container"}
	case "images":
		return []string{"ImageDigest", "DeclaredImageReference"}
	case "deployments":
		return []string{"Deployment"}
	case "replicasets":
		return []string{"ReplicaSet"}
	case "statefulsets":
		return []string{"StatefulSet"}
	case "daemonsets":
		return []string{"DaemonSet"}
	case "jobs":
		return []string{"Job"}
	case "cronjobs":
		return []string{"CronJob"}
	default:
		return nil
	}
}

func upsertKubernetesUnifiedAsset(ctx context.Context, tx kubernetesSnapshotTx, tenant, sourceNamespace, nativeID string, record kubernetesAssetRecord, report KubernetesObservationReport) error {
	sourceRefID := stableUnifiedAssetID("uasr_", tenant, kubernetesSourceType, sourceNamespace, nativeID)
	defaultAssetID := stableUnifiedAssetID("uaa_", tenant, kubernetesSourceType, sourceNamespace, nativeID)
	identityKey := unifiedAssetIdentityKey(kubernetesSourceType, sourceNamespace, nativeID)
	evidence, err := json.Marshal(record.evidence)
	if err != nil {
		return err
	}
	sourceObservedAt := parsedKubernetesSourceTime(report.Snapshot.ObservedAt)
	// Aggregate display_name/last_seen are moved only by the freshness-guarded
	// UPDATE below, with the same observation-time rule as endpoint reports.
	_, err = tx.Exec(ctx, `INSERT INTO agent_unified_assets(id,tenant_id,asset_type,identity_key,display_name,first_seen,last_seen)
		VALUES($1,$2,$3,$4,$5,LEAST($6,clock_timestamp()),LEAST($6,clock_timestamp()))
		ON CONFLICT (tenant_id,asset_type,identity_key) DO NOTHING`,
		defaultAssetID, tenant, record.assetType, identityKey, record.name, sourceObservedAt)
	if err != nil {
		return fmt.Errorf("insert Kubernetes unified asset: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_asset_source_refs(id,tenant_id,asset_id,source_type,source_namespace,native_id)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,source_type,source_namespace,native_id) DO NOTHING`,
		sourceRefID, tenant, defaultAssetID, kubernetesSourceType, sourceNamespace, nativeID)
	if err != nil {
		return fmt.Errorf("insert Kubernetes source ref: %w", err)
	}
	var assetID string
	if err = tx.QueryRow(ctx, `SELECT asset_id FROM agent_asset_source_refs WHERE tenant_id=$1 AND source_type=$2 AND source_namespace=$3 AND native_id=$4 FOR SHARE`,
		tenant, kubernetesSourceType, sourceNamespace, nativeID).Scan(&assetID); err != nil {
		return err
	}
	var canonicalID string
	if err = tx.QueryRow(ctx, `SELECT COALESCE(merged_into_id,id) FROM agent_unified_assets WHERE tenant_id=$1 AND id=$2`, tenant, assetID).Scan(&canonicalID); err != nil {
		return err
	}
	assetID = canonicalID
	instanceID := stableUnifiedAssetID("uai_", tenant, sourceRefID, kubernetesInstanceKey)
	_, err = tx.Exec(ctx, `INSERT INTO agent_unified_asset_instances(
		id,tenant_id,asset_id,source_asset_id,source_ref_id,instance_key,endpoint_id,display_name,version,content_hash,
		present,scan_status,scan_decision,evidence,first_seen,last_observed_at,last_received_at)
		VALUES($1,$2,$3,$4,$5,$6,NULL,$7,$8,$9,true,'','',$10::jsonb,clock_timestamp(),clock_timestamp(),clock_timestamp())
		ON CONFLICT (tenant_id,asset_id,source_ref_id,instance_key) DO NOTHING`,
		instanceID, tenant, assetID, assetID, sourceRefID, kubernetesInstanceKey, record.name, record.version, record.contentHash, evidence)
	if err != nil {
		return fmt.Errorf("insert Kubernetes asset instance: %w", err)
	}
	var actualInstanceID string
	if err = tx.QueryRow(ctx, `SELECT id FROM agent_unified_asset_instances WHERE tenant_id=$1 AND asset_id=$2 AND source_ref_id=$3 AND instance_key=$4 FOR UPDATE`,
		tenant, assetID, sourceRefID, kubernetesInstanceKey).Scan(&actualInstanceID); err != nil {
		return err
	}
	eventID := "k8s-run:" + report.RunID
	observationID := stableUnifiedAssetID("uao_", tenant, sourceRefID, eventID)
	var receivedAt time.Time
	err = tx.QueryRow(ctx, `INSERT INTO agent_unified_asset_observations(
		id,tenant_id,asset_id,source_asset_id,instance_id,source_ref_id,source_event_id,provenance,
		source_occurred_at,received_at,display_name,version,content_hash,present,scan_status,scan_decision,evidence)
		VALUES($1,$2,$3,$4,$5,$6,$7,'authenticated_source',$8,clock_timestamp(),$9,$10,$11,true,'','',$12::jsonb)
		ON CONFLICT (tenant_id,source_ref_id,source_event_id) DO NOTHING RETURNING received_at`,
		observationID, tenant, assetID, assetID, actualInstanceID, sourceRefID, eventID, sourceObservedAt,
		record.name, record.version, record.contentHash, evidence).Scan(&receivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("append Kubernetes asset observation: %w", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_unified_asset_instances SET
		display_name=$3,version=$4,content_hash=$5,present=true,scan_status='',scan_decision='',evidence=$6::jsonb,
		last_observed_at=$7,last_received_at=$7
		WHERE tenant_id=$1 AND id=$2`, tenant, actualInstanceID, record.name, record.version, record.contentHash, evidence, receivedAt); err != nil {
		return err
	}
	observedAt := boundedAgentAssetObservedAt(sourceObservedAt, receivedAt)
	_, err = tx.Exec(ctx, `UPDATE agent_unified_assets SET
		display_name=CASE WHEN $3<>'' AND last_seen<=$4 THEN $3 ELSE display_name END,
		first_seen=LEAST(first_seen,$4),last_seen=GREATEST(last_seen,$4),updated_at=clock_timestamp()
		WHERE tenant_id=$1 AND id=$2`, tenant, assetID, record.name, observedAt)
	return err
}

func tombstoneMissingKubernetesAssets(ctx context.Context, tx kubernetesSnapshotTx, tenant, sourceNamespace string, scope kubernetesRunScope, report KubernetesObservationReport, resource string, kinds []string, seen map[string]struct{}) error {
	rows, err := tx.Query(ctx, `SELECT s.id,s.native_id,i.id,i.asset_id,i.display_name,i.version,i.content_hash,i.scan_status,i.scan_decision,i.evidence
		FROM agent_asset_source_refs s
		JOIN agent_unified_asset_instances i ON i.tenant_id=s.tenant_id AND i.source_ref_id=s.id
		WHERE s.tenant_id=$1 AND s.source_type=$2 AND s.source_namespace=$3 AND i.present=true
		  AND split_part(s.native_id,chr(30),2)=ANY($4::text[])
		ORDER BY s.native_id LIMIT $5`, tenant, kubernetesSourceType, sourceNamespace, kinds, maxKubernetesObjects+1)
	if err != nil {
		return err
	}
	type prior struct {
		sourceRef, nativeID, instanceID, assetID, name, version, hash, scanStatus, scanDecision string
		evidence                                                                                []byte
	}
	priorRows := make([]prior, 0)
	for rows.Next() {
		var p prior
		if err := rows.Scan(&p.sourceRef, &p.nativeID, &p.instanceID, &p.assetID, &p.name, &p.version, &p.hash, &p.scanStatus, &p.scanDecision, &p.evidence); err != nil {
			rows.Close()
			return err
		}
		priorRows = append(priorRows, p)
		if len(priorRows) > maxKubernetesObjects {
			rows.Close()
			return fmt.Errorf("%w: tombstone candidate limit exceeded for %s", ErrKubernetesInvalid, resource)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	observedAt := parsedKubernetesSourceTime(report.Snapshot.ObservedAt)
	receivedAt := scope.ReceivedAt
	aggregateObservedAt := boundedAgentAssetObservedAt(observedAt, receivedAt)
	eventID := "k8s-run:" + report.RunID
	for _, p := range priorRows {
		if _, exists := seen[p.nativeID]; exists {
			continue
		}
		evidence := map[string]any{"kubernetes_presence": "absent_from_complete_list", "kubernetes_registration_id": scope.RegistrationID,
			"kubernetes_namespace_uid": scope.NamespaceUID, "kubernetes_run_id": report.RunID, "kubernetes_run_sequence": scope.Sequence,
			"kubernetes_report_id": report.ReportID, "resource_kind": resource}
		encoded, _ := json.Marshal(evidence)
		if _, err := tx.Exec(ctx, `UPDATE agent_unified_asset_instances SET present=false,scan_status='',scan_decision='',evidence=$3::jsonb,last_observed_at=$4,last_received_at=$4
			WHERE tenant_id=$1 AND id=$2 AND present=true`, tenant, p.instanceID, encoded, receivedAt); err != nil {
			return err
		}
		observationID := stableUnifiedAssetID("uao_", tenant, p.sourceRef, eventID)
		_, err := tx.Exec(ctx, `INSERT INTO agent_unified_asset_observations(
			id,tenant_id,asset_id,source_asset_id,instance_id,source_ref_id,source_event_id,provenance,
			source_occurred_at,received_at,display_name,version,content_hash,present,scan_status,scan_decision,evidence)
			VALUES($1,$2,$3,$3,$4,$5,$6,'authenticated_source',$7,$8,$9,$10,$11,false,'','',$12::jsonb)
			ON CONFLICT (tenant_id,source_ref_id,source_event_id) DO NOTHING`,
			observationID, tenant, p.assetID, p.instanceID, p.sourceRef, eventID, observedAt, receivedAt, p.name, p.version, p.hash, encoded)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE agent_unified_assets SET last_seen=GREATEST(last_seen,$3),updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND id=$2`, tenant, p.assetID, aggregateObservedAt)
		if err != nil {
			return err
		}
	}
	return nil
}

func parsedKubernetesSourceTime(value string) (result time.Time) {
	result, _ = time.Parse(time.RFC3339Nano, value)
	if result.IsZero() {
		return time.Now().UTC()
	}
	return result
}

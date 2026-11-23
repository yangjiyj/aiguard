package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var kubernetesTrackedResources = []string{"pods", "deployments", "replicasets", "statefulsets", "daemonsets", "jobs", "cronjobs", "namespaces", "images"}

type KubernetesSnapshotRunRequest struct {
	RequestID string `json:"request_id"`
}

type KubernetesSnapshotRun struct {
	RunID          string    `json:"run_id"`
	RequestID      string    `json:"request_id"`
	RegistrationID string    `json:"registration_id"`
	ClusterID      string    `json:"cluster_id"`
	NamespaceName  string    `json:"namespace_name"`
	NamespaceUID   string    `json:"namespace_uid"`
	Sequence       int64     `json:"sequence"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type KubernetesSnapshotIngestResult struct {
	RunID            string `json:"run_id"`
	Sequence         int64  `json:"sequence"`
	ReportID         string `json:"report_id"`
	Duplicate        bool   `json:"duplicate"`
	ProjectionStatus string `json:"projection_status"`
}

func (r *AgentKubernetesAssetRepository) BeginSnapshotRun(ctx context.Context, endpoint *AgentEndpointContext, request KubernetesSnapshotRunRequest) (*KubernetesSnapshotRun, error) {
	if r == nil || r.db == nil || endpoint == nil || endpoint.TenantID == "" || endpoint.EndpointID == "" ||
		endpoint.AgentProduct != KubernetesCollectorProduct {
		return nil, ErrKubernetesUnauthorized
	}
	if _, err := uuid.Parse(request.RequestID); err != nil {
		return nil, ErrKubernetesInvalid
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var result KubernetesSnapshotRun
	var runID string
	var seq int64
	var active bool
	err = tx.QueryRow(ctx, `SELECT n.id,c.cluster_label,n.namespace_name,n.namespace_uid,n.active,n.next_run_sequence
		FROM agent_kubernetes_namespace_registrations n
		JOIN agent_kubernetes_clusters c ON c.tenant_id=n.tenant_id AND c.id=n.cluster_registration_id
		JOIN agent_endpoints e ON e.tenant_id=n.tenant_id AND e.id=n.endpoint_id
		WHERE n.tenant_id=$1 AND n.endpoint_id=$2 AND e.agent_product=$3 AND n.active
		ORDER BY n.created_at DESC,n.id
		LIMIT 1
		FOR UPDATE OF n`, endpoint.TenantID, endpoint.EndpointID, KubernetesCollectorProduct).
		Scan(&result.RegistrationID, &result.ClusterID, &result.NamespaceName, &result.NamespaceUID, &active, &seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrKubernetesUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, ErrKubernetesUnauthorized
	}
	err = tx.QueryRow(ctx, `SELECT id,sequence,expires_at FROM agent_kubernetes_snapshot_runs
		WHERE tenant_id=$1 AND namespace_registration_id=$2 AND request_id=$3`,
		endpoint.TenantID, result.RegistrationID, request.RequestID).Scan(&runID, &seq, &result.ExpiresAt)
	if err == nil {
		result.RunID, result.RequestID, result.Sequence = runID, request.RequestID, seq
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err := tx.QueryRow(ctx, `UPDATE agent_kubernetes_namespace_registrations
		SET next_run_sequence=next_run_sequence+1
		WHERE tenant_id=$1 AND id=$2 AND active=true RETURNING next_run_sequence`,
		endpoint.TenantID, result.RegistrationID).Scan(&seq); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrKubernetesUnauthorized
		}
		return nil, err
	}
	runID = uuid.NewString()
	err = tx.QueryRow(ctx, `INSERT INTO agent_kubernetes_snapshot_runs(
		id,tenant_id,namespace_registration_id,endpoint_id,request_id,sequence,issued_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,clock_timestamp(),clock_timestamp()+($7::bigint * interval '1 second'))
		RETURNING expires_at`, runID, endpoint.TenantID, result.RegistrationID, endpoint.EndpointID, request.RequestID, seq, int64(KubernetesSnapshotRunTTL.Seconds())).Scan(&result.ExpiresAt)
	if err != nil {
		if isKubernetesUniqueViolation(err) {
			return nil, ErrKubernetesConflict
		}
		return nil, err
	}
	for _, resource := range kubernetesTrackedResources {
		_, err = tx.Exec(ctx, `INSERT INTO agent_kubernetes_resource_watermarks(
			tenant_id,namespace_registration_id,namespace_uid,resource_kind,last_run_sequence,last_status,last_report_id,updated_at)
			VALUES($1,$2,$3,$4,$5,'pending','',clock_timestamp())
			ON CONFLICT (tenant_id,namespace_registration_id,namespace_uid,resource_kind)
			DO UPDATE SET last_run_sequence=EXCLUDED.last_run_sequence,last_status='pending',last_report_id='',updated_at=clock_timestamp()`,
			endpoint.TenantID, result.RegistrationID, result.NamespaceUID, resource, seq)
		if err != nil {
			return nil, err
		}
	}
	result.RunID, result.RequestID, result.Sequence = runID, request.RequestID, seq
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &result, nil
}

type kubernetesRunScope struct {
	RegistrationID string
	ClusterLabel   string
	NamespaceName  string
	NamespaceUID   string
	Sequence       int64
	LatestSequence int64
	ExpiresAt      time.Time
	ReceivedAt     time.Time
	Active         bool
}

func (r *AgentKubernetesAssetRepository) IngestSnapshot(ctx context.Context, endpoint *AgentEndpointContext, report KubernetesObservationReport) (*KubernetesSnapshotIngestResult, error) {
	if r == nil || r.db == nil || endpoint == nil || endpoint.TenantID == "" || endpoint.EndpointID == "" ||
		endpoint.AgentProduct != KubernetesCollectorProduct {
		return nil, ErrKubernetesUnauthorized
	}
	if err := report.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKubernetesInvalid, err.Error())
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var scope kubernetesRunScope
	err = tx.QueryRow(ctx, `SELECT n.id,c.cluster_label,n.namespace_name,n.namespace_uid,r.sequence,
		n.next_run_sequence,r.expires_at,clock_timestamp(),n.active
		FROM agent_kubernetes_snapshot_runs r
		JOIN agent_kubernetes_namespace_registrations n
		  ON n.tenant_id=r.tenant_id AND n.id=r.namespace_registration_id
		JOIN agent_kubernetes_clusters c ON c.tenant_id=n.tenant_id AND c.id=n.cluster_registration_id
		WHERE r.tenant_id=$1 AND r.id=$2 AND r.endpoint_id=$3 AND n.endpoint_id=$3
		FOR UPDATE OF r,n`, endpoint.TenantID, report.RunID, endpoint.EndpointID).
		Scan(&scope.RegistrationID, &scope.ClusterLabel, &scope.NamespaceName, &scope.NamespaceUID, &scope.Sequence,
			&scope.LatestSequence, &scope.ExpiresAt, &scope.ReceivedAt, &scope.Active)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrKubernetesUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if err := validateKubernetesSnapshotScope(report.Snapshot, scope); err != nil {
		return nil, err
	}
	var priorDigest, priorStatus string
	var priorSequence int64
	err = tx.QueryRow(ctx, `SELECT content_digest,projection_status,run_sequence
		FROM agent_kubernetes_snapshot_receipts
		WHERE tenant_id=$1 AND namespace_registration_id=$2 AND run_id=$3`,
		endpoint.TenantID, scope.RegistrationID, report.RunID).Scan(&priorDigest, &priorStatus, &priorSequence)
	if err == nil {
		if priorDigest != report.ReportID {
			return nil, ErrKubernetesConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &KubernetesSnapshotIngestResult{RunID: report.RunID, Sequence: priorSequence, ReportID: report.ReportID, Duplicate: true, ProjectionStatus: priorStatus}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	coverage, gaps, collectionStatus, exactScope := normalizedKubernetesCoverage(report.Snapshot, scope.NamespaceUID)
	projectionStatus := "projected"
	switch {
	case !exactScope:
		projectionStatus = "receipt_only_scope_unverified"
	case !scope.Active || scope.Sequence != scope.LatestSequence:
		projectionStatus = "history_only_stale"
	case scope.ReceivedAt.After(scope.ExpiresAt):
		projectionStatus = "history_only_expired"
	}
	if projectionStatus == "projected" {
		if err := projectKubernetesSnapshot(ctx, tx, endpoint.TenantID, scope, report, coverage); err != nil {
			return nil, err
		}
	}
	coverageJSON, err := json.Marshal(coverage)
	if err != nil {
		return nil, err
	}
	gapsJSON, err := json.Marshal(gaps)
	if err != nil {
		return nil, err
	}
	observedAt, _ := time.Parse(time.RFC3339Nano, report.Snapshot.ObservedAt)
	receiptID := uuid.NewString()
	_, err = tx.Exec(ctx, `INSERT INTO agent_kubernetes_snapshot_receipts(
		id,tenant_id,namespace_registration_id,run_id,run_sequence,report_id,content_digest,
		source_observed_at,received_at,collection_status,resource_coverage,observation_gaps,projection_status)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp(),$9,$10::jsonb,$11::jsonb,$12)`,
		receiptID, endpoint.TenantID, scope.RegistrationID, report.RunID, scope.Sequence, report.ReportID, report.ReportID,
		observedAt, collectionStatus, coverageJSON, gapsJSON, projectionStatus)
	if err != nil {
		if isKubernetesUniqueViolation(err) {
			return nil, ErrKubernetesConflict
		}
		return nil, err
	}
	if projectionStatus == "projected" {
		if err := updateKubernetesWatermarks(ctx, tx, endpoint.TenantID, scope, report.ReportID, coverage); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &KubernetesSnapshotIngestResult{RunID: report.RunID, Sequence: scope.Sequence, ReportID: report.ReportID, ProjectionStatus: projectionStatus}, nil
}

func validateKubernetesSnapshotScope(snapshot KubernetesDiscoverySnapshot, scope kubernetesRunScope) error {
	if snapshot.ClusterID != scope.ClusterLabel || snapshot.Namespace.Name != scope.NamespaceName {
		return ErrKubernetesUnauthorized
	}
	if snapshot.Namespace.UID != "" && snapshot.Namespace.UID != scope.NamespaceUID {
		if snapshot.Namespace.IdentityStatus != "uid_mismatch" || snapshot.Status != "partial" ||
			len(snapshot.Workloads) != 0 || len(snapshot.Pods) != 0 || len(snapshot.Images) != 0 {
			return ErrKubernetesConflict
		}
		for _, status := range snapshot.Resources {
			if status.Status == "complete" {
				return ErrKubernetesConflict
			}
		}
		return nil
	}
	for _, workload := range snapshot.Workloads {
		if workload.Namespace != scope.NamespaceName || (workload.NamespaceUID != "" && workload.NamespaceUID != scope.NamespaceUID) {
			return ErrKubernetesConflict
		}
	}
	for _, pod := range snapshot.Pods {
		if pod.Namespace != scope.NamespaceName || (pod.NamespaceUID != "" && pod.NamespaceUID != scope.NamespaceUID) {
			return ErrKubernetesConflict
		}
	}
	return nil
}

func normalizedKubernetesCoverage(snapshot KubernetesDiscoverySnapshot, registeredNamespaceUID string) ([]KubernetesResourceStatus, []KubernetesObservationGap, string, bool) {
	statuses := make(map[string]KubernetesResourceStatus, len(kubernetesTrackedResources))
	for _, status := range snapshot.Resources {
		statuses[status.Resource] = status
	}
	for _, resource := range kubernetesTrackedResources {
		if _, ok := statuses[resource]; !ok {
			statuses[resource] = KubernetesResourceStatus{Resource: resource, Status: "partial"}
		}
	}
	gaps := append([]KubernetesObservationGap{}, snapshot.Gaps...)
	exactScope := snapshot.Namespace.IdentityStatus == "uid" && snapshot.Namespace.UID != "" && snapshot.Namespace.UID == registeredNamespaceUID
	if exactScope {
		statuses["namespaces"] = KubernetesResourceStatus{Resource: "namespaces", Status: "complete", Pages: 1, ObjectsObserved: 1}
	} else {
		statuses["namespaces"] = KubernetesResourceStatus{Resource: "namespaces", Status: "partial"}
		gaps = append(gaps, KubernetesObservationGap{Resource: "namespaces", Reason: "registered_namespace_uid_not_verified"})
		for resource, status := range statuses {
			if resource != "namespaces" && status.Status == "complete" {
				status.Status = "partial"
				statuses[resource] = status
			}
		}
	}

	counts := make(map[string]int)
	counts["pods"] = len(snapshot.Pods)
	objectNamespaceUIDMissing := map[string]bool{}
	for _, pod := range snapshot.Pods {
		if pod.NamespaceUID == "" {
			objectNamespaceUIDMissing["pods"] = true
		}
	}
	for _, workload := range snapshot.Workloads {
		resource := resourceForKubernetesKind(workload.Kind)
		counts[resource]++
		if workload.NamespaceUID == "" {
			objectNamespaceUIDMissing[resource] = true
		}
	}
	collectionStatus := "complete"
	for resource, status := range statuses {
		if resource == "namespaces" || resource == "images" {
			continue
		}
		if status.Status == "complete" && hasKubernetesResourceGap(gaps, resource) {
			status.Status = "partial"
			statuses[resource] = status
			gaps = append(gaps, KubernetesObservationGap{Resource: resource, Reason: "resource_gap_prevents_complete_list"})
		}
		if status.Status == "complete" && status.Pages < 1 {
			status.Status = "partial"
			statuses[resource] = status
			gaps = append(gaps, KubernetesObservationGap{Resource: resource, Reason: "complete_list_has_zero_pages"})
		}
		if status.Status == "complete" && status.ObjectsObserved != counts[resource] {
			status.Status = "partial"
			statuses[resource] = status
			gaps = append(gaps, KubernetesObservationGap{Resource: resource, Reason: "complete_list_object_count_mismatch"})
		}
		if status.Status == "complete" && objectNamespaceUIDMissing[resource] {
			status.Status = "partial"
			statuses[resource] = status
			gaps = append(gaps, KubernetesObservationGap{Resource: resource, Reason: "object_namespace_uid_missing"})
		}
		if status.Status != "complete" {
			collectionStatus = "partial"
		}
	}

	imageStatus, imageGap := deriveKubernetesImageCoverage(snapshot, statuses["pods"].Status == "complete")
	if imageStatus.Status == "complete" && hasKubernetesResourceGap(gaps, "images") {
		imageStatus.Status = "partial"
		imageGap = "resource_gap_prevents_complete_list"
	}
	statuses["images"] = imageStatus
	if imageGap != "" {
		gaps = append(gaps, KubernetesObservationGap{Resource: "images", Reason: imageGap})
		collectionStatus = "partial"
	}
	if statuses["images"].Status != "complete" {
		collectionStatus = "partial"
	}
	if !exactScope || len(gaps) > 0 || snapshot.Status != "complete" {
		collectionStatus = "partial"
	}
	result := make([]KubernetesResourceStatus, 0, len(statuses))
	for _, resource := range kubernetesTrackedResources {
		result = append(result, statuses[resource])
	}
	return result, gaps, collectionStatus, exactScope
}
func hasKubernetesResourceGap(gaps []KubernetesObservationGap, resource string) bool {
	for _, gap := range gaps {
		if gap.Resource == resource {
			return true
		}
	}
	return false
}

func updateKubernetesWatermarks(ctx context.Context, tx kubernetesSnapshotTx, tenant string, scope kubernetesRunScope, reportID string, coverage []KubernetesResourceStatus) error {
	for _, status := range coverage {
		_, err := tx.Exec(ctx, `INSERT INTO agent_kubernetes_resource_watermarks(
			tenant_id,namespace_registration_id,namespace_uid,resource_kind,last_run_sequence,last_status,last_report_id,last_complete_sequence,last_complete_at,updated_at)
			VALUES($1,$2,$3,$4,$5::bigint,$6,$7,CASE WHEN $6='complete' THEN $5::bigint ELSE 0::bigint END,
				CASE WHEN $6='complete' THEN clock_timestamp() ELSE NULL END,clock_timestamp())
			ON CONFLICT (tenant_id,namespace_registration_id,namespace_uid,resource_kind)
			DO UPDATE SET last_run_sequence=EXCLUDED.last_run_sequence,last_status=EXCLUDED.last_status,
				last_report_id=EXCLUDED.last_report_id,
				last_complete_sequence=CASE WHEN EXCLUDED.last_status='complete' THEN EXCLUDED.last_run_sequence ELSE agent_kubernetes_resource_watermarks.last_complete_sequence END,
				last_complete_at=CASE WHEN EXCLUDED.last_status='complete' THEN clock_timestamp() ELSE agent_kubernetes_resource_watermarks.last_complete_at END,
				updated_at=clock_timestamp()`,
			tenant, scope.RegistrationID, scope.NamespaceUID, status.Resource, scope.Sequence, status.Status, reportID)
		if err != nil {
			return err
		}
	}
	return nil
}

type kubernetesSnapshotTx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

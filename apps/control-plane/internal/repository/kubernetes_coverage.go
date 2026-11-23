package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type KubernetesClusterCoverage struct {
	ClusterID    string                        `json:"cluster_registration_id"`
	ClusterLabel string                        `json:"cluster_label"`
	Namespaces   []KubernetesNamespaceCoverage `json:"namespaces"`
}

type KubernetesNamespaceCoverage struct {
	RegistrationID         string                       `json:"namespace_registration_id"`
	EndpointID             string                       `json:"endpoint_id"`
	NamespaceName          string                       `json:"namespace_name"`
	NamespaceUID           string                       `json:"namespace_uid"`
	Active                 bool                         `json:"active"`
	LatestSequence         int64                        `json:"latest_sequence"`
	LatestIssuedAt         *time.Time                   `json:"latest_issued_at,omitempty"`
	LatestExpiresAt        *time.Time                   `json:"latest_expires_at,omitempty"`
	LatestRunStatus        string                       `json:"latest_run_status"`
	LatestProjectionStatus string                       `json:"latest_projection_status,omitempty"`
	Resources              []KubernetesResourceCoverage `json:"resources"`
}

type KubernetesResourceCoverage struct {
	Resource             string     `json:"resource"`
	Status               string     `json:"status"`
	LastRunSequence      int64      `json:"last_run_sequence"`
	LastCompleteSequence int64      `json:"last_complete_sequence"`
	LastCompleteAt       *time.Time `json:"last_complete_at,omitempty"`
	LastReportID         string     `json:"last_report_id,omitempty"`
	FactsState           string     `json:"facts_state"`
}

func (r *AgentKubernetesAssetRepository) GetCoverage(ctx context.Context, tenant, clusterID string) (*KubernetesClusterCoverage, error) {
	var result KubernetesClusterCoverage
	if err := r.db.QueryRow(ctx, `SELECT id,cluster_label FROM agent_kubernetes_clusters WHERE tenant_id=$1 AND id=$2`, tenant, clusterID).Scan(&result.ClusterID, &result.ClusterLabel); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrKubernetesNotFound
		}
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT n.id,n.endpoint_id,n.namespace_name,n.namespace_uid,n.active,
		lr.sequence,lr.issued_at,lr.expires_at,COALESCE(rr.projection_status,''),COALESCE(lr.expires_at < clock_timestamp(),false)
		FROM agent_kubernetes_namespace_registrations n
		LEFT JOIN LATERAL (
			SELECT id,sequence,issued_at,expires_at FROM agent_kubernetes_snapshot_runs
			WHERE tenant_id=n.tenant_id AND namespace_registration_id=n.id
			ORDER BY sequence DESC LIMIT 1
		) lr ON true
		LEFT JOIN agent_kubernetes_snapshot_receipts rr
			ON rr.tenant_id=n.tenant_id AND rr.namespace_registration_id=n.id AND rr.run_id=lr.id
		WHERE n.tenant_id=$1 AND n.cluster_registration_id=$2
		ORDER BY n.created_at,n.id`, tenant, clusterID)
	if err != nil {
		return nil, err
	}
	type namespaceRow struct {
		value           KubernetesNamespaceCoverage
		issued, expires *time.Time
		projection      string
		expired         bool
	}
	namespaces := make([]namespaceRow, 0)
	for rows.Next() {
		var n namespaceRow
		var sequence *int64
		if err := rows.Scan(&n.value.RegistrationID, &n.value.EndpointID, &n.value.NamespaceName, &n.value.NamespaceUID, &n.value.Active,
			&sequence, &n.issued, &n.expires, &n.projection, &n.expired); err != nil {
			rows.Close()
			return nil, err
		}
		if sequence != nil {
			n.value.LatestSequence = *sequence
		}
		n.value.LatestIssuedAt = n.issued
		n.value.LatestExpiresAt = n.expires
		n.value.Resources = []KubernetesResourceCoverage{}
		namespaces = append(namespaces, n)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for i := range namespaces {
		n := &namespaces[i]
		if n.value.LatestSequence == 0 {
			n.value.LatestRunStatus = "never_run"
		} else if n.projection != "" {
			n.value.LatestRunStatus = "submitted"
			n.value.LatestProjectionStatus = n.projection
		} else if n.expired {
			n.value.LatestRunStatus = "expired"
		} else {
			n.value.LatestRunStatus = "pending"
		}
		watermarks, err := r.db.Query(ctx, `SELECT resource_kind,last_status,last_run_sequence,last_complete_sequence,last_complete_at,last_report_id
			FROM agent_kubernetes_resource_watermarks WHERE tenant_id=$1 AND namespace_registration_id=$2 AND namespace_uid=$3
			ORDER BY resource_kind`, tenant, n.value.RegistrationID, n.value.NamespaceUID)
		if err != nil {
			return nil, err
		}
		for watermarks.Next() {
			var value KubernetesResourceCoverage
			if err := watermarks.Scan(&value.Resource, &value.Status, &value.LastRunSequence, &value.LastCompleteSequence, &value.LastCompleteAt, &value.LastReportID); err != nil {
				watermarks.Close()
				return nil, err
			}
			switch {
			case value.Status == "complete" && value.LastRunSequence == n.value.LatestSequence:
				value.FactsState = "current_complete"
			case value.Status == "pending":
				value.FactsState = "last_known_pending"
			case value.Status == "partial" || value.Status == "forbidden" || value.Status == "limited" || value.Status == "failed":
				value.FactsState = "last_known_partial"
			default:
				value.FactsState = "last_known"
			}
			n.value.Resources = append(n.value.Resources, value)
		}
		if err := watermarks.Err(); err != nil {
			watermarks.Close()
			return nil, err
		}
		watermarks.Close()
		result.Namespaces = append(result.Namespaces, n.value)
	}
	if result.Namespaces == nil {
		result.Namespaces = []KubernetesNamespaceCoverage{}
	}
	return &result, nil
}

package repository

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrKubernetesInvalid      = errors.New("invalid Kubernetes ingest request")
	ErrKubernetesUnauthorized = errors.New("Kubernetes collector is not registered for this scope")
	ErrKubernetesConflict     = errors.New("Kubernetes registration or report conflicts with existing state")
	ErrKubernetesNotFound     = errors.New("Kubernetes registration not found")
)

var kubernetesClusterLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type AgentKubernetesAssetRepository struct{ db *pgxpool.Pool }

func NewAgentKubernetesAssetRepository(db *pgxpool.Pool) *AgentKubernetesAssetRepository {
	return &AgentKubernetesAssetRepository{db: db}
}

type KubernetesClusterCreate struct {
	DisplayName  string
	ClusterLabel string
}

type KubernetesClusterRegistration struct {
	ID           string                                   `json:"id"`
	DisplayName  string                                   `json:"display_name"`
	ClusterLabel string                                   `json:"cluster_label"`
	CreatedAt    time.Time                                `json:"created_at"`
	Namespaces   []KubernetesNamespaceRegistrationSummary `json:"namespaces"`
}

type KubernetesNamespaceRegister struct {
	EndpointID string `json:"endpoint_id"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

type KubernetesNamespaceRegistrationSummary struct {
	ID         string    `json:"id"`
	EndpointID string    `json:"endpoint_id"`
	Name       string    `json:"name"`
	UID        string    `json:"uid"`
	Active     bool      `json:"active"`
	CreatedAt  time.Time `json:"created_at"`
}

func (r *AgentKubernetesAssetRepository) CreateCluster(ctx context.Context, tenant, actor string, req KubernetesClusterCreate) (*KubernetesClusterRegistration, error) {
	if r == nil || r.db == nil || strings.TrimSpace(tenant) == "" || strings.TrimSpace(actor) == "" ||
		len(req.DisplayName) < 1 || len(req.DisplayName) > 128 || strings.TrimSpace(req.DisplayName) != req.DisplayName ||
		!safeKubernetesText(req.DisplayName, 128) || !kubernetesClusterLabelPattern.MatchString(req.ClusterLabel) {
		return nil, ErrKubernetesInvalid
	}
	id := uuid.NewString()
	var created time.Time
	err := r.db.QueryRow(ctx, `INSERT INTO agent_kubernetes_clusters(id,tenant_id,display_name,cluster_label,created_by)
		VALUES($1,$2,$3,$4,$5) RETURNING created_at`, id, tenant, req.DisplayName, req.ClusterLabel, actor).Scan(&created)
	if err != nil {
		if isKubernetesUniqueViolation(err) {
			return nil, ErrKubernetesConflict
		}
		return nil, err
	}
	return &KubernetesClusterRegistration{ID: id, DisplayName: req.DisplayName, ClusterLabel: req.ClusterLabel, CreatedAt: created, Namespaces: []KubernetesNamespaceRegistrationSummary{}}, nil
}

func (r *AgentKubernetesAssetRepository) RegisterNamespace(ctx context.Context, tenant, actor, clusterID string, req KubernetesNamespaceRegister) (*KubernetesNamespaceRegistrationSummary, error) {
	if r == nil || r.db == nil || strings.TrimSpace(tenant) == "" || strings.TrimSpace(actor) == "" ||
		!validKubernetesIdentifier(req.EndpointID, 128) || !kubernetesNamespacePattern.MatchString(req.Name) ||
		!kubernetesObjectUIDPattern.MatchString(req.UID) {
		return nil, ErrKubernetesInvalid
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM agent_kubernetes_clusters WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, clusterID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrKubernetesNotFound
		}
		return nil, err
	}
	var product, status string
	if err := tx.QueryRow(ctx, `SELECT agent_product,status FROM agent_endpoints WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, req.EndpointID).Scan(&product, &status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrKubernetesNotFound
		}
		return nil, err
	}
	if product != KubernetesCollectorProduct || (status != "active" && status != "stale") {
		return nil, ErrKubernetesUnauthorized
	}
	id := uuid.NewString()
	var created time.Time
	err = tx.QueryRow(ctx, `INSERT INTO agent_kubernetes_namespace_registrations(
		id,tenant_id,cluster_registration_id,endpoint_id,namespace_name,namespace_uid,created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
		id, tenant, clusterID, req.EndpointID, req.Name, req.UID, actor).Scan(&created)
	if err != nil {
		if isKubernetesUniqueViolation(err) {
			return nil, ErrKubernetesConflict
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &KubernetesNamespaceRegistrationSummary{ID: id, EndpointID: req.EndpointID, Name: req.Name, UID: req.UID, Active: true, CreatedAt: created}, nil
}

func (r *AgentKubernetesAssetRepository) ListClusters(ctx context.Context, tenant string) ([]KubernetesClusterRegistration, error) {
	rows, err := r.db.Query(ctx, `SELECT c.id,c.display_name,c.cluster_label,c.created_at,
		n.id,n.endpoint_id,n.namespace_name,n.namespace_uid,n.active,n.created_at
		FROM agent_kubernetes_clusters c
		LEFT JOIN agent_kubernetes_namespace_registrations n
		  ON n.tenant_id=c.tenant_id AND n.cluster_registration_id=c.id
		WHERE c.tenant_id=$1
		ORDER BY c.created_at DESC,c.id,n.created_at,n.id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]KubernetesClusterRegistration, 0)
	index := make(map[string]int)
	for rows.Next() {
		var cluster KubernetesClusterRegistration
		var namespaceID, endpointID, namespaceName, namespaceUID *string
		var namespaceActive *bool
		var namespaceCreated *time.Time
		if err := rows.Scan(&cluster.ID, &cluster.DisplayName, &cluster.ClusterLabel, &cluster.CreatedAt,
			&namespaceID, &endpointID, &namespaceName, &namespaceUID, &namespaceActive, &namespaceCreated); err != nil {
			return nil, err
		}
		i, ok := index[cluster.ID]
		if !ok {
			cluster.Namespaces = []KubernetesNamespaceRegistrationSummary{}
			result = append(result, cluster)
			i = len(result) - 1
			index[cluster.ID] = i
		}
		if namespaceID != nil {
			result[i].Namespaces = append(result[i].Namespaces, KubernetesNamespaceRegistrationSummary{
				ID: *namespaceID, EndpointID: *endpointID, Name: *namespaceName, UID: *namespaceUID, Active: *namespaceActive, CreatedAt: *namespaceCreated,
			})
		}
	}
	return result, rows.Err()
}

func (r *AgentKubernetesAssetRepository) RevokeNamespace(ctx context.Context, tenant, actor, registrationID string) (bool, error) {
	if strings.TrimSpace(actor) == "" || !validKubernetesIdentifier(registrationID, 128) {
		return false, ErrKubernetesInvalid
	}
	tag, err := r.db.Exec(ctx, `UPDATE agent_kubernetes_namespace_registrations
		SET active=false,revoked_by=CASE WHEN active THEN $3 ELSE revoked_by END,
		    revoked_at=CASE WHEN active THEN clock_timestamp() ELSE revoked_at END
		WHERE tenant_id=$1 AND id=$2`, tenant, registrationID, actor)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func isKubernetesUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (r *AgentKubernetesAssetRepository) String() string {
	return fmt.Sprintf("AgentKubernetesAssetRepository(%t)", r != nil && r.db != nil)
}

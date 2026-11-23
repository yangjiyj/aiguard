package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentSession represents an agent session record
type AgentSession struct {
	ID             string
	TenantID       string
	ProjectID      string
	UserID         string
	SessionID      string
	AgentType      string
	WorkspaceID    string
	ClientName     string
	ClientVersion  string
	FirstRequestAt time.Time
	LastRequestAt  time.Time
	RequestCount   int
	RiskScore      int
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AgentSessionRepository handles agent session database operations
type AgentSessionRepository struct {
	db *pgxpool.Pool
}

// NewAgentSessionRepository creates a new agent session repository
func NewAgentSessionRepository(db *pgxpool.Pool) *AgentSessionRepository {
	return &AgentSessionRepository{db: db}
}

// scanAgentSession scans a row into an AgentSession, handling nullable columns
func scanAgentSession(row pgx.Row) (*AgentSession, error) {
	var s AgentSession
	var projectID, userID, agentType, workspaceID, clientName, clientVersion sql.NullString
	var firstRequest, lastRequest, createdAt, updatedAt sql.NullTime

	err := row.Scan(
		&s.ID, &s.TenantID, &projectID, &userID, &s.SessionID,
		&agentType, &workspaceID, &clientName, &clientVersion,
		&firstRequest, &lastRequest, &s.RequestCount, &s.RiskScore,
		&s.Status, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	s.ProjectID = projectID.String
	s.UserID = userID.String
	s.AgentType = agentType.String
	s.WorkspaceID = workspaceID.String
	s.ClientName = clientName.String
	s.ClientVersion = clientVersion.String
	if firstRequest.Valid {
		s.FirstRequestAt = firstRequest.Time
	}
	if lastRequest.Valid {
		s.LastRequestAt = lastRequest.Time
	}
	if createdAt.Valid {
		s.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		s.UpdatedAt = updatedAt.Time
	}

	return &s, nil
}

// scanAgentSessionFromRows scans from pgx.Rows (same logic as scanAgentSession)
func scanAgentSessionFromRows(rows pgx.Rows) (*AgentSession, error) {
	var s AgentSession
	var projectID, userID, agentType, workspaceID, clientName, clientVersion sql.NullString
	var firstRequest, lastRequest, createdAt, updatedAt sql.NullTime

	err := rows.Scan(
		&s.ID, &s.TenantID, &projectID, &userID, &s.SessionID,
		&agentType, &workspaceID, &clientName, &clientVersion,
		&firstRequest, &lastRequest, &s.RequestCount, &s.RiskScore,
		&s.Status, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	s.ProjectID = projectID.String
	s.UserID = userID.String
	s.AgentType = agentType.String
	s.WorkspaceID = workspaceID.String
	s.ClientName = clientName.String
	s.ClientVersion = clientVersion.String
	if firstRequest.Valid {
		s.FirstRequestAt = firstRequest.Time
	}
	if lastRequest.Valid {
		s.LastRequestAt = lastRequest.Time
	}
	if createdAt.Valid {
		s.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		s.UpdatedAt = updatedAt.Time
	}

	return &s, nil
}

// List returns all agent sessions for a tenant with pagination
func (r *AgentSessionRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]AgentSession, int, error) {
	tenantWhere := ""
	queryArgs := []any{limit, offset}
	countArgs := []any{}
	if strings.TrimSpace(tenantID) != "" {
		tenantWhere = "WHERE tenant_id = $1"
		queryArgs = []any{tenantID, limit, offset}
		countArgs = []any{tenantID}
	}
	query := fmt.Sprintf(`
		SELECT id, tenant_id, project_id, user_id, session_id, agent_type, workspace_id,
		       client_name, client_version, first_request_at, last_request_at,
		       COALESCE(request_count, 0), COALESCE(risk_score, 0), status, created_at, updated_at
		FROM agent_sessions
		%s
		ORDER BY last_request_at DESC
		LIMIT $%d OFFSET $%d
	`, tenantWhere, len(queryArgs)-1, len(queryArgs))

	rows, err := r.db.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	sessions := []AgentSession{}
	for rows.Next() {
		s, err := scanAgentSessionFromRows(rows)
		if err != nil {
			// Return error explicitly - do NOT silently continue
			// Silent continue causes data=[] with total>0, misleading API consumers
			return nil, 0, fmt.Errorf("failed to scan agent session row: %w", err)
		}
		sessions = append(sessions, *s)
	}

	// Check for row iteration errors (connection issues, etc.)
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("row iteration error: %w", err)
	}

	// Get total count
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM agent_sessions %s`, tenantWhere)
	var total int
	err = r.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get total count: %w", err)
	}

	return sessions, total, nil
}

// GetBySessionID returns an agent session by session_id within tenant scope
func (r *AgentSessionRepository) GetBySessionID(ctx context.Context, tenantID string, sessionID string) (*AgentSession, error) {
	query := `
		SELECT id, tenant_id, project_id, user_id, session_id, agent_type, workspace_id,
		       client_name, client_version, first_request_at, last_request_at,
		       COALESCE(request_count, 0), COALESCE(risk_score, 0), status, created_at, updated_at
		FROM agent_sessions
		WHERE tenant_id = $1 AND session_id = $2
	`

	return scanAgentSession(r.db.QueryRow(ctx, query, tenantID, sessionID))
}

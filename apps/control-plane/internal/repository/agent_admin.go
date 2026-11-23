package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const agentAdminDefaultPageSize = 50

type AgentAdminRepository struct{ db *pgxpool.Pool }

func NewAgentAdminRepository(db *pgxpool.Pool) *AgentAdminRepository {
	return &AgentAdminRepository{db: db}
}

type AgentAdminPage struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

type AgentOverview struct {
	EndpointsTotal   int `json:"endpoints_total"`
	EndpointsActive  int `json:"endpoints_active"`
	EndpointsStale   int `json:"endpoints_stale"`
	EndpointsRevoked int `json:"endpoints_revoked"`
	SessionsActive   int `json:"sessions_active"`
	Events24H        int `json:"events_24h"`
	AssetsPresent    int `json:"assets_present"`
}

type AgentAdminEndpoint struct {
	ID                string          `json:"id"`
	MachineID         string          `json:"machine_id"`
	Hostname          string          `json:"hostname"`
	OS                string          `json:"os"`
	OSVersion         string          `json:"os_version"`
	Arch              string          `json:"arch"`
	OSUser            string          `json:"os_user"`
	Product           string          `json:"product"`
	AgentVersion      string          `json:"agent_version"`
	AdapterName       string          `json:"adapter_name"`
	AdapterVersion    string          `json:"adapter_version"`
	HookdVersion      string          `json:"hookd_version"`
	Capabilities      json.RawMessage `json:"capabilities"`
	TokenPrefix       string          `json:"token_prefix"`
	Mode              *string         `json:"mode"`
	CaptureLevel      string          `json:"capture_level"`
	Status            string          `json:"status"`
	LastHeartbeatAt   *time.Time      `json:"last_heartbeat_at"`
	LastEventAt       *time.Time      `json:"last_event_at"`
	LastPolicyVersion int64           `json:"last_policy_version"`
	LastConfigVersion int64           `json:"last_config_version"`
	Health            json.RawMessage `json:"health"`
	// ControlBoundary is health.control_boundary as reported by hookd
	// heartbeats (schema jjdguard-control-boundary/v1). It is null when the
	// endpoint's hookd predates the report; consumers must show "not reported".
	ControlBoundary json.RawMessage `json:"control_boundary"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// ControlBoundaryFromHealth surfaces health.control_boundary only when it is a
// JSON object; anything else (absent, null, malformed) is reported as null.
func ControlBoundaryFromHealth(health json.RawMessage) json.RawMessage {
	var fields map[string]json.RawMessage
	if len(health) == 0 || json.Unmarshal(health, &fields) != nil {
		return nil
	}
	raw := fields["control_boundary"]
	var object map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &object) != nil || object == nil {
		return nil
	}
	return raw
}

type AgentEndpointFilter struct {
	Product, Status, OS, Mode, Query string
	Stale                            *bool
	Page, PageSize                   int
}

type AgentEndpointPage struct {
	Items []AgentAdminEndpoint `json:"items"`
	AgentAdminPage
}

type AgentEndpointModeUpdate struct {
	ModeSet         bool
	Mode            *string
	CaptureLevelSet bool
	CaptureLevel    *string
}

type AgentEnrollmentToken struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	TokenPrefix     string          `json:"token_prefix"`
	DefaultMode     string          `json:"default_mode"`
	AllowedProducts json.RawMessage `json:"allowed_products"`
	MaxEndpoints    int             `json:"max_endpoints"`
	Enabled         bool            `json:"enabled"`
	ExpiresAt       *time.Time      `json:"expires_at"`
	RevokedAt       *time.Time      `json:"revoked_at"`
	LastUsedAt      *time.Time      `json:"last_used_at"`
	CreatedBy       string          `json:"created_by"`
	CreatedAt       time.Time       `json:"created_at"`
}

type AgentEnrollmentTokenCreate struct {
	Name, DefaultMode string
	AllowedProducts   []string
	MaxEndpoints      int
	ExpiresAt         *time.Time
	CreatedBy         string
}

type AgentEnrollmentTokenCreated struct {
	AgentEnrollmentToken
	Token string `json:"token"`
}

type AgentEnrollmentTokenFilter struct {
	Enabled        *bool
	Page, PageSize int
}

type AgentEnrollmentTokenPage struct {
	Items []AgentEnrollmentToken `json:"items"`
	AgentAdminPage
}

type AgentAdminSession struct {
	ID                  string     `json:"id"`
	ProjectID           *string    `json:"project_id"`
	UserID              *string    `json:"user_id"`
	SessionID           string     `json:"session_id"`
	EndpointID          *string    `json:"endpoint_id"`
	Source              string     `json:"source"`
	ParentSessionID     *string    `json:"parent_session_id"`
	AgentID             *string    `json:"agent_id"`
	AgentRole           *string    `json:"agent_role"`
	Product             *string    `json:"product"`
	Model               *string    `json:"model"`
	AgentType           *string    `json:"agent_type"`
	WorkspaceID         *string    `json:"workspace_id"`
	CWDHash             *string    `json:"cwd_hash"`
	ProjectLabel        *string    `json:"project_label"`
	PermissionMode      *string    `json:"permission_mode"`
	Status              string     `json:"status"`
	RiskScore           int        `json:"risk_score"`
	StartedAt           *time.Time `json:"started_at"`
	EndedAt             *time.Time `json:"ended_at"`
	FirstRequestAt      *time.Time `json:"first_request_at"`
	LastRequestAt       *time.Time `json:"last_request_at"`
	TurnCount           int        `json:"turn_count"`
	EventCount          int        `json:"event_count"`
	ToolCallCount       int        `json:"tool_call_count"`
	BlockedCount        int        `json:"blocked_count"`
	WouldBlockCount     int        `json:"would_block_count"`
	GatewayRequestCount int        `json:"gateway_request_count"`
}

type AgentSessionFilter struct {
	EndpointID, Product, Status, Query string
	From, To                           *time.Time
	MinRisk                            *int
	Page, PageSize                     int
}

type AgentSessionPage struct {
	Items []AgentAdminSession `json:"items"`
	AgentAdminPage
}

type AgentTurn struct {
	ID               string     `json:"id"`
	PromptID         string     `json:"prompt_id"`
	Seq              int        `json:"seq"`
	StartedAt        *time.Time `json:"started_at"`
	EndedAt          *time.Time `json:"ended_at"`
	StopReason       string     `json:"stop_reason"`
	PromptHash       string     `json:"prompt_hash"`
	PromptPreview    string     `json:"prompt_preview,omitempty"`
	AssistantPreview string     `json:"assistant_preview,omitempty"`
	ToolCallCount    int        `json:"tool_call_count"`
	BlockedCount     int        `json:"blocked_count"`
}

type AgentAdminEvent struct {
	ID             string          `json:"id"`
	EndpointID     string          `json:"endpoint_id"`
	SessionID      string          `json:"session_id"`
	PromptID       string          `json:"prompt_id"`
	ToolUseID      string          `json:"tool_use_id"`
	EventType      string          `json:"event_type"`
	OccurredAt     time.Time       `json:"occurred_at"`
	ReceivedAt     time.Time       `json:"received_at"`
	ToolName       string          `json:"tool_name"`
	ToolType       string          `json:"tool_type"`
	MCPServer      string          `json:"mcp_server"`
	Payload        json.RawMessage `json:"payload"`
	LocalDecision  json.RawMessage `json:"local_decision"`
	ServerDecision json.RawMessage `json:"server_decision"`
	ToolCallLogID  string          `json:"tool_call_log_id,omitempty"`
	Severity       string          `json:"severity"`
}

type AgentEventFilter struct {
	SessionID, EndpointID, EventType string
	From, To                         *time.Time
	Page, PageSize                   int
}

type AgentEventPage struct {
	Items []AgentAdminEvent `json:"items"`
	AgentAdminPage
}

type AgentToolCall struct {
	ID          string          `json:"id"`
	RequestID   string          `json:"request_id"`
	ToolName    string          `json:"tool_name"`
	ToolType    string          `json:"tool_type"`
	RiskLevel   string          `json:"risk_level"`
	ArgsSummary json.RawMessage `json:"args_summary"`
	Status      string          `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
}

type AgentSessionAlert struct {
	ID             string          `json:"id"`
	EventID        *string         `json:"event_id"`
	Channel        *string         `json:"channel"`
	DeliveryStatus *string         `json:"delivery_status"`
	Severity       string          `json:"severity,omitempty"`
	AlertType      string          `json:"alert_type,omitempty"`
	Decision       string          `json:"decision,omitempty"`
	PayloadSummary json.RawMessage `json:"payload_summary"`
	CreatedAt      time.Time       `json:"created_at"`
}

type AgentSessionDetail struct {
	Overview     AgentAdminSession   `json:"overview"`
	Turns        []AgentTurn         `json:"turns"`
	Events       []AgentAdminEvent   `json:"events"`
	ToolCallLogs []AgentToolCall     `json:"tool_call_logs"`
	Alerts       []AgentSessionAlert `json:"alerts"`
}

type AgentEndpointAsset struct {
	ID           string          `json:"id"`
	EndpointID   string          `json:"endpoint_id"`
	AssetType    string          `json:"asset_type"`
	Name         string          `json:"name"`
	Version      string          `json:"version"`
	Source       string          `json:"source"`
	Hash         string          `json:"hash"`
	Evidence     json.RawMessage `json:"evidence"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	Present      bool            `json:"present"`
	ScanStatus   string          `json:"scan_status"`
	ScanDecision string          `json:"scan_decision"`
}

type AgentAssetFilter struct {
	EndpointID, AssetType string
	Present               *bool
	Page, PageSize        int
}

type AgentAssetPage struct {
	Items []AgentEndpointAsset `json:"items"`
	AgentAdminPage
}

type AgentPolicyBundle struct {
	ID          string          `json:"id"`
	Version     int64           `json:"version"`
	Checksum    string          `json:"checksum"`
	Bundle      json.RawMessage `json:"bundle,omitempty"`
	DerivedFrom json.RawMessage `json:"derived_from"`
	CreatedAt   time.Time       `json:"created_at"`
	CreatedBy   string          `json:"created_by"`
}

type AgentPolicyBundlePage struct {
	Items []AgentPolicyBundle `json:"items"`
	AgentAdminPage
}

func normalizeAgentPage(page, size int) (int, int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = agentAdminDefaultPageSize
	}
	if size > 200 {
		size = 200
	}
	return page, size, (page - 1) * size
}

func addAgentFilter(clauses *[]string, args *[]any, expression string, value any) {
	*args = append(*args, value)
	*clauses = append(*clauses, fmt.Sprintf(expression, len(*args)))
}

func agentWhere(clauses []string) string { return " WHERE " + strings.Join(clauses, " AND ") }

func (r *AgentAdminRepository) Overview(ctx context.Context, tenant string) (*AgentOverview, error) {
	var x AgentOverview
	err := r.db.QueryRow(ctx, `SELECT COUNT(*),COUNT(*) FILTER(WHERE status='active'),COUNT(*) FILTER(WHERE status='active' AND (last_heartbeat_at IS NULL OR last_heartbeat_at<now()-interval '15 minutes')),COUNT(*) FILTER(WHERE status='revoked') FROM agent_endpoints WHERE tenant_id=$1`, tenant).Scan(&x.EndpointsTotal, &x.EndpointsActive, &x.EndpointsStale, &x.EndpointsRevoked)
	if err != nil {
		return nil, err
	}
	if err = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_sessions WHERE tenant_id=$1 AND status='active'`, tenant).Scan(&x.SessionsActive); err != nil {
		return nil, err
	}
	if err = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_events WHERE tenant_id=$1 AND received_at>=now()-interval '24 hours'`, tenant).Scan(&x.Events24H); err != nil {
		return nil, err
	}
	if err = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_endpoint_assets WHERE tenant_id=$1 AND present`, tenant).Scan(&x.AssetsPresent); err != nil {
		return nil, err
	}
	return &x, nil
}

const agentEndpointColumns = `id,machine_id,hostname,os,os_version,arch,os_user,agent_product,agent_version,adapter_name,adapter_version,hookd_version,capabilities,token_prefix,mode_override,capture_level,status,last_heartbeat_at,last_event_at,last_policy_version,last_config_version,health,created_at,updated_at`

func scanAdminEndpoint(row pgx.Row) (*AgentAdminEndpoint, error) {
	var x AgentAdminEndpoint
	var mode sql.NullString
	var heartbeat, event sql.NullTime
	err := row.Scan(&x.ID, &x.MachineID, &x.Hostname, &x.OS, &x.OSVersion, &x.Arch, &x.OSUser, &x.Product, &x.AgentVersion, &x.AdapterName, &x.AdapterVersion, &x.HookdVersion, &x.Capabilities, &x.TokenPrefix, &mode, &x.CaptureLevel, &x.Status, &heartbeat, &event, &x.LastPolicyVersion, &x.LastConfigVersion, &x.Health, &x.CreatedAt, &x.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if mode.Valid {
		x.Mode = &mode.String
	}
	if heartbeat.Valid {
		x.LastHeartbeatAt = &heartbeat.Time
	}
	if event.Valid {
		x.LastEventAt = &event.Time
	}
	x.ControlBoundary = ControlBoundaryFromHealth(x.Health)
	return &x, nil
}

func (r *AgentAdminRepository) ListEndpoints(ctx context.Context, tenant string, f AgentEndpointFilter) (*AgentEndpointPage, error) {
	clauses, args := []string{"tenant_id=$1"}, []any{tenant}
	if f.Product != "" {
		addAgentFilter(&clauses, &args, "agent_product=$%d", f.Product)
	}
	if f.Status != "" {
		addAgentFilter(&clauses, &args, "status=$%d", f.Status)
	}
	if f.OS != "" {
		addAgentFilter(&clauses, &args, "os=$%d", f.OS)
	}
	if f.Mode != "" {
		addAgentFilter(&clauses, &args, "COALESCE(mode_override,'monitor')=$%d", f.Mode)
	}
	if f.Stale != nil {
		clauses = append(clauses, "status='active'")
		if *f.Stale {
			clauses = append(clauses, "(last_heartbeat_at IS NULL OR last_heartbeat_at<now()-interval '15 minutes')")
		} else {
			clauses = append(clauses, "last_heartbeat_at IS NOT NULL AND last_heartbeat_at>=now()-interval '15 minutes'")
		}
	}
	if f.Query != "" {
		addAgentFilter(&clauses, &args, "(id ILIKE '%%'||$%[1]d||'%%' OR hostname ILIKE '%%'||$%[1]d||'%%' OR machine_id ILIKE '%%'||$%[1]d||'%%' OR os_user ILIKE '%%'||$%[1]d||'%%')", f.Query)
	}
	where := agentWhere(clauses)
	page, size, offset := normalizeAgentPage(f.Page, f.PageSize)
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_endpoints`+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	queryArgs := append(append([]any{}, args...), size, offset)
	rows, err := r.db.Query(ctx, `SELECT `+agentEndpointColumns+` FROM agent_endpoints`+where+fmt.Sprintf(` ORDER BY updated_at DESC,id LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AgentAdminEndpoint{}
	for rows.Next() {
		x, err := scanAdminEndpoint(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *x)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return &AgentEndpointPage{Items: items, AgentAdminPage: AgentAdminPage{Page: page, PageSize: size, Total: total}}, nil
}

func (r *AgentAdminRepository) GetEndpoint(ctx context.Context, tenant, id string) (*AgentAdminEndpoint, error) {
	x, err := scanAdminEndpoint(r.db.QueryRow(ctx, `SELECT `+agentEndpointColumns+` FROM agent_endpoints WHERE tenant_id=$1 AND id=$2`, tenant, id))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return x, err
}

func (r *AgentAdminRepository) UpdateEndpointMode(ctx context.Context, tenant, id string, update AgentEndpointModeUpdate) (*AgentAdminEndpoint, error) {
	var mode, capture any
	if update.Mode != nil {
		mode = *update.Mode
	}
	if update.CaptureLevel != nil {
		capture = *update.CaptureLevel
	}
	x, err := scanAdminEndpoint(r.db.QueryRow(ctx, `UPDATE agent_endpoints SET mode_override=CASE WHEN $3 THEN $4::text ELSE mode_override END,capture_level=CASE WHEN $5 THEN COALESCE($6::text,'metadata') ELSE capture_level END,updated_at=now() WHERE tenant_id=$1 AND id=$2 RETURNING `+agentEndpointColumns, tenant, id, update.ModeSet, mode, update.CaptureLevelSet, capture))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return x, err
}

func (r *AgentAdminRepository) RevokeEndpoint(ctx context.Context, tenant, id string) (bool, error) {
	result, err := r.db.Exec(ctx, `UPDATE agent_endpoints SET status='revoked',updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, id)
	return result.RowsAffected() == 1, err
}

func (r *AgentAdminRepository) RotateEndpointToken(ctx context.Context, tenant, id string) (string, bool, error) {
	token, hash, err := NewAgentToken()
	if err != nil {
		return "", false, err
	}
	result, err := r.db.Exec(ctx, `UPDATE agent_endpoints SET token_hash=$3,token_prefix=$4,token_rotated_at=now(),updated_at=now() WHERE tenant_id=$1 AND id=$2 AND status<>'revoked'`, tenant, id, hash, token[:8])
	if err != nil {
		return "", false, err
	}
	return token, result.RowsAffected() == 1, nil
}

const enrollmentColumns = `id,name,token_prefix,default_mode,allowed_products,max_endpoints,enabled,expires_at,revoked_at,last_used_at,created_by,created_at`

func scanEnrollment(row pgx.Row) (*AgentEnrollmentToken, error) {
	var x AgentEnrollmentToken
	var expires, revoked, used sql.NullTime
	err := row.Scan(&x.ID, &x.Name, &x.TokenPrefix, &x.DefaultMode, &x.AllowedProducts, &x.MaxEndpoints, &x.Enabled, &expires, &revoked, &used, &x.CreatedBy, &x.CreatedAt)
	if err != nil {
		return nil, err
	}
	if expires.Valid {
		x.ExpiresAt = &expires.Time
	}
	if revoked.Valid {
		x.RevokedAt = &revoked.Time
	}
	if used.Valid {
		x.LastUsedAt = &used.Time
	}
	return &x, nil
}

func (r *AgentAdminRepository) ListEnrollmentTokens(ctx context.Context, tenant string, f AgentEnrollmentTokenFilter) (*AgentEnrollmentTokenPage, error) {
	clauses, args := []string{"tenant_id=$1"}, []any{tenant}
	if f.Enabled != nil {
		addAgentFilter(&clauses, &args, "enabled=$%d", *f.Enabled)
	}
	where := agentWhere(clauses)
	page, size, offset := normalizeAgentPage(f.Page, f.PageSize)
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_enrollment_tokens`+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	queryArgs := append(append([]any{}, args...), size, offset)
	rows, err := r.db.Query(ctx, `SELECT `+enrollmentColumns+` FROM agent_enrollment_tokens`+where+fmt.Sprintf(` ORDER BY created_at DESC,id LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AgentEnrollmentToken{}
	for rows.Next() {
		x, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *x)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return &AgentEnrollmentTokenPage{Items: items, AgentAdminPage: AgentAdminPage{Page: page, PageSize: size, Total: total}}, nil
}

func (r *AgentAdminRepository) CreateEnrollmentToken(ctx context.Context, tenant string, input AgentEnrollmentTokenCreate) (*AgentEnrollmentTokenCreated, error) {
	token, hash, err := NewAgentToken()
	if err != nil {
		return nil, err
	}
	allowed, err := json.Marshal(input.AllowedProducts)
	if err != nil {
		return nil, err
	}
	id := "aet_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	x, err := scanEnrollment(r.db.QueryRow(ctx, `INSERT INTO agent_enrollment_tokens(id,tenant_id,name,token_hash,token_prefix,default_mode,allowed_products,max_endpoints,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+enrollmentColumns, id, tenant, input.Name, hash, token[:8], input.DefaultMode, allowed, input.MaxEndpoints, input.ExpiresAt, input.CreatedBy))
	if err != nil {
		return nil, err
	}
	return &AgentEnrollmentTokenCreated{AgentEnrollmentToken: *x, Token: token}, nil
}

func (r *AgentAdminRepository) RevokeEnrollmentToken(ctx context.Context, tenant, id string) (bool, error) {
	result, err := r.db.Exec(ctx, `UPDATE agent_enrollment_tokens SET enabled=false,revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1 AND id=$2`, tenant, id)
	return result.RowsAffected() == 1, err
}

const agentSessionColumns = `id,project_id,user_id,session_id,endpoint_id,COALESCE(source,''),parent_session_id,agent_id,agent_role,product,model,agent_type,workspace_id,cwd_hash,project_label,permission_mode,COALESCE(status,''),COALESCE(risk_score,0),started_at,ended_at,first_request_at,last_request_at,COALESCE(turn_count,0),COALESCE(event_count,0),COALESCE(tool_call_count,0),COALESCE(blocked_count,0),COALESCE(would_block_count,0),COALESCE(gateway_request_count,0)`

func nullStringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	v := value.String
	return &v
}

func scanAdminSession(row pgx.Row) (*AgentAdminSession, error) {
	var x AgentAdminSession
	var project, user, endpoint, parent, agent, role, product, model, agentType, workspace, cwd, label, permission sql.NullString
	var started, ended, first, last sql.NullTime
	err := row.Scan(&x.ID, &project, &user, &x.SessionID, &endpoint, &x.Source, &parent, &agent, &role, &product, &model, &agentType, &workspace, &cwd, &label, &permission, &x.Status, &x.RiskScore, &started, &ended, &first, &last, &x.TurnCount, &x.EventCount, &x.ToolCallCount, &x.BlockedCount, &x.WouldBlockCount, &x.GatewayRequestCount)
	if err != nil {
		return nil, err
	}
	x.ProjectID, x.UserID, x.EndpointID = nullStringPtr(project), nullStringPtr(user), nullStringPtr(endpoint)
	x.ParentSessionID, x.AgentID, x.AgentRole = nullStringPtr(parent), nullStringPtr(agent), nullStringPtr(role)
	x.Product, x.Model, x.AgentType, x.WorkspaceID = nullStringPtr(product), nullStringPtr(model), nullStringPtr(agentType), nullStringPtr(workspace)
	x.CWDHash, x.ProjectLabel, x.PermissionMode = nullStringPtr(cwd), nullStringPtr(label), nullStringPtr(permission)
	if started.Valid {
		x.StartedAt = &started.Time
	}
	if ended.Valid {
		x.EndedAt = &ended.Time
	}
	if first.Valid {
		x.FirstRequestAt = &first.Time
	}
	if last.Valid {
		x.LastRequestAt = &last.Time
	}
	return &x, nil
}

func (r *AgentAdminRepository) ListSessions(ctx context.Context, tenant string, f AgentSessionFilter) (*AgentSessionPage, error) {
	clauses, args := []string{"tenant_id=$1"}, []any{tenant}
	if f.EndpointID != "" {
		addAgentFilter(&clauses, &args, "endpoint_id=$%d", f.EndpointID)
	}
	if f.Product != "" {
		addAgentFilter(&clauses, &args, "product=$%d", f.Product)
	}
	if f.Status != "" {
		addAgentFilter(&clauses, &args, "status=$%d", f.Status)
	}
	if f.From != nil {
		addAgentFilter(&clauses, &args, "COALESCE(started_at,first_request_at,created_at)>=$%d", *f.From)
	}
	if f.To != nil {
		addAgentFilter(&clauses, &args, "COALESCE(started_at,first_request_at,created_at)<=$%d", *f.To)
	}
	if f.MinRisk != nil {
		addAgentFilter(&clauses, &args, "COALESCE(risk_score,0)>=$%d", *f.MinRisk)
	}
	if f.Query != "" {
		addAgentFilter(&clauses, &args, "(session_id ILIKE '%%'||$%[1]d||'%%' OR COALESCE(project_label,'') ILIKE '%%'||$%[1]d||'%%' OR COALESCE(agent_id,'') ILIKE '%%'||$%[1]d||'%%')", f.Query)
	}
	where := agentWhere(clauses)
	page, size, offset := normalizeAgentPage(f.Page, f.PageSize)
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_sessions`+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	queryArgs := append(append([]any{}, args...), size, offset)
	rows, err := r.db.Query(ctx, `SELECT `+agentSessionColumns+` FROM agent_sessions`+where+fmt.Sprintf(` ORDER BY COALESCE(last_request_at,updated_at) DESC,id LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AgentAdminSession{}
	for rows.Next() {
		x, err := scanAdminSession(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *x)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return &AgentSessionPage{Items: items, AgentAdminPage: AgentAdminPage{Page: page, PageSize: size, Total: total}}, nil
}

func (r *AgentAdminRepository) getSession(ctx context.Context, tenant, id string) (*AgentAdminSession, error) {
	x, err := scanAdminSession(r.db.QueryRow(ctx, `SELECT `+agentSessionColumns+` FROM agent_sessions WHERE tenant_id=$1 AND (id=$2 OR session_id=$2)`, tenant, id))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return x, err
}

func scanAdminEvent(row pgx.Row) (*AgentAdminEvent, error) {
	var x AgentAdminEvent
	err := row.Scan(&x.ID, &x.EndpointID, &x.SessionID, &x.PromptID, &x.ToolUseID, &x.EventType, &x.OccurredAt, &x.ReceivedAt, &x.ToolName, &x.ToolType, &x.MCPServer, &x.Payload, &x.LocalDecision, &x.ServerDecision, &x.ToolCallLogID, &x.Severity)
	return &x, err
}

func (r *AgentAdminRepository) ListEvents(ctx context.Context, tenant string, f AgentEventFilter) (*AgentEventPage, error) {
	clauses, args := []string{"tenant_id=$1"}, []any{tenant}
	if f.SessionID != "" {
		addAgentFilter(&clauses, &args, "session_id=$%d", f.SessionID)
	}
	if f.EndpointID != "" {
		addAgentFilter(&clauses, &args, "endpoint_id=$%d", f.EndpointID)
	}
	if f.EventType != "" {
		addAgentFilter(&clauses, &args, "event_type=$%d", f.EventType)
	}
	if f.From != nil {
		addAgentFilter(&clauses, &args, "occurred_at>=$%d", *f.From)
	}
	if f.To != nil {
		addAgentFilter(&clauses, &args, "occurred_at<=$%d", *f.To)
	}
	where := agentWhere(clauses)
	page, size, offset := normalizeAgentPage(f.Page, f.PageSize)
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_events`+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	queryArgs := append(append([]any{}, args...), size, offset)
	rows, err := r.db.Query(ctx, `SELECT id,endpoint_id,session_id,prompt_id,tool_use_id,event_type,occurred_at,received_at,tool_name,tool_type,mcp_server,payload,local_decision,server_decision,COALESCE(tool_call_log_id,''),severity FROM agent_events`+where+fmt.Sprintf(` ORDER BY occurred_at DESC,id LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AgentAdminEvent{}
	for rows.Next() {
		x, err := scanAdminEvent(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *x)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return &AgentEventPage{Items: items, AgentAdminPage: AgentAdminPage{Page: page, PageSize: size, Total: total}}, nil
}

func (r *AgentAdminRepository) GetSessionDetail(ctx context.Context, tenant, id string) (*AgentSessionDetail, error) {
	session, err := r.getSession(ctx, tenant, id)
	if err != nil || session == nil {
		return nil, err
	}
	out := &AgentSessionDetail{Overview: *session, Turns: []AgentTurn{}, Events: []AgentAdminEvent{}, ToolCallLogs: []AgentToolCall{}, Alerts: []AgentSessionAlert{}}
	rows, err := r.db.Query(ctx, `SELECT id,prompt_id,seq,started_at,ended_at,stop_reason,prompt_hash,prompt_preview,assistant_preview,tool_call_count,blocked_count FROM agent_turns WHERE tenant_id=$1 AND session_id=$2 ORDER BY seq,id`, tenant, session.SessionID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var x AgentTurn
		var started, ended sql.NullTime
		if err = rows.Scan(&x.ID, &x.PromptID, &x.Seq, &started, &ended, &x.StopReason, &x.PromptHash, &x.PromptPreview, &x.AssistantPreview, &x.ToolCallCount, &x.BlockedCount); err != nil {
			rows.Close()
			return nil, err
		}
		if started.Valid {
			x.StartedAt = &started.Time
		}
		if ended.Valid {
			x.EndedAt = &ended.Time
		}
		out.Turns = append(out.Turns, x)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	events, err := r.ListEvents(ctx, tenant, AgentEventFilter{SessionID: session.SessionID, Page: 1, PageSize: 200})
	if err != nil {
		return nil, err
	}
	out.Events = events.Items
	rows, err = r.db.Query(ctx, `SELECT id,request_id,tool_name,tool_type,risk_level,parameters,status,COALESCE(created_at,to_timestamp(0)) FROM tool_call_logs WHERE tenant_id=$1 AND session_id=$2 ORDER BY created_at,id`, tenant, session.SessionID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var x AgentToolCall
		if err = rows.Scan(&x.ID, &x.RequestID, &x.ToolName, &x.ToolType, &x.RiskLevel, &x.ArgsSummary, &x.Status, &x.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.ToolCallLogs = append(out.ToolCallLogs, x)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	rows, err = r.db.Query(ctx, `
		SELECT a.id,a.event_id,a.channel,a.delivery_status,'' AS severity,'' AS alert_type,'' AS decision,
		       a.payload_summary,COALESCE(a.created_at,to_timestamp(0)) FROM alerts a
		JOIN security_events se ON se.tenant_id=$1 AND se.id=a.event_id
		JOIN request_logs rl ON rl.tenant_id=$1 AND rl.request_id=se.request_id
		WHERE a.tenant_id=$1 AND rl.session_id=$2
		UNION ALL
		SELECT se.id,se.id,NULL::text,'durable',se.severity,se.event_type,se.action_taken,
		       COALESCE(se.matched_summary,'{}'::jsonb),COALESCE(se.created_at,to_timestamp(0))
		FROM security_events se
		WHERE se.tenant_id=$1 AND se.matched_summary->>'source'='agent_endpoint'
		  AND se.matched_summary->>'session_id'=$2
		ORDER BY 9,1`, tenant, session.SessionID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var x AgentSessionAlert
		var event, channel, status sql.NullString
		if err = rows.Scan(&x.ID, &event, &channel, &status, &x.Severity, &x.AlertType, &x.Decision, &x.PayloadSummary, &x.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		x.EventID, x.Channel, x.DeliveryStatus = nullStringPtr(event), nullStringPtr(channel), nullStringPtr(status)
		out.Alerts = append(out.Alerts, x)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	return out, nil
}

func (r *AgentAdminRepository) ListAssets(ctx context.Context, tenant string, f AgentAssetFilter) (*AgentAssetPage, error) {
	clauses, args := []string{"tenant_id=$1"}, []any{tenant}
	if f.EndpointID != "" {
		addAgentFilter(&clauses, &args, "endpoint_id=$%d", f.EndpointID)
	}
	if f.AssetType != "" {
		addAgentFilter(&clauses, &args, "asset_type=$%d", f.AssetType)
	}
	if f.Present != nil {
		addAgentFilter(&clauses, &args, "present=$%d", *f.Present)
	}
	where := agentWhere(clauses)
	page, size, offset := normalizeAgentPage(f.Page, f.PageSize)
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_endpoint_assets`+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	queryArgs := append(append([]any{}, args...), size, offset)
	rows, err := r.db.Query(ctx, `SELECT id,endpoint_id,asset_type,name,version,source,hash,evidence,first_seen,last_seen,present,scan_status,scan_decision FROM agent_endpoint_assets`+where+fmt.Sprintf(` ORDER BY last_seen DESC,id LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AgentEndpointAsset{}
	for rows.Next() {
		var x AgentEndpointAsset
		if err = rows.Scan(&x.ID, &x.EndpointID, &x.AssetType, &x.Name, &x.Version, &x.Source, &x.Hash, &x.Evidence, &x.FirstSeen, &x.LastSeen, &x.Present, &x.ScanStatus, &x.ScanDecision); err != nil {
			return nil, err
		}
		items = append(items, x)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return &AgentAssetPage{Items: items, AgentAdminPage: AgentAdminPage{Page: page, PageSize: size, Total: total}}, nil
}

func (r *AgentAdminRepository) ListPolicyBundles(ctx context.Context, tenant string, page, size int) (*AgentPolicyBundlePage, error) {
	page, size, offset := normalizeAgentPage(page, size)
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_policy_bundles WHERE tenant_id=$1`, tenant).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT id,version,checksum,derived_from,created_at,created_by FROM agent_policy_bundles WHERE tenant_id=$1 ORDER BY version DESC LIMIT $2 OFFSET $3`, tenant, size, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AgentPolicyBundle{}
	for rows.Next() {
		var x AgentPolicyBundle
		if err = rows.Scan(&x.ID, &x.Version, &x.Checksum, &x.DerivedFrom, &x.CreatedAt, &x.CreatedBy); err != nil {
			return nil, err
		}
		items = append(items, x)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return &AgentPolicyBundlePage{Items: items, AgentAdminPage: AgentAdminPage{Page: page, PageSize: size, Total: total}}, nil
}

func (r *AgentAdminRepository) CurrentPolicyBundle(ctx context.Context, tenant string) (*AgentPolicyBundle, error) {
	var x AgentPolicyBundle
	err := r.db.QueryRow(ctx, `SELECT id,version,checksum,bundle,derived_from,created_at,created_by FROM agent_policy_bundles WHERE tenant_id=$1 ORDER BY version DESC LIMIT 1`, tenant).Scan(&x.ID, &x.Version, &x.Checksum, &x.Bundle, &x.DerivedFrom, &x.CreatedAt, &x.CreatedBy)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &x, err
}

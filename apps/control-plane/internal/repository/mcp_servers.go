package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MCPServer 表示一台登记在册的 MCP（Model Context Protocol）服务器，即工具/能力提供方。
// 099 起承载 MCP 安全网关的资产登记：传输方式、能力清单指纹（rug-pull 检测）、
// 鉴权凭据密文（AES-GCM，绝不回传前端）与内网放行开关。
type MCPServer struct {
	ID           string                 `json:"id"`
	TenantID     string                 `json:"tenant_id"`
	Name         string                 `json:"name"`
	ServerURL    string                 `json:"server_url"`
	Owner        string                 `json:"owner"`
	TrustLevel   string                 `json:"trust_level"`
	Capabilities map[string]interface{} `json:"capabilities"`
	Status       string                 `json:"status"`
	Transport    string                 `json:"transport"`     // streamable_http | sse
	ManifestHash string                 `json:"manifest_hash"` // tools 规范化 JSON 的 sha256
	// AuthCiphertext/AuthKeyRef 是鉴权凭据密文与密钥引用，只在服务端流转，
	// 序列化一律屏蔽（json:"-"）；前端只看派生的 AuthConfigured。
	AuthCiphertext     string `json:"-"`
	AuthKeyRef         string `json:"-"`
	AuthConfigured     bool   `json:"auth_configured"` // 派生字段：是否已配置鉴权凭据
	AllowPrivateEgress bool   `json:"allow_private_egress"`
	// EgressOverrides 是服务的高级出站放行（迁移 999 的 egress_overrides 列，默认全拒）。
	EgressOverrides          safetarget.EgressOverrides `json:"egress_overrides"`
	LastSyncedAt             *time.Time                 `json:"last_synced_at,omitempty"`
	LastManifestChangedAt    *time.Time                 `json:"last_manifest_changed_at,omitempty"` // rug-pull 标记
	AdmissionStatus          string                     `json:"admission_status"`
	ObservedManifestSnapshot json.RawMessage            `json:"observed_manifest_snapshot"`
	ApprovedManifestHash     string                     `json:"approved_manifest_hash"`
	ApprovedManifestSnapshot json.RawMessage            `json:"approved_manifest_snapshot"`
	QuarantineReason         string                     `json:"quarantine_reason,omitempty"`
	QuarantinedAt            *time.Time                 `json:"quarantined_at,omitempty"`
	AdmissionReviewedBy      string                     `json:"admission_reviewed_by,omitempty"`
	AdmissionReviewedAt      *time.Time                 `json:"admission_reviewed_at,omitempty"`
	ObservedRouteHash        string                     `json:"route_hash"`
	ApprovedRouteHash        string                     `json:"approved_route_hash"`
	AdmissionRevision        int64                      `json:"admission_revision"`
	CreatedAt                time.Time                  `json:"created_at"`
	UpdatedAt                time.Time                  `json:"updated_at"`
}

// MCPServersRepository 负责 mcp_servers 表的读写。
type MCPServersRepository struct {
	db *pgxpool.Pool
}

func NewMCPServersRepository(db *pgxpool.Pool) *MCPServersRepository {
	return &MCPServersRepository{db: db}
}

// Create 登记一台 MCP 服务器；trust_level/status/transport/capabilities 缺省时落默认值。
func (r *MCPServersRepository) Create(ctx context.Context, m *MCPServer) error {
	if m.ID == "" {
		m.ID = "mcp_" + uuid.New().String()[:8]
	}
	if m.TrustLevel == "" {
		m.TrustLevel = "low"
	}
	if m.Status == "" {
		m.Status = "active"
	}
	if m.Transport == "" {
		m.Transport = "streamable_http"
	}
	if m.Capabilities == nil {
		m.Capabilities = map[string]interface{}{}
	}
	capBytes, _ := json.Marshal(m.Capabilities)
	overridesJSON, _ := json.Marshal(m.EgressOverrides)
	query := `INSERT INTO mcp_servers
		(id, tenant_id, name, server_url, owner, trust_level, capabilities_json, status,
		 transport, auth_ciphertext, auth_key_ref, allow_private_egress, egress_overrides)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb)
		RETURNING created_at, updated_at`
	if err := r.db.QueryRow(ctx, query,
		m.ID, m.TenantID, m.Name, m.ServerURL, m.Owner, m.TrustLevel, string(capBytes), m.Status,
		m.Transport, m.AuthCiphertext, m.AuthKeyRef, m.AllowPrivateEgress, string(overridesJSON),
	).Scan(&m.CreatedAt, &m.UpdatedAt); err != nil {
		return err
	}
	m.AuthConfigured = m.AuthCiphertext != ""
	return nil
}

// MCPServerUpdateParams 是 Update 的字段集。SetAuth=false 时凭据两列保持不变
// （管理台约定：auth_token 传空 = 不改凭据），避免每次编辑都把已配置的凭据清掉。
type MCPServerUpdateParams struct {
	Name               string
	ServerURL          string
	Owner              string
	TrustLevel         string
	Capabilities       map[string]interface{}
	Status             string
	Transport          string
	AllowPrivateEgress bool
	// EgressOverrides 为 nil 时保持不变（编辑表单可以不回传高级出站）。
	EgressOverrides *safetarget.EgressOverrides
	SetAuth         bool
	AuthCiphertext  string
	AuthKeyRef      string
}

// Update 修改一台 MCP 服务器的登记信息。租户硬隔离：WHERE 同时按 id 与 tenant_id
// （修复历史上只按 id 的跨租户 IDOR）；无匹配行返回 pgx.ErrNoRows。
func (r *MCPServersRepository) Update(ctx context.Context, tenantID, id string, p MCPServerUpdateParams) error {
	if p.Transport == "" {
		p.Transport = "streamable_http"
	}
	// capabilities 省略（nil）= 保持不变（与 auth_token 传空=不变同一约定）：
	// 前端编辑表单不回传 capabilities，若无条件覆盖会把该列清成 {}。
	// 传非 nil（含空 map）才落库替换。
	var capText *string
	if p.Capabilities != nil {
		capBytes, _ := json.Marshal(p.Capabilities)
		s := string(capBytes)
		capText = &s
	}
	var overridesText *string
	if p.EgressOverrides != nil {
		encoded, _ := json.Marshal(*p.EgressOverrides)
		s := string(encoded)
		overridesText = &s
	}
	query := `UPDATE mcp_servers SET
			name = $3, server_url = $4, owner = $5, trust_level = $6,
			capabilities_json = COALESCE($7, capabilities_json),
			status = $8, transport = $9, allow_private_egress = $10,
			egress_overrides = COALESCE($11::jsonb, egress_overrides), updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2`
	args := []interface{}{id, tenantID, p.Name, p.ServerURL, p.Owner, p.TrustLevel, capText,
		p.Status, p.Transport, p.AllowPrivateEgress, overridesText}
	if p.SetAuth {
		query = `UPDATE mcp_servers SET
				name = $3, server_url = $4, owner = $5, trust_level = $6,
				capabilities_json = COALESCE($7, capabilities_json),
				status = $8, transport = $9, allow_private_egress = $10,
				egress_overrides = COALESCE($11::jsonb, egress_overrides),
				auth_ciphertext = $12, auth_key_ref = $13, updated_at = NOW()
			WHERE id = $1 AND tenant_id = $2`
		args = append(args, p.AuthCiphertext, p.AuthKeyRef)
	}
	tag, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// UpdateManifest 只回写能力同步产物（manifest_hash / last_synced_at / rug-pull 标记），
// 刻意不复用全字段 Update——否则会把管理员手工设置的 trust_level/owner 等清掉。
// manifestChanged=true 时刷新 last_manifest_changed_at（能力清单变更即 rug-pull 信号）。
func (r *MCPServersRepository) UpdateManifest(ctx context.Context, tenantID, id, manifestHash string, manifestChanged bool, protocolVersion string) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE mcp_servers SET
			manifest_hash = $3,
			last_synced_at = NOW(),
			last_manifest_changed_at = CASE WHEN $4 THEN NOW() ELSE last_manifest_changed_at END,
			capabilities_json = jsonb_set(COALESCE(capabilities_json, '{}'::jsonb),
				'{protocol_version}', to_jsonb($5::text), true),
			updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2`,
		id, tenantID, manifestHash, manifestChanged, protocolVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// Delete 注销一台 MCP 服务器（租户硬隔离，同 Update）；无匹配行返回 pgx.ErrNoRows。
func (r *MCPServersRepository) Delete(ctx context.Context, tenantID, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM mcp_servers WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

const mcpServerColumns = `id, tenant_id, name, server_url, owner, trust_level, capabilities_json, status,
	COALESCE(transport, 'streamable_http'), COALESCE(manifest_hash, ''),
	COALESCE(auth_ciphertext, ''), COALESCE(auth_key_ref, ''), COALESCE(allow_private_egress, FALSE),
	last_synced_at, last_manifest_changed_at,
	COALESCE(admission_status, 'unverified'), COALESCE(observed_manifest_snapshot, '[]'::jsonb)::text,
	COALESCE(approved_manifest_hash, ''), COALESCE(approved_manifest_snapshot, '[]'::jsonb)::text,
	COALESCE(quarantine_reason, ''), quarantined_at, COALESCE(admission_reviewed_by, ''),
	admission_reviewed_at, COALESCE(observed_route_hash,''), COALESCE(approved_route_hash,''), COALESCE(admission_revision, 0), created_at, COALESCE(updated_at, created_at),
	COALESCE(egress_overrides, '{}'::jsonb)::text`

// Get 按租户 + id 读回一台 MCP 服务器；无行时返回 pgx.ErrNoRows。
func (r *MCPServersRepository) Get(ctx context.Context, tenantID, id string) (*MCPServer, error) {
	row := r.db.QueryRow(ctx, `SELECT `+mcpServerColumns+` FROM mcp_servers WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return scanMCPServer(row)
}

// ListByTenant 按租户列出 MCP 服务器，最近登记的在前。
func (r *MCPServersRepository) ListByTenant(ctx context.Context, tenantID string) ([]*MCPServer, error) {
	rows, err := r.db.Query(ctx, `SELECT `+mcpServerColumns+` FROM mcp_servers WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMCPServers(rows)
}

type mcpServerScanner interface {
	Scan(dest ...any) error
}

func scanMCPServer(row mcpServerScanner) (*MCPServer, error) {
	m := &MCPServer{}
	var serverURL, owner *string
	var capStr, observedSnapshot, approvedSnapshot, overridesText string
	if err := row.Scan(
		&m.ID, &m.TenantID, &m.Name, &serverURL, &owner, &m.TrustLevel, &capStr, &m.Status,
		&m.Transport, &m.ManifestHash, &m.AuthCiphertext, &m.AuthKeyRef, &m.AllowPrivateEgress,
		&m.LastSyncedAt, &m.LastManifestChangedAt, &m.AdmissionStatus, &observedSnapshot,
		&m.ApprovedManifestHash, &approvedSnapshot, &m.QuarantineReason, &m.QuarantinedAt,
		&m.AdmissionReviewedBy, &m.AdmissionReviewedAt, &m.ObservedRouteHash, &m.ApprovedRouteHash,
		&m.AdmissionRevision, &m.CreatedAt, &m.UpdatedAt, &overridesText,
	); err != nil {
		return nil, err
	}
	m.EgressOverrides = parseStoredEgressOverrides(overridesText)
	if serverURL != nil {
		m.ServerURL = *serverURL
	}
	m.ObservedManifestSnapshot = json.RawMessage(observedSnapshot)
	m.ApprovedManifestSnapshot = json.RawMessage(approvedSnapshot)
	if owner != nil {
		m.Owner = *owner
	}
	if capStr != "" {
		_ = json.Unmarshal([]byte(capStr), &m.Capabilities)
	}
	if m.Capabilities == nil {
		m.Capabilities = map[string]interface{}{}
	}
	m.AuthConfigured = m.AuthCiphertext != ""
	return m, nil
}

func scanMCPServers(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}) ([]*MCPServer, error) {
	var out []*MCPServer
	for rows.Next() {
		m, err := scanMCPServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

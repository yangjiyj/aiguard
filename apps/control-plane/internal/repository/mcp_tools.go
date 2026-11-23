package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MCPTool 是能力识别产物：一台 MCP 服务器经 initialize+tools/list 同步回来的单个工具。
// manifest 中消失的工具只标 removed 不物理删——保留审计线索，也是 rug-pull 取证的一部分。
type MCPTool struct {
	ID                     string                 `json:"id"`
	ServerID               string                 `json:"server_id"`
	TenantID               string                 `json:"tenant_id"`
	ToolName               string                 `json:"tool_name"`
	Description            string                 `json:"description"`
	InputSchema            map[string]interface{} `json:"input_schema,omitempty"`
	RiskTags               []string               `json:"risk_tags"`
	SchemaHash             string                 `json:"schema_hash"`  // 单工具指纹（description+schema）
	PoisonFlags            []string               `json:"poison_flags"` // 描述投毒命中标签；非空会隔离该精确工具快照
	AdmissionStatus        string                 `json:"admission_status"`
	ApprovedSchemaHash     string                 `json:"approved_schema_hash"`
	ApprovedSchemaSnapshot json.RawMessage        `json:"approved_schema_snapshot"`
	QuarantineReason       string                 `json:"quarantine_reason,omitempty"`
	QuarantinedAt          *time.Time             `json:"quarantined_at,omitempty"`
	AdmissionReviewedBy    string                 `json:"admission_reviewed_by,omitempty"`
	AdmissionReviewedAt    *time.Time             `json:"admission_reviewed_at,omitempty"`
	AdmissionRevision      int64                  `json:"admission_revision"`

	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	Removed     bool      `json:"removed"`
}

// MCPToolsRepository 负责 mcp_tools 表的读写。
type MCPToolsRepository struct {
	db *pgxpool.Pool
}

func NewMCPToolsRepository(db *pgxpool.Pool) *MCPToolsRepository {
	return &MCPToolsRepository{db: db}
}

// FindActiveToolID 按租户、服务器与工具名返回在册资产 ID。
// 未知、已移除或跨租户记录统一返回空，不泄露资产是否存在。
func (r *MCPToolsRepository) FindActiveToolID(ctx context.Context, tenantID, serverID, toolName string) (string, error) {
	if r == nil || r.db == nil || tenantID == "" || serverID == "" || toolName == "" {
		return "", nil
	}
	var id string
	err := r.db.QueryRow(ctx, `
		SELECT id
		FROM mcp_tools
		WHERE tenant_id = $1 AND server_id = $2 AND tool_name = $3 AND removed = FALSE
	`, tenantID, serverID, toolName).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("find active MCP tool ID: %w", err)
	}
	return id, nil
}

// ReplaceForServer 用一次同步的完整工具清单整批 upsert：
//   - 清单内的工具：insert 或按 (server_id, tool_name) 冲突更新描述/schema/风险标签，
//     刷新 last_seen_at 并复活 removed=FALSE（工具回归也是信号，first_seen_at 保留首见时间）；
//   - 清单外的存量工具：标 removed=TRUE，不物理删。
//
// 整个替换在单事务内完成，租户硬隔离由 tenant_id 谓词兜底（server 归属由调用方先校验）。
func (r *MCPToolsRepository) ReplaceForServer(ctx context.Context, tenantID, serverID string, tools []*MCPTool) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin replace mcp tools: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 工具数已在 fetchMCPManifest 侧被 maxMCPToolsPerServer(500) 硬上限兜底，故下面逐条 tx.Exec
	// 的 upsert 循环最多约 500 次 + 1 次 removed 标记，单事务持有时间有界（无需改批量 INSERT/COPY）。
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		if t == nil || t.ToolName == "" {
			continue
		}
		if t.ID == "" {
			t.ID = "mcpt_" + uuid.New().String()[:8]
		}
		t.ServerID = serverID
		t.TenantID = tenantID
		names = append(names, t.ToolName)

		var schemaParam interface{}
		if t.InputSchema != nil {
			b, mErr := json.Marshal(t.InputSchema)
			if mErr != nil {
				return fmt.Errorf("marshal input_schema for %s: %w", t.ToolName, mErr)
			}
			schemaParam = string(b)
		}
		riskTags := t.RiskTags
		if riskTags == nil {
			riskTags = []string{}
		}
		tagBytes, mErr := json.Marshal(riskTags)
		if mErr != nil {
			return fmt.Errorf("marshal risk_tags for %s: %w", t.ToolName, mErr)
		}
		poisonFlags := t.PoisonFlags
		if poisonFlags == nil {
			poisonFlags = []string{}
		}
		poisonBytes, mErr := json.Marshal(poisonFlags)
		if mErr != nil {
			return fmt.Errorf("marshal poison_flags for %s: %w", t.ToolName, mErr)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO mcp_tools (id, server_id, tenant_id, tool_name, description, input_schema, risk_tags, schema_hash, poison_flags)
			VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9::jsonb)
			ON CONFLICT (server_id, tool_name) DO UPDATE SET
				description = EXCLUDED.description,
				input_schema = EXCLUDED.input_schema,
				risk_tags = EXCLUDED.risk_tags,
				schema_hash = EXCLUDED.schema_hash,
				poison_flags = EXCLUDED.poison_flags,
				last_seen_at = NOW(),
				removed = FALSE
			WHERE mcp_tools.tenant_id = EXCLUDED.tenant_id`,
			t.ID, serverID, tenantID, t.ToolName, t.Description, schemaParam, string(tagBytes), t.SchemaHash, string(poisonBytes),
		); err != nil {
			return fmt.Errorf("upsert mcp tool %s: %w", t.ToolName, err)
		}
	}

	// 清单外的存量工具标 removed（names 为空 = 服务器已无任何工具，全部标掉）。
	if _, err := tx.Exec(ctx, `
		UPDATE mcp_tools SET removed = TRUE
		WHERE server_id = $1 AND tenant_id = $2 AND removed = FALSE AND NOT (tool_name = ANY($3))`,
		serverID, tenantID, names,
	); err != nil {
		return fmt.Errorf("mark removed mcp tools: %w", err)
	}
	return tx.Commit(ctx)
}

// ListByServer 按租户 + 服务器列出全部工具（含 removed，供前端展示历史线索），按名称排序。
func (r *MCPToolsRepository) ListByServer(ctx context.Context, tenantID, serverID string) ([]*MCPTool, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, server_id, tenant_id, tool_name, description,
			COALESCE(input_schema::text, ''), COALESCE(risk_tags::text, '[]'),
			schema_hash, COALESCE(poison_flags::text, '[]'), COALESCE(admission_status,'unverified'),
			COALESCE(approved_schema_hash,''), COALESCE(approved_schema_snapshot,'{}'::jsonb)::text,
			COALESCE(quarantine_reason,''), quarantined_at, COALESCE(admission_reviewed_by,''),
			admission_reviewed_at, COALESCE(admission_revision,0), first_seen_at, last_seen_at, removed
		FROM mcp_tools
		WHERE tenant_id = $1 AND server_id = $2
		ORDER BY removed ASC, tool_name ASC`, tenantID, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*MCPTool
	for rows.Next() {
		t := &MCPTool{}
		var schemaStr, tagsStr, poisonStr, approvedSnapshot string
		if err := rows.Scan(
			&t.ID, &t.ServerID, &t.TenantID, &t.ToolName, &t.Description,
			&schemaStr, &tagsStr, &t.SchemaHash, &poisonStr, &t.AdmissionStatus,
			&t.ApprovedSchemaHash, &approvedSnapshot, &t.QuarantineReason, &t.QuarantinedAt,
			&t.AdmissionReviewedBy, &t.AdmissionReviewedAt, &t.AdmissionRevision, &t.FirstSeenAt, &t.LastSeenAt, &t.Removed,
		); err != nil {
			return nil, err
		}
		t.ApprovedSchemaSnapshot = json.RawMessage(approvedSnapshot)
		if schemaStr != "" {
			_ = json.Unmarshal([]byte(schemaStr), &t.InputSchema)
		}
		if err := json.Unmarshal([]byte(tagsStr), &t.RiskTags); err != nil || t.RiskTags == nil {
			t.RiskTags = []string{}
		}
		if err := json.Unmarshal([]byte(poisonStr), &t.PoisonFlags); err != nil || t.PoisonFlags == nil {
			t.PoisonFlags = []string{}
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// CountActiveByTenant 返回租户内每台服务器的在册（未 removed）工具数，供列表页 tool_count 展示。
func (r *MCPToolsRepository) CountActiveByTenant(ctx context.Context, tenantID string) (map[string]int, error) {
	rows, err := r.db.Query(ctx, `
		SELECT server_id, COUNT(*)::int
		FROM mcp_tools
		WHERE tenant_id = $1 AND removed = FALSE
		GROUP BY server_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var serverID string
		var count int
		if err := rows.Scan(&serverID, &count); err != nil {
			return nil, err
		}
		out[serverID] = count
	}
	return out, rows.Err()
}

// ListByTenant 列出租户内全部在册（未 removed）工具，跨 server，供影子工具检测。
func (r *MCPToolsRepository) ListByTenant(ctx context.Context, tenantID string) ([]*MCPTool, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, server_id, tenant_id, tool_name, description,
			COALESCE(input_schema::text, ''), COALESCE(risk_tags::text, '[]'),
			schema_hash, COALESCE(poison_flags::text, '[]'), COALESCE(admission_status,'unverified'),
			COALESCE(approved_schema_hash,''), COALESCE(approved_schema_snapshot,'{}'::jsonb)::text,
			COALESCE(quarantine_reason,''), quarantined_at, COALESCE(admission_reviewed_by,''),
			admission_reviewed_at, COALESCE(admission_revision,0), first_seen_at, last_seen_at, removed
		FROM mcp_tools
		WHERE tenant_id = $1 AND removed = FALSE
		ORDER BY tool_name ASC, server_id ASC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*MCPTool
	for rows.Next() {
		t := &MCPTool{}
		var schemaStr, tagsStr, poisonStr, approvedSnapshot string
		if err := rows.Scan(
			&t.ID, &t.ServerID, &t.TenantID, &t.ToolName, &t.Description,
			&schemaStr, &tagsStr, &t.SchemaHash, &poisonStr, &t.AdmissionStatus,
			&t.ApprovedSchemaHash, &approvedSnapshot, &t.QuarantineReason, &t.QuarantinedAt,
			&t.AdmissionReviewedBy, &t.AdmissionReviewedAt, &t.AdmissionRevision, &t.FirstSeenAt, &t.LastSeenAt, &t.Removed,
		); err != nil {
			return nil, err
		}
		t.ApprovedSchemaSnapshot = json.RawMessage(approvedSnapshot)
		if schemaStr != "" {
			_ = json.Unmarshal([]byte(schemaStr), &t.InputSchema)
		}
		if err := json.Unmarshal([]byte(tagsStr), &t.RiskTags); err != nil || t.RiskTags == nil {
			t.RiskTags = []string{}
		}
		if err := json.Unmarshal([]byte(poisonStr), &t.PoisonFlags); err != nil || t.PoisonFlags == nil {
			t.PoisonFlags = []string{}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MCPShadowToolServer 是影子工具告警里涉及的一台服务器（工具在此的指纹/风险标签）。
type MCPShadowToolServer struct {
	ServerID   string   `json:"server_id"`
	ServerName string   `json:"server_name"`
	SchemaHash string   `json:"schema_hash"`
	RiskTags   []string `json:"risk_tags"`
}

// MCPShadowToolWarning 是一条影子工具告警：同一 tool_name 出现在多台 server 上。
// 影子工具威胁：恶意/被攻陷的 server 提供与可信 server 同名的工具，诱导 agent 误调用。
type MCPShadowToolWarning struct {
	ToolName       string                `json:"tool_name"`
	Servers        []MCPShadowToolServer `json:"servers"`
	SchemaDiverges bool                  `json:"schema_diverges"` // 同名但指纹不一致=定义不同，更可疑
	Reason         string                `json:"reason"`
}

// DetectShadowTools 纯函数：在租户全量工具里找“同名跨 server”的影子工具。
// 同 schema 的多处登记只产提示；schema diverges 的新工具由 ApplySupplyChainSync 自动隔离。
// serverNames 为 server_id→中文名映射（可空，缺则回退 id）。
// 判据：同一 tool_name 出现在 ≥2 台不同 server → 影子工具告警；若这些同名工具的
// schema_hash 不一致，标 SchemaDiverges=true（定义不同=更可能是冒充而非同一工具多处登记）。
func DetectShadowTools(tools []*MCPTool, serverNames map[string]string) []MCPShadowToolWarning {
	byName := map[string][]*MCPTool{}
	order := []string{}
	for _, t := range tools {
		if t == nil || t.Removed || t.ToolName == "" {
			continue
		}
		if _, ok := byName[t.ToolName]; !ok {
			order = append(order, t.ToolName)
		}
		byName[t.ToolName] = append(byName[t.ToolName], t)
	}

	var out []MCPShadowToolWarning
	for _, name := range order {
		group := byName[name]
		// 去重 server_id（同一 server 同名工具只算一次）
		seenServer := map[string]bool{}
		var servers []MCPShadowToolServer
		hashes := map[string]bool{}
		for _, t := range group {
			if seenServer[t.ServerID] {
				continue
			}
			seenServer[t.ServerID] = true
			nm := serverNames[t.ServerID]
			if nm == "" {
				nm = t.ServerID
			}
			servers = append(servers, MCPShadowToolServer{
				ServerID: t.ServerID, ServerName: nm, SchemaHash: t.SchemaHash, RiskTags: t.RiskTags,
			})
			hashes[t.SchemaHash] = true
		}
		if len(servers) < 2 {
			continue // 只在单台 server = 非影子
		}
		sort.Slice(servers, func(i, j int) bool { return servers[i].ServerName < servers[j].ServerName })
		diverges := len(hashes) > 1
		reason := fmt.Sprintf("工具「%s」在 %d 台 MCP 服务上同名出现", name, len(servers))
		if diverges {
			reason += "，且定义指纹不一致——可能有服务在冒充同名工具诱导误调用"
		} else {
			reason += "，请确认是否为预期的多处登记"
		}
		out = append(out, MCPShadowToolWarning{
			ToolName: name, Servers: servers, SchemaDiverges: diverges, Reason: reason,
		})
	}
	return out
}

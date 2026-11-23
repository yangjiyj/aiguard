package repository

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MCPPolicy 是 MCP 工具调用权限策略：主体作用域（scope_type+scope_ref 通配回退）
// × server（”=全部）× tool_pattern（”=全部 / 精确 / 'ns.*' 前缀 glob）三维匹配。
// mode 在策略层原样存取、原样下发——SECURITY_AUDIT_ONLY 的钳制只发生在
// gateway-core 决策器（clampModeToCeiling），本层绝不掺和，保证留痕可回放。
type MCPPolicy struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	ScopeType   string `json:"scope_type"`
	ScopeRef    string `json:"scope_ref"`
	ServerID    string `json:"server_id"`
	ToolPattern string `json:"tool_pattern"`
	// TargetKind 策略目标类别（迁移 860）：tool（默认，tools/call）/resource/prompt/method。
	TargetKind string `json:"target_kind"`
	// ArgConditions 参数条件（迁移 863，W1 1.12）：全部成立时本策略才命中；空 = 不看参数。
	ArgConditions []MCPArgCondition `json:"arg_conditions"`
	Mode          string            `json:"mode"`           // observe | audit | strict
	DefaultAction string            `json:"default_action"` // allow | audit | confirm | block
	Priority      int               `json:"priority"`
	Enabled       bool              `json:"enabled"`
	Note          string            `json:"note"`
	CreatedBy     string            `json:"created_by,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// MCPPolicyScope 是一次 tools/call 的六元组主体 + server/tool 定位维度。
type MCPPolicyScope struct {
	TenantID  string
	ProjectID string
	UserID    string
	KeyPrefix string
	AgentID   string
	SessionID string
	ServerID  string
	ToolName  string
	// TargetKind 空 = tool。策略只与同类别目标匹配。
	TargetKind string
	// DepartmentID 调用者所在部门（W1 1.12，由控制面按 user_id 反查，网关不传）。
	DepartmentID string
	// ArgumentsJSON 为 tools/call 参数；nil 表示参数未知，此时带参数条件的策略一律不参与解析
	//（只收窄、不放宽）。IncludeConditional=true 时忽略参数、带条件的策略也参与排序（构造 arg_chain 用）。
	ArgumentsJSON      *string
	IncludeConditional bool
}

// NormalizeMCPTargetKind 归一目标类别；空 = tool，未知值返回 ok=false。
func NormalizeMCPTargetKind(kind string) (string, bool) {
	switch strings.TrimSpace(kind) {
	case "", "tool":
		return "tool", true
	case "resource", "prompt", "method":
		return strings.TrimSpace(kind), true
	default:
		return "", false
	}
}

// ResolveMCPPolicy 从候选策略中解析出最特定的一条命中（纯函数，可单测）。
// 匹配：enabled ∧ tenant 一致 ∧ 主体作用域匹配（scope_ref=”=该档位通配）
// ∧ server 匹配（server_id=”=通配）∧ tool 匹配（”=通配 / 精确 / 前缀 glob）。
// 排序取第一：scopeRank（session>key>agent>user>project>tenant，同 agentGuardScopeRank）
// → server 特定 > 通配 → tool 精确 > glob > 通配 → priority 大者 → created_at 新者。
// 全 miss 返回 nil，调用方折算为 {matched:false, mode:'audit', action:'audit'}
// （observe-first 上线姿态；默认拒绝交给租户级通配 block 策略，不硬编码在此）。
func ResolveMCPPolicy(policies []*MCPPolicy, scope MCPPolicyScope) *MCPPolicy {
	candidates := ResolveMCPPolicyCandidates(policies, scope)
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0]
}

// ResolveMCPPolicyCandidates 返回命中 scope 的全部候选策略，按解析优先级降序排序
// （胜出者在 [0]）。ResolveMCPPolicy 取首个即胜出者；simulate 预演端点用它回全排序候选，
// 二者共用同一排序，保证「预演」与「运行时解析」口径完全一致。
func ResolveMCPPolicyCandidates(policies []*MCPPolicy, scope MCPPolicyScope) []*MCPPolicy {
	var matches []*MCPPolicy
	scopeKind, _ := NormalizeMCPTargetKind(scope.TargetKind)
	for _, p := range policies {
		if p == nil || !p.Enabled || p.TenantID != scope.TenantID {
			continue
		}
		if policyKind, _ := NormalizeMCPTargetKind(p.TargetKind); policyKind != scopeKind {
			continue
		}
		if !mcpPolicyMatchesScope(p, scope) {
			continue
		}
		if p.ServerID != "" && p.ServerID != scope.ServerID {
			continue
		}
		if !mcpToolPatternMatches(p.ToolPattern, scope.ToolName) {
			continue
		}
		if len(p.ArgConditions) > 0 && !scope.IncludeConditional {
			if scope.ArgumentsJSON == nil || !MatchMCPArgConditions(p.ArgConditions, *scope.ArgumentsJSON, p.DefaultAction) {
				continue
			}
		}
		matches = append(matches, p)
	}
	sort.SliceStable(matches, func(i, j int) bool {
		li := mcpScopeRank(matches[i].ScopeType)
		lj := mcpScopeRank(matches[j].ScopeType)
		if li != lj {
			return li > lj
		}
		si := mcpServerSpecificity(matches[i].ServerID)
		sj := mcpServerSpecificity(matches[j].ServerID)
		if si != sj {
			return si > sj
		}
		ti := mcpToolPatternRank(matches[i].ToolPattern)
		tj := mcpToolPatternRank(matches[j].ToolPattern)
		if ti != tj {
			return ti > tj
		}
		if matches[i].Priority != matches[j].Priority {
			return matches[i].Priority > matches[j].Priority
		}
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	return matches
}

// mcpPolicyMatchesScope 判断策略主体作用域是否命中。与 agentGuardPolicyMatchesScope
// 的差异：MCP 策略约定 scope_ref=” 表示「该档位通配」（如 scope_type=key + scope_ref 空
// = 覆盖全部密钥），而非不合法配置。
func mcpPolicyMatchesScope(p *MCPPolicy, scope MCPPolicyScope) bool {
	switch p.ScopeType {
	case "tenant":
		return p.ScopeRef == "" || p.ScopeRef == scope.TenantID
	case "project":
		return p.ScopeRef == "" || p.ScopeRef == scope.ProjectID
	case "user":
		return p.ScopeRef == "" || p.ScopeRef == scope.UserID
	case "department":
		return p.ScopeRef == "" || p.ScopeRef == scope.DepartmentID
	case "key":
		return p.ScopeRef == "" || p.ScopeRef == scope.KeyPrefix
	case "agent":
		return p.ScopeRef == "" || p.ScopeRef == scope.AgentID
	case "session":
		return p.ScopeRef == "" || p.ScopeRef == scope.SessionID
	default:
		return false
	}
}

// mcpToolPatternMatches 工具名匹配：”/'*'=通配；精确名；'ns.*' 前缀 glob。
func mcpToolPatternMatches(pattern, toolName string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	if pattern == toolName {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(toolName, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

// mcpToolPatternRank 工具模式特异性：精确 2 > 前缀 glob 1 > 通配 0。
func mcpToolPatternRank(pattern string) int {
	pattern = strings.TrimSpace(pattern)
	switch {
	case pattern == "" || pattern == "*":
		return 0
	case strings.HasSuffix(pattern, ".*"):
		return 1
	default:
		return 2
	}
}

// mcpServerSpecificity server 维度特异性：指定 server 1 > 通配 0。
func mcpServerSpecificity(serverID string) int {
	if serverID == "" {
		return 0
	}
	return 1
}

// MCPPolicyShadowWarning 描述一条「block 策略被更宽松/更高优先的 allow 遮蔽」的告警。
// 遮蔽含义：存在 block 策略意图拦截的调用场景，实际解析（ResolveMCPPolicy，与网关运行时同源）
// 的胜出者却是一条 allow——该 block 在这些场景下永不生效。供管理台红字预警与保存前预演。
type MCPPolicyShadowWarning struct {
	ShadowedBlockID string `json:"shadowed_block_id"`
	WinningAllowID  string `json:"winning_allow_id"`
	Scope           string `json:"scope"`
	Reason          string `json:"reason"`
}

// DetectMCPPolicyShadows 纯函数：找出被更宽松 allow 遮蔽的 block 策略（零 DB 副作用，可单测）。
// 口径与网关运行时解析同源——对每对 (block B, allow A) 构造一个二者都命中的代表性 scope，
// 交给 ResolveMCPPolicy 判定胜出者；若胜出者是 allow（可能是 A，也可能是更高优先的第三条 allow），
// 说明 B 在该 scope 下永不生效，记一条告警。每条 block 至多产一条告警（命中即止）。
// 只在 ResolveMCPPolicy 实际返回 allow 时才告警，故无误报（不会警告实际仍生效的 block）。
func DetectMCPPolicyShadows(policies []*MCPPolicy) []MCPPolicyShadowWarning {
	warnings := []MCPPolicyShadowWarning{}
	for _, b := range policies {
		if b == nil || !b.Enabled || b.DefaultAction != AgentGuardActionBlock || len(b.ArgConditions) > 0 {
			continue
		}
		for _, a := range policies {
			if a == nil || a.ID == b.ID || !a.Enabled || a.DefaultAction != AgentGuardActionAllow || len(a.ArgConditions) > 0 {
				continue
			}
			if a.TenantID != b.TenantID {
				continue
			}
			aKind, _ := NormalizeMCPTargetKind(a.TargetKind)
			bKind, _ := NormalizeMCPTargetKind(b.TargetKind)
			if aKind != bKind {
				continue
			}
			scope, ok := mcpPolicyIntersectionScope(a, b)
			if !ok {
				continue
			}
			scope.TargetKind = bKind
			winner := ResolveMCPPolicy(policies, scope)
			if winner == nil || winner.ID == b.ID || winner.DefaultAction != AgentGuardActionAllow {
				continue
			}
			warnings = append(warnings, MCPPolicyShadowWarning{
				ShadowedBlockID: b.ID,
				WinningAllowID:  winner.ID,
				Scope:           describeMCPPolicyScope(b),
				Reason:          mcpShadowReason(winner, b),
			})
			break
		}
	}
	return warnings
}

// mcpPolicyIntersectionScope 构造一个同时命中 a 与 b 的代表性 scope；两者约束不相交时 ok=false。
// 各维度独立求交：主体档位（同档且都非通配但不等 → 不相交）、server（都指定且不同 → 不相交）、
// tool 模式（无公共工具名 → 不相交）。
func mcpPolicyIntersectionScope(a, b *MCPPolicy) (MCPPolicyScope, bool) {
	scope := MCPPolicyScope{TenantID: b.TenantID}
	set := func(scopeType, ref string) bool {
		if ref == "" {
			return true // 该档位通配，不约束具体值
		}
		field := mcpScopeField(&scope, scopeType)
		if field == nil {
			return false // 未知 scope_type
		}
		if *field != "" && *field != ref {
			return false // 同档位已被另一策略钉死为不同值 → 不相交
		}
		*field = ref
		return true
	}
	if !set(a.ScopeType, a.ScopeRef) || !set(b.ScopeType, b.ScopeRef) {
		return scope, false
	}
	// server：都指定且不同 → 不相交；否则取指定的那个（都通配则留空）。
	if a.ServerID != "" && b.ServerID != "" && a.ServerID != b.ServerID {
		return scope, false
	}
	scope.ServerID = a.ServerID
	if scope.ServerID == "" {
		scope.ServerID = b.ServerID
	}
	// tool：求一个同时命中两个模式的代表性工具名。
	toolName, ok := mcpToolPatternIntersection(a.ToolPattern, b.ToolPattern)
	if !ok {
		return scope, false
	}
	scope.ToolName = toolName
	return scope, true
}

// mcpScopeField 返回 scope 中对应 scope_type 的字段指针，未知类型返回 nil。
func mcpScopeField(scope *MCPPolicyScope, scopeType string) *string {
	switch scopeType {
	case "tenant":
		return &scope.TenantID
	case "project":
		return &scope.ProjectID
	case "user":
		return &scope.UserID
	case "department":
		return &scope.DepartmentID
	case "key":
		return &scope.KeyPrefix
	case "agent":
		return &scope.AgentID
	case "session":
		return &scope.SessionID
	default:
		return nil
	}
}

// mcpToolPatternIntersection 求同时命中两个工具模式的代表性工具名；无公共工具时 ok=false。
// 模式语义同 mcpToolPatternMatches：”/'*'=通配、'ns.*'=前缀 glob、其余=精确名。
func mcpToolPatternIntersection(a, b string) (string, bool) {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	aWild := a == "" || a == "*"
	bWild := b == "" || b == "*"
	if aWild && bWild {
		return "", true
	}
	if aWild {
		return mcpToolPatternRepresentative(b), true
	}
	if bWild {
		return mcpToolPatternRepresentative(a), true
	}
	aGlob := strings.HasSuffix(a, ".*")
	bGlob := strings.HasSuffix(b, ".*")
	switch {
	case !aGlob && !bGlob: // 两个精确名
		if a == b {
			return a, true
		}
		return "", false
	case aGlob && !bGlob: // a 是前缀 glob，b 是精确名：b 落在 a 前缀内才相交
		if strings.HasPrefix(b, strings.TrimSuffix(a, "*")) {
			return b, true
		}
		return "", false
	case !aGlob && bGlob:
		if strings.HasPrefix(a, strings.TrimSuffix(b, "*")) {
			return a, true
		}
		return "", false
	default: // 两个前缀 glob：一个前缀是另一个的前缀才相交，取更长（更严）的前缀
		pa := strings.TrimSuffix(a, "*")
		pb := strings.TrimSuffix(b, "*")
		if strings.HasPrefix(pa, pb) {
			return pa + "x", true
		}
		if strings.HasPrefix(pb, pa) {
			return pb + "x", true
		}
		return "", false
	}
}

// mcpToolPatternRepresentative 造一个命中给定非通配模式的代表性工具名（精确名原样；glob 造前缀内示例）。
func mcpToolPatternRepresentative(pattern string) string {
	if strings.HasSuffix(pattern, ".*") {
		return strings.TrimSuffix(pattern, "*") + "x"
	}
	return pattern
}

// describeMCPPolicyScope 把策略的作用域拼成人类可读串（供告警展示，纯中文/标识符，无裸英文枚举）。
func describeMCPPolicyScope(p *MCPPolicy) string {
	scopeRef := p.ScopeRef
	if scopeRef == "" {
		scopeRef = "全部"
	}
	server := p.ServerID
	if server == "" {
		server = "全部服务"
	}
	tool := p.ToolPattern
	if tool == "" || tool == "*" {
		tool = "全部工具"
	}
	return fmt.Sprintf("%s=%s · 服务=%s · 工具=%s", p.ScopeType, scopeRef, server, tool)
}

// mcpShadowReason 生成遮蔽原因说明（中文），点明胜出 allow 在何维度更优先。
func mcpShadowReason(winner, blocked *MCPPolicy) string {
	switch {
	case agentGuardScopeRank(winner.ScopeType) > agentGuardScopeRank(blocked.ScopeType):
		return fmt.Sprintf("放行策略 %s 的作用域档位（%s）比拦截策略（%s）更高优先，将覆盖此拦截", winner.ID, winner.ScopeType, blocked.ScopeType)
	case mcpServerSpecificity(winner.ServerID) > mcpServerSpecificity(blocked.ServerID):
		return fmt.Sprintf("放行策略 %s 指定了更具体的服务，优先级高于此通配拦截", winner.ID)
	case mcpToolPatternRank(winner.ToolPattern) > mcpToolPatternRank(blocked.ToolPattern):
		return fmt.Sprintf("放行策略 %s 的工具匹配更精确，优先级高于此拦截", winner.ID)
	case winner.Priority > blocked.Priority:
		return fmt.Sprintf("放行策略 %s 的优先级（%d）高于此拦截（%d）", winner.ID, winner.Priority, blocked.Priority)
	default:
		return fmt.Sprintf("放行策略 %s 在同等作用域下更晚创建/更优先，将覆盖此拦截", winner.ID)
	}
}

// MCPPoliciesRepository 负责 mcp_policies 表的读写。
type MCPPoliciesRepository struct {
	db *pgxpool.Pool
}

func NewMCPPoliciesRepository(db *pgxpool.Pool) *MCPPoliciesRepository {
	return &MCPPoliciesRepository{db: db}
}

const mcpPolicyColumns = `id, tenant_id, scope_type, scope_ref, server_id, tool_pattern,
	mode, default_action, priority, enabled, note, created_by, created_at, updated_at, target_kind,
	COALESCE(arg_conditions, '[]'::jsonb)`

// Create 创建一条策略；mode/default_action/scope_type/target_kind 缺省落 audit/audit/tenant/tool。
func (r *MCPPoliciesRepository) Create(ctx context.Context, p *MCPPolicy) error {
	return createMCPPolicy(ctx, r.db, p)
}

type mcpPolicyWriter interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func createMCPPolicy(ctx context.Context, db mcpPolicyWriter, p *MCPPolicy) error {
	if p == nil {
		return errors.New("policy is nil")
	}
	if p.ID == "" {
		p.ID = "mcppol_" + uuid.New().String()[:8]
	}
	if p.ScopeType == "" {
		p.ScopeType = "tenant"
	}
	if p.Mode == "" {
		p.Mode = AgentGuardModeAudit
	}
	if p.DefaultAction == "" {
		p.DefaultAction = AgentGuardActionAudit
	}
	kind, ok := NormalizeMCPTargetKind(p.TargetKind)
	if !ok {
		return fmt.Errorf("invalid target_kind %q", p.TargetKind)
	}
	p.TargetKind = kind
	argConditions, err := encodeMCPArgConditionsColumn(p)
	if err != nil {
		return err
	}
	return db.QueryRow(ctx, `
		INSERT INTO mcp_policies
			(id, tenant_id, scope_type, scope_ref, server_id, tool_pattern,
			 mode, default_action, priority, enabled, note, created_by, target_kind, arg_conditions)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING created_at, updated_at`,
		p.ID, p.TenantID, p.ScopeType, p.ScopeRef, p.ServerID, p.ToolPattern,
		p.Mode, p.DefaultAction, p.Priority, p.Enabled, p.Note, p.CreatedBy, p.TargetKind, argConditions,
	).Scan(&p.CreatedAt, &p.UpdatedAt)
}

// Update 按租户 + id 更新一条策略（租户硬隔离）；无匹配行返回 pgx.ErrNoRows。
func (r *MCPPoliciesRepository) Update(ctx context.Context, p *MCPPolicy) error {
	return updateMCPPolicy(ctx, r.db, p)
}

func updateMCPPolicy(ctx context.Context, db mcpPolicyWriter, p *MCPPolicy) error {
	if p == nil {
		return errors.New("policy is nil")
	}
	if p.Mode == "" {
		p.Mode = AgentGuardModeAudit
	}
	if p.DefaultAction == "" {
		p.DefaultAction = AgentGuardActionAudit
	}
	kind, ok := NormalizeMCPTargetKind(p.TargetKind)
	if !ok {
		return fmt.Errorf("invalid target_kind %q", p.TargetKind)
	}
	p.TargetKind = kind
	// ArgConditions 为 nil = 调用方没带该字段（如控制台启停开关），保留库里原值；
	// 显式空数组才清空。
	var argConditions []byte
	if p.ArgConditions != nil {
		encoded, err := encodeMCPArgConditionsColumn(p)
		if err != nil {
			return err
		}
		argConditions = encoded
	}
	row := db.QueryRow(ctx, `
		UPDATE mcp_policies SET
			scope_type = $3, scope_ref = $4, server_id = $5, tool_pattern = $6,
			mode = $7, default_action = $8, priority = $9, enabled = $10, note = $11,
			target_kind = $12, arg_conditions = COALESCE($13::jsonb, arg_conditions), updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
		RETURNING created_at, updated_at, created_by, arg_conditions`,
		p.ID, p.TenantID, p.ScopeType, p.ScopeRef, p.ServerID, p.ToolPattern,
		p.Mode, p.DefaultAction, p.Priority, p.Enabled, p.Note, p.TargetKind, argConditions)
	var stored []byte
	if err := row.Scan(&p.CreatedAt, &p.UpdatedAt, &p.CreatedBy, &stored); err != nil {
		return err
	}
	return decodeMCPArgConditionsColumn(stored, p)
}

// Delete 按租户 + id 删除一条策略；无匹配行返回 pgx.ErrNoRows。
func (r *MCPPoliciesRepository) Delete(ctx context.Context, tenantID, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM mcp_policies WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// Get 按租户 + id 读回一条策略；无行时返回 pgx.ErrNoRows。
func (r *MCPPoliciesRepository) Get(ctx context.Context, tenantID, id string) (*MCPPolicy, error) {
	row := r.db.QueryRow(ctx, `SELECT `+mcpPolicyColumns+` FROM mcp_policies WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return scanMCPPolicy(row)
}

// ListByTenant 按租户列出策略；serverID 非空时附加 server 维度过滤
// （含 server_id=” 的通配策略——它们对该 server 同样生效，管理台按 server 查看时应一并展示）。
func (r *MCPPoliciesRepository) ListByTenant(ctx context.Context, tenantID, serverID string) ([]*MCPPolicy, error) {
	query := `SELECT ` + mcpPolicyColumns + ` FROM mcp_policies WHERE tenant_id = $1 ORDER BY priority DESC, created_at DESC`
	args := []interface{}{tenantID}
	if serverID != "" {
		query = `SELECT ` + mcpPolicyColumns + ` FROM mcp_policies
			WHERE tenant_id = $1 AND (server_id = $2 OR server_id = '')
			ORDER BY priority DESC, created_at DESC`
		args = append(args, serverID)
	}
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*MCPPolicy
	for rows.Next() {
		p, err := scanMCPPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type mcpPolicyScanner interface {
	Scan(dest ...any) error
}

func scanMCPPolicy(row mcpPolicyScanner) (*MCPPolicy, error) {
	p := &MCPPolicy{}
	var argConditions []byte
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.ScopeType, &p.ScopeRef, &p.ServerID, &p.ToolPattern,
		&p.Mode, &p.DefaultAction, &p.Priority, &p.Enabled, &p.Note, &p.CreatedBy,
		&p.CreatedAt, &p.UpdatedAt, &p.TargetKind, &argConditions,
	); err != nil {
		return nil, err
	}
	if err := decodeMCPArgConditionsColumn(argConditions, p); err != nil {
		return nil, err
	}
	return p, nil
}

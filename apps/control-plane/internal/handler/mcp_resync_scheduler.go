package handler

// W1 1.4：MCP 能力清单定时重同步 + 漂移告警。
//
// 手动 POST /admin/v1/mcp-servers/{id}/sync 与定时任务共用 runMCPServerSync，保证
// 两条路径的指纹、投毒扫描、供应链准入完全一致。定时任务：
//   - 周期由 MCP_RESYNC_INTERVAL 配置（Go duration，默认 1h；"0"/"off" 关闭）；
//   - 每轮扫描所有「在用 + 已登记地址」的 server（streamable_http / sse / auto 均支持），并发 1（逐个串行），单个超时沿用 mcpSyncTimeout；
//   - 多副本部署下用 PG 咨询锁保证同一时刻只有一个副本在跑；
//   - 清单哈希变化或本轮新增隔离工具时写告警收件箱（同一 server 未读告警按 group_key 折叠）+ 操作审计。
//
// 启动接线：cmd/server/main.go 需调用 handler.StartMCPResyncScheduler(ctx, deps, db)。
// main.go 不属于 W1，接线由集成人追加（见 docs/changelog-fragments/ws1.md）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const (
	mcpResyncDefaultInterval = time.Hour
	mcpResyncMinInterval     = time.Minute
	mcpResyncLockSeed        = "mcp_resync_scheduler"
	mcpDriftAlertType        = "mcp_manifest_drift"
	mcpResyncSystemActor     = "system:mcp_resync"
)

// mcpSyncFetchError 标记「拉取上游清单」阶段的失败（手动同步映射为 502）。
type mcpSyncFetchError struct{ Err error }

func (e *mcpSyncFetchError) Error() string { return e.Err.Error() }
func (e *mcpSyncFetchError) Unwrap() error { return e.Err }

type mcpManifestFetcher func(ctx context.Context, server *repository.MCPServer) ([]mcpManifestTool, error)
type mcpDescriptionScanner func(ctx context.Context, requestID, toolName, description string) ([]string, error)

// mcpSyncOutcome 是一次同步的全部结果（手动同步响应与定时任务告警共用）。
type mcpSyncOutcome struct {
	NewHash         string
	PreviousHash    string
	Changed         bool
	Tools           []*repository.MCPTool
	PoisonedCount   int
	ProtocolVersion string
	Supply          *repository.MCPSupplyChainSyncResult
}

// runMCPServerSync 拉清单 → 单工具指纹 + 风险标注 → 描述投毒扫描 → 供应链准入落库。
// 由原 SyncMCPServer 处理器主体原样抽出，行为不变。
func runMCPServerSync(ctx context.Context, deps *Dependencies, tenantID string, server *repository.MCPServer, fetch mcpManifestFetcher, scan mcpDescriptionScanner) (*mcpSyncOutcome, error) {
	// 全局路由中间件 30s Timeout，同步外呼必须自限更短，慢 server 不能顶穿请求超时。
	syncCtx, cancel := context.WithTimeout(ctx, mcpSyncTimeout)
	defer cancel()

	manifest, err := fetch(syncCtx, server)
	if err != nil {
		return nil, &mcpSyncFetchError{Err: err}
	}

	// 工具级：风险启发式标注 + 单工具指纹。
	toolRows := make([]*repository.MCPTool, 0, len(manifest))
	for _, t := range manifest {
		if t.Name == "" {
			continue
		}
		toolRows = append(toolRows, &repository.MCPTool{
			ToolName:    t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
			RiskTags:    annotateMCPRiskTags(t.Name, t.Description, t.Annotations),
			SchemaHash:  mcpToolSchemaHash(t.Description, t.InputSchema),
		})
	}

	// 描述投毒扫描是“自动批准首次快照”的必要条件。扫描不可达不会让资产同步丢失，
	// 但新/未验证工具会以 description_scan_unavailable 自动隔离，不能把“未知”冒充“干净”。
	poisonedCount := 0
	descriptionScanComplete := true
	// 读不到防护项设置就不落库：按默认（告警放行）写会覆盖已配置的阻断。
	protections, err := mcpTenantProtections(ctx, deps, tenantID)
	if err != nil {
		return nil, err
	}
	scanCtx, scanCancel := context.WithTimeout(ctx, mcpPoisonScanBudgetFor(protections))
	for _, t := range toolRows {
		if t.Description == "" {
			continue
		}
		if scanCtx.Err() != nil {
			descriptionScanComplete = false
			break
		}
		flags, scanErr := scan(scanCtx, server.ID+":"+t.ToolName, t.ToolName, t.Description)
		if scanErr != nil {
			descriptionScanComplete = false
			continue
		}
		if len(flags) > 0 {
			t.PoisonFlags = flags
			poisonedCount++
		}
	}
	scanCancel()

	// 清单级：内容哈希即版本；与库里 manifest_hash 不一致 = 能力变更（rug-pull 标记）。
	newHash := mcpManifestHash(manifest)
	previousHash := server.ManifestHash
	changed := previousHash != "" && previousHash != newHash
	protocolVersion, _ := server.Capabilities["protocol_version"].(string)

	manifestSnapshot, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to encode MCP manifest snapshot")
	}
	supplyResult, err := deps.MCPSupplyChainRepo.ApplySupplyChainSync(ctx, repository.MCPSupplyChainSyncInput{
		TenantID: tenantID, ServerID: server.ID, ManifestHash: newHash,
		ManifestSnapshot: manifestSnapshot, ProtocolVersion: protocolVersion, Tools: toolRows,
		CapabilityPatch:         mcpSyncCapabilityPatch(server),
		DescriptionScanComplete: descriptionScanComplete,
		Protections:             protections,
	})
	if err != nil {
		return nil, err
	}
	return &mcpSyncOutcome{
		NewHash: newHash, PreviousHash: previousHash, Changed: changed, Tools: toolRows,
		PoisonedCount: poisonedCount, ProtocolVersion: protocolVersion, Supply: supplyResult,
	}, nil
}

// parseMCPResyncInterval：空 → 默认 1h；"0"/"off"/"false"/"disabled" → 关闭；非法值或小于 1m → 默认并告警。
func parseMCPResyncInterval(raw string) (time.Duration, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "":
		return mcpResyncDefaultInterval, true
	case "0", "off", "false", "disabled":
		return 0, false
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < mcpResyncMinInterval {
		log.Printf("[mcp-resync] MCP_RESYNC_INTERVAL=%q 无效（需 Go duration 且 >= %s），使用默认 %s", raw, mcpResyncMinInterval, mcpResyncDefaultInterval)
		return mcpResyncDefaultInterval, true
	}
	return d, true
}

// mcpResyncTarget 是一台需要定时重同步的 server。
type mcpResyncTarget struct {
	TenantID string
	ServerID string
}

type mcpResyncLister func(ctx context.Context) ([]mcpResyncTarget, error)

// mcpResyncLocker：拿到锁返回 release；没拿到返回 (nil, nil)。
type mcpResyncLocker func(ctx context.Context) (func(), error)

// mcpResyncScheduler 持有一轮重同步所需的全部可注入依赖。
type mcpResyncScheduler struct {
	deps   *Dependencies
	list   mcpResyncLister
	lock   mcpResyncLocker
	fetch  mcpManifestFetcher
	scan   mcpDescriptionScanner
	now    func() time.Time
	logf   func(format string, args ...any)
	inbox  func(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL, groupKey string) (bool, error)
	audit  func(ctx context.Context, op *repository.AuditOperation) error
	server func(ctx context.Context, tenantID, id string) (*repository.MCPServer, error)
}

// mcpResyncRoundResult 汇总一轮结果（测试与日志用）。
type mcpResyncRoundResult struct {
	Skipped bool // 未拿到锁
	Synced  int
	Failed  int
	Drifted int
}

// mcpDriftDetected：清单哈希相对上次成功同步发生变化。
// 注意 Supply.QuarantinedCount 是本轮「处于隔离态」的工具总数（含之前就隔离的存量），
// 不能单独作为漂移信号，否则存量隔离会每轮重复告警；只在哈希变化时用它抬高告警级别。
func mcpDriftDetected(outcome *mcpSyncOutcome) bool {
	return outcome != nil && outcome.Changed
}

func (s *mcpResyncScheduler) runOnce(ctx context.Context) mcpResyncRoundResult {
	var result mcpResyncRoundResult
	release, err := s.lock(ctx)
	if err != nil {
		s.logf("[mcp-resync] 获取调度锁失败，本轮跳过: %v", err)
		result.Skipped = true
		return result
	}
	if release == nil {
		result.Skipped = true
		return result
	}
	defer release()

	targets, err := s.list(ctx)
	if err != nil {
		s.logf("[mcp-resync] 列出待同步服务器失败: %v", err)
		return result
	}
	for _, target := range targets {
		if ctx.Err() != nil {
			return result
		}
		server, err := s.server(ctx, target.TenantID, target.ServerID)
		if err != nil || server == nil {
			result.Failed++
			continue
		}
		outcome, err := runMCPServerSync(ctx, s.deps, target.TenantID, server, s.fetch, s.scan)
		if err != nil {
			// 拉不到只记日志：上次成功的准入快照继续生效（与 D1 同口径），不自作主张改状态。
			result.Failed++
			s.logf("[mcp-resync] 同步失败 tenant=%s server=%s: %v", target.TenantID, target.ServerID, err)
			continue
		}
		result.Synced++
		s.recordAudit(ctx, server, outcome)
		if mcpDriftDetected(outcome) {
			result.Drifted++
			s.raiseDriftAlert(ctx, target.TenantID, server, outcome)
		}
	}
	return result
}

func (s *mcpResyncScheduler) recordAudit(ctx context.Context, server *repository.MCPServer, outcome *mcpSyncOutcome) {
	if s.audit == nil {
		return
	}
	op := &repository.AuditOperation{
		ID:         uuid.New().String(),
		ActionType: "mcp_server.sync",
		ActionDetail: map[string]interface{}{
			"server_id": server.ID, "tenant_id": server.TenantID, "manifest_hash": outcome.NewHash,
			"previous_hash": outcome.PreviousHash, "changed": outcome.Changed, "tool_count": len(outcome.Tools),
			"poisoned_tool_count": outcome.PoisonedCount, "protocol_version": outcome.ProtocolVersion,
			"supply_chain": outcome.Supply, "trigger": "scheduled", "actor": mcpResyncSystemActor,
		},
		TargetType: "mcp_server",
		TargetID:   server.ID,
	}
	if err := s.audit(ctx, op); err != nil {
		s.logf("[mcp-resync] 写操作审计失败 server=%s: %v", server.ID, err)
	}
}

func (s *mcpResyncScheduler) raiseDriftAlert(ctx context.Context, tenantID string, server *repository.MCPServer, outcome *mcpSyncOutcome) {
	s.logf("[mcp-resync] 能力清单漂移 tenant=%s server=%s changed=%v previous=%s new=%s",
		tenantID, server.ID, outcome.Changed, outcome.PreviousHash, outcome.NewHash)
	if s.inbox == nil {
		return
	}
	severity := "medium"
	if outcome.Supply != nil && outcome.Supply.QuarantinedCount > 0 {
		severity = "high"
	}
	body := map[string]any{
		"server_id": server.ID, "server_name": server.Name,
		"previous_hash": outcome.PreviousHash, "manifest_hash": outcome.NewHash,
		"changed": outcome.Changed, "tool_count": len(outcome.Tools),
		"poisoned_tool_count": outcome.PoisonedCount, "detected_at": s.now().UTC().Format(time.RFC3339),
	}
	if outcome.Supply != nil {
		body["quarantined_tool_count"] = outcome.Supply.QuarantinedCount
		body["reasons"] = outcome.Supply.Reasons
		body["server_status"] = outcome.Supply.ServerStatus
	}
	title := fmt.Sprintf("MCP 服务「%s」能力清单发生变化", server.Name)
	if _, err := s.inbox(ctx, tenantID, severity, mcpDriftAlertType, title, body, "/mcp-gateway/servers", "mcp_drift:"+server.ID); err != nil {
		s.logf("[mcp-resync] 写漂移告警失败 server=%s: %v", server.ID, err)
	}
}

// listMCPResyncTargets：跨租户列出在用、已登记地址的 server（含 sse / auto：旧 SSE 现已支持定时重同步）。
func listMCPResyncTargets(db *pgxpool.Pool) mcpResyncLister {
	return func(ctx context.Context) ([]mcpResyncTarget, error) {
		rows, err := db.Query(ctx, `
			SELECT tenant_id, id FROM mcp_servers
			WHERE lower(COALESCE(status,'')) IN ('active','approved')
			  AND COALESCE(server_url,'') <> ''
			ORDER BY last_synced_at NULLS FIRST, id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []mcpResyncTarget
		for rows.Next() {
			var target mcpResyncTarget
			if err := rows.Scan(&target.TenantID, &target.ServerID); err != nil {
				return nil, err
			}
			out = append(out, target)
		}
		return out, rows.Err()
	}
}

// pgMCPResyncLocker 用会话级咨询锁保证多副本只有一个在跑本轮。
func pgMCPResyncLocker(db *pgxpool.Pool) mcpResyncLocker {
	return func(ctx context.Context) (func(), error) {
		conn, err := db.Acquire(ctx)
		if err != nil {
			return nil, err
		}
		var locked bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, mcpResyncLockSeed).Scan(&locked); err != nil {
			raw := conn.Hijack()
			_ = raw.Close(context.Background())
			return nil, err
		}
		if !locked {
			conn.Release()
			return nil, nil
		}
		return func() {
			var unlocked bool
			if err := conn.QueryRow(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, mcpResyncLockSeed).Scan(&unlocked); err != nil || !unlocked {
				raw := conn.Hijack()
				_ = raw.Close(context.Background())
				return
			}
			conn.Release()
		}, nil
	}
}

var errMCPResyncNotConfigured = errors.New("mcp resync dependencies not configured")

func newMCPResyncScheduler(deps *Dependencies, db *pgxpool.Pool) (*mcpResyncScheduler, error) {
	if deps == nil || db == nil || deps.MCPServerRepo == nil || deps.MCPSupplyChainRepo == nil {
		return nil, errMCPResyncNotConfigured
	}
	s := &mcpResyncScheduler{
		deps:   deps,
		list:   listMCPResyncTargets(db),
		lock:   pgMCPResyncLocker(db),
		fetch:  fetchMCPManifestForServer,
		scan:   newSecurityEngineClient(deps.SecurityEngineURL, deps.SecurityEngineInternalToken).ScanToolDescriptionChecked,
		now:    time.Now,
		logf:   log.Printf,
		server: deps.MCPServerRepo.Get,
	}
	if deps.AlertService != nil {
		s.inbox = deps.AlertService.UpsertByGroup
	}
	if deps.SystemRepo != nil {
		s.audit = deps.SystemRepo.CreateAuditOperation
	}
	return s, nil
}

// StartMCPResyncScheduler 启动定时重同步（后台 goroutine，ctx 取消即退出）。
// 间隔读 MCP_RESYNC_INTERVAL；关闭时直接返回。
func StartMCPResyncScheduler(ctx context.Context, deps *Dependencies, db *pgxpool.Pool) {
	interval, enabled := parseMCPResyncInterval(os.Getenv("MCP_RESYNC_INTERVAL"))
	if !enabled {
		log.Printf("[mcp-resync] 已关闭（MCP_RESYNC_INTERVAL）")
		return
	}
	scheduler, err := newMCPResyncScheduler(deps, db)
	if err != nil {
		log.Printf("[mcp-resync] 未启动: %v", err)
		return
	}
	log.Printf("[mcp-resync] 已启动，间隔 %s", interval)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r := scheduler.runOnce(ctx)
				if !r.Skipped && (r.Synced > 0 || r.Failed > 0) {
					log.Printf("[mcp-resync] 本轮完成 synced=%d failed=%d drifted=%d", r.Synced, r.Failed, r.Drifted)
				}
			}
		}
	}()
}

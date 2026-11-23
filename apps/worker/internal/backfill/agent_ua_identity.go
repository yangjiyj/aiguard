package backfill

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/jackc/pgx/v5"
)

// agentUAIdentityMigration 是写入 agent_protocol_repairs.migration 的迁移号，
// 必须与注册本任务的迁移文件编号一致。
const agentUAIdentityMigration = "991"

// agentUAIdentityCodexMigration 是 agent_ua_identity_v2（Codex 客户端补齐后的回填）的迁移号。
const agentUAIdentityCodexMigration = "1011"

// agentUAIdentitySpec 是一个 UA 回填任务的范围。两个任务共用同一套候选/修正 SQL 与识别逻辑。
type agentUAIdentitySpec struct {
	// Migration 写入 agent_protocol_repairs.migration，同一行同一迁移只修一次（幂等屏障）。
	Migration string
	// WindowDays 是候选窗口：任务开始时间往前多少天。
	WindowDays int
	// AllowGenericClientHeader 允许改写"来源 client_header 但声明值是通用角色"的行（v1 的 WorkBuddy 场景）。
	AllowGenericClientHeader bool
	// Products 非空时只改写成这些产品；nil 表示任何具体产品。
	Products map[string]bool
}

// agentUAIdentitySpecFor 返回任务对应的回填范围。
//
// v1（迁移 991）：已在各现场跑完，范围保持不变。
// v2（迁移 1011）：网关补齐 Codex 官方客户端（codex-tui、codex_vscode、codex_cli_rs、originator 头…）后，
// 把此前被内容兜底错判的历史行改回 openai-codex。只改 Codex、只改弱来源（content / message_protocol /
// user_agent_runtime / 空），不碰客户端声明头，窗口放宽到 90 天以覆盖升级前的存量。
func agentUAIdentitySpecFor(taskName string) (agentUAIdentitySpec, bool) {
	switch taskName {
	case AgentUAIdentityTask:
		return agentUAIdentitySpec{Migration: agentUAIdentityMigration, WindowDays: 30, AllowGenericClientHeader: true}, true
	case AgentUAIdentityCodexTask:
		return agentUAIdentitySpec{Migration: agentUAIdentityCodexMigration, WindowDays: 90,
			Products: map[string]bool{"openai-codex": true}}, true
	}
	return agentUAIdentitySpec{}, false
}

// agentUAWeakSources 是可以被存储的请求头证据改写的识别来源（与 select SQL 一致）。
var agentUAWeakSources = map[string]bool{"": true, "message_protocol": true, "content": true, "user_agent_runtime": true}

// agentUAIdentityRow 是一行候选：用存储的 User-Agent 与声明类型还原请求头后重新识别。
type agentUAIdentityRow struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	RequestID         string    `json:"request_id"`
	CreatedAt         time.Time `json:"created_at"`
	UserAgent         string    `json:"user_agent"`
	Originator        string    `json:"originator"`
	DeclaredType      string    `json:"declared_type"`
	AgentType         string    `json:"agent_type"`
	Source            string    `json:"source"`
	Confidence        *float64  `json:"confidence"`
	EvidenceRunID     *string   `json:"evidence_run_id"`
	EvidenceRunSource *string   `json:"evidence_run_source"`
	SessionAgentType  *string   `json:"session_agent_type"`
}

// agentUAIdentityFix 是单行修正：新产品、来源固定 user_agent、置信度取检测结果。
type agentUAIdentityFix struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	RequestID        string          `json:"request_id"`
	CreatedAt        time.Time       `json:"created_at"`
	NewType          string          `json:"new_type"`
	Confidence       float64         `json:"confidence"`
	PreviousIdentity json.RawMessage `json:"previous_identity"`
	// PreviousType 是被修复行修复前的 agent_type（原样与 agentdetect 归一化各一份），
	// 会话已存值等于它，说明会话的错误值就是这行带进去的，同样可以被纠正。
	PreviousType     string `json:"previous_type"`
	PreviousTypeNorm string `json:"previous_type_norm"`
}

// detectAgentUAIdentity 返回应写入的产品；ok=false 表示不动。
// 只认 user_agent 来源且是具体产品的结果：通用角色、运行时（vscode）、待识别占位都不算。
func detectAgentUAIdentity(row agentUAIdentityRow, spec agentUAIdentitySpec) (agentdetect.Detection, bool) {
	if !agentUAWeakSources[row.Source] && !(spec.AllowGenericClientHeader && row.Source == "client_header") {
		return agentdetect.Detection{}, false
	}
	header := http.Header{}
	if row.UserAgent != "" {
		header.Set("User-Agent", row.UserAgent)
	}
	if row.Originator != "" {
		header.Set("Originator", row.Originator)
	}
	if row.DeclaredType != "" {
		header.Set("X-Agent-Type", row.DeclaredType)
	}
	detection, err := agentdetect.DetectFromHeaders(header)
	if err != nil || detection.Source != "user_agent" {
		return agentdetect.Detection{}, false
	}
	product := detection.Product
	if product == "" || agentdetect.IsGenericAgentIdentity(product) ||
		agentdetect.IsUpgradeableRuntimeIdentity(product) {
		return agentdetect.Detection{}, false
	}
	if spec.Products != nil && !spec.Products[product] {
		return agentdetect.Detection{}, false
	}
	if agentdetect.NormalizeAgentType(row.AgentType) == product {
		return agentdetect.Detection{}, false
	}
	// 来源已是客户端头时，只有当前值和声明值都是通用角色才允许用 UA 改写；
	// 声明了具体产品（含声明被第二个头顶替的情形）一律尊重。
	if row.Source == "client_header" &&
		(!agentdetect.IsGenericAgentIdentity(row.DeclaredType) || !agentdetect.IsGenericAgentIdentity(row.AgentType)) {
		return agentdetect.Detection{}, false
	}
	return detection, true
}

// 第一步：取一批候选（与其它任务同样的游标/重试语义），锁住行，登记被锁行的重试，
// 并把符合来源条件、尚无 repairs 记录的行带回 Go 做识别。绝不碰 explicit_header、
// product_identity、user_agent 来源，也不碰已绑定登记规则的行。
const agentUAIdentitySelectSQL = `
-- SET LOCAL lock_timeout and SET LOCAL statement_timeout are applied by caller.
WITH bounds AS (
  SELECT started_at - make_interval(days => $11::int) AS since
  FROM migration_backfill_tasks WHERE task_name=$2 AND task_version=$3
), candidates AS MATERIALIZED (
  SELECT rl.id,rl.created_at
  FROM request_logs rl
  -- 下界放在 CASE 外并用 InitPlan 取值：CASE 里的条件在通用计划下进不了索引，
  -- 首批 checkpoint 为空时会把窗口外历史全扫一遍。重试行本来就来自窗口内的候选，不受影响。
  WHERE rl.created_at >= (SELECT since FROM bounds)
  AND CASE WHEN $6::boolean THEN
    EXISTS (SELECT 1 FROM migration_backfill_retry_rows retry
      WHERE retry.task_name=$2 AND retry.task_version=$3
        AND retry.row_id=rl.id AND retry.next_retry_at<=NOW())
  ELSE
    ($4::timestamptz IS NULL OR (rl.created_at,rl.id)>($4::timestamptz,$5::text))
    AND (rl.created_at,rl.id)<=($7::timestamptz,$8::text)
    AND (COALESCE(rl.proxy_user_agent,'')<>''
      OR COALESCE(rl.agent_identity_headers->>'user_agent','')<>''
      OR COALESCE(rl.agent_identity_headers->>'originator','')<>'')
  END
  ORDER BY rl.created_at,rl.id LIMIT $1
), locked AS MATERIALIZED (
  SELECT rl.*
  FROM request_logs rl JOIN candidates candidate ON candidate.id=rl.id
  ORDER BY rl.created_at,rl.id
  FOR NO KEY UPDATE OF rl SKIP LOCKED
), retry_saved AS (
  INSERT INTO migration_backfill_retry_rows(
    task_name,task_version,row_id,row_created_at,attempts,next_retry_at,updated_at
  )
  SELECT $2,$3,candidate.id,candidate.created_at,1,NOW()+INTERVAL '5 seconds',NOW()
  FROM candidates candidate LEFT JOIN locked ON locked.id=candidate.id
  WHERE locked.id IS NULL
  ON CONFLICT(task_name,task_version,row_id) DO UPDATE SET
    attempts=migration_backfill_retry_rows.attempts+1,
    next_retry_at=NOW()+INTERVAL '5 seconds',updated_at=NOW()
  RETURNING row_id
), retry_cleared AS (
  DELETE FROM migration_backfill_retry_rows retry USING locked
  WHERE retry.task_name=$2 AND retry.task_version=$3 AND retry.row_id=locked.id
  RETURNING retry.row_id
), eligible AS (
  SELECT rl.id,rl.tenant_id,rl.request_id,rl.created_at,
    COALESCE(NULLIF(BTRIM(COALESCE(rl.proxy_user_agent,'')),''),rl.agent_identity_headers->>'user_agent','') AS user_agent,
    COALESCE(rl.agent_identity_headers->>'originator','') AS originator,
    COALESCE(rl.agent_identity_headers->>'declared_type','') AS declared_type,
    COALESCE(rl.agent_type,'') AS agent_type,
    COALESCE(rl.agent_detection_source,'') AS source,
    rl.agent_detection_confidence AS confidence,
    rl.evidence_run_id,rl.evidence_run_source,
    s.agent_type AS session_agent_type
  FROM locked rl
  LEFT JOIN agent_sessions s
    ON s.session_id=rl.session_id AND s.tenant_id=rl.tenant_id
  WHERE rl.created_at >= (SELECT since FROM bounds)
    AND rl.agent_identity_rule_id IS NULL
    AND (COALESCE(rl.proxy_user_agent,'')<>''
      OR COALESCE(rl.agent_identity_headers->>'user_agent','')<>''
      OR COALESCE(rl.agent_identity_headers->>'originator','')<>'')
    AND (
      COALESCE(rl.agent_detection_source,'') IN ('','message_protocol','content','user_agent_runtime')
      OR (
        rl.agent_detection_source='client_header'
        AND regexp_replace(lower(btrim(COALESCE(rl.agent_identity_headers->>'declared_type',''))),'[[:space:]_]+','-','g')
          = ANY($9::text[])
      )
    )
    AND NOT EXISTS (
      SELECT 1 FROM agent_protocol_repairs ap
      WHERE ap.migration=$10 AND ap.tenant_id=rl.tenant_id AND ap.request_id=rl.request_id
    )
)
SELECT (SELECT COUNT(*) FROM candidates),(SELECT COUNT(*) FROM retry_saved),
       (SELECT MAX(created_at) FROM candidates),
       COALESCE((SELECT id FROM candidates ORDER BY created_at DESC,id DESC LIMIT 1),''),
       COALESCE((SELECT jsonb_agg(to_jsonb(eligible) ORDER BY created_at,id) FROM eligible),'[]'::jsonb)
`

// 第二步：同一事务内先写前值，再改行，再纠正会话。会话已存值是空/通用值/可升级运行时值
// （$3，来自 agentdetect.SessionOverwritableIdentities），或等于被修复行的前值时才改；
// 已存的其它具体产品不动。同一会话取最早一条被修复行。
// 只有 repairs 写入成功的行才会被更新（审计屏障），已有 repairs 的行不会重复处理。
const agentUAIdentityApplySQL = `
WITH input AS (
  SELECT * FROM jsonb_to_recordset($1::jsonb) AS x(
    id text,tenant_id text,request_id text,created_at timestamptz,
    new_type text,confidence double precision,previous_identity jsonb,
    previous_type text,previous_type_norm text)
), repair_saved AS (
  INSERT INTO agent_protocol_repairs(migration,tenant_id,request_id,previous_identity)
  SELECT $2,tenant_id,request_id,previous_identity FROM input
  ON CONFLICT DO NOTHING
  RETURNING tenant_id,request_id
), changed AS (
  UPDATE request_logs rl SET
    agent_type=input.new_type,
    agent_detection_source='user_agent',
    agent_detection_confidence=input.confidence
  FROM input JOIN repair_saved rs
    ON rs.tenant_id=input.tenant_id AND rs.request_id=input.request_id
  WHERE rl.id=input.id AND rl.tenant_id=input.tenant_id
  RETURNING rl.id,rl.tenant_id,rl.session_id,input.new_type,input.created_at,
    input.previous_type,input.previous_type_norm
), session_pick AS (
  SELECT DISTINCT ON (tenant_id,session_id) tenant_id,session_id,new_type,
    regexp_replace(lower(btrim(COALESCE(previous_type,''))),'[[:space:]_]+','-','g') AS previous_type_key,
    COALESCE(previous_type_norm,'') AS previous_type_norm
  FROM changed WHERE COALESCE(session_id,'')<>''
  ORDER BY tenant_id,session_id,created_at,id
), session_fixed AS (
  UPDATE agent_sessions s SET agent_type=session_pick.new_type
  FROM session_pick
  WHERE s.tenant_id=session_pick.tenant_id AND s.session_id=session_pick.session_id
    AND (
      regexp_replace(lower(btrim(COALESCE(s.agent_type,''))),'[[:space:]_]+','-','g')
        = ANY($3::text[])
      OR regexp_replace(lower(btrim(COALESCE(s.agent_type,''))),'[[:space:]_]+','-','g')
        IN (session_pick.previous_type_key,session_pick.previous_type_norm)
    )
  RETURNING s.session_id
)
SELECT (SELECT COUNT(*) FROM changed),(SELECT COUNT(*) FROM session_fixed)
`

// agentUAGenericArray 是 select SQL 里判断"声明值是否通用"的名单：与
// agentdetect.IsGenericAgentIdentity 同源，并包含空串。
func agentUAGenericArray() []string {
	return append([]string{""}, agentdetect.GenericAgentIdentities()...)
}

func runAgentUAIdentityBatch(ctx context.Context, tx pgx.Tx, task *Task, retryPhase bool) (BatchResult, *time.Time, string, error) {
	var result BatchResult
	var cursorTime *time.Time
	var cursorID string
	var rowsJSON []byte
	spec, ok := agentUAIdentitySpecFor(task.Name)
	if !ok {
		return result, nil, "", fmt.Errorf("unknown agent UA identity task %q", task.Name)
	}
	// client_header 分支只在 v1 打开；空名单让 SQL 里的 = ANY 恒为假。
	generic := []string{}
	if spec.AllowGenericClientHeader {
		generic = agentUAGenericArray()
	}
	if err := tx.QueryRow(ctx, agentUAIdentitySelectSQL,
		task.BatchSize, task.Name, task.Version, task.CheckpointCreatedAt,
		task.CheckpointID, retryPhase, task.UpperCreatedAt, task.UpperID,
		generic, spec.Migration, spec.WindowDays,
	).Scan(&result.Scanned, &result.Skipped, &cursorTime, &cursorID, &rowsJSON); err != nil {
		return result, nil, "", err
	}
	var rows []agentUAIdentityRow
	if err := json.Unmarshal(rowsJSON, &rows); err != nil {
		return result, nil, "", err
	}
	fixes := make([]agentUAIdentityFix, 0, len(rows))
	for _, row := range rows {
		detection, ok := detectAgentUAIdentity(row, spec)
		if !ok {
			continue
		}
		previous, err := json.Marshal(map[string]any{
			"agent_type":          row.AgentType,
			"source":              row.Source,
			"confidence":          row.Confidence,
			"evidence_run_id":     row.EvidenceRunID,
			"evidence_run_source": row.EvidenceRunSource,
			"session_agent_type":  row.SessionAgentType,
		})
		if err != nil {
			return result, nil, "", err
		}
		fixes = append(fixes, agentUAIdentityFix{
			ID: row.ID, TenantID: row.TenantID, RequestID: row.RequestID, CreatedAt: row.CreatedAt,
			NewType: detection.Product, Confidence: detection.Confidence, PreviousIdentity: previous,
			PreviousType: row.AgentType, PreviousTypeNorm: agentdetect.NormalizeAgentType(row.AgentType),
		})
	}
	if len(fixes) > 0 {
		payload, err := json.Marshal(fixes)
		if err != nil {
			return result, nil, "", err
		}
		var changed, sessions int64
		if err = tx.QueryRow(ctx, agentUAIdentityApplySQL, string(payload), spec.Migration, agentdetect.SessionOverwritableIdentities()).Scan(&changed, &sessions); err != nil {
			return result, nil, "", err
		}
		result.Updated = changed
	}
	return result, cursorTime, cursorID, nil
}

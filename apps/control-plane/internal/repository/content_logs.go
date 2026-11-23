package repository

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/internaltitle"
	"github.com/yangjiyj/aiguard/packages/shared-go/userhistory"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// ContentLog represents a single message in a conversation
type ContentLog struct {
	ID               string    `json:"id"`
	RequestID        string    `json:"request_id"`
	TenantID         string    `json:"tenant_id"`
	UserID           string    `json:"user_id"`
	SessionID        string    `json:"session_id"`
	Role             string    `json:"role"` // user, assistant, system
	Content          string    `json:"content"`
	ContentTruncated bool      `json:"content_truncated,omitempty"`
	Tokens           int       `json:"tokens"`
	MessageIndex     *int      `json:"message_index,omitempty"`
	EnvironmentScope string    `json:"environment_scope,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// ContentLogRepository handles content audit log operations
type ContentLogRepository struct {
	db               *pgxpool.Pool
	environmentScope string
}

type ContentSessionListFilter struct {
	IncludeDevTraffic bool
	TenantID          string
	EnvironmentScope  string
	ProjectIDs        []string
	UserID            string
	Keyword           string
	Categories        []string
	Severities        []string
	Dispositions      []string
	StartTime         time.Time
	EndTime           time.Time
	Limit             int
	Offset            int
	SkipTotal         bool
	AlertOnly         bool
}

// NewContentLogRepository creates a new content log repository
func NewContentLogRepository(db *pgxpool.Pool, deploymentScope ...string) *ContentLogRepository {
	scope := retentionartifact.LegacyEnvironmentScope
	if len(deploymentScope) > 0 {
		scope = retentionartifact.NormalizeEnvironmentScope(deploymentScope[0])
	}
	return &ContentLogRepository{db: db, environmentScope: scope}
}

func resolveContentLogEnvironmentScope(explicit, deployment string) string {
	return retentionartifact.ResolveEnvironmentScope(explicit, deployment)
}

// Create inserts a new content log
func (r *ContentLogRepository) Create(ctx context.Context, log *ContentLog) error {
	if log.ID == "" {
		log.ID = "cl_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
	}

	// Truncate content if too long (> 10KB)
	if len(log.Content) > 10240 {
		log.Content = log.Content[:10240] + "...[truncated]"
	}

	log.EnvironmentScope = resolveContentLogEnvironmentScope(log.EnvironmentScope, r.environmentScope)
	query := `
		INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, message_index, environment_scope)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := r.db.Exec(ctx, query,
		log.ID, log.RequestID, log.TenantID, log.UserID, log.SessionID, log.Role, log.Content, log.Tokens, log.MessageIndex, log.EnvironmentScope,
	)
	if err != nil {
		return fmt.Errorf("failed to create content log: %w", err)
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	return nil
}

// ListBySession returns all messages in a session (time-ordered)
func (r *ContentLogRepository) ListBySession(ctx context.Context, tenantID, sessionID string) ([]ContentLog, error) {
	query := `
		SELECT
			cl.id,
			COALESCE(rl.request_id, cl.request_id),
			cl.tenant_id,
			COALESCE(cl.user_id, '') AS user_id,
			cl.session_id,
			cl.role,
			cl.content,
			cl.tokens,
			cl.message_index,
			cl.created_at
		FROM content_logs cl
		LEFT JOIN request_logs rl ON rl.id = cl.request_id
		WHERE cl.tenant_id = $1 AND cl.session_id = $2
		ORDER BY cl.created_at ASC
	`
	rows, err := r.retentionRead().Query(ctx, query, tenantID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list content logs: %w", err)
	}
	defer rows.Close()

	var logs []ContentLog
	for rows.Next() {
		var l ContentLog
		if err := rows.Scan(&l.ID, &l.RequestID, &l.TenantID, &l.UserID, &l.SessionID, &l.Role, &l.Content, &l.Tokens, &l.MessageIndex, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

func (r *ContentLogRepository) ListBySessionScoped(ctx context.Context, tenantID, sessionID string, start, end time.Time, environmentScope string) ([]ContentLog, error) {
	query := `
		SELECT
			cl.id,
			COALESCE(rl.request_id, cl.request_id),
			cl.tenant_id,
			COALESCE(cl.user_id, '') AS user_id,
			cl.session_id,
			cl.role,
			cl.content,
			cl.tokens,
			cl.message_index,
			cl.created_at
		FROM content_logs cl
		LEFT JOIN request_logs rl ON rl.id = cl.request_id AND rl.tenant_id = $1 AND rl.environment_scope = ANY($3) AND rl.created_at >= $4 AND rl.created_at < $5
		WHERE cl.tenant_id = $1 AND cl.session_id = $2
		  AND cl.environment_scope = ANY($3) AND cl.created_at >= $4 AND cl.created_at < $5
		ORDER BY cl.created_at ASC, cl.id ASC
	`
	return r.scanContentLogs(ctx, query, []interface{}{tenantID, sessionID, EnvironmentScopesForRead(environmentScope), start.UTC(), end.UTC()}, "failed to list scoped session content")
}

func (r *ContentLogRepository) scanContentLogs(ctx context.Context, query string, args []interface{}, errorPrefix string) ([]ContentLog, error) {
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errorPrefix, err)
	}
	defer rows.Close()
	logs := make([]ContentLog, 0)
	for rows.Next() {
		var l ContentLog
		if err := rows.Scan(&l.ID, &l.RequestID, &l.TenantID, &l.UserID, &l.SessionID, &l.Role, &l.Content, &l.Tokens, &l.MessageIndex, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

// ListBySessionPage returns one preview page for a session. includeNoise controls
// whether the manager view's user/assistant role filter is applied.
func (r *ContentLogRepository) ListBySessionPage(ctx context.Context, tenantID, sessionID string, includeNoise bool, limit, offset int) ([]ContentLog, int, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := r.retentionRead().Query(ctx, buildSessionContentPageQuery(includeNoise), tenantID, sessionID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list session content page: %w", err)
	}
	defer rows.Close()

	logs := make([]ContentLog, 0, limit)
	total := 0
	for rows.Next() {
		var l ContentLog
		var totalCount int64
		if err := rows.Scan(&l.ID, &l.RequestID, &l.TenantID, &l.UserID, &l.SessionID, &l.Role, &l.Content, &l.Tokens, &l.MessageIndex, &l.CreatedAt, &totalCount); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
		total = int(totalCount)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

func (r *ContentLogRepository) ListBySessionPageScoped(ctx context.Context, tenantID, sessionID string, includeNoise bool, limit, offset int, start, end time.Time, environmentScope string) ([]ContentLog, int, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	query := strings.ReplaceAll(buildSessionContentPageQuery(includeNoise),
		"WHERE cl.tenant_id = $1 AND cl.session_id = $2",
		"WHERE cl.tenant_id = $1 AND cl.session_id = $2 AND cl.environment_scope = ANY($5) AND cl.created_at >= $6 AND cl.created_at < $7")
	query = strings.ReplaceAll(query, "LEFT JOIN request_logs rl ON rl.id = cl.request_id", "LEFT JOIN request_logs rl ON rl.id = cl.request_id AND rl.tenant_id = $1 AND rl.environment_scope = ANY($5) AND rl.created_at >= $6 AND rl.created_at < $7")
	args := []interface{}{tenantID, sessionID, limit, offset, EnvironmentScopesForRead(environmentScope), start.UTC(), end.UTC()}
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list scoped session content page: %w", err)
	}
	defer rows.Close()
	logs := make([]ContentLog, 0, limit)
	total := 0
	totalKnown := offset == 0
	for rows.Next() {
		var l ContentLog
		var totalCount int64
		if err := rows.Scan(&l.ID, &l.RequestID, &l.TenantID, &l.UserID, &l.SessionID, &l.Role, &l.Content, &l.Tokens, &l.MessageIndex, &l.CreatedAt, &totalCount); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
		total = int(totalCount)
		totalKnown = true
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if !totalKnown {
		return logs, -1, nil
	}
	return logs, total, nil
}

func buildSessionContentPageQuery(includeNoise bool) string {
	roleFilter := ""
	if !includeNoise {
		roleFilter = " AND cl.role IN ('user', 'assistant')"
	}

	return fmt.Sprintf(`
		SELECT
			cl.id,
			COALESCE(rl.request_id, cl.request_id),
			cl.tenant_id,
			COALESCE(cl.user_id, '') AS user_id,
			cl.session_id,
			cl.role,
			cl.content,
			cl.tokens,
			cl.message_index,
			cl.created_at,
			COUNT(*) OVER() AS total_count
		FROM content_logs cl
		LEFT JOIN request_logs rl ON rl.id = cl.request_id
		WHERE cl.tenant_id = $1 AND cl.session_id = $2%s
		ORDER BY cl.created_at ASC, cl.id ASC
		LIMIT $3 OFFSET $4
	`, roleFilter)
}

// ListByUser returns recent content logs for a user
func (r *ContentLogRepository) ListByUser(ctx context.Context, tenantID, userID string, limit, offset int) ([]ContentLog, int, error) {
	countQuery := userhistory.AuditOwnersCTE + `SELECT COUNT(*) FROM content_logs WHERE tenant_id = $1 AND user_id IN (SELECT user_id FROM user_history)`
	var total int
	if err := r.db.QueryRow(ctx, countQuery, tenantID, userID).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := userhistory.AuditOwnersCTE + `
		SELECT
			cl.id,
			COALESCE(rl.request_id, cl.request_id),
			cl.tenant_id,
			COALESCE(cl.user_id, '') AS user_id,
			cl.session_id,
			cl.role,
			cl.content,
			cl.tokens,
			cl.message_index,
			cl.created_at
		FROM content_logs cl
		LEFT JOIN request_logs rl ON rl.id = cl.request_id
		WHERE cl.tenant_id = $1 AND cl.user_id IN (SELECT user_id FROM user_history)
		ORDER BY cl.created_at DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := r.db.Query(ctx, query, tenantID, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list user content logs: %w", err)
	}
	defer rows.Close()

	var logs []ContentLog
	for rows.Next() {
		var l ContentLog
		if err := rows.Scan(&l.ID, &l.RequestID, &l.TenantID, &l.UserID, &l.SessionID, &l.Role, &l.Content, &l.Tokens, &l.MessageIndex, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	return logs, total, nil
}

func (r *ContentLogRepository) ListByUserScoped(ctx context.Context, tenantID, userID string, limit, offset int, start, end time.Time, environmentScope string) ([]ContentLog, int, error) {
	scopes := EnvironmentScopesForRead(environmentScope)
	var total int
	if err := r.db.QueryRow(ctx, userhistory.AuditOwnersCTE+`SELECT COUNT(*) FROM content_logs WHERE tenant_id = $1 AND user_id IN (SELECT user_id FROM user_history) AND environment_scope = ANY($3) AND created_at >= $4 AND created_at < $5`, tenantID, userID, scopes, start.UTC(), end.UTC()).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := userhistory.AuditOwnersCTE + `
		SELECT cl.id, COALESCE(rl.request_id, cl.request_id), cl.tenant_id,
			COALESCE(cl.user_id, ''), cl.session_id, cl.role, cl.content, cl.tokens, cl.message_index, cl.created_at
		FROM content_logs cl
		LEFT JOIN request_logs rl ON rl.id = cl.request_id AND rl.tenant_id = $1 AND rl.environment_scope = ANY($3) AND rl.created_at >= $4 AND rl.created_at < $5
		WHERE cl.tenant_id = $1 AND cl.user_id IN (SELECT user_id FROM user_history) AND cl.environment_scope = ANY($3)
		  AND cl.created_at >= $4 AND cl.created_at < $5
		ORDER BY cl.created_at DESC
		LIMIT $6 OFFSET $7
	`
	logs, err := r.scanContentLogs(ctx, query, []interface{}{tenantID, userID, scopes, start.UTC(), end.UTC(), limit, offset}, "failed to list scoped user content logs")
	return logs, total, err
}

type ContentLogSearchFilter struct {
	TenantID         string
	EnvironmentScope string
	Keyword          string
	StartTime        time.Time
	EndTime          time.Time
	Limit            int
	Offset           int
	SkipTotal        bool
	// Role 为空时检索 user 与 assistant；设为 user 或 assistant 时只检索该角色。
	Role string
}

// SearchPage searches retained messages inside a bounded tenant/time window.
// Keyword searches from UI should set SkipTotal: counting every match is much
// more expensive than returning the newest bounded page and is not needed there.
func (r *ContentLogRepository) SearchPage(ctx context.Context, filter ContentLogSearchFilter) ([]ContentLog, int, error) {
	filter.Keyword = strings.TrimSpace(filter.Keyword)
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 100
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	pattern := "%" + escapePostgresLikeLiteral(filter.Keyword) + "%"
	where := []string{
		"cl.tenant_id = $1",
		"cl.role IN ('user', 'assistant')",
		"cl.content ILIKE $2 ESCAPE E'\\\\'",
		"jjdguard_customer_content_text(cl.content)",
	}
	args := []interface{}{filter.TenantID, pattern}
	if filter.Role == "user" || filter.Role == "assistant" {
		args = append(args, filter.Role)
		where = append(where, fmt.Sprintf("cl.role = $%d", len(args)))
	}
	scopeArg, startArg, endArg := 0, 0, 0
	if filter.EnvironmentScope != "" {
		args = append(args, EnvironmentScopesForRead(filter.EnvironmentScope))
		scopeArg = len(args)
		where = append(where, fmt.Sprintf("cl.environment_scope = ANY($%d)", len(args)))
	}
	if !filter.StartTime.IsZero() {
		args = append(args, filter.StartTime)
		startArg = len(args)
		where = append(where, fmt.Sprintf("cl.created_at >= $%d", len(args)))
	}
	if !filter.EndTime.IsZero() {
		args = append(args, filter.EndTime)
		endArg = len(args)
		where = append(where, fmt.Sprintf("cl.created_at < $%d", len(args)))
	}

	total := 0
	if !filter.SkipTotal {
		countQuery := `SELECT COUNT(*) FROM content_logs cl WHERE ` + strings.Join(where, " AND ")
		if err := r.retentionRead().QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
	}

	requestJoin := "LEFT JOIN request_logs rl ON rl.id = cl.request_id AND rl.tenant_id = $1"
	if scopeArg > 0 {
		requestJoin += fmt.Sprintf(" AND rl.environment_scope = ANY($%d)", scopeArg)
	}
	if startArg > 0 {
		requestJoin += fmt.Sprintf(" AND rl.created_at >= $%d", startArg)
	}
	if endArg > 0 {
		requestJoin += fmt.Sprintf(" AND rl.created_at < $%d", endArg)
	}
	query := `
		SELECT
			cl.id,
			COALESCE(rl.request_id, cl.request_id),
			cl.tenant_id,
			COALESCE(cl.user_id, '') AS user_id,
			cl.session_id,
			cl.role,
			cl.content,
			cl.tokens,
			cl.message_index,
			cl.created_at
		FROM content_logs cl
		` + requestJoin + `
			WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY cl.created_at DESC
		LIMIT $` + fmt.Sprintf("%d", len(args)+1) + ` OFFSET $` + fmt.Sprintf("%d", len(args)+2) + `
	`
	queryArgs := append(append([]interface{}{}, args...), filter.Limit, filter.Offset)
	rows, err := r.retentionRead().Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search content logs: %w", err)
	}
	defer rows.Close()

	var logs []ContentLog
	for rows.Next() {
		var l ContentLog
		if err := rows.Scan(&l.ID, &l.RequestID, &l.TenantID, &l.UserID, &l.SessionID, &l.Role, &l.Content, &l.Tokens, &l.MessageIndex, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	if filter.SkipTotal {
		total = len(logs)
	}
	return logs, total, nil
}

// Search keeps the legacy repository contract for non-UI callers.
func (r *ContentLogRepository) Search(ctx context.Context, tenantID, keyword string, limit, offset int) ([]ContentLog, int, error) {
	return r.SearchPage(ctx, ContentLogSearchFilter{TenantID: tenantID, Keyword: keyword, Limit: limit, Offset: offset})
}

// contentLogPruneBatch 是保留期清理每批删除的行数上限：分批短事务，避免磁盘慢时长事务堆积 WAL。
const contentLogPruneBatch = 5000

// contentLogPruneMaxRounds 防止异常情况下正文回收无限循环（5000×10000 远超实际规模）。
const contentLogPruneMaxRounds = 10000

// DeleteOlderThan deletes logs older than retention days, returning rows deleted.
// content_logs 是兼容视图（987）：直接分批删两张底表（消息行与历史表），再回收没有消息行引用的正文。
func (r *ContentLogRepository) DeleteOlderThan(ctx context.Context, retentionDays int) (int64, error) {
	// 脱敏原文留证（迁移 994）与内容留证同一个保留期；表不存在时无操作。
	// 原文留证清理失败只记日志，不能连带跳过下面 content_logs 的保留期清理。
	if _, err := NewRawEvidenceRepository(r.db).DeleteOlderThan(ctx, retentionDays); err != nil {
		log.Printf("[retention] raw evidence prune failed (content logs pruning continues): %v", err)
	}
	// 补丁可能先于迁移 987 上线（或 987 回滚后仍运行新版本）：此时 content_logs 仍是普通表，按原语义删除。
	var dedup bool
	if err := r.db.QueryRow(ctx, `SELECT to_regclass('content_log_entries') IS NOT NULL`).Scan(&dedup); err != nil {
		return 0, fmt.Errorf("failed to detect content log storage layout: %w", err)
	}
	if !dedup {
		var total int64
		for {
			tag, err := internaltitle.Prune(ctx, r.db, "content_logs", "created_at < CURRENT_DATE - INTERVAL '1 day' * $1", true, contentLogPruneBatch, retentionDays)
			if err != nil {
				return total, fmt.Errorf("failed to delete old content logs: %w", err)
			}
			total += tag.RowsAffected()
			if tag.RowsAffected() < contentLogPruneBatch {
				return total, nil
			}
		}
	}

	var total int64
	for _, table := range []string{"content_log_entries", "content_logs_legacy"} {
		for {
			tag, err := internaltitle.Prune(ctx, r.db, table, "created_at < CURRENT_DATE - INTERVAL '1 day' * $1", true, contentLogPruneBatch, retentionDays)
			if err != nil {
				return total, fmt.Errorf("failed to delete old content logs from %s: %w", table, err)
			}
			total += tag.RowsAffected()
			if tag.RowsAffected() < contentLogPruneBatch {
				break
			}
		}
	}
	// 只回收保留期截止时间之前首次出现的正文（之后出现的仍被新消息引用）；被并发写入引用的会跳过，
	// 所以一批删不满不代表回收完了，删到 0 为止。
	for round := 0; round < contentLogPruneMaxRounds; round++ {
		var pruned int
		if err := r.db.QueryRow(ctx,
			`SELECT prune_content_log_bodies($1, (CURRENT_DATE - INTERVAL '1 day' * $2)::timestamptz)`,
			contentLogPruneBatch, retentionDays).Scan(&pruned); err != nil {
			return total, fmt.Errorf("failed to prune content log bodies: %w", err)
		}
		if pruned == 0 {
			break
		}
	}
	return total, nil
}

// contentLogRequestPushdown 先按请求编号解析出 request_logs.id，再以数组条件下推进 content_logs 视图的两支。
// content_logs 是“正文条目 JOIN 去重正文 UNION ALL 旧表”的视图；只靠 JOIN request_logs 时请求条件推不进
// 第一支，计划会把时间窗口内的全部正文条目连同正文扫一遍（客户现场 2 天窗口 420ms、90 天 4 秒）。
// 原有的 JOIN 和条件保持不变，这里只追加一个等价的过滤，结果集不变。
func contentLogRequestPushdown(requestCond string) string {
	return "cl.request_id = ANY(ARRAY(SELECT rlx.id FROM request_logs rlx WHERE rlx.tenant_id = $1 AND " + requestCond + "))"
}

// ListByRequest returns all content logs for a specific request_id
func (r *ContentLogRepository) ListByRequest(ctx context.Context, tenantID, requestID string) ([]ContentLog, error) {
	query := `
		SELECT
			cl.id,
			rl.request_id,
			cl.tenant_id,
			COALESCE(cl.user_id, '') AS user_id,
			cl.session_id,
			cl.role,
			cl.content,
			cl.tokens,
			cl.message_index,
			cl.created_at
		FROM content_logs cl
		JOIN request_logs rl ON rl.id = cl.request_id
		WHERE cl.tenant_id = $1 AND (rl.id = $2 OR rl.request_id = $2)
			AND ` + contentLogRequestPushdown("(rlx.id = $2 OR rlx.request_id = $2)") + `
		ORDER BY cl.created_at ASC, cl.id ASC
	`
	rows, err := r.retentionRead().Query(ctx, query, tenantID, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to list content logs by request: %w", err)
	}
	defer rows.Close()

	var logs []ContentLog
	for rows.Next() {
		var l ContentLog
		if err := rows.Scan(&l.ID, &l.RequestID, &l.TenantID, &l.UserID, &l.SessionID, &l.Role, &l.Content, &l.Tokens, &l.MessageIndex, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

func (r *ContentLogRepository) ListByRequestScoped(
	ctx context.Context,
	tenantID, requestID string,
	start, end time.Time,
	environmentScope string,
) ([]ContentLog, error) {
	args := []interface{}{tenantID, requestID}
	where := []string{"cl.tenant_id = $1", "rl.tenant_id = $1", "(rl.id = $2 OR rl.request_id = $2)",
		contentLogRequestPushdown("(rlx.id = $2 OR rlx.request_id = $2)")}
	if environmentScope != "" {
		args = append(args, EnvironmentScopesForRead(environmentScope))
		where = append(where, fmt.Sprintf("cl.environment_scope = ANY($%d)", len(args)))
		where = append(where, fmt.Sprintf("rl.environment_scope = ANY($%d)", len(args)))
	}
	if !start.IsZero() {
		args = append(args, start)
		where = append(where, fmt.Sprintf("cl.created_at >= $%d", len(args)))
		where = append(where, fmt.Sprintf("rl.created_at >= $%d", len(args)))
	}
	if !end.IsZero() {
		args = append(args, end)
		where = append(where, fmt.Sprintf("cl.created_at < $%d", len(args)))
		where = append(where, fmt.Sprintf("rl.created_at < $%d", len(args)))
	}
	query := `
		SELECT
			cl.id,
			rl.request_id,
			cl.tenant_id,
			COALESCE(cl.user_id, '') AS user_id,
			cl.session_id,
			cl.role,
			cl.content,
			cl.tokens,
			cl.message_index,
			cl.created_at
		FROM content_logs cl
		JOIN request_logs rl ON rl.id = cl.request_id
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY cl.created_at ASC, cl.id ASC
	`
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list scoped content logs by request: %w", err)
	}
	defer rows.Close()
	logs := []ContentLog{}
	for rows.Next() {
		var item ContentLog
		if err := rows.Scan(&item.ID, &item.RequestID, &item.TenantID, &item.UserID, &item.SessionID, &item.Role, &item.Content, &item.Tokens, &item.MessageIndex, &item.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, item)
	}
	return logs, rows.Err()
}

func (r *ContentLogRepository) ListByRequests(ctx context.Context, tenantID string, requestIDs []string) ([]ContentLog, error) {
	if len(requestIDs) == 0 {
		return []ContentLog{}, nil
	}
	query := `
		SELECT cl.id, rl.request_id, cl.tenant_id, COALESCE(cl.user_id, '') AS user_id,
			cl.session_id, cl.role, cl.content, cl.tokens, cl.message_index, cl.created_at
		FROM content_logs cl
		JOIN request_logs rl ON rl.id = cl.request_id
		WHERE cl.tenant_id = $1 AND rl.request_id = ANY($2)
			AND ` + contentLogRequestPushdown("rlx.request_id = ANY($2)") + `
		ORDER BY rl.created_at ASC, rl.request_id ASC, cl.created_at ASC, cl.id ASC
	`
	rows, err := r.retentionRead().Query(ctx, query, tenantID, requestIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to list content logs by requests: %w", err)
	}
	defer rows.Close()
	logs := []ContentLog{}
	for rows.Next() {
		var item ContentLog
		if err := rows.Scan(&item.ID, &item.RequestID, &item.TenantID, &item.UserID, &item.SessionID, &item.Role, &item.Content, &item.Tokens, &item.MessageIndex, &item.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return logs, nil
}

func (r *ContentLogRepository) ListByRequestsScoped(
	ctx context.Context,
	tenantID string,
	requestIDs []string,
	start, end time.Time,
	environmentScope string,
) ([]ContentLog, error) {
	if len(requestIDs) == 0 {
		return []ContentLog{}, nil
	}
	args := []interface{}{tenantID, requestIDs}
	where := []string{"cl.tenant_id = $1", "rl.tenant_id = $1", "rl.request_id = ANY($2)",
		contentLogRequestPushdown("rlx.request_id = ANY($2)")}
	if environmentScope != "" {
		args = append(args, EnvironmentScopesForRead(environmentScope))
		where = append(where, fmt.Sprintf("cl.environment_scope = ANY($%d)", len(args)))
		where = append(where, fmt.Sprintf("rl.environment_scope = ANY($%d)", len(args)))
	}
	if !start.IsZero() {
		args = append(args, start)
		where = append(where, fmt.Sprintf("cl.created_at >= $%d", len(args)))
		where = append(where, fmt.Sprintf("rl.created_at >= $%d", len(args)))
	}
	if !end.IsZero() {
		args = append(args, end)
		where = append(where, fmt.Sprintf("cl.created_at < $%d", len(args)))
		where = append(where, fmt.Sprintf("rl.created_at < $%d", len(args)))
	}
	query := `
		SELECT cl.id, rl.request_id, cl.tenant_id, COALESCE(cl.user_id, '') AS user_id,
			cl.session_id, cl.role, cl.content, cl.tokens, cl.message_index, cl.created_at
		FROM content_logs cl
		JOIN request_logs rl ON rl.id = cl.request_id
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY rl.created_at ASC, rl.request_id ASC, cl.created_at ASC, cl.id ASC
	`
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list scoped content logs by requests: %w", err)
	}
	defer rows.Close()
	logs := []ContentLog{}
	for rows.Next() {
		var item ContentLog
		if err := rows.Scan(&item.ID, &item.RequestID, &item.TenantID, &item.UserID, &item.SessionID, &item.Role, &item.Content, &item.Tokens, &item.MessageIndex, &item.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, item)
	}
	return logs, rows.Err()
}

// ListSessions returns unique session IDs with metadata
func (r *ContentLogRepository) ListSessions(ctx context.Context, tenantID string, startTime, endTime time.Time, limit, offset int) ([]map[string]interface{}, int, error) {
	return r.ListSessionsFiltered(ctx, ContentSessionListFilter{
		TenantID: tenantID, StartTime: startTime, EndTime: endTime, Limit: limit, Offset: offset,
	})
}

func (r *ContentLogRepository) ListSessionsFiltered(ctx context.Context, filter ContentSessionListFilter) ([]map[string]interface{}, int, error) {
	total := 0

	// Actionable-alert pages must never take the full content-log ranking path just
	// to compute a total. The handler fetches one extra row and exposes progressive
	// server pagination, while every page still comes from this indexed query.
	useFastPath := filter.SkipTotal || filter.AlertOnly
	query := buildContentSessionListQueryScopedWithAlertOnly(useFastPath, filter.EnvironmentScope, filter.AlertOnly)
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to begin session list transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	_, _ = tx.Exec(ctx, `SET LOCAL jit = off`)

	args := []interface{}{filter.TenantID, filter.StartTime, filter.EndTime, filter.Limit, filter.Offset}
	scopeArg := 0
	if strings.TrimSpace(filter.EnvironmentScope) != "" {
		args = append(args, EnvironmentScopesForRead(filter.EnvironmentScope))
		scopeArg = len(args)
	}
	if filter.ProjectIDs != nil {
		args = append(args, filter.ProjectIDs)
		query = scopeContentSessionProjectQuery(query, len(args))
	}
	query = scopeContentSessionAlertFilters(query, filter, scopeArg, &args)
	query = addContentSessionDispositionProjection(query)
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []map[string]interface{}
	for rows.Next() {
		var sessionID string
		var userID sql.NullString
		var startTimeVal, endTimeVal time.Time
		var messageCount, turnCount, totalTokens, snapshotCount int64
		var securityEventCount, actionableAlertCount, matchedRuleCount int64
		var severityRank, actionRank int
		var dispositionStatus string
		var totalCount int64
		var riskCategoriesRaw string
		var sourceIP, provider, targetHost, callerID, username, clientName, source, requestID string
		var attribution contentSessionAttribution
		if err := rows.Scan(&sessionID, &userID, &startTimeVal, &endTimeVal, &messageCount, &turnCount, &totalTokens, &snapshotCount, &securityEventCount, &actionableAlertCount, &matchedRuleCount, &dispositionStatus, &actionRank, &severityRank, &riskCategoriesRaw, &sourceIP, &provider, &targetHost, &callerID, &username, &clientName, &source, &requestID, &totalCount,
			&attribution.DepartmentID, &attribution.DepartmentName, &attribution.AgentType,
			&attribution.ConversationID, &attribution.PrincipalKey, &attribution.PrincipalSource, &attribution.SourceIP,
			&attribution.ProxyNAT); err != nil {
			return nil, 0, err
		}
		if totalCount > 0 {
			total = int(totalCount)
		}
		credentialType := ""
		if callerID != "" {
			credentialType = "api_key"
		}
		sessions = append(sessions, map[string]interface{}{
			"session_id":             sessionID,
			"user_id":                userID.String,
			"start_time":             startTimeVal,
			"end_time":               endTimeVal,
			"message_count":          int(messageCount),
			"turn_count":             int(turnCount),
			"total_tokens":           int(totalTokens),
			"snapshot_count":         int(snapshotCount),
			"security_event_count":   int(securityEventCount),
			"actionable_alert_count": int(actionableAlertCount),
			"matched_rule_count":     int(matchedRuleCount),
			"disposition_status":     dispositionStatus,
			"action_taken":           contentSessionActionFromRank(actionRank),
			"highest_severity":       severityFromRank(severityRank),
			"risk_categories":        splitRiskCategories(riskCategoriesRaw),
			"source_ip":              sourceIP,
			"provider":               provider,
			"target_host":            targetHost,
			"client_id":              callerID,
			"username":               username,
			"client_name":            clientName,
			"credential_type":        credentialType,
			"credential_bound":       clientName != "",
			"_source":                source,
			"request_id":             requestID,
		})
		attribution.apply(sessions[len(sessions)-1])
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("failed to commit session list transaction: %w", err)
	}
	if filter.SkipTotal {
		total = len(sessions)
	}
	return sessions, total, nil
}

func scopeContentSessionProjectQuery(query string, projectArg int) string {
	projectPlaceholder := fmt.Sprintf("$%d", projectArg)
	query = strings.ReplaceAll(
		query,
		"se.tenant_id = $1",
		"se.tenant_id = $1 AND se.project_id = ANY("+projectPlaceholder+")",
	)
	query = strings.ReplaceAll(
		query,
		"cl.tenant_id = $1",
		"cl.tenant_id = $1 AND EXISTS (SELECT 1 FROM request_logs content_scope_rl WHERE content_scope_rl.tenant_id = $1 AND content_scope_rl.id = cl.request_id AND content_scope_rl.project_id = ANY("+projectPlaceholder+"))",
	)
	return query
}

func contentAuditEventDispositionExpr(alias string) string {
	return fmt.Sprintf(`COALESCE(
		(SELECT disposition_event.status FROM audit_dispositions disposition_event
		 WHERE disposition_event.tenant_id = %s.tenant_id AND disposition_event.subject_type = 'security_event' AND disposition_event.subject_id = %s.id),
		(SELECT disposition_request.status FROM audit_dispositions disposition_request
		 WHERE disposition_request.tenant_id = %s.tenant_id AND disposition_request.subject_type = 'request' AND disposition_request.subject_id = %s.request_id),
		(SELECT disposition_group.status FROM alert_groups disposition_group
		 WHERE disposition_group.tenant_id = %s.tenant_id AND disposition_group.id = %s.alert_group_id),
		'open')`, alias, alias, alias, alias, alias, alias)
}

func scopeContentSessionAlertFilters(query string, filter ContentSessionListFilter, scopeArg int, args *[]interface{}) string {
	predicates := make([]string, 0, 5)
	if filter.UserID != "" {
		*args = append(*args, filter.UserID)
		arg := len(*args)
		predicates = append(predicates, fmt.Sprintf(`(se.user_id = $%d OR EXISTS (
				SELECT 1 FROM request_logs user_filter_request
				LEFT JOIN internal_keys user_filter_key
				  ON user_filter_key.tenant_id = user_filter_request.tenant_id
				 AND (
				   user_filter_key.id = user_filter_request.client_id
				   OR (LEFT(user_filter_request.client_id, 7) = 'caller_' AND LEFT(user_filter_key.key_hash, 12) = SUBSTRING(user_filter_request.client_id FROM 8))
				 )
			WHERE user_filter_request.tenant_id = se.tenant_id
			  AND user_filter_request.request_id = se.request_id
			  AND (user_filter_request.user_id = $%d OR user_filter_key.user_id = $%d)
		))`, arg, arg, arg))
	}
	if len(filter.Categories) > 0 {
		*args = append(*args, filter.Categories)
		arg := len(*args)
		predicates = append(predicates, fmt.Sprintf(`(
			LOWER(COALESCE(se.event_type, '')) = ANY($%d)
			OR LOWER(COALESCE(se.matched_summary->>'category', '')) = ANY($%d)
				OR EXISTS (
					SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(se.matched_summary->'findings') = 'array' THEN se.matched_summary->'findings' ELSE '[]'::jsonb END) finding_filter
					WHERE COALESCE(finding_filter->>'counts_as_security_finding', 'true') <> 'false'
					  AND LOWER(COALESCE(NULLIF(finding_filter->>'category', ''), finding_filter->>'type', '')) = ANY($%d)
			)
			OR EXISTS (SELECT 1 FROM rules category_rule WHERE category_rule.id = se.rule_id AND LOWER(COALESCE(category_rule.rule_type, '')) = ANY($%d))
		)`, arg, arg, arg, arg))
	}
	if len(filter.Severities) > 0 {
		*args = append(*args, filter.Severities)
		predicates = append(predicates, fmt.Sprintf("LOWER(COALESCE(se.severity, '')) = ANY($%d)", len(*args)))
	}
	if len(filter.Dispositions) > 0 {
		*args = append(*args, filter.Dispositions)
		predicates = append(predicates, fmt.Sprintf("LOWER(%s) = ANY($%d)", contentAuditEventDispositionExpr("se"), len(*args)))
	}
	if strings.TrimSpace(filter.Keyword) != "" {
		*args = append(*args, "%"+escapePostgresLikeLiteral(strings.TrimSpace(filter.Keyword))+"%")
		arg := len(*args)
		scopePredicate := ""
		if scopeArg > 0 {
			scopePredicate = fmt.Sprintf(" AND keyword_request.environment_scope = ANY($%d)", scopeArg)
		}
		predicates = append(predicates, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM request_logs keyword_request
			WHERE keyword_request.tenant_id = se.tenant_id
			  AND keyword_request.request_id = se.request_id%s
			  AND keyword_request.created_at >= $2 AND keyword_request.created_at < $3
			  AND (
				EXISTS (
					SELECT 1 FROM content_logs keyword_content
					WHERE keyword_content.tenant_id = keyword_request.tenant_id
					  AND keyword_content.request_id IN (keyword_request.id, keyword_request.request_id)
					  AND keyword_content.environment_scope = keyword_request.environment_scope
					  AND keyword_content.created_at >= $2 AND keyword_content.created_at < $3
					  AND keyword_content.role IN ('user', 'assistant')
					  AND keyword_content.content ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_content.content)
				)
				OR EXISTS (
					SELECT 1 FROM access_content_logs keyword_access
					WHERE keyword_access.tenant_id = keyword_request.tenant_id
					  AND keyword_access.request_id = keyword_request.request_id
					  AND keyword_access.environment_scope = keyword_request.environment_scope
					  AND keyword_access.created_at >= $2 AND keyword_access.created_at < $3
					  AND (
							(keyword_access.request_content_redacted ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_access.request_content_redacted))
							OR (keyword_access.response_content_redacted ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_access.response_content_redacted))
							OR %s
					  )
				)
			  )
		)`, scopePredicate, arg, arg, arg, forwardProxyVisibleFileMetadataKeywordExpr("keyword_access", arg)))
	}
	if len(predicates) == 0 {
		return query
	}
	return strings.ReplaceAll(query, "se.tenant_id = $1", "se.tenant_id = $1 AND "+strings.Join(predicates, " AND "))
}

func addContentSessionDispositionProjection(query string) string {
	disposition := contentAuditEventDispositionExpr("se")
	securityProjection := `CASE WHEN COUNT(DISTINCT event_disposition.status) = 1 THEN MIN(event_disposition.status) ELSE 'mixed' END AS disposition_status,
	MAX(CASE LOWER(TRIM(COALESCE(se.action_taken, '')))
		WHEN 'block' THEN 3 WHEN 'deny' THEN 3 WHEN 'mask' THEN 2
		WHEN 'audit' THEN 1 WHEN 'security_audit' THEN 1 WHEN 'security_audit_only' THEN 1
		ELSE 0 END) AS action_rank,
	MAX(CASE se.severity`
	query = strings.ReplaceAll(query, "MAX(CASE se.severity", securityProjection)
	query = strings.ReplaceAll(
		query,
		"LEFT JOIN rules r ON r.id = se.rule_id",
		fmt.Sprintf("LEFT JOIN LATERAL (SELECT %s AS status) event_disposition ON TRUE\nLEFT JOIN rules r ON r.id = se.rule_id", disposition),
	)
	selectNeedle := "COALESCE(ps.security_event_count, 0), COALESCE(ps.actionable_alert_count, 0), COALESCE(ps.matched_rule_count, 0),"
	selectReplacement := selectNeedle + "\n       COALESCE(ps.disposition_status, 'open'), COALESCE(ps.action_rank, 0),"
	return strings.ReplaceAll(query, selectNeedle, selectReplacement)
}

func contentSessionActionFromRank(rank int) string {
	switch rank {
	case 3:
		return "block"
	case 2:
		return "mask"
	case 1:
		return "audit"
	default:
		return "allow"
	}
}

func contentActionableAlertCondition(alias string) string {
	findings := fmt.Sprintf("CASE WHEN jsonb_typeof(%s.matched_summary->'findings') = 'array' THEN %s.matched_summary->'findings' ELSE '[]'::jsonb END", alias, alias)
	return fmt.Sprintf(`%s.alert_group_id IS NOT NULL
AND LOWER(TRIM(COALESCE(%s.severity, ''))) IN ('medium','high','critical')
AND NOT (%s)
AND NOT (
  LOWER(TRIM(COALESCE(%s.action_taken, ''))) IN ('audit', 'security_audit', 'security_audit_only')
  AND jsonb_typeof(%s) = 'array'
  AND jsonb_array_length(%s) > 0
  AND NOT EXISTS (
    SELECT 1
    FROM jsonb_array_elements(%s) agent_finding
    WHERE LOWER(TRIM(COALESCE(agent_finding->>'rule_type', ''))) <> 'agent_detect'
       OR LEFT(LOWER(TRIM(COALESCE(agent_finding->>'category', ''))), 6) <> 'agent_'
       OR LEFT(LOWER(TRIM(COALESCE(agent_finding->>'category', ''))), 12) = 'agent_canary'
  )
)`, alias, alias, requestCapacityOnlyEventCondition(alias), alias, findings, findings, findings)
}

func buildFastContentSessionListQueryWithAlertOnly(alertOnly bool) string {
	alertPredicate := ""
	if alertOnly {
		alertPredicate = " AND " + contentActionableAlertCondition("se")
	}
	// 内容风险页只需要当前页记录，不需要全量总数。快速路径从安全事件的请求键开始，
	// 每个风险请求只用索引取一条会话定位记录；分页后才聚合大体量 content_logs。
	return addContentSessionAttributionFast(fmt.Sprintf(`
WITH recent_risk_events AS MATERIALIZED (
SELECT se.request_id, se.created_at
FROM security_events se
WHERE se.tenant_id = $1 AND COALESCE(se.request_id, '') <> ''%s
  AND (
    jsonb_typeof(se.matched_summary->'findings') IS DISTINCT FROM 'array'
    OR jsonb_array_length(se.matched_summary->'findings') = 0
    OR EXISTS (
      SELECT 1
      FROM jsonb_array_elements(se.matched_summary->'findings') finding
      WHERE COALESCE(finding->>'counts_as_security_finding', 'true') <> 'false'
    )
  )
ORDER BY se.created_at DESC
),
risk_request_keys AS MATERIALIZED (
SELECT recent.request_id
FROM recent_risk_events recent
JOIN request_logs risk_rl
  ON risk_rl.tenant_id = $1 AND risk_rl.request_id = recent.request_id
 AND risk_rl.created_at >= $2 AND risk_rl.created_at <= $3
GROUP BY recent.request_id
ORDER BY MAX(recent.created_at) DESC
),
request_candidates AS MATERIALIZED (
SELECT
rr.request_id as request_key,
COALESCE(rl.id, rr.request_id) as content_request_id,
rl.user_id,
NULLIF(rl.session_id, '') as client_session_id,
COALESCE(NULLIF(rl.proxy_source_ip, ''), NULLIF(rl.source_ip, '')) as source_ip,
COALESCE(NULLIF(rl.proxy_provider, ''), NULLIF(p.name, '')) as provider,
COALESCE(NULLIF(rl.proxy_target_host, ''), NULLIF(m.model_name, ''), NULLIF(rl.model_id, '')) as target_host,
NULLIF(rl.client_id, '') as caller_id,
COALESCE(rl.input_tokens, 0) + COALESCE(rl.output_tokens, 0) as request_tokens,
rl.created_at as request_created_at
FROM risk_request_keys rr
LEFT JOIN request_logs rl ON rl.tenant_id = $1 AND rl.request_id = rr.request_id
LEFT JOIN providers p ON p.id = rl.provider_id
LEFT JOIN models m ON m.id = rl.model_id
WHERE rl.id IS NULL OR (rl.created_at >= $2 AND rl.created_at <= $3)
),
request_sessions AS MATERIALIZED (
SELECT
rc.request_key,
rc.content_request_id,
CASE WHEN pick.session_id IS NULL THEN rc.request_key ELSE pick.session_id END AS session_id,
COALESCE(rc.user_id, pick.user_id) as user_id,
CASE WHEN pick.session_id IS NULL THEN NULL ELSE rc.client_session_id END AS client_session_id,
rc.source_ip,
rc.provider,
rc.target_host,
rc.caller_id,
rc.request_tokens,
COALESCE(rc.request_created_at, pick.created_at) as created_at
FROM request_candidates rc
LEFT JOIN LATERAL (
SELECT cl.session_id, cl.user_id, cl.created_at
FROM content_logs cl
WHERE cl.tenant_id = $1
  AND cl.request_id = rc.content_request_id
  AND cl.created_at >= $2 AND cl.created_at <= $3
  AND cl.session_id IS NOT NULL
ORDER BY cl.created_at DESC
LIMIT 1
) pick ON TRUE
),
session_candidates AS MATERIALIZED (
SELECT
rs.session_id,
rs.user_id,
MAX(rs.request_key) as request_key,
NULLIF(MAX(rs.client_session_id), '') as client_session_id,
NULLIF(MAX(rs.source_ip), '') as source_ip,
NULLIF(MAX(rs.provider), '') as provider,
NULLIF(MAX(rs.target_host), '') as target_host,
NULLIF(MAX(rs.caller_id), '') as caller_id,
MIN(rs.created_at) as start_time,
MAX(rs.created_at) as end_time,
SUM(rs.request_tokens)::bigint as session_total_tokens
FROM request_sessions rs
GROUP BY rs.session_id, rs.user_id
),
grouped_sessions AS MATERIALIZED (
SELECT
sc.*,
CASE
WHEN sc.client_session_id IS NOT NULL THEN 'client:' || sc.client_session_id
WHEN fu.first_user_content IS NOT NULL THEN 'fallback:' || md5(fu.first_user_content) || ':' || date_trunc('day', sc.start_time)::text
ELSE 'request:' || sc.session_id
END as conversation_key
FROM session_candidates sc
LEFT JOIN LATERAL (
SELECT cl.content as first_user_content
FROM content_logs cl
WHERE cl.tenant_id = $1
  AND cl.session_id = sc.session_id
  AND cl.role = 'user'
  AND cl.created_at >= $2 AND cl.created_at <= $3
  AND cl.content !~* '^The user stepped away and is coming back'
  AND cl.content !~* '^Recap in under [0-9]+ words'
  AND cl.content !~* '^<system-reminder>'
ORDER BY cl.created_at ASC
LIMIT 1
) fu ON sc.client_session_id IS NULL
),
ranked_sessions AS MATERIALIZED (
SELECT
gs.*,
ROW_NUMBER() OVER (
PARTITION BY COALESCE(gs.user_id, ''), gs.conversation_key
ORDER BY gs.end_time DESC, gs.session_id DESC
) as row_num
FROM grouped_sessions gs
),
page AS MATERIALIZED (
SELECT *
FROM ranked_sessions
WHERE row_num = 1
ORDER BY start_time DESC
LIMIT $4 OFFSET $5
),
page_group_totals AS (
SELECT
p.session_id,
COUNT(gs.session_id) as snapshot_count,
COALESCE(SUM(gs.session_total_tokens), 0)::bigint as grouped_total_tokens
FROM page p
JOIN grouped_sessions gs
  ON COALESCE(gs.user_id, '') = COALESCE(p.user_id, '')
 AND gs.conversation_key = p.conversation_key
GROUP BY p.session_id
),
page_content AS (
SELECT
p.session_id,
MIN(cl.created_at) as start_time,
MAX(cl.created_at) as end_time,
COUNT(*) as message_count,
COUNT(*) FILTER (
WHERE cl.role = 'user'
  AND cl.content !~* '^The user stepped away and is coming back'
  AND cl.content !~* '^Recap in under [0-9]+ words'
  AND cl.content !~* '^<system-reminder>'
) as turn_count
FROM page p
JOIN content_logs cl
  ON cl.tenant_id = $1
 AND cl.session_id = p.session_id
 AND cl.created_at >= $2 AND cl.created_at <= $3
GROUP BY p.session_id
),
page_requests AS (
SELECT DISTINCT p.session_id, rs.request_key
FROM page p
JOIN request_sessions rs ON rs.session_id = p.session_id
),
page_security AS (
SELECT
pr.session_id,
COUNT(DISTINCT se.id) as security_event_count,
COUNT(DISTINCT se.id) FILTER (WHERE %s) as actionable_alert_count,
COUNT(DISTINCT COALESCE(
NULLIF(se.rule_id, ''),
NULLIF(finding.value->>'rule_id', ''),
NULLIF(finding.value->>'rule_name', ''),
NULLIF(finding.value->>'category', ''),
NULLIF(finding.value->>'type', ''),
NULLIF(se.matched_summary->>'category', ''),
NULLIF(se.event_type, '')
)) as matched_rule_count,
MAX(CASE se.severity
WHEN 'critical' THEN 4
WHEN 'high' THEN 3
WHEN 'medium' THEN 2
WHEN 'low' THEN 1
ELSE 0
END) as severity_rank,
array_to_string(array_remove(array_agg(DISTINCT COALESCE(
NULLIF(r.rule_type, ''),
NULLIF(finding.value->>'category', ''),
NULLIF(finding.value->>'type', ''),
NULLIF(se.matched_summary->>'category', ''),
NULLIF(se.event_type, '')
)), NULL), ',') as risk_categories
FROM page_requests pr
JOIN security_events se ON se.tenant_id = $1 AND se.request_id = pr.request_key%s
 AND (
   jsonb_typeof(se.matched_summary->'findings') IS DISTINCT FROM 'array'
   OR jsonb_array_length(se.matched_summary->'findings') = 0
   OR EXISTS (
     SELECT 1
     FROM jsonb_array_elements(se.matched_summary->'findings') risk_finding
     WHERE COALESCE(risk_finding->>'counts_as_security_finding', 'true') <> 'false'
   )
 )
LEFT JOIN rules r ON r.id = se.rule_id
LEFT JOIN LATERAL jsonb_array_elements(
CASE
WHEN jsonb_typeof(se.matched_summary->'findings') = 'array'
THEN se.matched_summary->'findings'
ELSE '[]'::jsonb
END
) AS finding(value) ON COALESCE(finding.value->>'counts_as_security_finding', 'true') <> 'false'
GROUP BY pr.session_id
)
SELECT p.session_id, p.user_id,
       COALESCE(pc.start_time, p.start_time), COALESCE(pc.end_time, p.end_time),
       COALESCE(pc.message_count, 0), COALESCE(pc.turn_count, 0),
       COALESCE(pgt.grouped_total_tokens, 0), COALESCE(pgt.snapshot_count, 1),
       COALESCE(ps.security_event_count, 0), COALESCE(ps.actionable_alert_count, 0), COALESCE(ps.matched_rule_count, 0),
       COALESCE(ps.severity_rank, 0), COALESCE(ps.risk_categories, ''),
       COALESCE(p.source_ip, ''), COALESCE(p.provider, ''), COALESCE(p.target_host, ''),
       COALESCE(p.caller_id, ''),
       COALESCE(NULLIF(key_owner.username, ''), NULLIF(request_user.username, ''), '') AS username,
       COALESCE(NULLIF(client_key.name, ''), NULLIF(client_key.key_prefix, ''), '') AS client_name,
       CASE WHEN pc.session_id IS NULL THEN 'access_retention' ELSE 'content_logs' END AS _source,
       CASE WHEN pc.session_id IS NULL THEN p.request_key ELSE '' END AS request_id,
       0::bigint as total_count
FROM page p
LEFT JOIN page_group_totals pgt ON pgt.session_id = p.session_id
LEFT JOIN page_content pc ON pc.session_id = p.session_id
LEFT JOIN page_security ps ON ps.session_id = p.session_id
LEFT JOIN internal_keys client_key
  ON client_key.tenant_id = $1
 AND (
   client_key.id = p.caller_id
   OR (LEFT(p.caller_id, 7) = 'caller_' AND LEFT(client_key.key_hash, 12) = SUBSTRING(p.caller_id FROM 8))
 )
LEFT JOIN users request_user ON request_user.tenant_id = $1 AND request_user.id = p.user_id
LEFT JOIN users key_owner ON key_owner.tenant_id = $1 AND key_owner.id = client_key.user_id
ORDER BY COALESCE(pc.start_time, p.start_time) DESC
`, alertPredicate, contentActionableAlertCondition("se"), alertPredicate))
}

func buildFastContentSessionListQuery() string {
	return buildFastContentSessionListQueryWithAlertOnly(false)
}

func buildContentSessionListQuery(skipTotal bool) string {
	return buildContentSessionListQueryScopedWithAlertOnly(skipTotal, "", false)
}

func buildContentSessionListQueryScoped(skipTotal bool, environmentScope string) string {
	return buildContentSessionListQueryScopedWithAlertOnly(skipTotal, environmentScope, false)
}

func buildContentSessionListQueryScopedWithAlertOnly(skipTotal bool, environmentScope string, alertOnly bool) string {
	if skipTotal {
		query := buildFastContentSessionListQueryWithAlertOnly(alertOnly)
		return scopeContentSessionListQuery(query, environmentScope)
	}
	alertPredicate := ""
	if alertOnly {
		alertPredicate = " AND " + contentActionableAlertCondition("se")
	}
	totalExpr := "(SELECT COUNT(*) FROM ranked_sessions WHERE row_num = 1) as total_count"
	if skipTotal {
		totalExpr = "0::bigint as total_count"
	}
	// 性能改造（15s → ~3s，47万行/90天窗口实测）：
	// 1. 先按 (session, user, request) 一趟聚合，再卷到会话级——token 汇总随之并入单趟扫描，
	//    替代原来分页组内逐会话 LATERAL 回表（45万次行访问）。
	// 2. 首条用户消息用 DISTINCT ON 单趟取齐，替代逐会话 LATERAL（1万次索引回查+排序）。
	// 3. 风险标记（has_risk）在会话级用 security_events 索引点查探针完成，并在排名前过滤——
	//    修复原来「取最新50个会话后才在 Go 里过滤风险」导致风险记录被无风险会话挤出分页的问题。
	// 4. page_security 由 page_requests（分页会话的请求键）驱动，避免 planner 对整表排序做 merge join。
	query := fmt.Sprintf(`
		WITH session_request_stats AS (
			SELECT
				cl.session_id,
				cl.user_id,
				cl.request_id,
				NULLIF(MAX(rl.session_id), '') as client_session_id,
				MAX(rl.proxy_source_ip) as max_proxy_source_ip,
				MAX(rl.source_ip) as max_source_ip,
				COALESCE(NULLIF(MAX(rl.proxy_provider), ''), NULLIF(MAX(p.name), '')) as max_provider,
				COALESCE(NULLIF(MAX(rl.proxy_target_host), ''), NULLIF(MAX(m.model_name), ''), NULLIF(MAX(rl.model_id), '')) as max_target_host,
				MAX(rl.client_id) as max_caller_id,
				MIN(cl.created_at) as start_time,
				MAX(cl.created_at) as end_time,
				COUNT(*) as message_count,
				COUNT(*) FILTER (
					WHERE cl.role = 'user'
					  AND cl.content !~* '^The user stepped away and is coming back'
					  AND cl.content !~* '^Recap in under [0-9]+ words'
					  AND cl.content !~* '^<system-reminder>'
				) as turn_count,
				MAX(COALESCE(rl.input_tokens, 0)) + MAX(COALESCE(rl.output_tokens, 0)) as request_tokens,
				COALESCE(NULLIF(MAX(rl.request_id), ''), cl.request_id) as request_key
			FROM content_logs cl
			LEFT JOIN request_logs rl ON rl.id = cl.request_id
			LEFT JOIN providers p ON p.id = rl.provider_id
			LEFT JOIN models m ON m.id = rl.model_id
			WHERE cl.tenant_id = $1 AND cl.created_at >= $2 AND cl.created_at <= $3 AND cl.session_id IS NOT NULL
			GROUP BY cl.session_id, cl.user_id, cl.request_id
		),
		raw_sessions AS (
			SELECT
				srs.session_id,
				srs.user_id,
				NULLIF(MAX(srs.client_session_id), '') as client_session_id,
				COALESCE(NULLIF(MAX(srs.max_proxy_source_ip), ''), MAX(srs.max_source_ip), '') as source_ip,
				NULLIF(MAX(srs.max_provider), '') as provider,
				NULLIF(MAX(srs.max_target_host), '') as target_host,
				NULLIF(MAX(srs.max_caller_id), '') as caller_id,
				MIN(srs.start_time) as start_time,
				MAX(srs.end_time) as end_time,
				SUM(srs.message_count) as message_count,
				SUM(srs.turn_count) as turn_count,
				SUM(srs.request_tokens)::bigint as session_total_tokens,
				bool_or(se_hit.hit) as has_risk
			FROM session_request_stats srs
			LEFT JOIN LATERAL (
				SELECT TRUE as hit
				FROM security_events se
				WHERE se.tenant_id = $1 AND se.request_id = srs.request_key%s
				  AND (
					jsonb_typeof(se.matched_summary->'findings') IS DISTINCT FROM 'array'
					OR jsonb_array_length(se.matched_summary->'findings') = 0
					OR EXISTS (
						SELECT 1
						FROM jsonb_array_elements(se.matched_summary->'findings') finding
						WHERE COALESCE(finding->>'counts_as_security_finding', 'true') <> 'false'
					)
				  )
				LIMIT 1
			) se_hit ON TRUE
			GROUP BY srs.session_id, srs.user_id
		),
		first_user AS (
			SELECT DISTINCT ON (cl.session_id)
				cl.session_id,
				cl.content as first_user_content
			FROM content_logs cl
			WHERE cl.tenant_id = $1
			  AND cl.role = 'user'
			  AND cl.content !~* '^The user stepped away and is coming back'
			  AND cl.content !~* '^Recap in under [0-9]+ words'
			  AND cl.content !~* '^<system-reminder>'
			ORDER BY cl.session_id, cl.created_at ASC
		),
		grouped_sessions AS (
			SELECT
				rs.*,
				CASE
					WHEN rs.client_session_id IS NOT NULL THEN 'client:' || rs.client_session_id
					WHEN fu.first_user_content IS NOT NULL THEN 'fallback:' || md5(fu.first_user_content) || ':' || date_trunc('day', rs.start_time)::text
					ELSE 'request:' || rs.session_id
				END as conversation_key
			FROM raw_sessions rs
			LEFT JOIN first_user fu ON fu.session_id = rs.session_id
		),
		ranked_sessions AS (
			SELECT
				*,
				ROW_NUMBER() OVER (
					PARTITION BY COALESCE(user_id, ''), conversation_key
					ORDER BY end_time DESC, message_count DESC, session_id DESC
				) as row_num
			FROM grouped_sessions
			WHERE has_risk
		),
		page AS (
			SELECT *
			FROM ranked_sessions
			WHERE row_num = 1
			ORDER BY start_time DESC
			LIMIT $4 OFFSET $5
		),
		page_group_totals AS (
			SELECT
				p.session_id,
				COUNT(gs.session_id) as snapshot_count,
				COALESCE(SUM(gs.session_total_tokens), 0)::bigint as grouped_total_tokens
			FROM page p
			JOIN grouped_sessions gs
			  ON COALESCE(gs.user_id, '') = COALESCE(p.user_id, '')
			 AND gs.conversation_key = p.conversation_key
			GROUP BY p.session_id
		),
		page_requests AS (
			SELECT DISTINCT p.session_id, COALESCE(NULLIF(rl.request_id, ''), cl.request_id) as request_key
			FROM page p
			JOIN content_logs cl ON cl.tenant_id = $1 AND cl.session_id = p.session_id AND cl.created_at >= $2 AND cl.created_at <= $3
			LEFT JOIN request_logs rl ON rl.id = cl.request_id
			WHERE cl.request_id IS NOT NULL
		),
		page_security AS (
			SELECT
				pr.session_id,
				COUNT(DISTINCT se.id) as security_event_count,
				COUNT(DISTINCT se.id) FILTER (WHERE %s) as actionable_alert_count,
				COUNT(DISTINCT COALESCE(
					NULLIF(se.rule_id, ''),
					NULLIF(finding.value->>'rule_id', ''),
					NULLIF(finding.value->>'rule_name', ''),
					NULLIF(finding.value->>'category', ''),
					NULLIF(finding.value->>'type', ''),
					NULLIF(se.matched_summary->>'category', ''),
					NULLIF(se.event_type, '')
				)) as matched_rule_count,
				MAX(CASE se.severity
					WHEN 'critical' THEN 4
					WHEN 'high' THEN 3
					WHEN 'medium' THEN 2
					WHEN 'low' THEN 1
					ELSE 0
				END) as severity_rank,
				array_to_string(array_remove(array_agg(DISTINCT COALESCE(
					NULLIF(r.rule_type, ''),
					NULLIF(finding.value->>'category', ''),
					NULLIF(finding.value->>'type', ''),
					NULLIF(se.matched_summary->>'category', ''),
					NULLIF(se.event_type, '')
				)), NULL), ',') as risk_categories
			FROM page_requests pr
			JOIN security_events se ON se.tenant_id = $1 AND se.request_id = pr.request_key%s
			 AND (
				jsonb_typeof(se.matched_summary->'findings') IS DISTINCT FROM 'array'
				OR jsonb_array_length(se.matched_summary->'findings') = 0
				OR EXISTS (
					SELECT 1
					FROM jsonb_array_elements(se.matched_summary->'findings') risk_finding
					WHERE COALESCE(risk_finding->>'counts_as_security_finding', 'true') <> 'false'
				)
			 )
			LEFT JOIN rules r ON r.id = se.rule_id
			LEFT JOIN LATERAL jsonb_array_elements(
				CASE
					WHEN jsonb_typeof(se.matched_summary->'findings') = 'array'
					THEN se.matched_summary->'findings'
					ELSE '[]'::jsonb
				END
			) AS finding(value) ON COALESCE(finding.value->>'counts_as_security_finding', 'true') <> 'false'
			GROUP BY pr.session_id
		)
		SELECT p.session_id, p.user_id, p.start_time, p.end_time, p.message_count, p.turn_count,
		       COALESCE(pgt.grouped_total_tokens, 0), COALESCE(pgt.snapshot_count, 1),
		       COALESCE(ps.security_event_count, 0), COALESCE(ps.actionable_alert_count, 0), COALESCE(ps.matched_rule_count, 0),
		       COALESCE(ps.severity_rank, 0), COALESCE(ps.risk_categories, ''),
		       COALESCE(p.source_ip, ''), COALESCE(p.provider, ''), COALESCE(p.target_host, ''),
		       COALESCE(p.caller_id, ''),
		       COALESCE(NULLIF(key_owner.username, ''), NULLIF(request_user.username, ''), '') AS username,
		       COALESCE(NULLIF(client_key.name, ''), NULLIF(client_key.key_prefix, ''), '') AS client_name,
		       'content_logs' AS _source,
		       '' AS request_id,
		       %s
		FROM page p
		LEFT JOIN page_group_totals pgt ON pgt.session_id = p.session_id
		LEFT JOIN page_security ps ON ps.session_id = p.session_id
		LEFT JOIN internal_keys client_key
		  ON client_key.tenant_id = $1
		 AND (
		   client_key.id = p.caller_id
		   OR (LEFT(p.caller_id, 7) = 'caller_' AND LEFT(client_key.key_hash, 12) = SUBSTRING(p.caller_id FROM 8))
		 )
		LEFT JOIN users request_user ON request_user.tenant_id = $1 AND request_user.id = p.user_id
		LEFT JOIN users key_owner ON key_owner.tenant_id = $1 AND key_owner.id = client_key.user_id
		ORDER BY p.start_time DESC
	`, alertPredicate, contentActionableAlertCondition("se"), alertPredicate, totalExpr)
	return scopeContentSessionListQuery(addContentSessionAttributionScoped(query), environmentScope)
}

func scopeContentSessionListQuery(query, environmentScope string) string {
	if strings.TrimSpace(environmentScope) == "" {
		return strings.ReplaceAll(query, "created_at <= $3", "created_at < $3")
	}
	query = strings.ReplaceAll(query, "cl.tenant_id = $1", "cl.tenant_id = $1 AND cl.environment_scope = ANY($6)")
	query = strings.ReplaceAll(query, "LEFT JOIN request_logs rl ON rl.id = cl.request_id", "LEFT JOIN request_logs rl ON rl.id = cl.request_id AND rl.tenant_id = $1")
	query = strings.ReplaceAll(query, " rl.tenant_id = $1", " rl.tenant_id = $1 AND rl.environment_scope = ANY($6)")
	query = strings.ReplaceAll(query, "risk_rl.tenant_id = $1", "risk_rl.tenant_id = $1 AND risk_rl.environment_scope = ANY($6)")
	query = strings.ReplaceAll(query, "cl.tenant_id = $1 AND cl.environment_scope = ANY($6)", "cl.tenant_id = $1 AND cl.environment_scope = ANY($6) AND cl.created_at >= $2 AND cl.created_at < $3")
	query = strings.ReplaceAll(query, " rl.tenant_id = $1 AND rl.environment_scope = ANY($6)", " rl.tenant_id = $1 AND rl.environment_scope = ANY($6) AND rl.created_at >= $2 AND rl.created_at < $3")
	query = strings.ReplaceAll(query, "se.tenant_id = $1", "se.tenant_id = $1 AND se.created_at >= $2 AND se.created_at < $3 AND EXISTS (SELECT 1 FROM request_logs se_scope_rl WHERE se_scope_rl.tenant_id = $1 AND se_scope_rl.request_id = se.request_id AND se_scope_rl.environment_scope = ANY($6) AND se_scope_rl.created_at >= $2 AND se_scope_rl.created_at < $3)")
	query = strings.ReplaceAll(query, "created_at <= $3", "created_at < $3")
	return query
}

func severityFromRank(rank int) string {
	switch rank {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return ""
	}
}

func splitRiskCategories(raw string) []string {
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

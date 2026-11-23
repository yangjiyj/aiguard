package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RawEvidenceRepository 读取 content_raw_evidence（迁移 994）。列表只返回元数据，
// 密文只在"按条查看原文"时取出，由处理器解密。
type RawEvidenceRepository struct {
	db *pgxpool.Pool
}

func NewRawEvidenceRepository(db *pgxpool.Pool) *RawEvidenceRepository {
	return &RawEvidenceRepository{db: db}
}

// RawEvidenceMeta 是不含原文的留证元数据（也不含原文摘要：摘要可被用来离线核对号码）。
type RawEvidenceMeta struct {
	ID           string    `json:"id"`
	RequestID    string    `json:"request_id"`
	SessionID    string    `json:"session_id,omitempty"`
	UserID       string    `json:"user_id,omitempty"`
	Direction    string    `json:"direction"`
	Role         string    `json:"role"`
	MessageIndex int       `json:"message_index"`
	Disposition  string    `json:"disposition"`
	BlockID      string    `json:"block_id,omitempty"`
	RuleIDs      []string  `json:"rule_ids"`
	RuleNames    []string  `json:"rule_names"`
	Categories   []string  `json:"categories"`
	ContentChars int       `json:"content_chars"`
	CreatedAt    time.Time `json:"created_at"`
	// Truncated：原文超过 512K 字符被截断保存；OriginalChars 是截断前的字符数。
	Truncated     bool `json:"truncated"`
	OriginalChars int  `json:"original_chars"`
	// RefEvidenceID 非空：本行是去重后的引用行（不含密文），原文取自同会话首次出现的那条留证。
	RefEvidenceID string `json:"ref_evidence_id,omitempty"`
}

// RawEvidenceRow 带密文，仅供处理器解密使用，绝不序列化给前端。
type RawEvidenceRow struct {
	RawEvidenceMeta
	TenantID   string
	Ciphertext string
}

type RawEvidenceFilter struct {
	TenantID    string
	RequestID   string
	BlockID     string
	Rule        string // 规则编号或名称（精确，大小写不敏感）
	Direction   string
	Disposition string
	Start, End  time.Time
	Limit       int
	Offset      int
}

const rawEvidenceMetaColumns = `id, request_id, COALESCE(session_id,''), COALESCE(user_id,''), direction, role, message_index, disposition,
	COALESCE(block_id,''), rule_ids, rule_names, categories, content_chars, created_at, content_truncated, original_chars, COALESCE(ref_evidence_id,'')`

func (r *RawEvidenceRepository) List(ctx context.Context, f RawEvidenceFilter) ([]RawEvidenceMeta, int, error) {
	if f.TenantID == "" {
		return nil, 0, fmt.Errorf("tenant is required")
	}
	where := []string{"tenant_id = $1"}
	args := []interface{}{f.TenantID}
	add := func(cond string, v interface{}) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if f.RequestID != "" {
		add("request_id = ?", f.RequestID)
	}
	if f.BlockID != "" {
		add("block_id = ?", f.BlockID)
	}
	if f.Rule != "" {
		add("(EXISTS (SELECT 1 FROM unnest(rule_ids) x WHERE lower(x) = lower(?)) OR EXISTS (SELECT 1 FROM unnest(rule_names) x WHERE lower(x) = lower(?)))", f.Rule)
	}
	if f.Direction != "" {
		add("direction = ?", f.Direction)
	}
	if f.Disposition != "" {
		add("disposition = ?", f.Disposition)
	}
	if !f.Start.IsZero() {
		add("created_at >= ?", f.Start)
	}
	if !f.End.IsZero() {
		add("created_at < ?", f.End)
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM content_raw_evidence WHERE `+clause, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count raw evidence: %w", err)
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx, `SELECT `+rawEvidenceMetaColumns+` FROM content_raw_evidence WHERE `+clause+
		fmt.Sprintf(` ORDER BY created_at DESC, id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list raw evidence: %w", err)
	}
	defer rows.Close()
	items := []RawEvidenceMeta{}
	for rows.Next() {
		var m RawEvidenceMeta
		if err := rows.Scan(&m.ID, &m.RequestID, &m.SessionID, &m.UserID, &m.Direction, &m.Role, &m.MessageIndex, &m.Disposition,
			&m.BlockID, &m.RuleIDs, &m.RuleNames, &m.Categories, &m.ContentChars, &m.CreatedAt, &m.Truncated, &m.OriginalChars, &m.RefEvidenceID); err != nil {
			return nil, 0, err
		}
		items = append(items, m)
	}
	return items, total, rows.Err()
}

// Get 取一条带密文的留证；租户不符视为不存在。
func (r *RawEvidenceRepository) Get(ctx context.Context, tenantID, id string) (*RawEvidenceRow, error) {
	var row RawEvidenceRow
	err := r.db.QueryRow(ctx, `SELECT `+rawEvidenceMetaColumns+`, tenant_id, COALESCE(content_ciphertext,'')
		FROM content_raw_evidence WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(
		&row.ID, &row.RequestID, &row.SessionID, &row.UserID, &row.Direction, &row.Role, &row.MessageIndex, &row.Disposition,
		&row.BlockID, &row.RuleIDs, &row.RuleNames, &row.Categories, &row.ContentChars, &row.CreatedAt, &row.Truncated, &row.OriginalChars, &row.RefEvidenceID,
		&row.TenantID, &row.Ciphertext)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get raw evidence: %w", err)
	}
	return &row, nil
}

// RequestIDsWithEvidence 返回给定请求里存在原文留证的请求编号（供列表页决定是否显示"查看原文"）。
func (r *RawEvidenceRepository) RequestIDsWithEvidence(ctx context.Context, tenantID string, requestIDs []string) (map[string]int, error) {
	out := map[string]int{}
	if len(requestIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.Query(ctx, `SELECT request_id, COUNT(*) FROM content_raw_evidence WHERE tenant_id = $1 AND request_id = ANY($2) GROUP BY request_id`, tenantID, requestIDs)
	if err != nil {
		return nil, fmt.Errorf("count raw evidence by request: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// RequestIDsWithBlockedInputEvidence 返回给定请求里存在“输入方向、已阻断”原文留证的请求编号集合。
// 原文留证表不存在（迁移 994 之前的老库）时返回空集合而不是错误。
func (r *RawEvidenceRepository) RequestIDsWithBlockedInputEvidence(ctx context.Context, tenantID string, requestIDs []string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	if len(requestIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.Query(ctx, `SELECT DISTINCT request_id FROM content_raw_evidence WHERE tenant_id = $1 AND request_id = ANY($2) AND direction = 'input' AND disposition = 'blocked'`, tenantID, requestIDs)
	if err != nil {
		if isUndefinedTable(err) {
			return map[string]struct{}{}, nil
		}
		return nil, fmt.Errorf("query blocked input raw evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		if isUndefinedTable(err) {
			return map[string]struct{}{}, nil
		}
		return nil, err
	}
	return out, nil
}

// DeleteOlderThan 与 content_logs 同一个保留期（天数由调用方传入）。表不存在（迁移 994 之前）时无操作。
func (r *RawEvidenceRepository) DeleteOlderThan(ctx context.Context, retentionDays int) (int64, error) {
	var exists bool
	if err := r.db.QueryRow(ctx, `SELECT to_regclass('content_raw_evidence') IS NOT NULL`).Scan(&exists); err != nil {
		return 0, fmt.Errorf("detect raw evidence table: %w", err)
	}
	if !exists {
		return 0, nil
	}
	var total int64
	for {
		tag, err := r.db.Exec(ctx, `DELETE FROM content_raw_evidence WHERE id IN (
			SELECT id FROM content_raw_evidence WHERE created_at < CURRENT_DATE - INTERVAL '1 day' * $1 LIMIT 5000)`, retentionDays)
		if err != nil {
			return total, fmt.Errorf("delete expired raw evidence: %w", err)
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < 5000 {
			return total, nil
		}
	}
}

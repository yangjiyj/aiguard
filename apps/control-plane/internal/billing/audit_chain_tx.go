package billing

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// AuditChainTx 在调用方已打开的事务里追加一条审计链记录。
// 事务回滚时审计链记录一并回滚；审计链写不进去时返回错误，调用方应让整个业务事务失败。
// repository.AuditChainRepository 满足该接口（结构化匹配，billing 不依赖 repository 包）。
type AuditChainTx interface {
	AppendTx(ctx context.Context, tx pgx.Tx, tenantID, eventType, eventID string, payload map[string]any) error
}

// SetAuditChain 在启动阶段设置一次，之后只读，不加锁。传 nil 表示审计链未启用（只写 audit_operations）。
func (s *Store) SetAuditChain(chain AuditChainTx) {
	s.auditChain = chain
}

// AuditChainInTx 报告关键计费审计是否已由本包在业务事务内写入审计链。
// 为 true 时调用方不要再事后追加同一条记录。
func (s *Store) AuditChainInTx() bool {
	return s != nil && s.auditChain != nil
}

func (s *Store) appendAuditChainTx(ctx context.Context, tx pgx.Tx, tenantID, auditID string, payload map[string]any) error {
	if s.auditChain == nil {
		return nil
	}
	return s.auditChain.AppendTx(ctx, tx, tenantID, "audit_op", auditID, payload)
}

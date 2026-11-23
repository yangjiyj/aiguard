package repository

import (
	"context"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/internaltitle"
)

// internalTitleSettleWindow 是请求创建后到允许缓存判定的沉淀时间。
const internalTitleSettleWindow = "15 minutes"

// BackfillInternalTitleRequests 每批最多 500 行，优先处理最近请求。
// 先锁行，下一条语句使用新快照计算；避免等待写入锁后仍用旧快照保存错误结果。
// 超时或取消整批回滚，NULL 队列天然可重入；SKIP LOCKED 支持多实例。
func (r *RequestLogRepository) BackfillInternalTitleRequests(ctx context.Context, batch int) (int64, error) {
	if batch <= 0 || batch > 500 {
		batch = 500
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL statement_timeout = '8s'"); err != nil {
		return 0, err
	}
	// 只判定已沉淀的请求：正文、智能体识别等写入在请求结束后陆续到达，写路径不维护该列，
	// 过早判定会缓存半份内容的结论。窗口内的新请求保持 NULL，读侧按原规则实时计算（量小）。
	rows, err := tx.Query(ctx, `SELECT id FROM request_logs WHERE internal_title_request IS NULL
 AND created_at < now() - $2::interval
 ORDER BY created_at DESC, id DESC LIMIT $1 FOR UPDATE SKIP LOCKED`, batch, internalTitleSettleWindow)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := tx.Exec(ctx, "UPDATE request_logs rl SET internal_title_request = NOT ("+internaltitle.RawPredicate()+") WHERE rl.id = ANY($1)", ids)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

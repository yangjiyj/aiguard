package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SecretFlowPair 是一条「密钥内容指纹 × 目的地主机」的流动组合。
// 指纹取 finding.matched_text_preview_sha256（检测引擎已算好的内容哈希），
// 目的地取事件 matched_summary 顶层 target_host（正向代理路径特征）。
type SecretFlowPair struct {
	SecretFP   string
	TargetHost string
}

// SecretFlowFirstSeenRepository 维护 secret_flow_first_seen 首见登记表（迁移 098）。
// 告警桥用它做 secret novelty 判定：重复的 (指纹,目的地) 流动折叠进告警组不再进收件箱，
// 新密钥或旧密钥流向新目的地照常提升。只影响收件箱/通知层，security_events 留证不受影响。
type SecretFlowFirstSeenRepository struct {
	db *pgxpool.Pool
}

func NewSecretFlowFirstSeenRepository(db *pgxpool.Pool) *SecretFlowFirstSeenRepository {
	return &SecretFlowFirstSeenRepository{db: db}
}

// MarkSeen 幂等登记一批 (指纹,目的地) 对（INSERT ... ON CONFLICT DO NOTHING，
// 照 anomaly_events 的 DB 锚定先例），返回本次真正新插入（=首见）的对数。
// 返回 0 表示全部已见过；调用方据此决定折叠还是提升。
func (r *SecretFlowFirstSeenRepository) MarkSeen(ctx context.Context, tenantID string, pairs []SecretFlowPair) (int, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("secret flow first seen repository db is nil")
	}
	if tenantID == "" || len(pairs) == 0 {
		return 0, nil
	}
	fps := make([]string, 0, len(pairs))
	hosts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if p.SecretFP == "" || p.TargetHost == "" {
			continue
		}
		fps = append(fps, p.SecretFP)
		hosts = append(hosts, p.TargetHost)
	}
	if len(fps) == 0 {
		return 0, nil
	}
	tag, err := r.db.Exec(ctx, `
		INSERT INTO secret_flow_first_seen (tenant_id, secret_fp, target_host, first_seen_at)
		SELECT $1, t.fp, t.host, NOW()
		FROM unnest($2::text[], $3::text[]) AS t(fp, host)
		ON CONFLICT (tenant_id, secret_fp, target_host) DO NOTHING
	`, tenantID, fps, hosts)
	if err != nil {
		return 0, fmt.Errorf("mark secret flow seen: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

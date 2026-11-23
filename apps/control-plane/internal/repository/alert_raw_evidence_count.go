package repository

import (
	"context"
	"errors"
	"log"

	"github.com/jackc/pgx/v5/pgconn"
)

func rawEvidenceRequestIDs(items []AlertOccurrence) []string {
	seen := map[string]bool{}
	var ids []string
	for _, item := range items {
		if item.RequestID != "" && !seen[item.RequestID] {
			seen[item.RequestID] = true
			ids = append(ids, item.RequestID)
		}
	}
	return ids
}

func applyRawEvidenceCounts(items []AlertOccurrence, counts map[string]int) {
	for index := range items {
		if count, ok := counts[items[index].RequestID]; ok {
			items[index].RawEvidenceCount = count
		}
	}
}

// attachRawEvidenceCounts 给本页命中补上原文留证条数。查不到（表不存在、查询失败）只记日志，
// 告警列表照常返回：少一个“查看原文”入口，好过整页打不开。
func (r *AlertOccurrenceRepository) attachRawEvidenceCounts(ctx context.Context, tenantID string, items []AlertOccurrence) {
	ids := rawEvidenceRequestIDs(items)
	if len(ids) == 0 {
		return
	}
	counts, err := NewRawEvidenceRepository(r.db).RequestIDsWithEvidence(ctx, tenantID, ids)
	if err != nil {
		if isUndefinedTable(err) {
			return // 迁移 994 之前没有原文留证表
		}
		log.Printf("alert occurrences: raw evidence count lookup failed: %v", err)
		return
	}
	applyRawEvidenceCounts(items, counts)
}

// isUndefinedTable 判断 PostgreSQL 错误是否为“表不存在”（42P01）。
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

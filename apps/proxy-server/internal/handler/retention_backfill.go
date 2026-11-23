package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

// BackfillResult 汇总历史 inline 附件外移的结果。
type BackfillResult struct {
	RowsScanned             int
	RowsRewritten           int
	AttachmentsExternalized int
	AttachmentsRemaining    int // 处理后仍带 data_base64(externalize 失败,需排查)
}

// BackfillExternalizeInlineAttachments 把 access_content_logs.file_metadata_json 里残留的
// 历史 inline data_base64(2026-06-17 前 json_data_url 附件)外移到 LocalStore,DB 只留指针。
// 复用写路径同一套 externalizeRetainedAttachmentData,迁移后形状与现网正常 externalized 行一致。
// keyset 游标遍历、按行提交、幂等可重入(已 externalized 的附件不动);dryRun=只统计不写。
// 中断安全:已处理行有 object_key(走 LocalStore 回读),未处理行仍有 data_base64(内联可读)。
func BackfillExternalizeInlineAttachments(ctx context.Context, db *pgxpool.Pool, store retentionstore.Store, batch int, dryRun bool) (BackfillResult, error) {
	var res BackfillResult
	if db == nil {
		return res, fmt.Errorf("db is nil")
	}
	if store == nil && !dryRun {
		return res, fmt.Errorf("retention store is required for non-dry-run backfill")
	}
	if batch <= 0 {
		batch = 200
	}

	type pending struct {
		id, tenantID, requestID, metaJSON string
		retentionUntil                    time.Time
	}

	cursor := ""
	for {
		rows, err := db.Query(ctx, `
			SELECT id, tenant_id, request_id, file_metadata_json::text, retention_until
			FROM access_content_logs
			WHERE file_metadata_json::text LIKE '%data_base64%' AND id > $1
			ORDER BY id
			LIMIT $2
		`, cursor, batch)
		if err != nil {
			return res, fmt.Errorf("query inline-base64 rows: %w", err)
		}
		var batchRows []pending
		for rows.Next() {
			var p pending
			var ru *time.Time
			if err := rows.Scan(&p.id, &p.tenantID, &p.requestID, &p.metaJSON, &ru); err != nil {
				rows.Close()
				return res, fmt.Errorf("scan row: %w", err)
			}
			if ru != nil {
				p.retentionUntil = *ru
			}
			batchRows = append(batchRows, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return res, err
		}
		if len(batchRows) == 0 {
			break
		}

		for _, p := range batchRows {
			cursor = p.id
			res.RowsScanned++

			var items []retainedAttachmentMetadata
			if err := json.Unmarshal([]byte(p.metaJSON), &items); err != nil {
				continue // 结构异常,跳过不动(保持可读)
			}

			if dryRun {
				for _, it := range items {
					if strings.TrimSpace(it.DataBase64) != "" {
						res.AttachmentsExternalized++ // dry-run 计为"将外移"
					}
				}
				continue
			}

			record := ProxyAuditRecord{TenantID: p.tenantID, RequestID: p.requestID}
			newItems := externalizeRetainedAttachmentData(ctx, store, record, p.retentionUntil, items)
			externalizedHere, remainingHere := 0, 0
			for _, it := range newItems {
				if strings.TrimSpace(it.DataBase64) != "" {
					remainingHere++
				} else if it.RetentionStatus == "externalized" {
					externalizedHere++
				}
			}
			newJSON, err := json.Marshal(newItems)
			if err != nil {
				continue
			}
			if _, err := db.Exec(ctx, `UPDATE access_content_logs SET file_metadata_json = $1::jsonb WHERE id = $2`, string(newJSON), p.id); err != nil {
				return res, fmt.Errorf("update row %s: %w", p.id, err)
			}
			res.RowsRewritten++
			res.AttachmentsExternalized += externalizedHere
			res.AttachmentsRemaining += remainingHere
		}
	}
	return res, nil
}

// BackfillReferenceImages 把历史"引用式图片"(json_image_url/json_file_url:只有 download_url、
// 无内联字节、无 object_key)的真字节抓回并外移落盘。仅当抓回字节能解码为栅格图(png/jpeg/gif)
// 才存——从而跳过已过期 URL 的占位 SVG / HTML 错误页 / 截断数据,保证留证图真实可信。
// 抓到的有效图当作 data_base64 喂回 externalizeRetainedAttachmentData 的内联分支,落盘格式与现网一致;
// 跳过项预标 url_only,使 externalize 不再对其抓取。keyset 遍历、按行提交、幂等;dryRun 只统计。
func BackfillReferenceImages(ctx context.Context, db *pgxpool.Pool, store retentionstore.Store, batch int, dryRun bool) (BackfillResult, error) {
	var res BackfillResult
	if db == nil {
		return res, fmt.Errorf("db is nil")
	}
	if store == nil && !dryRun {
		return res, fmt.Errorf("retention store is required for non-dry-run backfill")
	}
	if batch <= 0 {
		batch = 200
	}

	type pending struct {
		id, tenantID, requestID, metaJSON string
		retentionUntil                    time.Time
	}

	cursor := ""
	for {
		rows, err := db.Query(ctx, `
			SELECT id, tenant_id, request_id, file_metadata_json::text, retention_until
			FROM access_content_logs
			WHERE id > $1
			  AND jsonb_typeof(file_metadata_json) = 'array'
			  AND file_metadata_json::text LIKE '%download_url%'
			ORDER BY id
			LIMIT $2
		`, cursor, batch)
		if err != nil {
			return res, fmt.Errorf("query reference-url rows: %w", err)
		}
		var batchRows []pending
		for rows.Next() {
			var p pending
			var ru *time.Time
			if err := rows.Scan(&p.id, &p.tenantID, &p.requestID, &p.metaJSON, &ru); err != nil {
				rows.Close()
				return res, fmt.Errorf("scan row: %w", err)
			}
			if ru != nil {
				p.retentionUntil = *ru
			}
			batchRows = append(batchRows, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return res, err
		}
		if len(batchRows) == 0 {
			break
		}

		for _, p := range batchRows {
			cursor = p.id
			res.RowsScanned++

			var items []retainedAttachmentMetadata
			if err := json.Unmarshal([]byte(p.metaJSON), &items); err != nil {
				continue // 结构异常,跳过不动(保持可读)
			}

			changed := false
			for i := range items {
				it := items[i]
				if it.Source != "json_image_url" && it.Source != "json_file_url" {
					continue
				}
				if it.ObjectKey != "" || strings.TrimSpace(it.DataBase64) != "" || strings.TrimSpace(it.DownloadURL) == "" {
					continue
				}
				b := fetchRetainedAttachmentBytes(ctx, it.DownloadURL)
				if len(b) == 0 || !bytesAreDecodableImage(b) {
					if !dryRun {
						items[i].RetentionStatus = "url_only" // 明确标记已尝试,externalize 不再抓
					}
					continue
				}
				if dryRun {
					res.AttachmentsExternalized++ // dry-run 计"将回填"
					continue
				}
				items[i].DataBase64 = base64.StdEncoding.EncodeToString(b)
				items[i].Size = int64(len(b))
				changed = true
			}

			if dryRun || !changed {
				continue
			}

			record := ProxyAuditRecord{TenantID: p.tenantID, RequestID: p.requestID}
			newItems := externalizeRetainedAttachmentData(ctx, store, record, p.retentionUntil, items)
			externalizedHere, remainingHere := 0, 0
			for _, it := range newItems {
				if strings.TrimSpace(it.DataBase64) != "" {
					remainingHere++
				} else if it.RetentionStatus == "externalized" {
					externalizedHere++
				}
			}
			newJSON, err := json.Marshal(newItems)
			if err != nil {
				continue
			}
			if _, err := db.Exec(ctx, `UPDATE access_content_logs SET file_metadata_json = $1::jsonb WHERE id = $2`, string(newJSON), p.id); err != nil {
				return res, fmt.Errorf("update row %s: %w", p.id, err)
			}
			res.RowsRewritten++
			res.AttachmentsExternalized += externalizedHere
			res.AttachmentsRemaining += remainingHere
		}
	}
	return res, nil
}

// bytesAreDecodableImage 判定抓回字节是否为可解码栅格图(png/jpeg/gif),用于回填时滤掉
// 过期 URL 的占位 SVG / HTML 错误页 / 截断数据。
func bytesAreDecodableImage(b []byte) bool {
	if len(b) < 512 {
		return false
	}
	if _, _, err := image.DecodeConfig(bytes.NewReader(b)); err != nil {
		return false
	}
	return true
}

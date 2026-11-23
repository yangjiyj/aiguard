package repository

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

var evidenceLocation = regexp.MustCompile(`^content\[([0-9]{1,9}):([0-9]{1,9})\]$`)
var evidenceSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)

func evidencePlaceholder(value string) bool {
	switch strings.TrimSpace(value) {
	case "<deterministic-catalog-match>", "<MASKED>":
		return true
	}
	return false
}
func normalizeOccurrenceEvidence(item *AlertOccurrence, allowed bool) {
	if !allowed {
		return
	}
	if evidencePlaceholder(item.RawEvidence) {
		item.RawEvidence = ""
	}
	if evidencePlaceholder(item.EvidenceContext) {
		item.EvidenceContext = ""
	}
	if evidencePlaceholder(item.MatchedTextPreview) {
		item.MatchedTextPreview = ""
	}
	if item.RawEvidence == "" && item.EvidenceContext == "" && item.RawEvidenceStatus == "available" {
		item.RawEvidenceStatus = "missing"
	}
	if item.RawEvidence == "" && item.EvidenceContext == "" && item.MatchedTextPreview == "" && item.RedactedEvidence == "" {
		item.EvidenceStatus = "missing"
	}
}

// evidenceRecoveryCandidate 是一条可以按哈希从留存核验回捞的命中。
type evidenceRecoveryCandidate struct {
	index                 int
	requestID, projectID  string
	start, end            int
	rawSHA256, contextSHA string
	role                  string
}

func occurrenceRecoveryCandidate(index int, item *AlertOccurrence) (evidenceRecoveryCandidate, bool) {
	if item.RawEvidence != "" || item.RequestID == "" || !evidenceSHA256.MatchString(item.RawEvidenceSHA256) {
		return evidenceRecoveryCandidate{}, false
	}
	if item.EvidenceContextSHA256 != "" && !evidenceSHA256.MatchString(item.EvidenceContextSHA256) {
		return evidenceRecoveryCandidate{}, false
	}
	match := evidenceLocation.FindStringSubmatch(item.MatchedLocation)
	if len(match) != 3 {
		return evidenceRecoveryCandidate{}, false
	}
	start, e1 := strconv.Atoi(match[1])
	end, e2 := strconv.Atoi(match[2])
	if e1 != nil || e2 != nil || end <= start || end-start > 65536 || end > 4*1024*1024 {
		return evidenceRecoveryCandidate{}, false
	}
	role := item.MessageRole
	if role == "" {
		switch item.ContentSource {
		case "tool_result", "tool_output":
			role = "tool"
		case "user", "user_history", "verified_user_input":
			role = "user"
		case "model_output", "assistant_history", "verified_final_output":
			role = "assistant"
		}
	}
	return evidenceRecoveryCandidate{index: index, requestID: item.RequestID, projectID: item.ProjectID, start: start, end: end,
		rawSHA256: item.RawEvidenceSHA256, contextSHA: item.EvidenceContextSHA256, role: role}, true
}

// recoverOccurrenceEvidenceBatchQuery 一次核验整页命中。先按（租户、请求编号）定位请求记录，再用这些
// 记录的两个编号（content_logs.request_id 存的是 request_logs.id，历史数据里也有存外部请求编号的）作为
// 不相关子查询数组下推进 content_logs 视图，只读这些请求自己的正文。过去写成
// JOIN … ON (c.request_id=rl.id OR c.request_id=rl.request_id)，计划会对全部正文并行顺序扫描并逐条算
// sha256(substring)，现场单条 637ms。每条命中仍按自己的请求、项目、作用域、角色、位置和两个哈希独立核验。
const recoverOccurrenceEvidenceBatchQuery = `WITH cand AS (
 SELECT * FROM unnest($2::int[],$3::text[],$4::text[],$5::int[],$6::int[],$7::text[],$8::text[],$9::text[])
   AS cand(idx,request_id,project_id,start_at,end_at,raw_sha,context_sha,role)
), req AS MATERIALIZED (
 SELECT rl.id, rl.request_id, COALESCE(rl.project_id,'') AS project_id,
   COALESCE(to_jsonb(rl)->>'environment_scope','legacy') AS environment_scope
 FROM request_logs rl WHERE rl.tenant_id=$1 AND rl.request_id = ANY($3::text[])
), body AS MATERIALIZED (
 SELECT c.id, c.request_id, c.role, c.content, c.created_at,
   COALESCE(to_jsonb(c)->>'environment_scope','legacy') AS environment_scope
 FROM content_logs c
 WHERE c.tenant_id=$1 AND c.request_id = ANY(ARRAY(SELECT id FROM req UNION SELECT request_id FROM req))
)
SELECT cand.idx, e.raw, CASE WHEN cand.context_sha<>'' THEN e.context ELSE '' END
 FROM cand
 CROSS JOIN LATERAL (
   SELECT e.raw, e.context
   FROM req rl
   JOIN body c ON (c.request_id=rl.id OR c.request_id=rl.request_id) AND c.environment_scope=rl.environment_scope
   CROSS JOIN LATERAL (SELECT
     substring(c.content FROM cand.start_at+1 FOR cand.end_at-cand.start_at) AS raw,
     (CASE WHEN cand.start_at>500 THEN '…' ELSE '' END)||
     substring(c.content FROM GREATEST(0,cand.start_at-500)+1 FOR LEAST(length(c.content),cand.end_at+500)-GREATEST(0,cand.start_at-500))||
     (CASE WHEN cand.end_at+500<length(c.content) THEN '…' ELSE '' END) AS context
   ) e
   WHERE rl.request_id=cand.request_id AND rl.project_id=cand.project_id
     AND (cand.role='' OR c.role=cand.role) AND length(c.content)>=cand.end_at AND length(c.content)<=4194304
     AND encode(sha256(convert_to(e.raw,'UTF8')),'hex')=cand.raw_sha
     AND (cand.context_sha='' OR encode(sha256(convert_to(e.context,'UTF8')),'hex')=cand.context_sha)
   ORDER BY c.created_at,c.id LIMIT 1
 ) e`

// recoverOccurrenceEvidenceBatch 只为有内容证据权限且请求了原文的读取，按事件里存的哈希从该请求
// 自己的留存消息里恢复原始命中片段和附近内容。整页一次查询；不更新任何审计事件，也不假设检测时的
// 消息序号与留存序号一致（留存的对话可能被压缩过）。
func (r *AlertOccurrenceRepository) recoverOccurrenceEvidenceBatch(ctx context.Context, f AlertOccurrenceFilter, items []AlertOccurrence) error {
	if !f.IncludeRaw || !f.CanReadEvidence || len(items) == 0 {
		return nil
	}
	var (
		indexes                                   []int32
		requests, projects, raws, contexts, roles []string
		starts, ends                              []int32
	)
	for index := range items {
		candidate, ok := occurrenceRecoveryCandidate(index, &items[index])
		if !ok {
			continue
		}
		indexes = append(indexes, int32(candidate.index))
		requests = append(requests, candidate.requestID)
		projects = append(projects, candidate.projectID)
		starts = append(starts, int32(candidate.start))
		ends = append(ends, int32(candidate.end))
		raws = append(raws, candidate.rawSHA256)
		contexts = append(contexts, candidate.contextSHA)
		roles = append(roles, candidate.role)
	}
	if len(indexes) == 0 {
		return nil
	}
	return pgx.BeginTxFunc(ctx, r.db, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL jit = off"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, recoverOccurrenceEvidenceBatchQuery, f.TenantID, indexes, requests, projects, starts, ends, raws, contexts, roles)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var index int32
			var raw, surrounding string
			if err := rows.Scan(&index, &raw, &surrounding); err != nil {
				return err
			}
			if int(index) < 0 || int(index) >= len(items) {
				continue
			}
			item := &items[index]
			item.RawEvidence = raw
			item.EvidenceContext = surrounding
			item.EvidenceRecovered = true
			item.RawEvidenceStatus = "available"
			item.EvidenceStatus = "available"
		}
		return rows.Err()
	})
}

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
	"strings"
	"time"
)

func (s *SecurityClient) executeInspectionPart(ctx context.Context, payload map[string]interface{}, force bool) (map[string]interface{}, error) {
	// The ordinary inline client has a ten-second timeout. Durable attachment
	// retries need the worker's full bounded budget for extraction/OCR.
	worker := *s
	if s.client != nil {
		httpClient := *s.client
		httpClient.Timeout = 60 * time.Second
		worker.client = &httpClient
	}
	s = &worker
	p := copyInspectionPayload(payload)
	if _, isAttachment := p["inspection_attachment"]; !isAttachment && !inspectionPartInScope(s.inspectionPolicy(ctx), p) {
		// Queued under an older binary or policy: the live scope owns the decision.
		return inspectionScopeExcludedResult(), nil
	}
	ctxMap := p["context"].(map[string]interface{})
	tenant, _ := ctxMap["tenant_id"].(string)
	request, _ := p["request_id"].(string)
	provider, _ := ctxMap["provider"].(string)
	source, _ := p["content_source"].(string)
	text, _ := p["content"].(string)
	epoch, _ := payload["inspection_cache_epoch"].(string)
	delete(p, "inspection_source_part")
	delete(p, "inspection_cache_epoch")
	attRaw, isAttachment := p["inspection_attachment"]
	delete(p, "inspection_attachment")
	// referenceFindings 是带字节的附件上文件引用的告警命中，并入字节检测结果。
	var referenceFindings []interface{}
	if isAttachment {
		b, _ := json.Marshal(attRaw)
		var attachment ExtractedAttachment
		if err := json.Unmarshal(b, &attachment); err != nil {
			return nil, err
		}
		if attachment.DataBase64 == "" && attachment.ReferenceID == "" {
			return nil, fmt.Errorf("inspection_attachment_bytes_missing")
		}
		if attachment.ReferenceID != "" {
			// 只带文件 id 的引用按文件策略两项处置和内容例外立即决定（与网关、内联路径同口径）：
			// 没有检测记录、检测未完成、查询失败不再当成“检测未完成”反复重试。
			findings, blocks, err := s.durableFileReference(ctx, tenant, provider, attachment.ReferenceID)
			if err != nil {
				return nil, err
			}
			if blocks {
				return durableFileReferenceResult("block", findings), nil
			}
			if attachment.DataBase64 == "" {
				action := "allow"
				if len(findings) > 0 {
					action = "audit"
				}
				return durableFileReferenceResult(action, findings), nil
			}
			referenceFindings = findings
		}
		// Objects are materialized for each attempt and consumed after it; durable work
		// never holds an expiring object ID as its only copy.
		attachments, objects, failed := s.materializeObjectsWithSnapshot(ctx, tenant, request, provider, []ExtractedAttachment{attachment}, true)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.consumeObjects(cleanup, tenant, objects)
		}()
		if failed {
			return nil, fmt.Errorf("inspection_attachment_unavailable")
		}
		ctxMap["attachments"] = attachments
	}
	// Scope includes all policy inputs (including header identities), source and a
	// freshly probed engine/rules/semantic epoch. No cross-tenant or cross-policy hit.
	scopeData, _ := json.Marshal(map[string]interface{}{"context": ctxMap, "principal": p["principal"], "source": source, "epoch": epoch})
	scope := scanfp.SHA256Hex(string(scopeData))
	sha := scanfp.SHA256Hex(text)
	if !force && !isAttachment && epoch != "" && s.fingerprints != nil {
		if entry, ok := s.fingerprints.LookupScoped(ctx, tenant, sha, scope); ok {
			if !entry.HasFindings() {
				return map[string]interface{}{"action": "allow", "findings": []interface{}{}, "semantic_status": "completed", "inspection_status": "completed"}, nil
			}
			replayContext := map[string]interface{}{}
			for k, v := range ctxMap {
				replayContext[k] = v
			}
			replayContext["content"] = text
			replayContext["content_source"] = source
			result, err := s.postJSON(ctx, strings.TrimRight(s.baseURL, "/")+"/apply-context/", map[string]interface{}{"tenant_id": tenant, "raw_findings": entry.RawFindings, "context": replayContext, "principal": p["principal"]})
			if err == nil {
				result["semantic_status"] = "completed"
				result["inspection_status"] = "completed"
				return result, nil
			}
		}
	}
	result, err := s.postJSON(ctx, strings.TrimRight(s.baseURL, "/")+"/check-input/", p)
	if err != nil {
		return nil, err
	}
	if len(referenceFindings) > 0 {
		items, _ := result["findings"].([]interface{})
		result["findings"] = append(items, referenceFindings...)
		if action, _ := result["action"].(string); action == "" || action == "allow" {
			result["action"] = "audit"
		}
	}
	if inspectionComplete(result) && !isAttachment && s.fingerprints != nil {
		build, _ := result["engine_build"].(string)
		rules, _ := result["rule_pack_version"].(string)
		revision, _ := result["semantic_config_revision"].(string)
		raw, hasRaw := result["raw_findings"]
		if hasRaw && build != "" && rules != "" {
			// The first real scan establishes the same epoch used by following requests.
			if force {
				scopeData, _ = json.Marshal(map[string]interface{}{"context": ctxMap, "principal": p["principal"], "source": source, "epoch": fmt.Sprintf("%s|%s|%s", build, rules, revision)})
				scope = scanfp.SHA256Hex(string(scopeData))
			}
			b, _ := json.Marshal(raw)
			s.fingerprints.StoreResult(ctx, scanfp.Entry{TenantID: tenant, ContentSHA256: sha, ContextScope: scope, RulePackVersion: rules, EngineBuild: build, SemanticConfigRevision: revision, RawFindings: b, FirstRequestID: request})
		}
	}
	return result, nil
}

// durableFileReference 处置持久化检测里一个只带文件 id 的引用：查检测结论，按租户文件策略两项处置，
// 可过例外的（未经扫描、处置不是放行）先核对内容例外。返回要留的命中和是否拦截。请求已结束
// （租约到期、客户端断开）时的查询失败不是处置，返回错误留给下一次尝试。
func (s *SecurityClient) durableFileReference(ctx context.Context, tenant, provider, fileID string) ([]interface{}, bool, error) {
	status := ""
	var hitCategories []string
	verdict, err := s.LookupFileVerdict(ctx, tenant, "", provider, fileID)
	if err != nil && ctx.Err() != nil {
		return nil, false, err
	}
	if err == nil && verdict != nil {
		status, hitCategories = verdict.Status, verdict.HitCategories
	}
	outcome := filereference.Decide(status, err, s.fileReferencePolicyFor(ctx, tenant))
	if outcome.Action == filereference.Allow {
		return nil, false, nil
	}
	if outcome.NeedsExceptionCheck() {
		batch := &filereference.ExceptionBatch{}
		batch.Add(&outcome)
		s.applyFileReferenceExceptions(ctx, tenant, provider, batch)
	}
	finding := proxyReferenceFinding(outcome)
	if len(hitCategories) > 0 {
		finding["hit_categories"] = hitCategories
	}
	return []interface{}{finding}, outcome.Blocks(), nil
}

func durableFileReferenceResult(action string, findings []interface{}) map[string]interface{} {
	if findings == nil {
		findings = []interface{}{}
	}
	return map[string]interface{}{"action": action, "semantic_status": "completed", "findings": findings}
}

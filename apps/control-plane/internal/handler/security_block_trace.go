package handler

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

type securityBlockAuditTrace struct {
	RequestID       string                           `json:"request_id"`
	Request         *repository.BlockRequestMetadata `json:"request"`
	SecurityEvents  []types.SecurityEventInfo        `json:"security_events"`
	ContentRecords  []repository.BlockContentRecord  `json:"content_records"`
	ToolRecords     []repository.BlockToolRecord     `json:"tool_records"`
	ContentCount    int                              `json:"content_count"`
	ToolCount       int                              `json:"tool_count"`
	Status          string                           `json:"status"`
	ContentEvidence types.AuditContentEvidenceInfo   `json:"content_evidence"`
	DetailURL       string                           `json:"detail_url"`
	RetentionURL    string                           `json:"retention_url"`
}

type securityBlockTrace struct {
	Block        *repository.SecurityBlockRecord `json:"block"`
	Alerts       *repository.AlertOccurrencePage `json:"alerts"`
	AlertsStatus string                          `json:"alerts_status"`
	Audit        securityBlockAuditTrace         `json:"audit"`
}

// GetSecurityBlockTrace 把客户报来的阻断编号关联到真实的告警命中和请求留痕元数据。
//
// 留存的请求、回复正文（content_logs、内容留证）不在这里返回，只给出条数和“有无正文”，
// 看正文要走内容留证接口（那里另有更严的权限与读取审计）。
//
// 告警命中原文（2.9.22 起随安全事件入库）按内容证据权限（canReadFullTenantContentEvidence）返回：
// 有权限的角色拿到安全事件摘要 matched_summary（含命中原文 raw_evidence、不打码前后文 evidence_context）、
// 命中明细的原文、预览与前后文、阻断记录的命中原文；其他角色不返回摘要，这些字段为空。
// 端点本地决策（agent_endpoint_evidence.local_decision）对所有角色都不返回。
func GetSecurityBlockTrace(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedContentEvidenceUser(w, r)
		if !ok {
			return
		}
		if user.DepartmentAssignmentMode == "emergency" {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "block record not found")
			return
		}
		if deps == nil || deps.SecurityEventRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "block trace is unavailable")
			return
		}
		blockID := strings.TrimSpace(chi.URLParam(r, "block_id"))
		if blockID == "" || len(blockID) > 128 {
			writeError(w, "invalid_request", "invalid block id")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		block, err := deps.SecurityEventRepo.GetBlockRecord(ctx, user.TenantID, blockID)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "block record not found")
			return
		}
		if err != nil {
			log.Printf("GetSecurityBlockTrace block: tenant=%s err=%v", user.TenantID, err)
			writeError(w, "internal_error", "failed to read block record")
			return
		}
		scope, scopeOK := resolveUsageScope(r, deps)
		if !scopeOK || (!scope.FullTenant && !containsString(scope.ProjectIDs, block.ProjectID)) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "block record not found")
			return
		}
		var projectIDs []string
		if !scope.FullTenant {
			projectIDs = append([]string{}, scope.ProjectIDs...)
		}
		trace := securityBlockTrace{
			Block: block, AlertsStatus: "unavailable",
			Audit: securityBlockAuditTrace{
				RequestID: block.RequestID, Status: "available",
				SecurityEvents: []types.SecurityEventInfo{},
				ContentRecords: []repository.BlockContentRecord{},
				ToolRecords:    []repository.BlockToolRecord{},
			},
		}
		canReadContent := canReadFullTenantContentEvidence(user)
		blockRecordForViewer(block, canReadContent)
		metadata, auditErr := deps.SecurityEventRepo.GetBlockAuditMetadata(ctx, user.TenantID, block.RequestID, projectIDs)
		if metadata != nil {
			trace.Audit.Request = metadata.Request
			trace.Audit.ContentRecords = metadata.ContentRecords
			trace.Audit.ToolRecords = metadata.ToolRecords
			trace.Audit.ContentCount, trace.Audit.ToolCount = metadata.ContentCount, metadata.ToolCount
		}
		if auditErr != nil {
			log.Printf("GetSecurityBlockTrace audit: tenant=%s request=%s err=%v", user.TenantID, block.RequestID, auditErr)
			trace.Audit.Status = "unavailable"
			trace.Audit.ContentEvidence = buildContentEvidenceInfo(time.Now(), nil, nil, nil, auditErr)
		} else {
			trace.Audit.ContentEvidence = blockTraceContentEvidence(metadata, canReadContent)
			if metadata.Request == nil {
				trace.Audit.Status = "not_found"
			}
		}
		events, eventErr := deps.SecurityEventRepo.ListByRequest(ctx, user.TenantID, block.RequestID)
		if eventErr != nil {
			log.Printf("GetSecurityBlockTrace events: tenant=%s request=%s err=%v", user.TenantID, block.RequestID, eventErr)
			trace.Audit.Status = "unavailable"
		} else {
			for _, event := range events {
				if !scope.FullTenant && !containsString(projectIDs, event.ProjectID) {
					continue
				}
				info := mapSecurityEventToInfo(event)
				// matched_summary carries the hit's raw evidence (2.9.22) and can embed a
				// request; only content-evidence readers get it.
				if !canReadContent {
					info.MatchedSummary = nil
				}
				trace.Audit.SecurityEvents = append(trace.Audit.SecurityEvents, info)
			}
		}
		if deps.AlertOccurrenceRepo != nil {
			page, alertErr := deps.AlertOccurrenceRepo.List(ctx, repository.AlertOccurrenceFilter{
				TenantID: user.TenantID, RequestID: block.RequestID, ProjectIDs: projectIDs,
				Grouping: "hits", IncludeSuppressed: true, IncludeRaw: canReadContent, CanReadEvidence: canReadContent, CanViewRawEvidence: canViewRawEvidenceUser(user), Limit: 100,
			})
			if alertErr != nil || page == nil {
				log.Printf("GetSecurityBlockTrace alerts: tenant=%s request=%s err=%v", user.TenantID, block.RequestID, alertErr)
			} else {
				for i := range page.Items {
					item := &page.Items[i]
					if item.AgentEndpointEvidence != nil {
						item.AgentEndpointEvidence.LocalDecision = nil
					}
					if !canReadContent {
						stripAlertOccurrenceEvidence(item)
						item.Reason = ""
						if item.ReasonStatus == "available" {
							item.ReasonStatus = "restricted"
						}
						item.RawEvidenceStatus = "restricted"
					}
				}
				trace.Alerts, trace.AlertsStatus = page, "available"
			}
		}
		if canReadContent {
			start, end := block.CreatedAt.Add(-24*time.Hour), block.CreatedAt.Add(24*time.Hour)
			if trace.Audit.Request != nil {
				if at := trace.Audit.Request.CreatedAt; at.Before(start) {
					start = at.Add(-time.Hour)
				}
			}
			query := url.Values{"from": {start.UTC().Format(time.RFC3339)}, "to": {end.UTC().Format(time.RFC3339)}}
			alertQuery := url.Values{"request_id": {block.RequestID}, "start_time": {start.UTC().Format(time.RFC3339)}, "end_time": {end.UTC().Format(time.RFC3339)}}
			trace.Audit.DetailURL = "/security/alerts?" + alertQuery.Encode()
			query.Set("request_id", block.RequestID)
			trace.Audit.RetentionURL = "/audit/access-retention?" + query.Encode()
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, trace)
	}
}

func blockTraceContentEvidence(metadata *repository.BlockAuditMetadata, canRead bool) types.AuditContentEvidenceInfo {
	if metadata.Request == nil {
		return types.AuditContentEvidenceInfo{Status: "unavailable", ReasonCode: "request_record_missing", Summary: "请求留痕记录未找到，保留的安全事件仍可查看。"}
	}
	var requestEvidence repository.RequestEvidenceMetadata
	requestEvidence.ProxyContentRetained = metadata.Request.ContentRetained
	requestEvidence.RetentionUntil = metadata.Request.RetentionUntil
	var content []repository.ContentLog
	if metadata.HasContent {
		// Presence was checked in SQL. No retained body is read for this view.
		content = []repository.ContentLog{{Content: "present"}}
	}
	evidence := buildContentEvidenceInfo(time.Now(), content, nil, &requestEvidence, nil)
	if evidence.CanView && !canRead {
		evidence.CanView = false
		evidence.Status, evidence.ReasonCode = "restricted", "content_permission_required"
		evidence.Summary = "已有内容留证，请由有取证权限的管理员查看。"
	}
	return evidence
}

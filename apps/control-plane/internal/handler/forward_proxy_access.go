package handler

import (
	"encoding/csv"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
)

func applyForwardProxyAccessTimeWindow(r *http.Request, filter *repository.ForwardProxyAccessFilter) error {
	if r == nil || filter == nil {
		return nil
	}
	_, start, end, err := retentionScopeAndWindow(r)
	if err != nil {
		return err
	}
	filter.StartTime = start
	filter.EndTime = end
	return nil
}

func ListForwardProxyAccess(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		repo := deps.ForwardProxyAccessRepo
		if repo == nil && deps.RequestLogRepo != nil {
			repo = deps.RequestLogRepo
		}
		if repo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "forward proxy access repository is not configured")
			return
		}
		keyword, ok := validatedAuditKeyword(w, r.URL.Query().Get("keyword"))
		if !ok {
			return
		}

		filter := repository.ForwardProxyAccessFilter{
			EnvironmentScope: "customer",
			RiskState:        r.URL.Query().Get("risk_state"),
			AccessType:       r.URL.Query().Get("access_type"),
			Provider:         r.URL.Query().Get("provider"),
			TargetHost:       r.URL.Query().Get("target_host"),
			SourceIP:         r.URL.Query().Get("source_ip"),
			UserID:           r.URL.Query().Get("user_id"),
			Disposition:      r.URL.Query().Get("disposition"),
			Keyword:          keyword,
			KeywordScope:     r.URL.Query().Get("keyword_scope"),
			Direction:        r.URL.Query().Get("direction"),
			RequestID:        strings.TrimSpace(r.URL.Query().Get("request_id")),
			AgentType:        r.URL.Query().Get("agent_type"),
			ContentOnly:      parseBoolParam(r.URL.Query().Get("content_only")),
			Limit:            normalizeForwardProxyPageLimit(parseIntParam(r.URL.Query().Get("limit"), 100)),
			Offset:           parseIntParam(r.URL.Query().Get("offset"), 0),
			// skip_total 让仓储跳过无界 COUNT（安全告警页只用行，不显示总数）
			SkipTotal:    parseBoolParam(r.URL.Query().Get("skip_total")) || keyword != "",
			ProbeHasMore: true,
		}
		if filter.Offset < 0 {
			filter.Offset = 0
		}
		if err := applyForwardProxyAccessTimeWindow(r, &filter); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid UTC window")
			return
		}
		if !validateAuditKeywordWindow(w, keyword, filter.StartTime, filter.EndTime) {
			return
		}
		queryCtx, finishSearch, ok := beginAuditKeywordSearch(w, r, user.TenantID, keyword)
		if !ok {
			return
		}
		defer finishSearch()

		if parseBoolParam(r.URL.Query().Get("summary_only")) {
			var summary repository.ForwardProxyAccessSummary
			var err error
			if r.URL.Query().Get("summary_detail") == "counts" {
				countsRepo, ok := repo.(ForwardProxyAccessCountsRepo)
				if !ok {
					writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "forward proxy access counts repository is not configured")
					return
				}
				summary, err = countsRepo.GetForwardProxyAccessCounts(queryCtx, user.TenantID, filter)
			} else {
				summary, err = repo.GetForwardProxyAccessSummary(queryCtx, user.TenantID, filter)
			}
			summaryError := ""
			if err != nil {
				log.Printf("access retention summary failed: request_id=%q err=%v", r.Header.Get("X-Request-ID"), err)
				summary = repository.ForwardProxyAccessSummary{}
				summaryError = "summary_unavailable"
			}
			resp := types.ForwardProxyAccessListResponse{
				Data:         []types.ForwardProxyAccessInfo{},
				Total:        summary.Total,
				TotalKnown:   true,
				Summary:      mapForwardProxySummaryToInfo(summary),
				SummaryError: summaryError,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		items, total, err := repo.ListForwardProxyAccess(queryCtx, user.TenantID, filter)
		if err != nil {
			log.Printf("access retention list failed: request_id=%q err=%v", r.Header.Get("X-Request-ID"), err)
			writeAuditKeywordQueryError(w, err, "failed to list forward proxy access records")
			return
		}
		// skip_summary 跳过整表汇总聚合（安全告警页丢弃 summary）；默认仍返回，
		// 留存详情页(AccessRetention)与内容审计页不带此参数，行为不变。
		var summary repository.ForwardProxyAccessSummary
		summaryError := ""
		if !parseBoolParam(r.URL.Query().Get("skip_summary")) && keyword == "" {
			summary, err = repo.GetForwardProxyAccessSummary(queryCtx, user.TenantID, filter)
			if err != nil {
				log.Printf("access retention summary failed: request_id=%q err=%v", r.Header.Get("X-Request-ID"), err)
				summary = repository.ForwardProxyAccessSummary{}
				summaryError = "summary_unavailable"
			}
		}

		hasMore := len(items) > filter.Limit
		if hasMore {
			items = items[:filter.Limit]
		}
		totalKnown := !filter.SkipTotal
		if totalKnown {
			hasMore = filter.Offset+len(items) < total
		} else {
			total = filter.Offset + len(items)
			if hasMore {
				total++
			}
		}
		data := make([]types.ForwardProxyAccessInfo, len(items))
		for i, item := range items {
			data[i] = mapForwardProxyAccessToInfo(item)
		}
		resp := types.ForwardProxyAccessListResponse{
			Data:         data,
			Total:        total,
			HasMore:      hasMore,
			TotalKnown:   totalKnown,
			Summary:      mapForwardProxySummaryToInfo(summary),
			SummaryError: summaryError,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func normalizeForwardProxyPageLimit(limit int) int {
	if limit <= 0 || limit > 500 {
		return 100
	}
	return limit
}

func mapForwardProxyAccessToInfo(item repository.ForwardProxyAccessRecord) types.ForwardProxyAccessInfo {
	return types.ForwardProxyAccessInfo{
		RequestID:            item.RequestID,
		TenantID:             item.TenantID,
		UserID:               item.UserID,
		Username:             item.Username,
		CreatedAt:            item.CreatedAt.Format(time.RFC3339),
		SourceIP:             item.SourceIP,
		TargetHost:           item.TargetHost,
		TargetPath:           item.TargetPath,
		Method:               item.Method,
		Provider:             item.Provider,
		ProviderCN:           item.ProviderCN,
		Product:              item.Product,
		ProductCN:            item.ProductCN,
		AccessType:           item.AccessType,
		EndpointKind:         item.EndpointKind,
		PathTemplate:         item.PathTemplate,
		Status:               item.Status,
		StatusCode:           item.StatusCode,
		ResponseBytes:        item.ResponseBytes,
		RequestBytes:         item.RequestBytes,
		TunnelDurationMS:     item.TunnelDurationMS,
		TLSInspected:         item.TLSInspected,
		RetentionLevel:       item.RetentionLevel,
		ContentRetained:      item.ContentRetained,
		RiskState:            item.RiskState,
		RiskReasons:          item.RiskReasons,
		ActionTaken:          item.ActionTaken,
		SecurityEventCount:   item.SecurityEventCount,
		ActionableAlertCount: item.ActionableAlertCount,
		DispositionStatus:    item.DispositionStatus,
		AccessDirection:      item.AccessDirection,
		AgentType:            item.AgentType,
		AgentLabel:           forwardProxyAgentLabel(item.AgentType),
		ClientID:             customerVisibleCorrelationValue(item.ClientID),
		ClientName:           item.ClientName,
		IdentityKind:         item.IdentityKind,
		KeyOwner:             item.KeyOwner,
		MemberCount:          item.MemberCount,
		TurnCount:            item.TurnCount,
		MemberRequestIDs:     item.MemberRequestIDs,
	}
}

// forwardProxyAgentLabel 返回智能体的面向人展示名；无智能体标记时返回空串，
// 前端据此显示「—」而非「未知智能体」，避免把普通网页流量误标为智能体。
func forwardProxyAgentLabel(agentType string) string {
	if strings.TrimSpace(agentType) == "" {
		return ""
	}
	return agentdetect.Label(agentType)
}

func mapForwardProxySummaryToInfo(item repository.ForwardProxyAccessSummary) types.ForwardProxyAccessSummaryInfo {
	freshUntil := ""
	if item.DataFreshUntil != nil {
		freshUntil = item.DataFreshUntil.UTC().Format(time.RFC3339)
	}
	return types.ForwardProxyAccessSummaryInfo{
		Total:                  item.Total,
		NormalCount:            item.NormalCount,
		RiskCount:              item.RiskCount,
		BlockedCount:           item.BlockedCount,
		LLMCount:               item.LLMCount,
		AIIdeCount:             item.AIIdeCount,
		NormalPublicCount:      item.NormalPublicCount,
		RetainedContentCount:   item.RetainedContentCount,
		UndetectedCount:        item.UndetectedCount,
		ForwardCount:           item.ForwardCount,
		ReverseCount:           item.ReverseCount,
		DeviceCount:            item.DeviceCount,
		AgentRequestCount:      item.AgentRequestCount,
		IdentifiedAgentCount:   item.IdentifiedAgentCount,
		UnidentifiedAgentCount: item.UnidentifiedAgentCount,
		UniqueModelCount:       item.UniqueModelCount,
		EvidenceQuality: types.ForwardProxyEvidenceQualityInfo{
			CompleteCount:     item.EvidenceQuality.CompleteCount,
			RequestOnlyCount:  item.EvidenceQuality.RequestOnlyCount,
			ResponseOnlyCount: item.EvidenceQuality.ResponseOnlyCount,
			MetadataOnlyCount: item.EvidenceQuality.MetadataOnlyCount,
		},
		TopProviders:      mapForwardProxyDimensionsToInfo(maskForwardProxyProviders(item.TopProviders)),
		TopTargets:        mapForwardProxyDimensionsToInfo(item.TopTargets),
		TopAgents:         mapForwardProxyAgentDimensionsToInfo(item.TopAgents),
		Timeline:          mapForwardProxyTimelineToInfo(item.Timeline),
		TopRiskCategories: mapForwardProxyRiskCategoriesToInfo(item.TopRiskCategories),
		DataFreshUntil:    freshUntil,
	}
}

func mapForwardProxyTimelineToInfo(items []repository.ForwardProxyAccessTimelinePoint) []types.ForwardProxyAccessTimelinePointInfo {
	out := make([]types.ForwardProxyAccessTimelinePointInfo, len(items))
	for i, item := range items {
		out[i] = types.ForwardProxyAccessTimelinePointInfo{
			Bucket:       item.Bucket.UTC().Format(time.RFC3339),
			TotalCount:   item.TotalCount,
			NormalCount:  item.NormalCount,
			RiskCount:    item.RiskCount,
			BlockedCount: item.BlockedCount,
		}
	}
	return out
}

func mapForwardProxyRiskCategoriesToInfo(items []repository.ForwardProxyRiskCategory) []types.ForwardProxyRiskCategoryInfo {
	out := make([]types.ForwardProxyRiskCategoryInfo, len(items))
	for i, item := range items {
		out[i] = types.ForwardProxyRiskCategoryInfo{Name: item.Name, Count: item.Count}
	}
	return out
}

func mapForwardProxyAgentDimensionsToInfo(items []repository.ForwardProxyAccessDimension) []types.ForwardProxyAccessAgentDimensionInfo {
	out := make([]types.ForwardProxyAccessAgentDimensionInfo, 0, len(items))
	for _, item := range items {
		out = append(out, types.ForwardProxyAccessAgentDimensionInfo{
			Name: item.Name, Label: agentdetect.Label(item.Name), Count: item.Count, RiskCount: item.RiskCount,
		})
	}
	return out
}

// maskForwardProxyProviders 把非大厂上游合并成单一「第三方」维度（客户可见审计页脱敏），
// 大厂与 unknown/直连原样保留。TopProviders 同时驱动「服务商流量占比」饼图与服务商筛选
// 下拉，在此（rollup 与非 rollup 两条 summary 来源的汇合点）收口即可一处覆盖两者，与
// 记录级 enrichForwardProxyCatalogLabels、筛选 buildForwardProxyWhere 的第三方口径一致。
func maskForwardProxyProviders(items []repository.ForwardProxyAccessDimension) []repository.ForwardProxyAccessDimension {
	out := make([]repository.ForwardProxyAccessDimension, 0, len(items))
	var third repository.ForwardProxyAccessDimension
	hasThird := false
	for _, item := range items {
		if llmcatalog.IsMaskedProvider(item.Name) {
			third.Name = llmcatalog.ThirdPartyLabel
			third.Count += item.Count
			third.RiskCount += item.RiskCount
			hasThird = true
			continue
		}
		out = append(out, item)
	}
	if hasThird {
		out = append(out, third)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].RiskCount > out[j].RiskCount
	})
	return out
}

func mapForwardProxyDimensionsToInfo(items []repository.ForwardProxyAccessDimension) []types.ForwardProxyAccessDimensionInfo {
	out := make([]types.ForwardProxyAccessDimensionInfo, len(items))
	for i, item := range items {
		out[i] = types.ForwardProxyAccessDimensionInfo{
			Name:      item.Name,
			Count:     item.Count,
			RiskCount: item.RiskCount,
		}
	}
	return out
}

func ExportForwardProxyAccess(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		repo := deps.ForwardProxyAccessRepo
		if repo == nil && deps.RequestLogRepo != nil {
			repo = deps.RequestLogRepo
		}
		if repo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "forward proxy access repository is not configured")
			return
		}
		keyword, ok := validatedAuditKeyword(w, r.URL.Query().Get("keyword"))
		if !ok {
			return
		}

		filter := repository.ForwardProxyAccessFilter{
			EnvironmentScope: "customer",
			RiskState:        r.URL.Query().Get("risk_state"),
			AccessType:       r.URL.Query().Get("access_type"),
			Provider:         r.URL.Query().Get("provider"),
			TargetHost:       r.URL.Query().Get("target_host"),
			SourceIP:         r.URL.Query().Get("source_ip"),
			UserID:           r.URL.Query().Get("user_id"),
			Disposition:      r.URL.Query().Get("disposition"),
			Keyword:          keyword,
			KeywordScope:     r.URL.Query().Get("keyword_scope"),
			Direction:        r.URL.Query().Get("direction"),
			RequestID:        strings.TrimSpace(r.URL.Query().Get("request_id")),
			AgentType:        r.URL.Query().Get("agent_type"),
			ContentOnly:      parseBoolParam(r.URL.Query().Get("content_only")),
			Limit:            parseIntParam(r.URL.Query().Get("limit"), 10000),
			Offset:           parseIntParam(r.URL.Query().Get("offset"), 0),
			AllowLargeLimit:  true,
			SkipTotal:        keyword != "",
		}
		if err := applyForwardProxyAccessTimeWindow(r, &filter); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid UTC window")
			return
		}
		if keyword != "" && filter.Limit > 5000 {
			filter.Limit = 5000
		}
		if !validateAuditKeywordWindow(w, keyword, filter.StartTime, filter.EndTime) {
			return
		}
		queryCtx, finishSearch, ok := beginAuditKeywordSearch(w, r, user.TenantID, keyword)
		if !ok {
			return
		}
		defer finishSearch()

		items, total, err := repo.ListForwardProxyAccess(queryCtx, user.TenantID, filter)
		if err != nil {
			log.Printf("access retention export list failed: request_id=%q err=%v", r.Header.Get("X-Request-ID"), err)
			writeAuditKeywordQueryError(w, err, "failed to list forward proxy access records")
			return
		}

		if r.URL.Query().Get("format") == "json" {
			data := make([]types.ForwardProxyAccessInfo, len(items))
			for i, item := range items {
				data[i] = mapForwardProxyAccessToInfo(item)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", `attachment; filename="access-retention-export.json"`)
			json.NewEncoder(w).Encode(struct {
				Data  []types.ForwardProxyAccessInfo `json:"data"`
				Total int                            `json:"total"`
			}{Data: data, Total: total})
			return
		}

		// default: CSV (with UTF-8 BOM so Excel renders Chinese correctly)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="access-retention-export.csv"`)
		w.Write([]byte("\xEF\xBB\xBF"))
		cw := csv.NewWriter(w)
		cw.Write([]string{
			"请求ID", "时间", "流量方向", "智能体", "来源IP", "目标主机", "目标路径", "方法",
			"服务商", "产品", "访问类型", "状态", "状态码", "响应字节", "上行字节", "隧道时长（毫秒）",
			"留存级别", "已留存内容", "风险状态", "处置动作", "安全事件数", "处置状态",
		})
		for _, item := range items {
			cw.Write([]string{
				item.RequestID,
				item.CreatedAt.Format(time.RFC3339),
				accessDirectionLabel(item.AccessDirection),
				forwardProxyAgentLabel(item.AgentType),
				item.SourceIP,
				item.TargetHost,
				item.TargetPath,
				item.Method,
				firstNonEmpty(item.ProviderCN, item.Provider),
				firstNonEmpty(item.ProductCN, item.Product),
				accessTypeLabel(item.AccessType),
				item.Status,
				strconv.Itoa(item.StatusCode),
				strconv.FormatInt(item.ResponseBytes, 10),
				strconv.FormatInt(item.RequestBytes, 10),
				strconv.FormatInt(item.TunnelDurationMS, 10),
				item.RetentionLevel,
				boolCN(item.ContentRetained),
				item.RiskState,
				item.ActionTaken,
				strconv.Itoa(item.SecurityEventCount),
				item.DispositionStatus,
			})
		}
		cw.Flush()
	}
}

func accessTypeLabel(value string) string {
	switch value {
	case "llm":
		return "大模型访问"
	case "ai_ide":
		return "AI开发工具访问"
	case "normal_public":
		return "普通公网访问"
	case "unknown_ai_candidate":
		return "待识别AI访问"
	default:
		return value
	}
}

func accessDirectionLabel(d string) string {
	switch d {
	case "forward":
		return "正向代理"
	case "device":
		return "经过设备"
	default:
		return "反向代理"
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func boolCN(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

func parseBoolParam(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

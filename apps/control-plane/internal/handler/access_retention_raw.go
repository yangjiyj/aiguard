package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionfmt"
)

// retentionRawSection 是「全部原文」视图里的一段。这一路由已经在 RequireFullTenantContentEvidence
// 之后，段内容不再做客户视图脱标识——它本来就是给审计员看的完整证据。
// Role 由写入侧的角色标签还原（见 retentionfmt.SplitRetainedSections）。
type retentionRawSection struct {
	RequestID string `json:"request_id,omitempty"`
	Direction string `json:"direction"` // request | response
	Role      string `json:"role"`      // user | assistant | system | tool | other
	Content   string `json:"content"`
}

// retentionEvidenceFallbackEntry 是正文全空时的兜底：规则命中那一刻截取的原文。
// 取自 security_events.matched_summary.findings[]——写侧只对 matched/secret/token/credential/preview
// 类字段做脱标识，raw_evidence / evidence_context 原样保留（凭据规则命中处留的正是凭据片段），
// 因此这里必须整块标注"未脱敏"，而不是悄悄并进正文。
type retentionEvidenceFallbackEntry struct {
	EventID         string `json:"event_id"`
	RuleName        string `json:"rule_name,omitempty"`
	Category        string `json:"category,omitempty"`
	Severity        string `json:"severity,omitempty"`
	ContentSource   string `json:"content_source,omitempty"`
	MessageRole     string `json:"message_role,omitempty"`
	MessageIndex    int    `json:"message_index,omitempty"`
	RawEvidence     string `json:"raw_evidence,omitempty"`
	EvidenceContext string `json:"evidence_context,omitempty"`
}

type accessRetentionRawResponse struct {
	RequestID        string                           `json:"request_id"`
	RetentionUntil   string                           `json:"retention_until,omitempty"`
	DecoderVersion   string                           `json:"decoder_version,omitempty"`
	Sections         []retentionRawSection            `json:"sections"`
	ToolCalls        []json.RawMessage                `json:"tool_calls"`
	EvidenceFallback []retentionEvidenceFallbackEntry `json:"evidence_fallback"`
}

// maxRetentionEvidenceFallbackEntries 给兜底证据封顶：一个请求可能命中几十条规则，
// 但"全部原文"面板是给人看的，超出部分没有边际信息量。
const maxRetentionEvidenceFallbackEntries = 50

// retentionSecurityEventReader 只暴露 view=raw 兜底需要的按请求查询能力。
type retentionSecurityEventReader interface {
	ListByRequestScoped(ctx context.Context, tenantID, requestID string, start, end time.Time, environmentScope string) ([]*repository.SecurityEvent, error)
}

func retentionSecurityEventReaderFor(deps *Dependencies) retentionSecurityEventReader {
	if deps == nil {
		return nil
	}
	if deps.RetentionSecurityEventReader != nil {
		return deps.RetentionSecurityEventReader
	}
	if deps.SecurityEventRepo != nil {
		return deps.SecurityEventRepo
	}
	return nil
}

// serveAccessRetentionRaw 处理 view=raw：把留证正文按写入侧的角色标签还原成分段原文，
// 连同工具调用索引一起给出；正文确实没有留存时，回退到安全事件命中时截取的原文。
//
// 与 view=turns / 默认视图的差别只有两点：不脱标识（权限门已在路由中间件上），
// 以及不分轮折叠（审计要看的是完整原文与顺序）。
func serveAccessRetentionRaw(
	w http.ResponseWriter,
	r *http.Request,
	deps *Dependencies,
	tenantID, requestID string,
	memberIDs []string,
	items []repository.AccessContentLog,
	scope string,
	start, end time.Time,
) {
	ordered := append([]repository.AccessContentLog(nil), items...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].CreatedAt.Equal(ordered[j].CreatedAt) {
			return ordered[i].RequestID < ordered[j].RequestID
		}
		return ordered[i].CreatedAt.Before(ordered[j].CreatedAt)
	})

	byRequest := make(map[string]repository.AccessContentLog, len(ordered))
	orderedIDs := make([]string, 0, len(ordered))
	for _, item := range ordered {
		orderedIDs = append(orderedIDs, item.RequestID)
		byRequest[item.RequestID] = item
	}
	if len(orderedIDs) == 0 {
		orderedIDs = append(orderedIDs, memberIDs...)
	}
	if len(orderedIDs) == 0 {
		orderedIDs = []string{requestID}
	}

	response := accessRetentionRawResponse{
		RequestID:        requestID,
		Sections:         []retentionRawSection{},
		ToolCalls:        []json.RawMessage{},
		EvidenceFallback: []retentionEvidenceFallbackEntry{},
	}
	var latestUntil *time.Time
	for _, id := range orderedIDs {
		item, present := byRequest[id]
		if present {
			if item.RetentionUntil != nil && (latestUntil == nil || item.RetentionUntil.After(*latestUntil)) {
				latestUntil = item.RetentionUntil
			}
			if strings.TrimSpace(item.DecoderVersion) != "" {
				response.DecoderVersion = strings.TrimSpace(item.DecoderVersion)
			}
			if len(item.ToolCallMetadataJSON) > 0 {
				var batch []json.RawMessage
				if json.Unmarshal(item.ToolCallMetadataJSON, &batch) == nil {
					response.ToolCalls = append(response.ToolCalls, batch...)
				}
			}
		}

		memberSections, hasRequest, hasResponse := retentionRawMemberSections(id, item, present)
		// 请求正文没留下来时才用 content_logs 回退：主链路（反向代理/主对话）只写 content_logs，
		// 正向代理才写 access_content_logs，两条路径都要能看。
		if !hasRequest && deps != nil && deps.ContentLogReader != nil {
			logs, err := listContentLogsByRequest(r.Context(), deps.ContentLogReader, tenantID, id, scope, start, end)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get content logs")
				return
			}
			for _, log := range logs {
				direction, role := retentionContentLogSection(log.Role)
				if direction == "response" && hasResponse {
					continue
				}
				content := strings.TrimSpace(log.Content)
				if content == "" {
					continue
				}
				memberSections = append(memberSections, retentionRawSection{RequestID: id, Direction: direction, Role: role, Content: content})
				if direction == "request" {
					hasRequest = true
				} else {
					hasResponse = true
				}
			}
		}
		response.Sections = append(response.Sections, memberSections...)
	}
	if latestUntil != nil {
		response.RetentionUntil = latestUntil.UTC().Format("2006-01-02T15:04:05Z")
	}

	if retentionEvidenceFallbackNeeded(response.Sections, ordered) {
		entries, err := buildRetentionEvidenceFallback(r.Context(), deps, tenantID, orderedIDs, scope, start, end)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get security event evidence")
			return
		}
		if entries != nil {
			response.EvidenceFallback = entries
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// retentionRawMemberSections 把一条留证记录还原成请求段在前、响应段在后的分段列表。
// present=false（该请求没有 access_content_logs 行）时返回空列表，交给 content_logs 回退。
func retentionRawMemberSections(id string, item repository.AccessContentLog, present bool) ([]retentionRawSection, bool, bool) {
	if !present {
		return nil, false, false
	}
	out := []retentionRawSection{}
	hasRequest, hasResponse := false, false
	for _, section := range retentionfmt.SplitRetainedSections(item.RequestContent, "user") {
		out = append(out, retentionRawSection{RequestID: id, Direction: "request", Role: section.Role, Content: section.Content})
		hasRequest = true
	}
	for _, section := range retentionfmt.SplitRetainedSections(item.ResponseContent, "assistant") {
		out = append(out, retentionRawSection{RequestID: id, Direction: "response", Role: section.Role, Content: section.Content})
		hasResponse = true
	}
	return out, hasRequest, hasResponse
}

// retentionContentLogSection 把 content_logs.role 直接映射成 (direction, role)。
func retentionContentLogSection(role string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "assistant":
		return "response", "assistant"
	case "system", "developer":
		return "request", "system"
	case "tool", "function":
		return "request", "tool"
	case "user", "":
		return "request", "user"
	default:
		return "request", "other"
	}
}

// retentionEvidenceFallbackNeeded 判定是否要回退到安全事件留证：整份视图一段正文都没有，
// 或者某条成员的用户正文连安全投影都判不出人话（evidence_gap：命中的是文件名/编码负载这类
// 只剩协议残留的内容）且没有模型回复。
func retentionEvidenceFallbackNeeded(sections []retentionRawSection, items []repository.AccessContentLog) bool {
	if len(sections) == 0 {
		return true
	}
	for _, item := range items {
		if _, status := safeRetentionUserInput(item.RequestContent); status != "evidence_gap" {
			continue
		}
		if strings.TrimSpace(item.ResponseContent) == "" {
			return true
		}
	}
	return false
}

func buildRetentionEvidenceFallback(
	ctx context.Context,
	deps *Dependencies,
	tenantID string,
	requestIDs []string,
	scope string,
	start, end time.Time,
) ([]retentionEvidenceFallbackEntry, error) {
	reader := retentionSecurityEventReaderFor(deps)
	if reader == nil {
		return nil, nil
	}
	out := []retentionEvidenceFallbackEntry{}
	for _, id := range requestIDs {
		events, err := reader.ListByRequestScoped(ctx, tenantID, id, start, end, scope)
		if err != nil {
			return nil, err
		}
		for _, event := range events {
			if event == nil {
				continue
			}
			for _, finding := range retentionFindingMaps(event.MatchedSummary["findings"]) {
				entry := retentionEvidenceFallbackEntry{
					EventID:         event.ID,
					RuleName:        firstNonEmpty(retentionFindingString(finding, "rule_name"), event.RuleName),
					Category:        retentionFindingString(finding, "category"),
					Severity:        firstNonEmpty(retentionFindingString(finding, "severity"), event.Severity),
					ContentSource:   retentionFindingString(finding, "content_source"),
					MessageRole:     retentionFindingString(finding, "message_role"),
					MessageIndex:    retentionFindingInt(finding, "message_index"),
					RawEvidence:     retentionFindingString(finding, "raw_evidence"),
					EvidenceContext: retentionFindingString(finding, "evidence_context"),
				}
				if strings.TrimSpace(entry.RawEvidence) == "" && strings.TrimSpace(entry.EvidenceContext) == "" {
					continue
				}
				out = append(out, entry)
				if len(out) >= maxRetentionEvidenceFallbackEntries {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

func retentionFindingMaps(raw interface{}) []map[string]interface{} {
	switch typed := raw.(type) {
	case []map[string]interface{}:
		return typed
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			if finding, ok := item.(map[string]interface{}); ok {
				out = append(out, finding)
			}
		}
		return out
	default:
		return nil
	}
}

func retentionFindingString(finding map[string]interface{}, key string) string {
	value, _ := finding[key].(string)
	return strings.TrimSpace(value)
}

func retentionFindingInt(finding map[string]interface{}, key string) int {
	switch typed := finding[key].(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return int(parsed)
		}
	}
	return 0
}

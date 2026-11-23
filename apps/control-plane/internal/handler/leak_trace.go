package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/aicontentlabel"
)

// 泄露溯源：管理员粘贴一段疑似泄露的 AI 回复，先解网关加的零宽水印，校验通过就定位原始请求；
// 没有水印时从文本里切几段片段，在留存的助手回复里按关键字检索候选请求。只返回请求元数据，不返回正文。

const (
	leakTraceMaxBodyBytes  = 64 << 10
	leakTraceMaxTextRunes  = 20000
	leakTraceMaxFragments  = 3
	leakTraceFragmentMin   = 20
	leakTraceFragmentMax   = 128
	leakTraceMaxCandidates = 20
)

type leakTraceRequest struct {
	Text string `json:"text"`
	From string `json:"from"`
	To   string `json:"to"`
}

type leakTraceMatch struct {
	RequestID  string    `json:"request_id"`
	OccurredAt time.Time `json:"occurred_at"`
	UserID     string    `json:"user_id"`
	Username   string    `json:"username"`
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	AgentType  string    `json:"agent_type"`
	Provider   string    `json:"provider"`
	Target     string    `json:"target"`
	// Fragments 是命中的片段序号（从 1 开始），水印命中时为空。
	Fragments []int `json:"fragments,omitempty"`
}

type leakTraceResponse struct {
	// Method 是 watermark（水印定位）、fragments（片段检索）或 none（无法检索）。
	Method string `json:"method"`
	// Watermark 是水印检查结果：verified、forged（格式完整但校验失败）、absent。
	Watermark string           `json:"watermark"`
	Fragments []string         `json:"fragments,omitempty"`
	Matches   []leakTraceMatch `json:"matches"`
	Note      string           `json:"note,omitempty"`
}

// leakTraceDeps 是泄露溯源依赖的最小接口，便于测试替换。
type leakTraceDeps interface {
	evidenceMetadata(ctx context.Context, tenantID, requestID string) (*repository.RequestEvidenceMetadata, error)
	searchAssistant(ctx context.Context, tenantID, keyword string, start, end time.Time) ([]repository.ContentLog, error)
}

type leakTraceRepoDeps struct{ deps *Dependencies }

func (d leakTraceRepoDeps) evidenceMetadata(ctx context.Context, tenantID, requestID string) (*repository.RequestEvidenceMetadata, error) {
	if d.deps == nil || d.deps.RequestLogRepo == nil {
		return nil, nil
	}
	return d.deps.RequestLogRepo.GetEvidenceMetadata(ctx, tenantID, requestID)
}

func (d leakTraceRepoDeps) searchAssistant(ctx context.Context, tenantID, keyword string, start, end time.Time) ([]repository.ContentLog, error) {
	if d.deps == nil || d.deps.ContentLogRepo == nil {
		return nil, nil
	}
	logs, _, err := d.deps.ContentLogRepo.SearchPage(ctx, repository.ContentLogSearchFilter{
		TenantID: tenantID, EnvironmentScope: customerRetentionScope, Keyword: keyword, Role: "assistant",
		StartTime: start, EndTime: end, Limit: 100, SkipTotal: true,
	})
	return logs, err
}

// LeakTrace 处理 POST /admin/v1/audit/leak-trace。
func LeakTrace(deps *Dependencies) http.HandlerFunc {
	return leakTraceHandler(deps, leakTraceRepoDeps{deps: deps})
}

func leakTraceHandler(deps *Dependencies, store leakTraceDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		var req leakTraceRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, leakTraceMaxBodyBytes)).Decode(&req); err != nil {
			writeError(w, "invalid_request", "请求格式不正确")
			return
		}
		text := strings.TrimSpace(req.Text)
		if text == "" {
			writeError(w, "invalid_request", "请粘贴要溯源的文本")
			return
		}
		if utf8.RuneCountInString(text) > leakTraceMaxTextRunes {
			writeError(w, "invalid_request", "文本过长，请只粘贴疑似泄露的片段（最多 20000 字）")
			return
		}

		resp := leakTraceResponse{Method: "none", Watermark: "absent", Matches: []leakTraceMatch{}}
		key := aicontentlabel.DeriveKey(leakTraceSecret(deps))
		seen := map[string]bool{}
		for _, frame := range aicontentlabel.Find(text) {
			requestID, ok := aicontentlabel.Verify(frame, key)
			if !ok {
				if resp.Watermark == "absent" {
					resp.Watermark = "forged"
				}
				continue
			}
			resp.Watermark = "verified"
			if seen[requestID] {
				continue
			}
			seen[requestID] = true
			meta, err := store.evidenceMetadata(r.Context(), user.TenantID, requestID)
			if err != nil {
				writeError(w, "internal_error", "查询请求记录失败")
				return
			}
			if meta != nil {
				resp.Matches = append(resp.Matches, leakTraceMatchFromMeta(meta, nil))
			}
		}
		if resp.Watermark == "verified" {
			resp.Method = "watermark"
			if len(resp.Matches) == 0 {
				resp.Note = "水印校验通过，但对应请求已超出保留期或不属于当前租户"
			}
			logLeakTrace(r, deps, resp)
			writeJSON(w, resp)
			return
		}

		fragments := leakTraceFragments(aicontentlabel.Strip(text))
		if len(fragments) == 0 {
			resp.Note = "文本里没有可用于检索的连续文字（每段至少 20 字）"
			logLeakTrace(r, deps, resp)
			writeJSON(w, resp)
			return
		}
		start, end, ok := leakTraceWindow(w, req)
		if !ok {
			return
		}
		resp.Method = "fragments"
		resp.Fragments = fragments
		byRequest := map[string]*leakTraceMatch{}
		var order []string
		for i, fragment := range fragments {
			ctx, release, ok := beginAuditKeywordSearch(w, r, user.TenantID, fragment)
			if !ok {
				return
			}
			logs, err := store.searchAssistant(ctx, user.TenantID, fragment, start, end)
			release()
			if err != nil {
				writeAuditKeywordQueryError(w, err, "检索留存正文失败")
				return
			}
			for _, l := range logs {
				if m, exists := byRequest[l.RequestID]; exists {
					if m.Fragments[len(m.Fragments)-1] != i+1 {
						m.Fragments = append(m.Fragments, i+1)
					}
					continue
				}
				if len(order) >= leakTraceMaxCandidates {
					continue
				}
				m := &leakTraceMatch{RequestID: l.RequestID, OccurredAt: l.CreatedAt, UserID: l.UserID, Fragments: []int{i + 1}}
				byRequest[l.RequestID] = m
				order = append(order, l.RequestID)
			}
		}
		for _, id := range order {
			m := byRequest[id]
			if meta, err := store.evidenceMetadata(r.Context(), user.TenantID, id); err == nil && meta != nil {
				*m = leakTraceMatchFromMeta(meta, m.Fragments)
			}
			resp.Matches = append(resp.Matches, *m)
		}
		if len(resp.Matches) == 0 {
			resp.Note = "在所选时间范围内没有找到包含这些片段的助手回复"
		}
		logLeakTrace(r, deps, resp)
		writeJSON(w, resp)
	}
}

func leakTraceSecret(deps *Dependencies) string {
	if deps == nil {
		return ""
	}
	return deps.SecurityEngineInternalToken
}

func leakTraceMatchFromMeta(meta *repository.RequestEvidenceMetadata, fragments []int) leakTraceMatch {
	return leakTraceMatch{
		RequestID: meta.RequestID, OccurredAt: meta.OccurredAt, UserID: meta.UserID, Username: meta.Username,
		ClientID: meta.ClientID, ClientName: meta.ClientName, AgentType: meta.AgentType,
		Provider: meta.Provider, Target: meta.Target, Fragments: fragments,
	}
}

func leakTraceWindow(w http.ResponseWriter, req leakTraceRequest) (time.Time, time.Time, bool) {
	end := time.Now().UTC()
	start := end.Add(-30 * 24 * time.Hour)
	if strings.TrimSpace(req.From) != "" || strings.TrimSpace(req.To) != "" {
		from, errFrom := time.Parse(time.RFC3339, strings.TrimSpace(req.From))
		to, errTo := time.Parse(time.RFC3339, strings.TrimSpace(req.To))
		if errFrom != nil || errTo != nil {
			writeError(w, "invalid_request", "时间范围格式不正确")
			return time.Time{}, time.Time{}, false
		}
		start, end = from.UTC(), to.UTC()
	}
	if !validateAuditKeywordWindow(w, "fragment", start, end) {
		return time.Time{}, time.Time{}, false
	}
	return start, end, true
}

var (
	leakTraceMarkdownNoise = regexp.MustCompile("(?m)^\\s{0,3}(#{1,6}\\s+|[-*+]\\s+|>\\s?|\\d+[.)]\\s+)|[*_`~|]+")
	leakTraceLineBreaks    = regexp.MustCompile(`\s*\n+\s*`)
	leakTraceSentenceEnd   = regexp.MustCompile(`[。！？!?；;]`)
)

// leakTraceFragments 从文本里取最多 3 段连续文字作为检索关键词：去掉 markdown 符号，按行和句号切开，
// 只保留 20–128 字的片段，优先取最长的，并按原文顺序返回。
func leakTraceFragments(text string) []string {
	text = leakTraceMarkdownNoise.ReplaceAllString(text, "")
	type candidate struct {
		text  string
		order int
	}
	var candidates []candidate
	order := 0
	for _, line := range leakTraceLineBreaks.Split(text, -1) {
		for _, piece := range splitKeepingSentences(line) {
			piece = strings.TrimSpace(piece)
			runes := []rune(piece)
			if len(runes) < leakTraceFragmentMin {
				continue
			}
			if len(runes) > leakTraceFragmentMax {
				piece = string(runes[:leakTraceFragmentMax])
			}
			candidates = append(candidates, candidate{piece, order})
			order++
		}
	}
	// 选最长的几段（更具体），再按原文顺序输出。
	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0 && utf8.RuneCountInString(candidates[j].text) > utf8.RuneCountInString(candidates[j-1].text); j-- {
			candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
		}
	}
	if len(candidates) > leakTraceMaxFragments {
		candidates = candidates[:leakTraceMaxFragments]
	}
	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0 && candidates[j].order < candidates[j-1].order; j-- {
			candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
		}
	}
	out := make([]string, 0, len(candidates))
	seen := map[string]bool{}
	for _, c := range candidates {
		if !seen[c.text] {
			seen[c.text] = true
			out = append(out, c.text)
		}
	}
	return out
}

// splitKeepingSentences 按句末标点切开，标点留在前一句末尾。
func splitKeepingSentences(line string) []string {
	var out []string
	last := 0
	for _, loc := range leakTraceSentenceEnd.FindAllStringIndex(line, -1) {
		out = append(out, line[last:loc[1]])
		last = loc[1]
	}
	if last < len(line) {
		out = append(out, line[last:])
	}
	return out
}

func logLeakTrace(r *http.Request, deps *Dependencies, resp leakTraceResponse) {
	ids := make([]string, 0, len(resp.Matches))
	for _, m := range resp.Matches {
		ids = append(ids, m.RequestID)
	}
	// 只记方法、结果和命中的请求号，不记粘贴的原文。
	logAudit(r, deps, "audit.leak_trace", map[string]interface{}{
		"method": resp.Method, "watermark": resp.Watermark, "fragment_count": len(resp.Fragments),
		"match_count": len(resp.Matches), "request_ids": ids,
	}, "leak_trace", "")
}

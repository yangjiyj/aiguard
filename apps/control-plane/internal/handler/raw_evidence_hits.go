package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// 原文弹窗定位命中：管理员打开“脱敏前原文”时，直接告诉他是哪条规则、命中了原文哪一段。
// 命中位置来自本请求的安全事件（matched_summary.findings）：
//   - 优先用 matched_location（检测器扫描时的字符下标）切原文，并用事件里存的 raw_evidence_sha256 校验，
//     校验不过（下标对应的是拼接后的文本、不是这条消息）就不用这个下标；
//   - 下标不可用时按 sha256 在原文里滑窗找同长度片段（打码的密钥、手机号也能定位）；
//   - 没有 sha256 的老事件，退回用未打码的命中词 / 证据上下文在原文里查找。
// 只返回位置（UTF-16 下标，前端直接切字符串）与规则名，不额外返回任何原文。

type rawEvidenceHit struct {
	Start    int    `json:"start"`
	End      int    `json:"end"`
	RuleName string `json:"rule_name"`
	Action   string `json:"action,omitempty"`
}

type rawEvidenceRuleNote struct {
	RuleName string `json:"rule_name"`
	Action   string `json:"action,omitempty"`
	Located  bool   `json:"located"`
	// Semantic：智能分析（语义判官）是对整段上下文下的结论，没有“命中词”；前端显示“整段判定”和判定理由。
	Semantic bool   `json:"semantic,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type rawEvidenceFinding struct {
	Type            string `json:"type"`
	Action          string `json:"action"`
	RuleName        string `json:"rule_name"`
	MatchedLocation string `json:"matched_location"`
	RawEvidence     string `json:"raw_evidence"`
	RawEvidenceSHA  string `json:"raw_evidence_sha256"`
	EvidenceContext string `json:"evidence_context"`
	EvidenceKind    string `json:"evidence_kind"`
	EvidenceReason  string `json:"evidence_reason"`
	Counts          *bool  `json:"counts_as_security_finding"`
}

type rawEvidenceSummary struct {
	Stage    string               `json:"stage"`
	Findings []rawEvidenceFinding `json:"findings"`
}

var rawEvidenceLocationRE = regexp.MustCompile(`^content\[(\d+):(\d+)\]$`)

const rawEvidenceMaxHits = 200

// rawEvidenceFindingsLoader 读本请求的安全事件摘要；测试里替换。
type rawEvidenceFindingsLoader func(ctx context.Context, tenantID, requestID string) ([]json.RawMessage, error)

func loadRawEvidenceSummaries(deps *Dependencies) rawEvidenceFindingsLoader {
	return func(ctx context.Context, tenantID, requestID string) ([]json.RawMessage, error) {
		if deps == nil || deps.DB == nil {
			return nil, nil
		}
		rows, err := deps.DB.Query(ctx, `SELECT matched_summary::text FROM security_events
			WHERE tenant_id = $1 AND request_id = $2 AND matched_summary IS NOT NULL ORDER BY created_at LIMIT 50`, tenantID, requestID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []json.RawMessage
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return nil, err
			}
			out = append(out, json.RawMessage(s))
		}
		return out, rows.Err()
	}
}

func rawEvidenceFindingRelevant(f rawEvidenceFinding) bool {
	if f.Counts != nil && !*f.Counts {
		return false
	}
	switch f.Action {
	case "block", "mask":
	default:
		return false
	}
	return strings.TrimSpace(f.RuleName) != ""
}

func rawEvidenceFindingSemantic(f rawEvidenceFinding) bool {
	return strings.HasPrefix(f.Type, "semantic") || f.EvidenceKind == "semantic"
}

// rawEvidenceSemanticReason 取判定理由的结论部分，去掉“策略基准/本次风险”这类分级说明。
func rawEvidenceSemanticReason(f rawEvidenceFinding) string {
	r := strings.TrimSpace(f.EvidenceReason)
	if i := strings.Index(r, "；策略基准"); i >= 0 {
		r = r[:i]
	}
	if rs := []rune(r); len(rs) > 160 {
		r = string(rs[:160]) + "…"
	}
	return r
}

func rawEvidenceLooksRedacted(s string) bool {
	return s == "" || strings.Contains(s, "****") || strings.Contains(s, "<MASKED>") || strings.Contains(s, "<已打码") ||
		strings.Contains(s, "<已隐藏") || strings.Contains(s, "<REDACTED") || strings.HasPrefix(s, "<deterministic")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// locateRawEvidenceHits 在原文里定位命中；返回命中段（UTF-16 下标）与每条规则是否定位到。
func locateRawEvidenceHits(text, direction string, summaries []json.RawMessage) ([]rawEvidenceHit, []rawEvidenceRuleNote) {
	runes := []rune(text)
	// 码点下标 → UTF-16 下标
	u16 := make([]int, len(runes)+1)
	for i, r := range runes {
		u16[i+1] = u16[i] + len(utf16.Encode([]rune{r}))
	}
	var hits []rawEvidenceHit
	seenHit := map[string]bool{}
	notes := []rawEvidenceRuleNote{}
	noteIdx := map[string]int{}
	add := func(a, b int, f rawEvidenceFinding) {
		key := f.RuleName + "|" + strconv.Itoa(a) + "|" + strconv.Itoa(b)
		if seenHit[key] || len(hits) >= rawEvidenceMaxHits {
			return
		}
		seenHit[key] = true
		hits = append(hits, rawEvidenceHit{Start: u16[a], End: u16[b], RuleName: f.RuleName, Action: f.Action})
	}
	wantStage := "input"
	if direction == "output" {
		wantStage = "output"
	}
	for _, raw := range summaries {
		var s rawEvidenceSummary
		if json.Unmarshal(raw, &s) != nil {
			continue
		}
		if s.Stage != "" && s.Stage != wantStage {
			continue
		}
		for _, f := range s.Findings {
			if !rawEvidenceFindingRelevant(f) {
				continue
			}
			semantic := rawEvidenceFindingSemantic(f)
			before := len(hits)
			var located bool
			if semantic {
				// 语义判定只认经 sha256 校验的判定窗口，不做模糊查找，免得把整段结论标到某个词上。
				located = rawEvidenceLocateWindow(runes, f, func(a, b int) { add(a, b, f) })
			} else {
				located = rawEvidenceLocateOne(runes, f, func(a, b int) { add(a, b, f) })
			}
			if !located && len(hits) > before {
				located = true
			}
			key := f.RuleName + "|" + f.Action
			if i, ok := noteIdx[key]; ok {
				notes[i].Located = notes[i].Located || located
				if semantic && notes[i].Reason == "" {
					notes[i].Reason = rawEvidenceSemanticReason(f)
				}
			} else {
				note := rawEvidenceRuleNote{RuleName: f.RuleName, Action: f.Action, Located: located}
				if semantic {
					note.Semantic = true
					note.Reason = rawEvidenceSemanticReason(f)
				}
				noteIdx[key] = len(notes)
				notes = append(notes, note)
			}
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Start < hits[j].Start })
	return hits, notes
}

func rawEvidenceLocateWindow(runes []rune, f rawEvidenceFinding, add func(a, b int)) bool {
	m := rawEvidenceLocationRE.FindStringSubmatch(f.MatchedLocation)
	if m == nil || f.RawEvidenceSHA == "" {
		return false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	if a < 0 || b <= a || b > len(runes) || sha256Hex(string(runes[a:b])) != f.RawEvidenceSHA {
		return false
	}
	add(a, b)
	return true
}

func rawEvidenceLocateOne(runes []rune, f rawEvidenceFinding, add func(a, b int)) bool {
	n := len(runes)
	// 1) 下标 + sha256 校验
	if m := rawEvidenceLocationRE.FindStringSubmatch(f.MatchedLocation); m != nil {
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		if a >= 0 && b > a && b <= n {
			seg := string(runes[a:b])
			if (f.RawEvidenceSHA != "" && sha256Hex(seg) == f.RawEvidenceSHA) ||
				(f.RawEvidenceSHA == "" && !rawEvidenceLooksRedacted(f.RawEvidence) && seg == f.RawEvidence) {
				add(a, b)
				return true
			}
			// 2) sha256 滑窗：同长度片段逐个比对（原文最多 512K 字，单条规则一遍）。
			if f.RawEvidenceSHA != "" {
				l := b - a
				found := false
				for i := 0; i+l <= n; i++ {
					if sha256Hex(string(runes[i:i+l])) == f.RawEvidenceSHA {
						add(i, i+l)
						found = true
					}
				}
				if found {
					return true
				}
			}
		}
	}
	// 3) 未打码的命中词
	if !rawEvidenceLooksRedacted(f.RawEvidence) {
		if rawEvidenceFindAll(runes, []rune(f.RawEvidence), add) {
			return true
		}
	}
	// 4) 证据上下文（去掉两头省略号）
	ctx := strings.Trim(strings.TrimSpace(f.EvidenceContext), "…")
	if len([]rune(ctx)) >= 8 && !rawEvidenceLooksRedacted(ctx) {
		return rawEvidenceFindAll(runes, []rune(ctx), add)
	}
	return false
}

func rawEvidenceFindAll(runes, needle []rune, add func(a, b int)) bool {
	if len(needle) == 0 || len(needle) > len(runes) {
		return false
	}
	found := false
	hay := string(runes)
	nd := string(needle)
	off := 0 // 码点偏移
	for {
		idx := strings.Index(hay, nd)
		if idx < 0 {
			break
		}
		start := off + len([]rune(hay[:idx]))
		add(start, start+len(needle))
		found = true
		cut := idx + len(nd)
		off = start + len(needle)
		hay = hay[cut:]
	}
	return found
}

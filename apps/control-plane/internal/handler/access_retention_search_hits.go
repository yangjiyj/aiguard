package handler

import (
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"strings"
	"unicode"
)

type retentionSearchQuery struct{ keyword, scope string }

// Match only the existing customer-safe projection, never raw transport fields.
func (q retentionSearchQuery) appendHit(p *retentionTurnProjection, hit types.AccessRetentionSearchHit, text string) {
	if q.keyword == "" || text == "" {
		return
	}
	if q.scope == "request" && hit.Role != "user" || q.scope == "response" && hit.Role != "assistant" {
		return
	}
	snippet := retentionKeywordSnippet(text, q.keyword)
	if snippet == "" {
		return
	}
	hit.Snippet = snippet
	for _, old := range p.SearchHits {
		if old.RequestID == hit.RequestID && old.Kind == hit.Kind && old.Role == hit.Role && old.Snippet == hit.Snippet {
			return
		}
	}
	if len(p.SearchHits) >= 60 {
		p.SearchHitsTruncated = true
		return
	}
	p.SearchHits = append(p.SearchHits, hit)
}

func retentionKeywordSnippet(text, keyword string) string {
	source, needle := []rune(text), []rune(keyword)
	if len(needle) == 0 {
		return ""
	}
	for i := 0; i+len(needle) <= len(source); i++ {
		match := true
		for j, r := range needle {
			if unicode.ToLower(source[i+j]) != unicode.ToLower(r) {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		lo, hi := max(0, i-90), min(len(source), i+len(needle)+110)
		snippet := string(source[lo:hi])
		if lo > 0 {
			snippet = "…" + snippet
		}
		if hi < len(source) {
			snippet += "…"
		}
		return snippet
	}
	return ""
}

func (q retentionSearchQuery) complete(p *retentionTurnProjection, items []repository.AccessContentLog, artifacts []types.AccessRetentionArtifactInfo) {
	if q.keyword == "" {
		return
	}
	contextHits := p.SearchHits
	contextTruncated := p.SearchHitsTruncated
	p.SearchHits = nil
	p.SearchHitsTruncated = false
	for _, turn := range p.Turns {
		requestID := ""
		if len(turn.RequestIDs) > 0 {
			requestID = turn.RequestIDs[0]
		}
		q.appendHit(p, types.AccessRetentionSearchHit{RequestID: requestID, TurnID: turn.ID, Kind: "user_input", Role: "user"}, turn.UserInput)
		if turn.Answer != nil {
			q.appendHit(p, types.AccessRetentionSearchHit{RequestID: turn.Answer.RequestID, TurnID: turn.ID, Kind: "model_output", Role: "assistant"}, turn.Answer.Content)
		}
		for _, message := range p.Process[turn.ID] {
			q.appendHit(p, types.AccessRetentionSearchHit{RequestID: message.RequestID, TurnID: turn.ID, Kind: "process", Role: "assistant"}, message.Content)
		}
	}
	// A retained historical row can duplicate a visible turn. Prefer the location
	// the customer can navigate to, and otherwise label it as request context.
	for _, hit := range contextHits {
		duplicate := false
		for _, visible := range p.SearchHits {
			if visible.RequestID == hit.RequestID && visible.Role == hit.Role && visible.Snippet == hit.Snippet {
				duplicate = true
				break
			}
		}
		if !duplicate {
			q.appendHit(p, hit, hit.Snippet)
		}
	}
	for _, item := range items {
		input, _ := safeRetentionUserInput(item.RequestContent)
		for _, candidate := range []struct{ role, text string }{{"user", input}, {"assistant", safeRetentionModelOutput(item.ResponseContent)}} {
			duplicate := false
			snippet := retentionKeywordSnippet(candidate.text, q.keyword)
			for _, hit := range p.SearchHits {
				if hit.RequestID == item.RequestID && hit.Role == candidate.role && hit.Snippet == snippet {
					duplicate = true
					break
				}
			}
			if !duplicate {
				q.appendHit(p, types.AccessRetentionSearchHit{RequestID: item.RequestID, Role: candidate.role, Kind: "retained_text"}, candidate.text)
			}
		}
	}
	if q.scope == "" || q.scope == "all" {
		for _, artifact := range artifacts {
			q.appendHit(p, types.AccessRetentionSearchHit{RequestID: artifact.RequestID, Role: "file", Kind: "file"}, strings.TrimSpace(artifact.DisplayName))
		}
	}
	p.SearchHitsTruncated = p.SearchHitsTruncated || contextTruncated
}

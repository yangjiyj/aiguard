package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
)

type retentionTurnProjection struct {
	Turns               []types.AccessRetentionTurnInfo
	SearchHits          []types.AccessRetentionSearchHit
	SearchHitsTruncated bool
	Process             map[string][]types.AccessRetentionMessageInfo
}
type retentionTurnSnapshot struct {
	continuation                          bool
	contextIdentity                       string
	requestStatus                         string
	links                                 map[string]bool
	anchors                               []string
	requestID, input, output, key, source string
	started, ended                        time.Time
	partial                               bool
	verifiedHistory                       bool
	tools                                 []retentionturn.ToolObservation
}

// Historical wire records do not prove an agent completed. The last observed
// reply is a candidate, and a later response gap invalidates that candidate.
func buildAccessRetentionTurnsScoped(ctx context.Context, deps *Dependencies, tenantID string, requestIDs []string, accessItems []repository.AccessContentLog, scope string, start, end time.Time, searches ...retentionSearchQuery) (retentionTurnProjection, error) {
	out := retentionTurnProjection{Turns: []types.AccessRetentionTurnInfo{}, Process: map[string][]types.AccessRetentionMessageInfo{}}
	allowed := map[string]bool{}
	for _, id := range requestIDs {
		allowed[id] = true
	}
	states := map[string]repository.RetentionRequestState{}
	if reader, ok := deps.ContentLogReader.(interface {
		ListRetentionRequestStatesScoped(context.Context, string, []string, time.Time, time.Time, string) ([]repository.RetentionRequestState, error)
	}); ok {
		records, err := reader.ListRetentionRequestStatesScoped(ctx, tenantID, requestIDs, start, end, scope)
		if err != nil {
			return out, err
		}
		for _, record := range records {
			if allowed[record.RequestID] {
				states[record.RequestID] = record
			}
		}
	}
	rowsByRequest := map[string][]repository.ContentLog{}
	var rows []repository.ContentLog
	var err error
	if reader, ok := deps.ContentLogReader.(scopedContentLogBatchReader); ok {
		rows, err = reader.ListByRequestsScoped(ctx, tenantID, requestIDs, start, end, scope)
	} else if reader, ok := deps.ContentLogReader.(ContentLogBatchReader); ok {
		rows, err = reader.ListByRequests(ctx, tenantID, requestIDs)
	} else if deps.ContentLogReader != nil {
		for _, id := range requestIDs {
			batch, e := listContentLogsByRequest(ctx, deps.ContentLogReader, tenantID, id, scope, start, end)
			if e != nil {
				return out, e
			}
			for _, row := range batch {
				if row.RequestID == "" {
					row.RequestID = id
				}
				rows = append(rows, row)
			}
		}
	}
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		if !allowed[row.RequestID] || (row.TenantID != "" && row.TenantID != tenantID) {
			continue
		}
		rowsByRequest[row.RequestID] = append(rowsByRequest[row.RequestID], row)
		if len(searches) > 0 && searches[0].keyword != "" {
			search := searches[0]
			text := ""
			if row.Role == "user" {
				text, _ = safeRetentionUserInput(row.Content)
			}
			if row.Role == "assistant" {
				text = safeRetentionLegacyModelOutput(row.Content)
			}
			kind := "retained_text"
			if row.MessageIndex != nil {
				kind = "request_context"
			}
			search.appendHit(&out, types.AccessRetentionSearchHit{RequestID: row.RequestID, Kind: kind, Role: row.Role, MessageIndex: row.MessageIndex}, text)
		}
	}
	access := map[string]repository.AccessContentLog{}
	for _, item := range accessItems {
		if allowed[item.RequestID] {
			access[item.RequestID] = item
		}
	}
	snapshots := []retentionTurnSnapshot{}
	seen := map[string]bool{}
	for _, id := range requestIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		logs := rowsByRequest[id]
		// Numbered rows are replayed request history. The separately retained
		// response has no message index and must follow that history, even when
		// asynchronous writes gave it an earlier timestamp.
		sort.SliceStable(logs, func(i, j int) bool {
			if (logs[i].MessageIndex == nil) != (logs[j].MessageIndex == nil) {
				return logs[i].MessageIndex != nil
			}
			if logs[i].MessageIndex != nil && logs[j].MessageIndex != nil && *logs[i].MessageIndex != *logs[j].MessageIndex {
				return *logs[i].MessageIndex < *logs[j].MessageIndex
			}
			return false
		})
		p := projectRetentionContentLogs(logs)
		if p.runtimeOnly {
			continue
		}
		s := retentionTurnSnapshot{requestID: id, input: p.userInput, output: p.modelOutput, started: p.userCreatedAt, ended: p.modelCreatedAt}
		history := []string{}
		s.links = map[string]bool{}
		for index, row := range logs {
			if row.Role != "assistant" && row.Role != "tool" {
				continue
			}
			digest := sha256.Sum256([]byte(row.Role + "\x00" + row.Content))
			anchor := fmt.Sprintf("%x", digest[:])
			if index == len(logs)-1 {
				s.anchors = []string{anchor}
			}
			if index < len(logs)-1 || row.Role != "assistant" {
				s.links[anchor] = true
			}
		}
		historyPartial := false
		identity := ""
		for _, row := range logs {
			if s.started.IsZero() || (!row.CreatedAt.IsZero() && row.CreatedAt.Before(s.started)) {
				s.started = row.CreatedAt
			}
			if row.CreatedAt.After(s.ended) {
				s.ended = row.CreatedAt
			}
			s.partial = s.partial || row.ContentTruncated || strings.Contains(row.Content, "...[truncated]")
			if row.Role != "user" || aimsg.IsRetainedUserTransportOnly(row.Content) {
				continue
			}
			text, status := safeRetentionUserInput(row.Content)
			if status != "complete" || text == "" {
				continue
			}
			if identity == "" {
				session := row.SessionID
				if session == id {
					session = ""
				} // gateway fallback is a physical request, not a session
				identity = row.UserID + "\x00" + session
			}
			history = append(history, text)
			historyPartial = historyPartial || row.ContentTruncated || strings.Contains(row.Content, "...[truncated]")
		}
		item, hasAccess := access[id]
		if hasAccess {
			if isRetentionBackgroundWorkload(item.RequestContent) {
				continue
			}
			text, status := safeRetentionUserInput(item.RequestContent)
			if status == "complete" {
				s.input = text
				s.output = safeRetentionModelOutput(item.ResponseContent)
			}
			if s.started.IsZero() {
				s.started = item.CreatedAt
			}
			if s.ended.IsZero() {
				s.ended = item.CreatedAt
			}
		}
		if state, ok := states[id]; ok {
			s.requestStatus = state.Status
			if !state.CreatedAt.IsZero() {
				s.started = state.CreatedAt
				s.ended = state.CreatedAt.Add(time.Duration(state.LatencyMS) * time.Millisecond)
			}
		}
		var turnContext retentionturn.Context
		if state, ok := states[id]; ok && len(state.TurnContext) > 0 {
			_ = json.Unmarshal(state.TurnContext, &turnContext)
		}
		// Old ingress marked a complete human history partial when it skipped
		// client metadata. Verify its retained human text against the *whole*
		// one-message history digest; a truncated or redacted input cannot pass.
		if turnContext.Request != nil {
			s.tools = append(s.tools, turnContext.Request.Tools...)
		}
		if turnContext.Response != nil {
			s.tools = append(s.tools, turnContext.Response.Tools...)
		}
		verifiedSingleHistory := false
		if hasAccess && s.input != "" && !strings.Contains(s.input, "...[truncated]") && turnContext.Request != nil && turnContext.Request.UserCount == 1 {
			framed, _ := json.Marshal([]string{s.input})
			verifiedSingleHistory = retentionturn.Digest(string(framed)) == turnContext.Request.HistoryKey
		}
		if turnContext.Version == 1 && turnContext.Request != nil && (!turnContext.Request.Partial || verifiedSingleHistory) && turnContext.Request.IdentityKey != "" && ((turnContext.Request.UserCount > 0 && turnContext.Request.HistoryKey != "") || (turnContext.Request.UserCount == 0 && len(turnContext.Request.Links) > 0)) {
			request := turnContext.Request
			s.contextIdentity = request.IdentityKey
			s.continuation = request.UserCount == 0
			if s.continuation && s.input == "" && hasAccess {
				s.output = safeRetentionModelOutput(item.ResponseContent)
			}
			s.key = "context:" + request.IdentityKey + "\x00" + request.HistoryKey
			s.source = "ingress_context"
			// A conversation plus the complete human-history occurrence separates
			// new submissions (including identical repeated words) from replayed
			// model calls. The content-derived conversation is only a presentation
			// grouping: never claim a client task/turn identifier from it.
			if hasAccess && states[id].ConversationID != "" && request.UserCount > 0 {
				s.key += "\x00conversation:" + states[id].ConversationID
				s.verifiedHistory = true
				s.source = "conversation_history"
			}
			s.partial = s.partial || request.Partial
			s.links = map[string]bool{}
			for _, link := range request.Links {
				s.links[link] = true
			}
			s.anchors = nil
			if turnContext.Response != nil {
				s.anchors = turnContext.Response.Links
			}
		} else if len(history) > 0 && !historyPartial {
			framed, _ := json.Marshal([]interface{}{identity, history})
			digest := sha256.Sum256(framed)
			s.key = fmt.Sprintf("history:%x", digest[:])
			s.source = "history_occurrence"
		} else if hasAccess && strings.TrimSpace(item.SectionID) != "" {
			// A text digest is not a human-submission ID. Without history, avoid
			// merging two indistinguishable submissions based on that digest alone.
			digest := sha256.Sum256([]byte(s.input))
			if item.SectionID != fmt.Sprintf("%x", digest[:]) {
				s.key = "section:" + item.SectionID + "\x00" + s.input
				s.source = "section"
			}
		}
		if s.key == "" {
			s.key = "request:" + id
			s.source = "unlinked"
		}
		if s.input == "" && s.output == "" && !s.continuation {
			continue
		}
		snapshots = append(snapshots, s)
	}
	sort.SliceStable(snapshots, func(i, j int) bool {
		a, b := snapshots[i].started, snapshots[j].started
		if a.IsZero() || b.IsZero() || a.Equal(b) {
			return snapshots[i].requestID < snapshots[j].requestID
		}
		return a.Before(b)
	})
	indices := map[string][]int{}
	anchors := map[int][]string{}
	contextIdentities := map[int]string{}
	for _, s := range snapshots {
		idx, matches := 0, 0
		candidates := indices[s.key]
		if s.continuation {
			candidates = nil
			for candidate, identity := range contextIdentities {
				if identity == s.contextIdentity {
					candidates = append(candidates, candidate)
				}
			}
		}
		for _, candidate := range candidates {
			linked := s.source == "section" || s.verifiedHistory
			for _, anchor := range anchors[candidate] {
				linked = linked || s.links[anchor]
			}
			if linked {
				idx = candidate
				matches++
			}
		}
		exists := matches == 1
		if matches > 1 {
			// Replayed boilerplate can match parallel tasks. Do not arbitrarily
			// attach the request to whichever candidate happened to sort first.
			s.key, s.source = "request:"+s.requestID, "unlinked"
		}
		if !exists {
			if s.continuation {
				s.source = "unlinked"
				s.partial = true
			}
			if s.input == "" && s.output == "" {
				continue
			}
			digest := sha256.Sum256([]byte(tenantID + "\x00" + s.requestID))
			input := s.input
			turn := types.AccessRetentionTurnInfo{ID: fmt.Sprintf("turn_%x", digest[:16]), Index: len(out.Turns) + 1, UserInput: input,
				RequestIDs: []string{}, Status: "response_unavailable", CorrelationSource: s.source, FinalitySource: "not_observed"}
			if !s.started.IsZero() {
				turn.StartedAt = s.started.UTC().Format(time.RFC3339Nano)
			}
			out.Turns = append(out.Turns, turn)
			idx = len(out.Turns) - 1
			indices[s.key] = append(indices[s.key], idx)
		}
		contextIdentities[idx] = s.contextIdentity
		// Keep causal evidence across tool-only calls. An empty text response
		// does not erase the earlier reply that the next request replays.
		anchors[idx] = append(anchors[idx], s.anchors...)
		turn := &out.Turns[idx]
		turn.RequestIDs = append(turn.RequestIDs, s.requestID)
		turn.RequestCount++
		for _, tool := range s.tools {
			found := false
			for i := range turn.Tools {
				if turn.Tools[i].ID == tool.ID {
					found = true
					if tool.Name != "" {
						turn.Tools[i].Name = tool.Name
					}
					if tool.Kind == "result_observed" {
						turn.Tools[i].Kind = tool.Kind
					}
					break
				}
			}
			if !found {
				turn.Tools = append(turn.Tools, types.AccessRetentionToolInfo{ID: tool.ID, Name: tool.Name, Kind: tool.Kind, RequestID: s.requestID})
			}
		}
		if !s.ended.IsZero() {
			turn.LastObservedAt = s.ended.UTC().Format(time.RFC3339Nano)
		}
		if turn.StartedAt != "" && turn.LastObservedAt != "" {
			a, _ := time.Parse(time.RFC3339Nano, turn.StartedAt)
			b, _ := time.Parse(time.RFC3339Nano, turn.LastObservedAt)
			turn.ObservedDurationMS = max(int64(0), b.Sub(a).Milliseconds())
		}
		if turn.Answer != nil {
			previous := *turn.Answer
			previous.Kind = "assistant_progress"
			out.Process[turn.ID] = append(out.Process[turn.ID], previous)
			turn.Answer = nil
		}
		turn.Status = "response_unavailable"
		turn.FinalitySource = "not_observed"
		if s.output != "" {
			message := types.AccessRetentionMessageInfo{ID: "answer_" + s.requestID, RequestID: s.requestID, Sequence: turn.RequestCount, Role: "assistant", Kind: "answer_candidate", Content: s.output}
			if !s.ended.IsZero() {
				message.CreatedAt = s.ended.UTC().Format(time.RFC3339Nano)
			}
			turn.Answer = &message
			turn.Status = "unconfirmed"
			turn.FinalitySource = "last_observed_response"
		}
		switch s.requestStatus {
		case "cancelled", "canceled", "client_canceled", "stream_aborted":
			turn.Status = "interrupted"
			turn.FinalitySource = "request_outcome"
		case "target_resolution_failed", "failed", "provider_unavailable", "error", "timeout", "provider_timeout":
			turn.Status = "request_failed"
			turn.FinalitySource = "request_outcome"
		case "blocked", "egress_denied", "security_replied":
			turn.Status = "blocked"
			turn.FinalitySource = "request_outcome"
		}
		if s.partial {
			turn.EvidenceStatus = "partial"
		} else if turn.EvidenceStatus == "" {
			turn.EvidenceStatus = "complete"
		}
		turn.ProcessCount = len(out.Process[turn.ID])
	}
	return out, nil
}

func serveAccessRetentionTurns(w http.ResponseWriter, r *http.Request, deps *Dependencies, user *repository.User, tenantID, requestID string, members []string, items []repository.AccessContentLog, scope string, start, end time.Time) {
	view := r.URL.Query().Get("view")
	offset, limit := 0, 50
	if view == "turn_process" {
		var err error
		if raw := r.URL.Query().Get("offset"); raw != "" {
			offset, err = strconv.Atoi(raw)
		}
		if err != nil || offset < 0 {
			writeErrorWithStatus(w, 400, "invalid_request", "invalid offset")
			return
		}
		if raw := r.URL.Query().Get("limit"); raw != "" {
			limit, err = strconv.Atoi(raw)
		}
		if err != nil || limit < 1 || limit > 100 {
			writeErrorWithStatus(w, 400, "invalid_request", "limit must be between 1 and 100")
			return
		}
	}
	keyword, valid := validatedAuditKeyword(w, r.URL.Query().Get("keyword"))
	if !valid {
		return
	}
	search := retentionSearchQuery{keyword: keyword, scope: r.URL.Query().Get("keyword_scope")}
	if search.scope != "" && search.scope != "all" && search.scope != "request" && search.scope != "response" {
		writeErrorWithStatus(w, 400, "invalid_request", "invalid keyword scope")
		return
	}
	p, err := buildAccessRetentionTurnsScoped(r.Context(), deps, tenantID, members, items, scope, start, end, search)
	if err != nil {
		writeErrorWithStatus(w, 500, "internal_error", "failed to build retained turns")
		return
	}
	artifacts, err := accessRetentionArtifactsForRequestsScoped(deps, r.Context(), tenantID, members, nil, scope, start, end)
	if err != nil {
		writeErrorWithStatus(w, 500, "internal_error", "failed to load turn artifacts")
		return
	}
	// Legacy metadata belongs to its physical request. Merging metadata first
	// would incorrectly attach every file to the task's representative request.
	withArtifacts := map[string]bool{}
	for _, artifact := range artifacts {
		withArtifacts[artifact.RequestID] = true
	}
	for _, item := range items {
		if withArtifacts[item.RequestID] {
			continue
		}
		for _, artifact := range legacyRetentionArtifacts(item.FileMetadataJSON) {
			artifact.RequestID = item.RequestID
			artifacts = append(artifacts, artifact)
		}
	}
	artifacts = collapseAccessRetentionArtifactReferences(artifacts)
	status := "complete"
	for _, turn := range p.Turns {
		if turn.EvidenceStatus != "complete" {
			status = "evidence_gap"
		}
	}
	for _, artifact := range artifacts {
		if artifact.RetentionStatus != "retained" {
			status = "evidence_gap"
		}
		assigned := false
		for _, turn := range p.Turns {
			for _, id := range turn.RequestIDs {
				if id == artifact.RequestID {
					assigned = true
				}
			}
		}
		if !assigned && artifact.RequestID != "" {
			digest := sha256.Sum256([]byte(tenantID + "\x00" + artifact.RequestID))
			p.Turns = append(p.Turns, types.AccessRetentionTurnInfo{ID: fmt.Sprintf("turn_%x", digest[:16]), Index: len(p.Turns) + 1, RequestIDs: []string{artifact.RequestID}, RequestCount: 1, Status: "response_unavailable", FinalitySource: "not_observed", CorrelationSource: "unlinked", EvidenceStatus: "partial"})
			status = "evidence_gap"
		}
	}
	if view == "turn_process" {
		id := r.URL.Query().Get("turn_id")
		found := false
		for _, turn := range p.Turns {
			if turn.ID == id {
				found = true
				break
			}
		}
		if !found {
			writeErrorWithStatus(w, 404, "not_found", "turn not found")
			return
		}
		all := p.Process[id]
		total := len(all)
		lo := min(offset, total)
		hi := lo + min(limit, total-lo)
		data := append([]types.AccessRetentionMessageInfo{}, all[lo:hi]...)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data, "total": total, "offset": offset, "limit": limit, "has_more": hi < total})
		return
	}
	if len(p.Turns) == 0 {
		status = "evidence_gap"
	}
	search.complete(&p, items, artifacts)
	if deps != nil && deps.DB != nil {
		attachBlockedInputEvidenceRequestIDs(r.Context(), user, p.Turns, repository.NewRawEvidenceRepository(deps.DB).RequestIDsWithBlockedInputEvidence)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(types.AccessRetentionContentInfo{TurnViewVersion: 1, RequestID: requestID, Turns: p.Turns, Artifacts: artifacts, EvidenceStatus: status, SearchHits: p.SearchHits, SearchHitsTruncated: p.SearchHitsTruncated})
}

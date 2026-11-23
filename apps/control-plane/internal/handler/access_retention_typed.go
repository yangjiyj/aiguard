package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionfmt"
)

// GetAccessRetentionContent 返回带证据读取审计的 handler（Low-2）：读取成功后写 evidence.read，见 AuditEvidenceRead。
func GetAccessRetentionContent(deps *Dependencies) http.HandlerFunc {
	return auditedEvidenceHandler(deps, "content", getAccessRetentionContentInner(deps))
}

func getAccessRetentionContentInner(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		requestID := strings.TrimSpace(chi.URLParam(r, "request_id"))
		if requestID == "" {
			writeError(w, "invalid_request", "request id is required")
			return
		}
		repo := accessRetentionContentRepo(deps)
		if repo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "access content repository is not configured")
			return
		}
		scope, start, end, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid UTC retention window")
			return
		}
		item, err := getAccessContentLog(r.Context(), repo, user.TenantID, requestID, scope, start, end)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get access content")
			return
		}
		memberIDs, err := readEvidenceMemberIDs(w, r, requestID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		accessItems := []repository.AccessContentLog{}
		if len(memberIDs) > 1 {
			logs, merr := getAccessContentLogs(r.Context(), repo, user.TenantID, memberIDs, scope, start, end)
			if merr != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get turn member content")
				return
			}
			accessItems = logs
			if merged := mergeTurnAccessContentLogs(requestID, memberIDs, logs); merged != nil {
				item = merged
			}
		} else if item != nil {
			accessItems = append(accessItems, *item)
		}

		if view := r.URL.Query().Get("view"); view == "turns" || view == "turn_process" {
			serveAccessRetentionTurns(w, r, deps, user, user.TenantID, requestID, memberIDs, accessItems, scope, start, end)
			return
		}
		// view=raw：「全部原文」。与其余视图共用同一路由权限门（RequireFullTenantContentEvidence），
		// 差别只在读侧不脱标识、不分轮折叠。
		if r.URL.Query().Get("view") == "raw" {
			serveAccessRetentionRaw(w, r, deps, user.TenantID, requestID, memberIDs, accessItems, scope, start, end)
			return
		}

		var userInput, modelOutput string
		evidenceStatus := "complete"
		if item != nil {
			userInput, evidenceStatus = safeRetentionUserInput(item.RequestContent)
			if evidenceStatus == "complete" {
				modelOutput = safeRetentionModelOutput(item.ResponseContent)
			}
		} else if deps.ContentLogReader != nil {
			logs, lerr := listContentLogsByRequest(r.Context(), deps.ContentLogReader, user.TenantID, requestID, scope, start, end)
			if lerr != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get content logs")
				return
			}
			userInput, modelOutput, evidenceStatus = safeRetentionContentLogProjection(logs)
		} else {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "access content not found")
			return
		}
		if item == nil && userInput == "" && modelOutput == "" {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "access content not found")
			return
		}
		messages, merr := buildAccessRetentionMessagesScoped(r.Context(), deps, user.TenantID, memberIDs, accessItems, scope, start, end)
		if merr != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to build retained messages")
			return
		}

		legacyMetadata := []byte(nil)
		if item != nil {
			legacyMetadata = item.FileMetadataJSON
		}
		artifacts, aerr := accessRetentionArtifactsForRequestsScoped(deps, r.Context(), user.TenantID, memberIDs, legacyMetadata, scope, start, end)
		if aerr != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get retained artifacts")
			return
		}
		messages = ensureInputArtifactMessages(messages, artifacts)
		hasRetainedInputEvidence := false
		for _, artifact := range artifacts {
			if artifact.RetentionStatus != "retained" {
				evidenceStatus = "evidence_gap"
				break
			}
			if artifact.Direction == "input" {
				hasRetainedInputEvidence = true
			}
		}
		if userInput == "" && !hasRetainedInputEvidence {
			evidenceStatus = "evidence_gap"
		}

		info := types.AccessRetentionContentInfo{
			RequestID:      requestID,
			UserInput:      userInput,
			ModelOutput:    modelOutput,
			Artifacts:      artifacts,
			EvidenceStatus: evidenceStatus,
			Messages:       messages,
		}
		if item != nil && item.RetentionUntil != nil {
			info.RetentionUntil = item.RetentionUntil.UTC().Format("2006-01-02T15:04:05Z")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}
}

func accessRetentionContentRepo(deps *Dependencies) AccessContentRepo {
	if deps == nil {
		return nil
	}
	if deps.AccessContentRepo != nil {
		return deps.AccessContentRepo
	}
	return deps.RequestLogRepo
}

func accessRetentionArtifactRepo(deps *Dependencies) RetainedArtifactRepo {
	if deps == nil {
		return nil
	}
	if deps.RetainedArtifactRepo != nil {
		return deps.RetainedArtifactRepo
	}
	if deps.RequestLogRepo != nil {
		return deps.RequestLogRepo
	}
	return nil
}

func accessRetentionArtifactsForRequests(deps *Dependencies, ctx context.Context, tenantID string, requestIDs []string, legacyMetadata []byte) ([]types.AccessRetentionArtifactInfo, error) {
	return accessRetentionArtifactsForRequestsScoped(deps, ctx, tenantID, requestIDs, legacyMetadata, "", time.Time{}, time.Time{})
}

func accessRetentionArtifactsForRequestsScoped(deps *Dependencies, ctx context.Context, tenantID string, requestIDs []string, legacyMetadata []byte, scope string, start, end time.Time) ([]types.AccessRetentionArtifactInfo, error) {
	if len(requestIDs) == 0 {
		return []types.AccessRetentionArtifactInfo{}, nil
	}
	legacyFallback := func() []types.AccessRetentionArtifactInfo {
		items := legacyRetentionArtifacts(legacyMetadata)
		for index := range items {
			items[index].RequestID = requestIDs[0]
		}
		return collapseAccessRetentionArtifactReferences(items)
	}
	repo := accessRetentionArtifactRepo(deps)
	if repo == nil {
		return legacyFallback(), nil
	}
	out := []types.AccessRetentionArtifactInfo{}
	appendRows := func(rows []repository.RetainedArtifact) {
		for _, row := range rows {
			out = append(out, types.AccessRetentionArtifactInfo{
				ID: row.ID, RequestID: row.RequestID, Direction: row.Direction, Kind: row.Kind,
				DisplayName: row.DisplayName, MediaType: row.MediaType, ByteSize: row.ByteSize,
				SHA256: row.SHA256, RetentionStatus: row.Status, FailureCode: row.FailureCode,
				HasPreview: row.Status == "retained" && (row.PreviewObjectKey != "" ||
					(row.OriginalObjectKey != "" && safeInlinePreview(row.MediaType))),
				EnvironmentScope: row.EnvironmentScope, LinkEnvironmentScope: row.LinkEnvironmentScope,
				RequestCreatedAt: row.RequestCreatedAt, LinkCreatedAt: row.LinkCreatedAt, Ordinal: row.Ordinal,
			})
		}
	}
	if scopedRepo, ok := repo.(scopedRetainedArtifactRepo); ok && len(requestIDs) > 1 {
		rows, err := scopedRepo.ListRetainedArtifactsByRequestsScoped(ctx, tenantID, requestIDs, start, end, scope)
		if err != nil {
			return nil, err
		}
		appendRows(rows)
	} else if batchRepo, ok := repo.(RetainedArtifactBatchRepo); ok && len(requestIDs) > 1 {
		rows, err := batchRepo.ListRetainedArtifactsByRequests(ctx, tenantID, requestIDs)
		if err != nil {
			return nil, err
		}
		appendRows(rows)
	} else {
		for _, requestID := range requestIDs {
			var rows []repository.RetainedArtifact
			var err error
			if scopedRepo, ok := repo.(scopedRetainedArtifactRepo); ok {
				rows, err = scopedRepo.ListRetainedArtifactsScoped(ctx, tenantID, requestID, start, end, scope)
			} else {
				rows, err = repo.ListRetainedArtifacts(ctx, tenantID, requestID)
			}
			if err != nil {
				return nil, err
			}
			appendRows(rows)
		}
	}
	if len(out) == 0 {
		return legacyFallback(), nil
	}
	return collapseAccessRetentionArtifactReferences(out), nil
}

func collapseAccessRetentionArtifactReferences(items []types.AccessRetentionArtifactInfo) []types.AccessRetentionArtifactInfo {
	sort.SliceStable(items, func(i, j int) bool {
		left, right := items[i], items[j]
		if !left.RequestCreatedAt.Equal(right.RequestCreatedAt) {
			if left.RequestCreatedAt.IsZero() {
				return false
			}
			if right.RequestCreatedAt.IsZero() {
				return true
			}
			return left.RequestCreatedAt.Before(right.RequestCreatedAt)
		}
		if !left.LinkCreatedAt.Equal(right.LinkCreatedAt) {
			if left.LinkCreatedAt.IsZero() {
				return false
			}
			if right.LinkCreatedAt.IsZero() {
				return true
			}
			return left.LinkCreatedAt.Before(right.LinkCreatedAt)
		}
		if left.Direction != right.Direction {
			return left.Direction < right.Direction
		}
		if left.Ordinal != right.Ordinal {
			return left.Ordinal < right.Ordinal
		}
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		return left.RequestID < right.RequestID
	})
	seen := make(map[string]int, len(items))
	out := make([]types.AccessRetentionArtifactInfo, 0, len(items))
	for _, item := range items {
		referenceCount := item.ReferenceCount
		if referenceCount < 1 {
			referenceCount = 1
		}
		sha256 := strings.TrimSpace(item.SHA256)
		key := strings.Join([]string{
			strings.TrimSpace(item.EnvironmentScope),
			strings.TrimSpace(item.LinkEnvironmentScope),
			strings.TrimSpace(item.Direction),
			sha256,
		}, "\x00")
		if sha256 == "" {
			key = strings.Join([]string{
				strings.TrimSpace(item.EnvironmentScope),
				strings.TrimSpace(item.LinkEnvironmentScope),
				strings.TrimSpace(item.Direction),
				"link",
				item.ID,
				item.RequestID,
			}, "\x00")
		}
		if index, ok := seen[key]; ok {
			out[index].ReferenceCount += referenceCount
			continue
		}
		item.ReferenceCount = referenceCount
		seen[key] = len(out)
		out = append(out, item)
	}
	return out
}

// legacyRetentionArtifacts is a conservative compatibility reader. It never trusts
// old object keys, URLs, Base64 or reference identifiers, so every fallback item is
// reference_only and has no download route.
func legacyRetentionArtifacts(raw []byte) []types.AccessRetentionArtifactInfo {
	var entries []map[string]interface{}
	if len(raw) == 0 || json.Unmarshal(raw, &entries) != nil {
		return []types.AccessRetentionArtifactInfo{}
	}
	out := make([]types.AccessRetentionArtifactInfo, 0, len(entries))
	for _, entry := range entries {
		name := stringMetadata(entry, "file_name", "name")
		sum := stringMetadata(entry, "sha256")
		if name == "" && sum == "" {
			continue
		}
		mediaType := stringMetadata(entry, "content_type", "mime_type")
		direction := stringMetadata(entry, "direction", "stage")
		if direction == "response" || direction == "output" {
			direction = "output"
		} else {
			direction = "input"
		}
		kind := "file"
		if strings.HasPrefix(strings.ToLower(mediaType), "image/") {
			kind = "image"
		}
		size := int64Metadata(entry, "size", "byte_size")
		fingerprint := fmt.Sprintf("%s|%s|%s|%s|%d", direction, name, mediaType, sum, size)
		digest := sha256.Sum256([]byte(fingerprint))
		out = append(out, types.AccessRetentionArtifactInfo{
			ID: "legacy_" + fmt.Sprintf("%x", digest[:8]), Direction: direction, Kind: kind,
			DisplayName: safeArtifactFilename(name, kind), MediaType: mediaType,
			ByteSize: size, SHA256: sum, RetentionStatus: "reference_only",
			FailureCode: "legacy_unlinked",
		})
	}
	return out
}

func stringMetadata(entry map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := entry[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func int64Metadata(entry map[string]interface{}, keys ...string) int64 {
	for _, key := range keys {
		switch value := entry[key].(type) {
		case float64:
			return int64(value)
		case int64:
			return value
		case int:
			return int64(value)
		}
	}
	return 0
}

func safeRetentionUserInput(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "evidence_gap"
	}
	// Project known agent wrappers before the generic text fallback. This keeps
	// Codex/WorkBuddy transport metadata out of both the typed task view and the
	// legacy access-retention detail, even when the row was written by an older
	// decoder.
	if text, _ := retentionfmt.SplitUserQuery(raw); text != "" {
		if text = safeRetentionCustomerText(text); text != "" {
			return text, "complete"
		}
		return "", "evidence_gap"
	}
	if text, status, matched := aimsg.NormalizeAgentEnvelope(raw); matched {
		if status == aimsg.ParseComplete {
			if text = safeRetentionCustomerText(text); text != "" {
				return text, "complete"
			}
		}
		return "", "evidence_gap"
	}
	if text := aimsg.NormalizeRetainedUserText(raw); text != "" {
		if text = safeRetentionCustomerText(text); text != "" {
			return text, "complete"
		}
		return "", "evidence_gap"
	}
	if envelope, ok := parseResponsesRetentionEnvelope(raw); ok {
		if text := safeRetentionCustomerText(responsesRetentionUserText(envelope.Input)); text != "" {
			return text, "complete"
		}
		return "", "evidence_gap"
	}
	if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
		return "", "evidence_gap"
	}
	if raw = safeRetentionCustomerText(raw); raw == "" {
		return "", "evidence_gap"
	}
	return raw, "complete"
}

func safeRetentionModelOutput(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	projected := aimsg.NormalizeRetainedAssistantText(raw)
	if hasAssistantPrivateTransportOutsideCode(projected) {
		projected = aimsg.NormalizeLegacyRetainedAssistantText(projected)
	}
	if projected == "" || isRetainedModelTransportJSON(projected) {
		return ""
	}
	return safeRetentionModelCustomerText(projected)
}

func safeRetentionLegacyModelOutput(raw string) string {
	projected := aimsg.NormalizeLegacyRetainedAssistantText(strings.TrimSpace(raw))
	if projected == "" || isRetainedModelTransportJSON(projected) {
		return ""
	}
	return safeRetentionModelCustomerText(projected)
}

func hasAssistantPrivateTransportOutsideCode(content string) bool {
	inCodeFence := false
	unclosedFenceHasPrivateTransport := false
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if inCodeFence && isRetentionMarkdownCodeFenceClose(line) {
			inCodeFence = false
			unclosedFenceHasPrivateTransport = false
			continue
		}
		if !inCodeFence && aimsg.IsRetainedMarkdownCodeFence(line) {
			inCodeFence = true
			continue
		}
		lower := strings.ToLower(trimmed)
		for _, marker := range []string{
			"<tool_call", "</tool_call", "<tool_result", "</tool_result",
			"<tool_use", "</tool_use", "<function_call", "</function_call",
			"[tool]", "[tool_use:", "[tool_result", "[reasoning]",
		} {
			if strings.Contains(lower, marker) {
				if inCodeFence {
					unclosedFenceHasPrivateTransport = true
					break
				}
				return true
			}
		}
	}
	return inCodeFence && unclosedFenceHasPrivateTransport
}

func isRetainedModelTransportJSON(content string) bool {
	content = strings.TrimSpace(content)
	if !json.Valid([]byte(content)) {
		return false
	}
	var object map[string]json.RawMessage
	if json.Unmarshal([]byte(content), &object) == nil && object != nil {
		if _, ok := object["choices"]; ok {
			return true
		}
		if _, ok := object["tool_calls"]; ok {
			return true
		}
		if _, ok := object["candidates"]; ok {
			return true
		}
		var objectType string
		_ = json.Unmarshal(object["object"], &objectType)
		if strings.Contains(strings.ToLower(objectType), "completion") || strings.EqualFold(objectType, "response") {
			return true
		}
		var itemType string
		_ = json.Unmarshal(object["type"], &itemType)
		if strings.HasPrefix(strings.ToLower(itemType), "response.") {
			return true
		}
		var role string
		_ = json.Unmarshal(object["role"], &role)
		if _, hasContent := object["content"]; hasContent {
			switch strings.ToLower(strings.TrimSpace(role)) {
			case "assistant", "user", "system", "developer", "tool":
				return true
			}
		}
		_, hasOutput := object["output"]
		_, hasUsage := object["usage"]
		if hasOutput && hasUsage {
			return true
		}
		return false
	}
	var items []map[string]json.RawMessage
	if json.Unmarshal([]byte(content), &items) != nil {
		return false
	}
	for _, item := range items {
		var itemType string
		_ = json.Unmarshal(item["type"], &itemType)
		if strings.HasPrefix(strings.ToLower(itemType), "response.") {
			return true
		}
		if _, hasRole := item["role"]; hasRole {
			if _, hasContent := item["content"]; hasContent {
				return true
			}
		}
	}
	return false
}

// safeRetentionCustomerText fails closed for runtime envelopes. The original
// records remain in the internal audit chain; this helper only shapes customer
// content fields and retained-message projections.
func safeRetentionCustomerText(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || isRetentionRuntimeContent(raw) {
		return ""
	}
	lower := strings.ToLower(raw)
	cut := len(raw)
	for _, marker := range []string{
		"\n\n【",
		"\n\n<environment_context",
		"\n\n<skills_instructions",
		"\n\n<available_skills",
		"\n\n<oai-mem-citation",
		"\n\n<citation_entries",
		"\n\n<rollout_ids",
		"\n\n<tool_call",
		"\n\n<tool_result",
		"\n\n<tool_use",
		"\n\n<function_call",
		"\n\n<system-reminder",
		"\n\n<task_management",
		"\n\n[tool]",
		"\n\n[tool_use:",
		"\n\n[reasoning]",
		"\n\ninternal recap:",
		"\n\nyou are codex",
		"\n\nwaits on a yielded `exec` cell",
		"\n\nthis tool only accepts string inputs",
		"\n\ntools for spawning and managing sub-agents",
		"\n\navailable model overrides",
		"\n\nrequest user input for one to three short questions",
		"\n\nidentifier of the running exec cell",
		"\nwaits on a yielded `exec` cell",
		"\nthis tool only accepts string inputs",
		"\ntools for spawning and managing sub-agents",
		"\navailable model overrides",
		"\nrequest user input for one to three short questions",
		"\nidentifier of the running exec cell",
	} {
		if index := strings.Index(lower, marker); index >= 0 && index < cut {
			cut = index
		}
	}
	if index := retentionVSCodeRuntimeEnvelopeLineIndex(raw); index >= 0 && index < cut {
		cut = index
	}
	return strings.TrimSpace(raw[:cut])
}

func safeRetentionModelCustomerText(raw string) string {
	raw = safeRetentionCustomerText(raw)
	if raw == "" {
		return ""
	}
	if index := retentionModelRuntimeContentLineIndex(raw); index >= 0 {
		return strings.TrimSpace(raw[:index])
	}
	return raw
}

func isRetentionRuntimeContent(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || retentionfmt.IsAgentMetaContent(raw) || isCodexRuntimeInstruction(raw) || isRetentionBackgroundWorkload(raw) {
		return raw != ""
	}
	if retentionVSCodeRuntimeEnvelopeLineIndex(raw) == 0 {
		return true
	}
	lower := strings.ToLower(raw)
	for _, marker := range []string{
		"<environment_context",
		"<skills_instructions",
		"<available_skills",
		"<oai-mem-citation",
		"<citation_entries",
		"<rollout_ids",
		"<tool_call",
		"<tool_result",
		"<tool_use",
		"<function_call",
		"<system-reminder",
		"<task_management",
		"[tool]",
		"[tool_use:",
		"[reasoning]",
		"<internal_recap",
		"internal recap:",
		"# files mentioned by the user:",
		"# files pasted by the user:",
		"waits on a yielded `exec` cell",
		"this tool only accepts string inputs",
		"tools for spawning and managing sub-agents",
		"available model overrides",
		"request user input for one to three short questions",
		"identifier of the running exec cell",
		"you are codex",
		"you are claude code",
		"# skills",
		"## skills",
		"【system】",
		"【tool】",
		"【developer】",
		"【系统】",
		"【工具】",
		"【其它】",
	} {
		if strings.HasPrefix(lower, marker) {
			return true
		}
	}
	return false
}

var retentionRuntimeToolDocumentationLinePrefixes = []string{
	"output token budget for this wait call.",
	"true stops the running exec cell;",
	"wait before yielding more output.",
}

func retentionVSCodeRuntimeEnvelopeLineIndex(raw string) int {
	return retentionContentLineIndexOutsideCode(raw, func(_ string, remainder string) bool {
		return isRetentionVSCodeRuntimeEnvelope(remainder)
	})
}

func retentionModelRuntimeContentLineIndex(raw string) int {
	return retentionContentLineIndexOutsideCode(raw, func(lowerLine, remainder string) bool {
		for _, prefix := range retentionRuntimeToolDocumentationLinePrefixes {
			if strings.HasPrefix(lowerLine, prefix) {
				return true
			}
		}
		return isRetentionImageGenOrchestration(remainder)
	})
}

func retentionContentLineIndexOutsideCode(raw string, matches func(lowerLine, remainder string) bool) int {
	inCodeFence := false
	fencedCandidate := -1
	offset := 0
	for _, line := range strings.SplitAfter(raw, "\n") {
		lineWithoutNewline := strings.TrimSuffix(line, "\n")
		if inCodeFence && isRetentionMarkdownCodeFenceClose(lineWithoutNewline) {
			inCodeFence = false
			fencedCandidate = -1
			offset += len(line)
			continue
		}
		if !inCodeFence && aimsg.IsRetainedMarkdownCodeFence(lineWithoutNewline) {
			inCodeFence = true
			offset += len(line)
			continue
		}
		contentStart := len(lineWithoutNewline) - len(strings.TrimLeft(lineWithoutNewline, " \t"))
		lowerLine := strings.ToLower(lineWithoutNewline[contentStart:])
		candidate := -1
		if matches(lowerLine, raw[offset+contentStart:]) {
			candidate = offset + contentStart
		}
		if candidate >= 0 {
			if !inCodeFence {
				return candidate
			}
			if fencedCandidate < 0 {
				fencedCandidate = candidate
			}
		}
		offset += len(line)
	}
	if inCodeFence {
		return fencedCandidate
	}
	return -1
}

func isRetentionMarkdownCodeFenceClose(line string) bool {
	return strings.TrimRight(strings.TrimSuffix(line, "\r"), " \t") == "```"
}

func isRetentionVSCodeRuntimeEnvelope(raw string) bool {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	const openTag = "<current_datetime>"
	const closeTag = "</current_datetime>"
	if !strings.HasPrefix(lower, openTag) {
		return false
	}
	closeIndex := strings.Index(lower[len(openTag):], closeTag)
	if closeIndex < 0 {
		return false
	}
	closeIndex += len(openTag)
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw[len(openTag):closeIndex])); err != nil {
		return false
	}
	remainder := lower[closeIndex+len(closeTag):]
	return strings.Contains(remainder, "<system_reminder")
}

func isRetentionImageGenOrchestration(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(lower, "use the built-in image_gen tool directly.") {
		return strings.Contains(lower, "generate exactly one image") &&
			strings.Contains(lower, "do not inspect the repository, skills, configuration")
	}
	if strings.HasPrefix(lower, "you have an internal tool called image_gen") {
		return strings.Contains(lower, "task: generate an image") &&
			strings.Contains(lower, "prompt:")
	}
	return false
}

var retentionHeartbeatEnvelope = regexp.MustCompile(`(?i)^\[[a-z]{3} [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} GMT[+-][0-9:]+\]\s*\[OpenClaw heartbeat poll\]$`)

func isRetentionHeartbeat(raw string) bool {
	text := strings.TrimSpace(raw)
	return retentionHeartbeatEnvelope.MatchString(text) || strings.HasPrefix(strings.ToLower(text), "heartbeat poll:")
}

func isRetentionBackgroundWorkload(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(lower, "## memory writing agent:") && strings.Contains(lower, "you are a memory writing agent.") {
		return true
	}
	if isRetentionHeartbeat(raw) {
		return true
	}
	if strings.HasPrefix(lower, "critical: respond with text only. do not call any tools.") && strings.Contains(lower, "summary") {
		return true
	}
	if strings.HasPrefix(lower, "this session is being continued from a previous conversation that ran out of context.") && strings.Contains(lower, "summary") {
		return true
	}
	if !strings.HasPrefix(lower, "analyze this rollout") {
		return false
	}
	if strings.Contains(lower, "durable memory") {
		return true
	}
	hits := 0
	for _, marker := range []string{
		"rollout_context:",
		"rendered conversation",
		"raw_memory",
		"rollout_summary",
		"rollout_slug",
	} {
		if strings.Contains(lower, marker) {
			hits++
		}
	}
	return hits >= 2
}

func safeRetentionContentLogProjection(logs []repository.ContentLog) (string, string, string) {
	projection := projectRetentionContentLogs(logs)
	status := "complete"
	if projection.userInput == "" {
		status = "evidence_gap"
	}
	return projection.userInput, projection.modelOutput, status
}

type projectedRetentionContentLog struct {
	runtimeOnly    bool
	userInput      string
	userCreatedAt  time.Time
	userOrdinal    int
	modelOutput    string
	modelCreatedAt time.Time
}

func projectRetentionContentLogs(logs []repository.ContentLog) projectedRetentionContentLog {
	var out projectedRetentionContentLog
	lastRole := ""
	pendingRuntimeInput := false
	for _, row := range logs {
		role := strings.ToLower(strings.TrimSpace(row.Role))
		lastRole = role
		if role == "user" && aimsg.IsRetainedUserTransportOnly(row.Content) {
			continue
		}
		switch role {
		case "user":
			if text, status := safeRetentionUserInput(row.Content); status == "complete" && text != "" {
				pendingRuntimeInput = false
				out.userOrdinal++
				out.userInput = text
				out.userCreatedAt = row.CreatedAt
			} else {
				pendingRuntimeInput = true
				out.modelOutput = ""
				out.modelCreatedAt = time.Time{}
			}
		case "assistant":
			if pendingRuntimeInput {
				continue
			}
			if text := safeRetentionLegacyModelOutput(row.Content); text != "" {
				out.modelOutput = text
				out.modelCreatedAt = row.CreatedAt
			}
		default:
			// system/tool/developer rows are never projected. A later assistant
			// row may still be the customer-visible answer to the safe user input.
		}
	}
	// content_logs 先写完整请求历史，随后才追加本次文本响应。若最后一条不是
	// assistant，前面的 assistant 都是客户端重发的历史，不能伪造成本次模型输出。
	if lastRole != "assistant" {
		out.modelOutput = ""
		out.modelCreatedAt = time.Time{}
	}
	out.runtimeOnly = pendingRuntimeInput
	return out
}

func buildAccessRetentionMessages(ctx context.Context, deps *Dependencies, tenantID string, requestIDs []string, accessItems []repository.AccessContentLog) ([]types.AccessRetentionMessageInfo, error) {
	return buildAccessRetentionMessagesScoped(ctx, deps, tenantID, requestIDs, accessItems, "", time.Time{}, time.Time{})
}

func buildAccessRetentionMessagesScoped(ctx context.Context, deps *Dependencies, tenantID string, requestIDs []string, accessItems []repository.AccessContentLog, scope string, start, end time.Time) ([]types.AccessRetentionMessageInfo, error) {
	byRequest := make(map[string]repository.AccessContentLog, len(accessItems))
	requestCreatedAt := make(map[string]time.Time, len(requestIDs))
	rememberRequestTime := func(requestID string, createdAt time.Time) {
		requestID = strings.TrimSpace(requestID)
		if requestID == "" || createdAt.IsZero() {
			return
		}
		if existing := requestCreatedAt[requestID]; existing.IsZero() || createdAt.Before(existing) {
			requestCreatedAt[requestID] = createdAt
		}
	}
	for _, item := range accessItems {
		if item.RequestID != "" {
			byRequest[item.RequestID] = item
			rememberRequestTime(item.RequestID, item.CreatedAt)
		}
	}
	contentLogsByRequest := map[string][]repository.ContentLog{}
	batchContentLogs := false
	if scopedReader, ok := deps.ContentLogReader.(scopedContentLogBatchReader); ok && len(requestIDs) > 1 {
		logs, err := scopedReader.ListByRequestsScoped(ctx, tenantID, requestIDs, start, end, scope)
		if err != nil {
			return nil, err
		}
		batchContentLogs = true
		for _, log := range logs {
			contentLogsByRequest[log.RequestID] = append(contentLogsByRequest[log.RequestID], log)
			rememberRequestTime(log.RequestID, log.CreatedAt)
		}
	} else if batchReader, ok := deps.ContentLogReader.(ContentLogBatchReader); ok && len(requestIDs) > 1 {
		logs, err := batchReader.ListByRequests(ctx, tenantID, requestIDs)
		if err != nil {
			return nil, err
		}
		batchContentLogs = true
		for _, log := range logs {
			contentLogsByRequest[log.RequestID] = append(contentLogsByRequest[log.RequestID], log)
			rememberRequestTime(log.RequestID, log.CreatedAt)
		}
	}
	orderedRequestIDs := make([]string, 0, len(requestIDs))
	orderedRequestSeen := make(map[string]bool, len(requestIDs))
	for _, requestID := range requestIDs {
		requestID = strings.TrimSpace(requestID)
		if requestID == "" || orderedRequestSeen[requestID] {
			continue
		}
		orderedRequestSeen[requestID] = true
		orderedRequestIDs = append(orderedRequestIDs, requestID)
	}
	sort.SliceStable(orderedRequestIDs, func(i, j int) bool {
		left, right := requestCreatedAt[orderedRequestIDs[i]], requestCreatedAt[orderedRequestIDs[j]]
		if left.IsZero() || right.IsZero() || left.Equal(right) {
			return false
		}
		return left.Before(right)
	})
	messages := make([]types.AccessRetentionMessageInfo, 0, len(orderedRequestIDs)*2)
	seenUsers := map[string]bool{}
	lastUserSourceByStream := map[string]string{}
	sequence := 0
	appendMessage := func(requestID, role, kind, content string, createdAt time.Time, userKey, replayStreamKey string) {
		content = strings.TrimSpace(content)
		if content == "" {
			return
		}
		if role == "user" {
			var nextSource string
			content, nextSource = incrementalRetentionUserText(lastUserSourceByStream[replayStreamKey], content)
			lastUserSourceByStream[replayStreamKey] = nextSource
			if content == "" {
				return
			}
			if seenUsers[userKey] {
				return
			}
			seenUsers[userKey] = true
		}
		sequence++
		digest := sha256.Sum256([]byte(requestID + "\x00" + role + "\x00" + kind + "\x00" + fmt.Sprint(sequence)))
		message := types.AccessRetentionMessageInfo{
			ID: "msg_" + fmt.Sprintf("%x", digest[:12]), RequestID: requestID,
			Sequence: sequence, Role: role, Kind: kind, Content: content,
		}
		if !createdAt.IsZero() {
			message.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
		}
		messages = append(messages, message)
	}

	for _, requestID := range orderedRequestIDs {
		if item, ok := byRequest[requestID]; ok {
			input, status := safeRetentionUserInput(item.RequestContent)
			if status == "complete" && input != "" {
				digest := sha256.Sum256([]byte(input))
				sectionKey := strings.TrimSpace(item.SectionID)
				appendMessage(requestID, "user", "user_input", input, item.CreatedAt,
					fmt.Sprintf("access:%s:%x", sectionKey, digest[:]), "access:"+sectionKey)
			}
			if status == "complete" {
				appendMessage(requestID, "assistant", "model_output", safeRetentionModelOutput(item.ResponseContent), item.CreatedAt, "", "")
			}
			continue
		}
		if deps.ContentLogReader == nil {
			continue
		}
		logs := contentLogsByRequest[requestID]
		var err error
		if !batchContentLogs {
			logs, err = listContentLogsByRequest(ctx, deps.ContentLogReader, tenantID, requestID, scope, start, end)
		}
		if err != nil {
			return nil, err
		}
		projection := projectRetentionContentLogs(logs)
		if projection.userInput != "" {
			digest := sha256.Sum256([]byte(projection.userInput))
			userKey := fmt.Sprintf("content:%d:%x", projection.userOrdinal, digest[:])
			appendMessage(requestID, "user", "user_input", projection.userInput, projection.userCreatedAt,
				userKey, fmt.Sprintf("content:%d", projection.userOrdinal))
		}
		appendMessage(requestID, "assistant", "model_output", projection.modelOutput, projection.modelCreatedAt, "", "")
	}
	return messages, nil
}

func incrementalRetentionUserText(previous, current string) (string, string) {
	previous = strings.TrimSpace(previous)
	current = strings.TrimSpace(current)
	if current == "" {
		return "", previous
	}
	if previous == current {
		return "", current
	}
	if previous != "" && strings.HasPrefix(current, previous) {
		remainder := strings.TrimPrefix(current, previous)
		if strings.HasPrefix(remainder, "\n") {
			if delta := strings.TrimSpace(remainder); delta != "" {
				return delta, current
			}
		}
	}
	return current, current
}

func ensureInputArtifactMessages(messages []types.AccessRetentionMessageInfo, artifacts []types.AccessRetentionArtifactInfo) []types.AccessRetentionMessageInfo {
	userRequests := make(map[string]bool, len(messages))
	for _, message := range messages {
		if message.Role == "user" && strings.TrimSpace(message.RequestID) != "" {
			userRequests[message.RequestID] = true
		}
	}
	for _, artifact := range artifacts {
		requestID := strings.TrimSpace(artifact.RequestID)
		if artifact.Direction != "input" || requestID == "" || userRequests[requestID] {
			continue
		}
		createdAt := artifact.RequestCreatedAt
		if createdAt.IsZero() {
			createdAt = artifact.LinkCreatedAt
		}
		digest := sha256.Sum256([]byte(requestID + "\x00artifact-input"))
		message := types.AccessRetentionMessageInfo{
			ID:        "msg_" + fmt.Sprintf("%x", digest[:12]),
			RequestID: requestID,
			Role:      "user",
			Kind:      "user_input",
			Content:   "",
		}
		if !createdAt.IsZero() {
			message.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
		}
		messages = append(messages, message)
		userRequests[requestID] = true
	}
	sort.SliceStable(messages, func(i, j int) bool {
		left, leftErr := time.Parse(time.RFC3339Nano, messages[i].CreatedAt)
		right, rightErr := time.Parse(time.RFC3339Nano, messages[j].CreatedAt)
		if leftErr == nil && rightErr == nil && !left.Equal(right) {
			return left.Before(right)
		}
		if messages[i].RequestID == messages[j].RequestID && messages[i].Role != messages[j].Role {
			return messages[i].Role == "user"
		}
		return messages[i].Sequence < messages[j].Sequence
	})
	for index := range messages {
		messages[index].Sequence = index + 1
	}
	return messages
}

// GetAccessRetentionArtifact serves only a normalized tenant/request/artifact link.
// preview=true selects the separately retained preview; original always downloads.
// GetAccessRetentionArtifact 返回带证据读取审计的附件 handler：preview=true 记 artifact_preview，否则 artifact_original。
func GetAccessRetentionArtifact(preview bool, deps *Dependencies) http.HandlerFunc {
	kind := "artifact_original"
	if preview {
		kind = "artifact_preview"
	}
	return auditedEvidenceHandler(deps, kind, getAccessRetentionArtifactInner(preview, deps))
}

func getAccessRetentionArtifactInner(preview bool, deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		requestID := strings.TrimSpace(chi.URLParam(r, "request_id"))
		artifactID := strings.TrimSpace(chi.URLParam(r, "artifact_id"))
		if strings.TrimSpace(r.URL.Query().Get("key")) != "" {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "retained artifact not found")
			return
		}
		if artifactID == "" {
			artifactID = strings.TrimSpace(r.URL.Query().Get("artifact_id"))
		}
		repo := accessRetentionArtifactRepo(deps)
		if requestID == "" || artifactID == "" || repo == nil || deps.RetentionStore == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "retained artifact not found")
			return
		}
		scope, start, end, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid UTC window")
			return
		}
		var artifact *repository.RetainedArtifact
		var err error
		if scoped, ok := repo.(interface {
			GetRetainedArtifactScoped(context.Context, string, string, string, time.Time, time.Time, string) (*repository.RetainedArtifact, error)
		}); ok {
			artifact, err = scoped.GetRetainedArtifactScoped(r.Context(), user.TenantID, requestID, artifactID, start, end, scope)
		} else {
			artifact, err = repo.GetRetainedArtifact(r.Context(), user.TenantID, requestID, artifactID)
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get retained artifact")
			return
		}
		if artifact == nil || artifact.Status != "retained" {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "retained artifact not found")
			return
		}
		key := artifact.OriginalObjectKey
		if preview {
			key = artifact.PreviewObjectKey
			if key == "" && artifact.OriginalObjectKey != "" && safeInlinePreview(artifact.MediaType) {
				key = artifact.OriginalObjectKey
			}
		}
		if key == "" {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "retained artifact not found")
			return
		}
		obj, err := deps.RetentionStore.GetObject(r.Context(), user.TenantID, key)
		if err != nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "retained artifact not found")
			return
		}
		defer obj.Body.Close()

		contentType := strings.TrimSpace(obj.Metadata.ContentType)
		if contentType == "" {
			contentType = strings.TrimSpace(artifact.MediaType)
		}
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		if preview && !safeInlinePreview(contentType) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "retained artifact preview not found")
			return
		}
		name := safeArtifactFilename(artifact.DisplayName, artifact.Kind)
		disposition := "attachment"
		if preview && safeInlinePreview(contentType) {
			disposition = "inline"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": name}))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "private, no-store")
		if obj.Metadata.SHA256 != "" {
			w.Header().Set("ETag", "\""+obj.Metadata.SHA256+"\"")
		}
		_, _ = io.Copy(w, io.LimitReader(obj.Body, 64<<20))
	}
}

func safeArtifactFilename(name, kind string) string {
	name = path.Base(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, name)
	if name == "" || name == "." {
		if kind == "image" {
			return "artifact-image"
		}
		return "artifact-file"
	}
	return name
}

func safeInlinePreview(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return strings.HasPrefix(contentType, "image/") && contentType != "image/svg+xml"
}

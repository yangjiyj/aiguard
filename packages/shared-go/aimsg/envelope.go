package aimsg

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	workBuddyImagePathPattern      = regexp.MustCompile(`(?is)[\t ]*\r?\n?<image_local_path(?:\s[^>]*)?>.*?</image_local_path>[\t ]*\r?\n?`)
	workBuddyImagePathOpenPattern  = regexp.MustCompile(`(?im)[\t ]*<image_local_path(?:\s[^>]*)?>[^\r\n<]*(?:</image_local_path>)?`)
	workBuddyImageRefPattern       = regexp.MustCompile(`(?im)(?:^|[\r\n])[\t ]*@image#[0-9]+:[^\t \r\n]+[\t ]*`)
	workBuddyInlineImageRefPattern = regexp.MustCompile(`(?i)@image#[0-9]+:[^\s]+[\t ]*`)
	workBuddyLoopGuardPattern      = regexp.MustCompile(`(?is)^\s*\[\s*Loop detected:\s*the tool\s+["'][^"'\r\n]+["']\s+has been called\s+\d+\s+consecutive times with identical arguments\.\s*STOP calling tools immediately\.\s*Do NOT make any more tool calls\.\s*Instead, tell the user what happened and suggest they switch models or modify their prompt to retry\.\s*\]\s*\[LOOP_DETECTED\]\s*$`)
	vscodeLocalImagePathPattern    = regexp.MustCompile(`(?im)^[\t ]*Image file at path[\t ]+(?:[A-Z]:\\|/)[^\r\n]*$`)
	codexImageBlockPattern         = regexp.MustCompile(`(?is)[\t ]*\r?\n?<image\s+name=\[Image\s*#[0-9]+\]\s+path=(?:"[^"]*"|'[^']*')[^>]*>.*?</image\s*>[\t ]*\r?\n?`)
	currentDateTimeBlockPattern    = regexp.MustCompile(`(?is)[\t ]*\r?\n?<current_datetime(?:\s[^>]*)?>[0-9TZ:+.\-]+</current_datetime>[\t ]*\r?\n?`)
	runtimeEnvelopePrefixPattern   = regexp.MustCompile(`(?is)^\s*<current_datetime(?:\s[^>]*)?>([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9TZ:+.\-]+)</current_datetime>`)
	systemReminderBlockPattern     = regexp.MustCompile(`(?is)[\t ]*\r?\n?<system_reminder(?:\s[^>]*)?>.*?</system_reminder>[\t ]*\r?\n?`)
	userQueryPattern               = regexp.MustCompile(`(?is)<user_query(?:\s[^>]*)?>(.*?)</user_query>`)
	assistantReasoningPattern      = regexp.MustCompile(`(?im)^[\t ]*\[(?:reasoning|thinking|analysis|chain_of_thought|cot)\][^\r\n]*(?:\r?\n|$)`)
	assistantMemoryPattern         = regexp.MustCompile(`(?is)[\t ]*\r?\n?<oai-mem-citation(?:\s[^>]*)?>.*?</oai-mem-citation>[\t ]*\r?\n?`)
	assistantPrivateLinePattern    = regexp.MustCompile(`(?im)^[\t ]*\[(?:tool|tool_use(?::[^\]\r\n]*)?|tool_result(?::[^\]\r\n]*)?)\][^\r\n]*(?:\r?\n|$)`)
	assistantPrivateBlockPattern   = regexp.MustCompile(`(?is)[\t ]*\r?\n?<(?:oai-mem-citation|citation_entries|rollout_ids|tool_call|tool_result|tool_use|function_call|internal_recap)(?:\s[^>]*)?>.*?</(?:oai-mem-citation|citation_entries|rollout_ids|tool_call|tool_result|tool_use|function_call|internal_recap)>[\t ]*\r?\n?`)
	assistantPrivateClosePattern   = regexp.MustCompile(`(?i)</(?:oai-mem-citation|citation_entries|rollout_ids|tool_call|tool_result|tool_use|function_call|internal_recap)>`)
	assistantPrivateOpenPattern    = regexp.MustCompile(`(?is)[\t ]*\r?\n?<(?:oai-mem-citation|citation_entries|rollout_ids|tool_call|tool_result|tool_use|function_call|internal_recap)(?:\s[^>]*)?>`)
	assistantMarkdownFencePattern  = regexp.MustCompile("^```[A-Za-z0-9_+.-]*[\\t ]*$")
	assistantMarkdownFenceClose    = regexp.MustCompile("^```[\\t ]*$")
	promptEnvelopePattern          = regexp.MustCompile(`(?is)^\s*<prompt(?:\s[^>]*)?>(.*?)</prompt>\s*$`)
	agentFilesHeaderPattern        = regexp.MustCompile(`(?im)^#\s*Files\s+(?:mentioned|pasted|attached|provided|selected|referenced)\s+by\s+the\s+user\s*:\s*$`)
	userRequestHeaderPattern       = regexp.MustCompile(`(?im)^##\s*My\s+request(?:\s+for\s+Codex)?\s*:\s*$`)
	workBuddyUserContextPattern    = regexp.MustCompile(
		`(?is)^\s*<system-reminder\b[^>]*\bdata-role\s*=\s*["']user-context["'][^>]*>.*</system-reminder>\s*$`,
	)
)

var inAppBrowserContextOpenPattern = regexp.MustCompile(`(?is)^\s*<in-app-browser-context\b[^>]*\ssource\s*=\s*(?:"ambient-ui-state"|'ambient-ui-state')[^>]*>`)
var inAppBrowserContextClosePattern = regexp.MustCompile(`(?is)</in-app-browser-context>\s*`)
var codeBuddyImagePathRefPattern = regexp.MustCompile("(?im)^[\\t ]*@image(?:#[0-9]+)?:(?:[A-Z]:\\\\|/)[^\\r\\n]*$")
var toolsChangedNoticeBlockPattern = regexp.MustCompile("(?is)[\\t ]*\\r?\\n?<tools_changed_notice(?:\\s[^>]*)?>.*?</tools_changed_notice>[\\t ]*\\r?\\n?")
var toolsChangedNoticeTailPattern = regexp.MustCompile(`(?is)[\t ]*<tools_changed_notice(?:\s[^>]*)?>\s*Tools no longer available\b`)

// NormalizeAgentEnvelope returns only an explicitly identifiable human segment
// from known agent envelopes. A matched but incomplete envelope is ambiguous and
// never falls back to its raw machine content.
func NormalizeAgentEnvelope(content string) (string, ParseStatus, bool) {
	content = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(content, "\r\n", "\n"), "\r", "\n"))
	if IsRetainedUserTransportOnly(content) {
		return "", ParseAmbiguous, true
	}
	if match := promptEnvelopePattern.FindStringSubmatch(content); len(match) == 2 {
		visible := strings.TrimSpace(match[1])
		if visible == "" {
			return "", ParseAmbiguous, true
		}
		visible, _ = stripUserTransportMetadata(visible)
		if visible == "" {
			return "", ParseAmbiguous, true
		}
		return visible, ParseComplete, true
	}
	if visible, matched, complete := projectImageGenUserEnvelope(content); matched {
		if !complete || visible == "" {
			return "", ParseAmbiguous, true
		}
		return visible, ParseComplete, true
	}
	if visible, matched, complete := projectClineTaskEnvelope(content); matched {
		if !complete || visible == "" {
			return "", ParseAmbiguous, true
		}
		return visible, ParseComplete, true
	}
	if visible, matched, complete := projectWorkBuddyImageSession(content); matched {
		if !complete || visible == "" {
			return "", ParseAmbiguous, true
		}
		return visible, ParseComplete, true
	}
	if inAppBrowserContextOpenPattern.MatchString(content) {
		open := inAppBrowserContextOpenPattern.FindStringIndex(content)
		close := inAppBrowserContextClosePattern.FindStringIndex(content[open[1]:])
		if close == nil {
			return "", ParseAmbiguous, true
		}
		remainder := strings.TrimSpace(content[open[1]+close[1]:])
		marker := userRequestHeaderPattern.FindStringIndex(remainder)
		if marker == nil || marker[0] != 0 {
			return "", ParseAmbiguous, true
		}
		request, _ := stripUserTransportMetadata(remainder[marker[1]:])
		if request == "" {
			return "", ParseAmbiguous, true
		}
		return request, ParseComplete, true
	}
	if codexEnvelope(content) || codexFilesEnvelope(content) {
		markers := userRequestHeaderPattern.FindAllStringIndex(content, -1)
		if len(markers) > 0 {
			marker := markers[len(markers)-1]
			request, transportMatched := stripUserTransportMetadata(content[marker[1]:])
			if request != "" {
				return request, ParseComplete, true
			}
			if transportMatched {
				return "", ParseAmbiguous, true
			}
		}
		return "", ParseAmbiguous, true
	}
	if strings.Contains(strings.ToLower(content), "<system-reminder") || strings.Contains(strings.ToLower(content), "<user_query") {
		matches := userQueryPattern.FindAllStringSubmatch(content, -1)
		if len(matches) == 0 {
			return "", ParseAmbiguous, true
		}
		queries := make([]string, 0, len(matches))
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			if query, _ := stripUserTransportMetadata(match[1]); query != "" {
				queries = append(queries, query)
			}
		}
		query := strings.Join(queries, "\n")
		if query == "" {
			return "", ParseAmbiguous, true
		}
		return query, ParseComplete, true
	}
	if isOrchestratorUserEnvelope(content) {
		return "", ParseAmbiguous, true
	}
	if visible, matched, complete := stripKnownRuntimeMetadata(content); matched {
		if !complete {
			return "", ParseAmbiguous, true
		}
		visible, _ = stripUserTransportMetadata(visible)
		if visible == "" {
			return "", ParseAmbiguous, true
		}
		return visible, ParseComplete, true
	}
	if visible, matched := stripUserTransportMetadata(content); matched {
		if visible == "" {
			return "", ParseAmbiguous, true
		}
		return visible, ParseComplete, true
	}
	return content, ParseComplete, false
}

func projectImageGenUserEnvelope(content string) (string, bool, bool) {
	lower := strings.ToLower(strings.TrimSpace(content))
	var required []string
	switch {
	case strings.HasPrefix(lower, "use the built-in image_gen tool directly."):
		required = []string{
			"generate exactly one image",
			"do not inspect the repository, skills, configuration",
		}
	case strings.HasPrefix(lower, "you have an internal tool called image_gen"):
		required = []string{"task: generate an image"}
	default:
		return content, false, true
	}

	promptAt := imageGenPromptMarkerIndex(content)
	fingerprintText := lower
	if promptAt >= 0 {
		fingerprintText = strings.ToLower(content[:promptAt])
	}
	for _, marker := range required {
		if !strings.Contains(fingerprintText, marker) {
			return content, false, true
		}
	}
	if promptAt < 0 {
		return "", true, false
	}
	visible := strings.TrimSpace(content[promptAt+len("PROMPT:"):])
	return visible, true, visible != ""
}

func imageGenPromptMarkerIndex(content string) int {
	inFence := false
	offset := 0
	for _, line := range strings.SplitAfter(content, "\n") {
		lineWithoutNewline := strings.TrimSuffix(line, "\n")
		if inFence && isRetainedMarkdownCodeFenceClose(lineWithoutNewline) {
			inFence = false
			offset += len(line)
			continue
		}
		if !inFence && IsRetainedMarkdownCodeFence(lineWithoutNewline) {
			inFence = true
			offset += len(line)
			continue
		}
		if !inFence {
			searchFrom := 0
			for searchFrom < len(lineWithoutNewline) {
				relative := strings.Index(lineWithoutNewline[searchFrom:], "PROMPT:")
				if relative < 0 {
					break
				}
				markerAt := searchFrom + relative
				if markerAt == 0 || isImageGenPromptBoundary(lineWithoutNewline[markerAt-1]) {
					return offset + markerAt
				}
				searchFrom = markerAt + len("PROMPT:")
			}
		}
		offset += len(line)
	}
	return -1
}

func isImageGenPromptBoundary(value byte) bool {
	return value == ' ' || value == '\t' || value == ':' || value == '-'
}

func projectClineTaskEnvelope(content string) (string, bool, bool) {
	if !strings.HasPrefix(content, "<task>") {
		return content, false, true
	}
	closeAt := strings.Index(content[len("<task>"):], "</task>")
	if closeAt < 0 {
		return content, false, true
	}
	closeAt += len("<task>")
	remainder := content[closeAt+len("</task>"):]
	if !strings.HasPrefix(remainder, "\n") {
		return content, false, true
	}
	remainder = strings.TrimSpace(remainder)
	firstLineEnd := strings.IndexByte(remainder, '\n')
	firstLine := remainder
	if firstLineEnd >= 0 {
		firstLine = remainder[:firstLineEnd]
	}
	if firstLine != "# task_progress RECOMMENDED" {
		return content, false, true
	}
	if !strings.Contains(remainder, "<environment_details>") {
		return content, false, true
	}
	if !strings.HasSuffix(remainder, "</environment_details>") {
		return "", true, false
	}
	visible := strings.TrimSpace(content[len("<task>"):closeAt])
	return visible, true, visible != ""
}

func projectWorkBuddyImageSession(content string) (string, bool, bool) {
	firstLineEnd := strings.IndexByte(content, '\n')
	if firstLineEnd < 0 || strings.TrimSpace(content[:firstLineEnd]) != "<session>" {
		return content, false, true
	}
	body := content[firstLineEnd+1:]
	if !workBuddyInlineImageRefPattern.MatchString(body) && !strings.Contains(strings.ToLower(body), "<image_local_path") {
		return content, false, true
	}
	lastLineStart := strings.LastIndexByte(body, '\n')
	if lastLineStart < 0 || strings.TrimSpace(body[lastLineStart+1:]) != "</session>" {
		return "", true, false
	}
	visible, _ := stripUserTransportMetadata(body[:lastLineStart])
	visible = strings.TrimSpace(visible)
	return visible, true, visible != ""
}

// IsWorkBuddyUserContextEnvelope identifies the complete metadata-only wrapper
// emitted by WorkBuddy as a protocol-level user message. It intentionally
// requires the data-role attribute and a closing outer tag so a prefix alone
// cannot downgrade arbitrary user text.
func IsWorkBuddyUserContextEnvelope(content string) bool {
	return workBuddyUserContextPattern.MatchString(content)
}

func codexEnvelope(content string) bool {
	return strings.Contains(content, "# AGENTS.md instructions") &&
		strings.Contains(content, "<INSTRUCTIONS>") &&
		strings.Contains(content, "</INSTRUCTIONS>") &&
		strings.Contains(content, "<environment_context>")
}

func codexFilesEnvelope(content string) bool {
	return agentFilesHeaderPattern.MatchString(content) && userRequestHeaderPattern.MatchString(content)
}

func stripUserTransportMetadata(content string) (string, bool) {
	content = strings.TrimSpace(content)
	if workBuddyLoopGuardPattern.MatchString(content) {
		return "", true
	}
	withoutPaths := workBuddyImagePathPattern.ReplaceAllString(content, "\n")
	withoutPaths = workBuddyImagePathOpenPattern.ReplaceAllString(withoutPaths, "\n")
	withoutPaths = codexImageBlockPattern.ReplaceAllString(withoutPaths, "\n")
	withoutPaths = codeBuddyImagePathRefPattern.ReplaceAllString(withoutPaths, "\n")
	withoutRefs := workBuddyImageRefPattern.ReplaceAllString(withoutPaths, "")
	withoutRefs = workBuddyInlineImageRefPattern.ReplaceAllString(withoutRefs, "")
	withoutRefs = stripUserLineMetadataOutsideCodeFences(withoutRefs)
	matched := withoutRefs != content
	return strings.TrimSpace(withoutRefs), matched
}

func stripUserLineMetadataOutsideCodeFences(content string) string {
	return transformUserTextOutsideCodeFences(content, func(chunk string) string {
		cleaned := vscodeLocalImagePathPattern.ReplaceAllString(chunk, "\n")
		cleaned = toolsChangedNoticeBlockPattern.ReplaceAllString(cleaned, "\n")
		if start := toolsChangedNoticeTailPattern.FindStringIndex(cleaned); start != nil {
			cleaned = cleaned[:start[0]]
		}
		return cleaned
	})
}

// IsRetainedUserTransportOnly identifies a complete, known client control
// message that must not start a new customer turn in historical projections.
func IsRetainedUserTransportOnly(content string) bool {
	content = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(content, "\r\n", "\n"), "\r", "\n"))
	if workBuddyLoopGuardPattern.MatchString(content) {
		return true
	}
	// Complete metadata-only client envelopes carry no human occurrence. A
	// user_query or trailing human text keeps the normal projection path.
	if strings.HasPrefix(content, "<system-reminder") && strings.HasSuffix(content, "</system-reminder>") && !strings.Contains(content, "<user_query") && !userRequestHeaderPattern.MatchString(content) {
		return strings.Contains(content, "<system-reminder>") || strings.HasPrefix(content, "<system-reminder ")
	}
	return strings.HasPrefix(content, "<environment_details>") && strings.HasSuffix(content, "</environment_details>") && (strings.Contains(content, "# VSCode") || strings.Contains(content, "# Current Mode") || strings.Contains(content, "Current Working Directory"))
}

func transformUserTextOutsideCodeFences(content string, transform func(string) string) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	output := make([]string, 0, len(lines))
	outside := make([]string, 0, len(lines))
	fenced := make([]string, 0)
	inFence := false
	flushOutside := func() {
		if len(outside) == 0 {
			return
		}
		original := strings.Join(outside, "\n")
		cleaned := transform(original)
		if cleaned != original {
			cleaned = strings.TrimSpace(cleaned)
		}
		if cleaned != "" {
			output = append(output, strings.Split(cleaned, "\n")...)
		}
		outside = outside[:0]
	}
	for _, line := range lines {
		if !inFence && IsRetainedMarkdownCodeFence(line) {
			flushOutside()
			inFence = true
			fenced = append(fenced[:0], line)
			continue
		}
		if inFence && isRetainedMarkdownCodeFenceClose(line) {
			fenced = append(fenced, line)
			output = append(output, fenced...)
			fenced = fenced[:0]
			inFence = false
			continue
		}
		if inFence {
			fenced = append(fenced, line)
		} else {
			outside = append(outside, line)
		}
	}
	if inFence {
		outside = append(outside, fenced...)
	}
	flushOutside()
	return strings.Join(output, "\n")
}

func stripKnownRuntimeMetadata(content string) (string, bool, bool) {
	if RuntimeContextKey(content) == "" {
		return content, false, true
	}
	visible := transformUserTextOutsideCodeFences(content, func(chunk string) string {
		chunk = currentDateTimeBlockPattern.ReplaceAllString(chunk, "\n")
		chunk = systemReminderBlockPattern.ReplaceAllString(chunk, "\n")
		return toolsChangedNoticeBlockPattern.ReplaceAllString(chunk, "\n")
	})
	matched := visible != content
	if !matched {
		return content, false, true
	}
	if hasUserRuntimeMarkerOutsideCodeFences(visible) {
		return "", true, false
	}
	return strings.TrimSpace(visible), true, true
}

func hasUserRuntimeMarkerOutsideCodeFences(content string) bool {
	found := false
	transformUserTextOutsideCodeFences(content, func(chunk string) string {
		lower := strings.ToLower(chunk)
		for _, marker := range []string{
			"<current_datetime", "</current_datetime>",
			"<system_reminder", "</system_reminder>",
			"<tools_changed_notice", "</tools_changed_notice>",
		} {
			if strings.Contains(lower, marker) {
				found = true
				break
			}
		}
		return chunk
	})
	return found
}

// RuntimeContextKey returns the bounded context identifier used by VS Code
// agent envelopes. It requires both an RFC3339-like leading timestamp and the
// complete underscore-form reminder block observed on that protocol.
func RuntimeContextKey(content string) string {
	content = strings.TrimSpace(content)
	match := runtimeEnvelopePrefixPattern.FindStringSubmatch(content)
	if len(match) != 2 {
		return ""
	}
	lower := strings.ToLower(content)
	if !strings.Contains(lower, "<system_reminder") || !strings.Contains(lower, "</system_reminder>") {
		return ""
	}
	return strings.TrimSpace(match[1])
}

// NormalizeRetainedUserText projects stored request text to customer-visible
// human content. Raw protocol and security evidence remain unchanged elsewhere.
func NormalizeRetainedUserText(content string) string {
	visible, status, _ := NormalizeAgentEnvelope(content)
	if status != ParseComplete {
		return ""
	}
	paragraphs := strings.Split(strings.ReplaceAll(visible, "\r\n", "\n"), "\n\n")
	kept := make([]string, 0, len(paragraphs))
	for _, paragraph := range paragraphs {
		trimmed := strings.TrimSpace(paragraph)
		if trimmed == "" || hasInternalRolePrefix(trimmed) {
			continue
		}
		kept = append(kept, trimmed)
	}
	return strings.TrimSpace(strings.Join(kept, "\n\n"))
}

func hasInternalRolePrefix(content string) bool {
	for _, prefix := range []string{
		"【系统】", "【工具】", "【system】", "【tool】", "【developer】", "【其它】",
	} {
		if strings.HasPrefix(content, prefix) {
			return true
		}
	}
	return false
}

// NormalizeRetainedAssistantText removes model-private reasoning and Codex
// memory citation transport blocks from the customer-visible response.
func NormalizeRetainedAssistantText(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = assistantReasoningPattern.ReplaceAllString(content, "")
	content = assistantMemoryPattern.ReplaceAllString(content, "\n")
	lines := strings.Split(content, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}
	return strings.Join(kept, "\n")
}

// NormalizeLegacyRetainedAssistantText additionally recognizes historical
// agent tool payloads written before protocol decoders exposed VisibleText.
func NormalizeLegacyRetainedAssistantText(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	return stripLegacyPrivateOutsideCodeFences(content)
}

// IsRetainedMarkdownCodeFence mirrors the customer renderer's supported fence
// syntax. Broader Markdown variants cannot become privacy exemptions.
func IsRetainedMarkdownCodeFence(line string) bool {
	return assistantMarkdownFencePattern.MatchString(strings.TrimSuffix(line, "\r"))
}

func isRetainedMarkdownCodeFenceClose(line string) bool {
	return assistantMarkdownFenceClose.MatchString(strings.TrimSuffix(line, "\r"))
}

func stripLegacyPrivateOutsideCodeFences(content string) string {
	lines := strings.Split(content, "\n")
	output := make([]string, 0, len(lines))
	outside := make([]string, 0, len(lines))
	fenced := make([]string, 0)
	inFence := false
	flushOutside := func() {
		if len(outside) == 0 {
			return
		}
		chunk := strings.Join(outside, "\n")
		chunk = stripLegacyPrivateChunk(chunk)
		if chunk != "" {
			output = append(output, strings.Split(chunk, "\n")...)
		}
		outside = outside[:0]
	}
	for _, line := range lines {
		if !inFence && IsRetainedMarkdownCodeFence(line) {
			flushOutside()
			inFence = true
			fenced = append(fenced[:0], line)
			continue
		}
		if inFence && isRetainedMarkdownCodeFenceClose(line) {
			fenced = append(fenced, line)
			output = append(output, fenced...)
			fenced = fenced[:0]
			inFence = false
			continue
		}
		if inFence {
			fenced = append(fenced, line)
		} else {
			outside = append(outside, line)
		}
	}
	if inFence {
		// An unterminated fence is not a trustworthy privacy boundary.
		outside = append(outside, fenced...)
	}
	flushOutside()
	return strings.TrimSpace(strings.Join(output, "\n"))
}

func stripLegacyPrivateChunk(content string) string {
	content = NormalizeRetainedAssistantText(content)
	content = assistantPrivateLinePattern.ReplaceAllString(content, "")
	content = assistantPrivateBlockPattern.ReplaceAllString(content, "\n")
	content = assistantPrivateClosePattern.ReplaceAllString(content, "")
	// Historical rows can contain a private transport block cut by the byte cap.
	// With no trustworthy closing boundary, discard only that legacy suffix.
	if match := assistantPrivateOpenPattern.FindStringIndex(content); match != nil {
		content = content[:match[0]]
	}
	return stripTrailingAgentToolPayload(strings.TrimSpace(content))
}

func stripTrailingAgentToolPayload(content string) string {
	content = strings.TrimSpace(content)
	for index := 0; index < len(content); index++ {
		if content[index] != '{' {
			continue
		}
		candidate := strings.TrimSpace(content[index:])
		var payload map[string]json.RawMessage
		if json.Unmarshal([]byte(candidate), &payload) != nil || !looksLikeAgentToolPayload(payload) {
			continue
		}
		return strings.TrimSpace(content[:index])
	}
	return content
}

func looksLikeAgentToolPayload(payload map[string]json.RawMessage) bool {
	if len(payload) == 0 {
		return false
	}
	for _, visibleKey := range []string{"answer", "content", "message", "result"} {
		if _, ok := payload[visibleKey]; ok {
			return false
		}
	}
	for _, toolKey := range []string{"command", "cmd", "file_path", "old_string", "new_string"} {
		if _, ok := payload[toolKey]; ok {
			return true
		}
	}
	return false
}

func retainedUserProjection(message ConvMessage) (string, ParseStatus) {
	if message.Source != SourceUser {
		return "", ParseUnsupported
	}
	content, status, _ := NormalizeAgentEnvelope(message.Content)
	return content, status
}

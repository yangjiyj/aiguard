package handler

import (
	"regexp"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
)

const protocolAgentDetectionConfidence = 0.98

var (
	trustedGeneratedAgentEnvelopePattern = regexp.MustCompile(`(?is)^\s*(<system-reminder\b[^>]*\bdata-role\s*=\s*(?:"user-context"|'user-context')[^>]*>.*?</system-reminder>)\s*<user_query\b[^>]*>.*?</user_query>\s*$`)
	trustedGeneratedUserInfoPattern      = regexp.MustCompile(`(?is)<user_info(?:\s[^>]*)?>.*?</user_info>`)
)

func refineChatAgentAttribution(info *auth.AuthInfo, messages []Message) {
	if info == nil || !isGenericAgentIdentity(info.AgentType) {
		return
	}
	for _, message := range messages {
		if strings.EqualFold(message.Role, "user") {
			if product := agentdetect.InferFromProductEnvelope(messageText(message.Content)); product != "" {
				info.AgentType, info.AgentDetectionSource, info.AgentDetectionConfidence = product, "product_identity", protocolAgentDetectionConfidence
				return
			}
		}
	}
	if inferred := inferAgentTypeFromProtocolMessages(messages); inferred != "" {
		info.AgentType = inferred
		info.AgentDetectionSource = "message_protocol"
		info.AgentDetectionConfidence = protocolAgentDetectionConfidence
	}
}

func isGenericAgentIdentity(value string) bool {
	return agentdetect.IsGenericAgentIdentity(value)
}

func inferAgentTypeFromProtocolMessages(messages []Message) string {
	// Product-owned context is evaluated before generic system prose.
	for _, message := range messages {
		if strings.EqualFold(message.Role, "user") {
			if product := agentdetect.InferFromProductEnvelope(messageText(message.Content)); product != "" {
				return product
			}
		}
	}
	for _, message := range messages {
		role := strings.ToLower(strings.TrimSpace(message.Role))
		content := messageText(message.Content)
		if content == "" {
			continue
		}
		if role == "system" || role == "developer" {
			if inferred := agentdetect.InferFromTrustedText(content); inferred != "" {
				return inferred
			}
			continue
		}
		if role != "user" {
			continue
		}
		context, ok := trustedGeneratedAgentUserContext(content)
		if !ok {
			continue
		}
		if inferred := agentdetect.InferFromTrustedText(context); inferred != "" {
			return inferred
		}
	}
	return ""
}

func trustedGeneratedAgentUserContext(content string) (string, bool) {
	match := trustedGeneratedAgentEnvelopePattern.FindStringSubmatch(strings.TrimSpace(content))
	if len(match) != 2 || !trustedGeneratedUserInfoPattern.MatchString(match[1]) {
		return "", false
	}
	return match[1], true
}

package agentdetect

import (
	"regexp"
	"strings"
)

var productEnvelope = regexp.MustCompile(`(?s)^\s*<system-reminder\s+data-role=["']user-context["']>\s*(.*?)</system-reminder>\s*<user_query>.*?</user_query>\s*$`)
var productIdentity = regexp.MustCompile(`(?s)<product_identity>\s*(.*?)\s*</product_identity>`)
var productUserInfo = regexp.MustCompile(`(?s)<user_info>.*?</user_info>`)

// A dedicated product_identity field outranks incidental product names in memory,
// documentation, skills and workspace rules. Only inspect the generated envelope,
// never the human query, a tool result or assistant text.
func InferFromProductEnvelope(text string) string {
	m := productEnvelope.FindStringSubmatch(strings.TrimSpace(text))
	if len(m) != 2 || !productUserInfo.MatchString(m[1]) {
		return ""
	}
	fields := productIdentity.FindAllStringSubmatch(m[1], -1)
	if len(fields) != 1 {
		return ""
	}
	return InferFromTrustedText(fields[0][1])
}

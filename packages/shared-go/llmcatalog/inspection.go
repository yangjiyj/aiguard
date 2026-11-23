package llmcatalog

import "github.com/yangjiyj/aiguard/packages/shared-go/aiadapters"

// IsTelemetry uses catalog host/path rules. Body words such as "histogram" or
// "telemetry" are never sufficient to exempt a dialogue request.
func IsTelemetry(host, path string) bool {
	entry, ok := aiadapters.MatchCatalog(host, path)
	return ok && entry.RequestDecoder == "telemetry"
}

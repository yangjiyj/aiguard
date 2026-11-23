package repository

import "fmt"

// requestCapacityOnlyEventCondition recognizes the legacy proxy body-size guard
// without suppressing any co-occurring real finding or changing original evidence.
func requestCapacityOnlyEventCondition(alias string) string {
	findings := fmt.Sprintf("CASE WHEN jsonb_typeof(%s.matched_summary->'findings') = 'array' THEN %s.matched_summary->'findings' ELSE '[]'::jsonb END", alias, alias)
	return fmt.Sprintf(`(jsonb_array_length(%s) > 0 AND NOT EXISTS (
 SELECT 1 FROM jsonb_array_elements(%s) capacity_finding
 WHERE COALESCE(capacity_finding->>'category', '') NOT IN ('file_content_request_oversized', 'request_body_limit_exceeded')
 ))`, findings, findings)
}

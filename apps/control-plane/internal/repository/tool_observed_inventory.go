package repository

import (
	"context"
	"fmt"
	"time"
)

const ObservedToolInventoryLimit = 200

// ObservedTool contains only lifecycle metadata, never arguments, results or
// targets. Counts are observed events, not proof of completed tool execution.
type ObservedTool struct {
	ToolName                string    `json:"tool_name"`
	ToolTypes               []string  `json:"tool_types"`
	RuntimeToolType         string    `json:"runtime_tool_type"`
	RuntimeTypeSource       string    `json:"runtime_type_source"`
	MCPGatewayObserved      bool      `json:"mcp_gateway_observed"`
	DefinitionExposedCount  int64     `json:"definition_exposed_count"`
	InvocationProposedCount int64     `json:"invocation_proposed_count"`
	ExecutionForwardedCount int64     `json:"execution_forwarded_count"`
	ResultObservedCount     int64     `json:"result_observed_count"`
	UnknownEventCount       int64     `json:"unknown_event_count"`
	EventCount              int64     `json:"event_count"`
	LastSeen                time.Time `json:"last_seen"`
}

func (r *ToolCallLogRepository) GetObservedTools(ctx context.Context, tenantID string, start, end time.Time) ([]ObservedTool, bool, error) {
	if tenantID == "" || !end.After(start) || end.Sub(start) > 7*24*time.Hour {
		return nil, false, fmt.Errorf("tenant_id and a window of at most seven days are required")
	}
	query := `WITH observations AS (
		SELECT tcl.tool_name, COALESCE(NULLIF(tcl.tool_type,''),'unknown') AS tool_type,
		       ` + riskOverviewEventKindSQL + ` AS event_kind,
		       tcl.execution_observed, tcl.result_observed, tcl.created_at,
		       COALESCE(tcl.provenance='mcp_gateway' AND tcl.protocol='mcp',FALSE) AS mcp_gateway_observed
		FROM tool_call_logs tcl
		WHERE tcl.tenant_id=$1 AND tcl.created_at >= $2 AND tcl.created_at < $3
		  AND tcl.tool_name <> ''
	)
	SELECT tool_name, ARRAY_AGG(DISTINCT tool_type ORDER BY tool_type),
	 COUNT(*) FILTER (WHERE event_kind='definition_exposed'),
	 COUNT(*) FILTER (WHERE event_kind='invocation_proposed'),
	 COUNT(*) FILTER (WHERE event_kind='execution_forwarded' AND execution_observed),
	 COUNT(*) FILTER (WHERE event_kind='result_observed' AND result_observed),
	 COUNT(*) FILTER (WHERE event_kind='legacy_unknown'), COUNT(*), MAX(created_at), BOOL_AND(mcp_gateway_observed)
	FROM observations GROUP BY tool_name ORDER BY MAX(created_at) DESC, tool_name ASC LIMIT $4`
	rows, err := r.db.Query(ctx, query, tenantID, start, end, ObservedToolInventoryLimit+1)
	if err != nil {
		return nil, false, fmt.Errorf("query observed tool inventory: %w", err)
	}
	defer rows.Close()
	items := []ObservedTool{}
	for rows.Next() {
		var item ObservedTool
		if err := rows.Scan(&item.ToolName, &item.ToolTypes, &item.DefinitionExposedCount, &item.InvocationProposedCount, &item.ExecutionForwardedCount, &item.ResultObservedCount, &item.UnknownEventCount, &item.EventCount, &item.LastSeen, &item.MCPGatewayObserved); err != nil {
			return nil, false, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(items) > ObservedToolInventoryLimit
	if truncated {
		items = items[:ObservedToolInventoryLimit]
	}
	return items, truncated, nil
}

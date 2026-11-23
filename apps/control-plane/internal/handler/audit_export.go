package handler

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// ExportAuditLogs exports request logs filtered by security action
func ExportAuditLogs(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session == nil {
			writeUnauthorized(w, "not authenticated")
			return
		}

		// Parse query parameters
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "json"
		}
		if format != "json" && format != "csv" {
			writeError(w, "invalid_request", "format must be json or csv")
			return
		}

		action := r.URL.Query().Get("action")
		// action is optional; empty string means export all actions

		// Parse time range (default: last 7 days)
		endTime := time.Now()
		startTime := endTime.AddDate(0, 0, -7)
		if s := r.URL.Query().Get("start_time"); s != "" {
			if parsed, err := time.Parse(time.RFC3339, s); err == nil {
				startTime = parsed
			}
		}
		if e := r.URL.Query().Get("end_time"); e != "" {
			if parsed, err := time.Parse(time.RFC3339, e); err == nil {
				endTime = parsed
			}
		}

		// Query logs (limit 1000 for export)
		logs, total, err := deps.RequestLogRepo.ListByAuditAction(r.Context(), session.TenantID, action, startTime, endTime, 1000, 0)
		if err != nil {
			writeError(w, "internal_error", "failed to query audit logs")
			return
		}

		actionLabel := action
		if actionLabel == "" {
			actionLabel = "all"
		}
		filename := fmt.Sprintf("audit_export_%s_%s_%s", actionLabel, startTime.Format("20060102"), endTime.Format("20060102"))

		if format == "csv" {
			exportAuditLogsCSV(w, logs, filename)
		} else {
			// 审计结果里的命中原文（2.9.22 起入库）只导给有内容证据权限的角色。
			exportAuditLogsJSON(w, logs, total, filename, canReadFullTenantContentEvidence(auth.GetUser(r.Context())))
		}
	}
}

func exportAuditLogsCSV(w http.ResponseWriter, logs []*repository.RequestLog, filename string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", filename))

	writer := csv.NewWriter(w)
	// Write header
	header := []string{"request_id", "user_id", "model_id", "request_status", "input_tokens", "output_tokens", "total_cost", "created_at", "input_action", "input_rule_ids", "output_action", "output_rule_ids"}
	writer.Write(header)

	for _, log := range logs {
		inputAction := ""
		inputRuleIDs := ""
		if log.InputAuditResult != nil {
			if a, ok := log.InputAuditResult["action_taken"].(string); ok {
				inputAction = a
			}
			if ids, ok := log.InputAuditResult["matched_rule_ids"].([]interface{}); ok {
				for _, id := range ids {
					if s, ok := id.(string); ok {
						if inputRuleIDs != "" {
							inputRuleIDs += ","
						}
						inputRuleIDs += s
					}
				}
			}
		}

		outputAction := ""
		outputRuleIDs := ""
		if log.OutputAuditResult != nil {
			if a, ok := log.OutputAuditResult["action_taken"].(string); ok {
				outputAction = a
			}
			if ids, ok := log.OutputAuditResult["matched_rule_ids"].([]interface{}); ok {
				for _, id := range ids {
					if s, ok := id.(string); ok {
						if outputRuleIDs != "" {
							outputRuleIDs += ","
						}
						outputRuleIDs += s
					}
				}
			}
		}

		row := []string{
			log.RequestID,
			log.UserID,
			log.ModelID,
			log.RequestStatus,
			fmt.Sprintf("%d", log.InputTokens),
			fmt.Sprintf("%d", log.OutputTokens),
			fmt.Sprintf("%.6f", log.TotalCost),
			log.CreatedAt.Format(time.RFC3339),
			inputAction,
			inputRuleIDs,
			outputAction,
			outputRuleIDs,
		}
		writer.Write(row)
	}
	writer.Flush()
}

func exportAuditLogsJSON(w http.ResponseWriter, logs []*repository.RequestLog, total int, filename string, canReadEvidence bool) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.json", filename))

	// Build export data
	exportData := make([]map[string]interface{}, len(logs))
	for i, log := range logs {
		exportData[i] = map[string]interface{}{
			"request_id":          log.RequestID,
			"user_id":             log.UserID,
			"model_id":            log.ModelID,
			"request_status":      log.RequestStatus,
			"input_tokens":        log.InputTokens,
			"output_tokens":       log.OutputTokens,
			"total_cost":          log.TotalCost,
			"created_at":          log.CreatedAt.Format(time.RFC3339),
			"input_audit_result":  summaryForViewer(log.InputAuditResult, canReadEvidence),
			"output_audit_result": summaryForViewer(log.OutputAuditResult, canReadEvidence),
		}
	}

	resp := map[string]interface{}{
		"data":        exportData,
		"total":       total,
		"exported":    len(logs),
		"exported_at": time.Now().Format(time.RFC3339),
	}
	json.NewEncoder(w).Encode(resp)
}

package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/endpointevents"

	"github.com/jackc/pgx/v5"
)

const maxAgentEventBatchSize = 200

type AgentEventBatchRequest struct {
	SchemaVersion string            `json:"schema_version"`
	EndpointID    string            `json:"endpoint_id"`
	HookdVersion  string            `json:"hookd_version"`
	SentAt        string            `json:"sent_at"`
	Events        []json.RawMessage `json:"events"`
}

type AgentEventBatchResult struct {
	Accepted   []string `json:"accepted"`
	Duplicates []string `json:"duplicates"`
	Rejected   []string `json:"rejected"`
	// Rejections carries the reason per rejected id. hookd a0296bf6 only reads rejected[] (ids)
	// and ignores unknown fields, so the reason lives beside it instead of inside it.
	Rejections []AgentEventRejection `json:"rejections"`
}

type AgentEventRejection struct {
	EventID string `json:"event_id"`
	Code    string `json:"code"`
}

func (r *AgentEventBatchResult) reject(eventID, code string) {
	r.Rejected = append(r.Rejected, eventID)
	r.Rejections = append(r.Rejections, AgentEventRejection{EventID: eventID, Code: code})
}

type AgentEventBatchError struct {
	Code     string
	EventIDs []string
	Err      error
}

func (e *AgentEventBatchError) Error() string {
	if e == nil || e.Err == nil {
		return "agent event batch failed"
	}
	return e.Err.Error()
}

func (e *AgentEventBatchError) Unwrap() error { return e.Err }

type agentEventRecord struct {
	EndpointID                                                string
	Native                                                    map[string]any
	HasResult                                                 bool
	Assets                                                    []*agentEventAsset
	ID, EventType, SessionID, PromptID, ToolUseID, ToolCallID string
	ToolName, ToolType, MCPServer, Status, Result             string
	InstanceKey                                               string
	UnifiedNativeID                                           string
	ArgumentsHash, ResultHash                                 string
	ResultLength                                              int
	HasResultLength                                           bool
	ResultSuccess, HasResultSuccess                           bool
	Severity, RiskLevel, Decision                             string
	OccurredAt                                                time.Time
	Payload, LocalDecision, ServerDecision                    []byte
	Asset                                                     *agentEventAsset
}

type agentEventAsset struct {
	AssetType, Name, Version, Source, Hash, ScanStatus, ScanDecision string
	Evidence                                                         []byte
	Present                                                          bool
}

func agentEventString(values ...any) string {
	for _, value := range values {
		if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func agentEventMap(value any) map[string]any {
	m, _ := value.(map[string]any)
	return m
}

func agentEventDecision(event, payload, local, server map[string]any) string {
	// An effective decision must never be masked by a higher-priority source's
	// raw decision (e.g. raw=block but effective=would_block).
	for _, field := range []string{"effective_decision", "decision", "raw_decision"} {
		for _, source := range []map[string]any{server, local, event, payload} {
			if decision := agentEventString(source[field]); decision != "" {
				return strings.ToLower(decision)
			}
		}
	}
	return ""
}

func decodeAgentEvent(raw json.RawMessage, endpoint string) (*agentEventRecord, error) {
	event, err := endpointevents.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("decode event: %w", err)
	}
	if endpointevents.IsNested(event) {
		return decodeNestedAgentEvent(event, endpoint)
	}
	id := agentEventString(event["event_id"])
	typ := agentEventString(event["event_type"])
	occurredRaw := agentEventString(event["occurred_at"])
	if id == "" || len(id) > 256 || typ == "" || occurredRaw == "" {
		return nil, fmt.Errorf("event_id, event_type and occurred_at are required")
	}
	if supplied := agentEventString(event["endpoint_id"]); supplied != "" && supplied != endpoint {
		return nil, fmt.Errorf("event endpoint_id does not match authenticated endpoint")
	}
	if sid, _ := event["session_id"].(string); agentEventPlaceholderSessionID(sid) {
		return nil, fmt.Errorf("session_id %q is a placeholder, not a session identity: %w", sid, errAgentEventInvalidSession)
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, occurredRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid occurred_at: %w", err)
	}
	now := time.Now().UTC()
	if occurredAt.Before(now.Add(-30*24*time.Hour)) || occurredAt.After(now.Add(24*time.Hour)) {
		return nil, fmt.Errorf("occurred_at outside accepted window")
	}
	payload := agentEventMap(event["payload"])
	local := agentEventMap(event["local_decision"])
	server := agentEventMap(event["server_decision"])
	tool := agentEventMap(event["tool"])
	if tool == nil {
		tool = agentEventMap(payload["tool"])
	}
	canonical, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("encode event: %w", err)
	}
	localJSON, err := json.Marshal(local)
	if err != nil {
		return nil, err
	}
	serverJSON, err := json.Marshal(server)
	if err != nil {
		return nil, err
	}
	record := &agentEventRecord{
		ID: id, EventType: typ, OccurredAt: occurredAt.UTC(), Payload: canonical, EndpointID: endpoint,
		SessionID: agentEventString(event["session_id"]), PromptID: agentEventString(event["prompt_id"]),
		ToolUseID:  agentEventString(event["tool_use_id"], payload["tool_use_id"]),
		ToolCallID: agentEventString(event["tool_call_id"], payload["tool_call_id"], event["tool_use_id"], payload["tool_use_id"]),
		ToolName:   agentEventString(event["tool_name"], payload["tool_name"]),
		ToolType:   agentEventString(event["tool_type"], payload["tool_type"]),
		MCPServer:  agentEventString(event["mcp_server"], payload["mcp_server"]),
		Status:     agentEventString(event["status"], payload["status"]), Result: agentEventString(event["result"], payload["result"]),
		Severity:      strings.ToLower(agentEventString(event["severity"], payload["severity"], local["severity"], server["severity"])),
		RiskLevel:     strings.ToLower(agentEventString(event["risk_level"], payload["risk_level"], local["risk_level"], server["risk_level"])),
		LocalDecision: localJSON, ServerDecision: serverJSON,
	}
	record.ArgumentsHash = agentEventString(event["arguments_hash"], event["args_hash"], payload["arguments_hash"], payload["args_hash"], tool["args_hash"])
	result := agentEventMap(tool["result"])
	if result == nil {
		result = agentEventMap(event["result_metadata"])
	}
	if result == nil {
		result = agentEventMap(payload["result_metadata"])
	}
	record.ResultHash = agentEventString(result["hash"], event["result_hash"], payload["result_hash"])
	record.ResultLength, record.HasResultLength = agentEventInt(result["len"], event["result_length"], payload["result_length"])
	if success, ok := result["success"].(bool); ok {
		record.ResultSuccess, record.HasResultSuccess = success, true
	}
	record.Decision = agentEventDecision(event, payload, local, server)
	assetType := agentEventString(event["asset_type"], payload["asset_type"])
	assetName := agentEventString(event["asset_name"], payload["asset_name"])
	assetHash := agentEventString(event["asset_hash"], payload["asset_hash"])
	present, presentOK := event["asset_present"].(bool)
	if !presentOK {
		present, presentOK = payload["asset_present"].(bool)
	}
	if assetType != "" || assetName != "" || assetHash != "" || presentOK {
		if assetType == "" || assetName == "" || assetHash == "" || !presentOK {
			return nil, fmt.Errorf("asset_type, asset_name, asset_hash and asset_present must be supplied together")
		}
		evidence := agentEventMap(event["asset_evidence"])
		if evidence == nil {
			evidence = agentEventMap(payload["asset_evidence"])
		}
		evidenceJSON, marshalErr := json.Marshal(evidence)
		if marshalErr != nil {
			return nil, marshalErr
		}
		record.Asset = &agentEventAsset{
			AssetType: assetType, Name: assetName, Hash: assetHash, Present: present,
			Version:      agentEventString(event["asset_version"], payload["asset_version"]),
			Source:       agentEventString(event["asset_source"], payload["asset_source"]),
			ScanStatus:   agentEventString(event["scan_status"], payload["scan_status"]),
			ScanDecision: agentEventString(event["scan_decision"], payload["scan_decision"]), Evidence: evidenceJSON,
		}
	}
	return record, nil
}

func agentEventInt(values ...any) (int, bool) {
	maxInt := int64(^uint(0) >> 1)
	for _, value := range values {
		switch number := value.(type) {
		case float64:
			if number < 0 || number > float64(maxInt) || number != float64(int(number)) {
				return -1, true
			}
			return int(number), true
		case int:
			if number < 0 {
				return -1, true
			}
			return number, true
		case json.Number:
			parsed, err := strconv.ParseInt(string(number), 10, 64)
			if err != nil || parsed < 0 || parsed > maxInt {
				return -1, true
			}
			return int(parsed), true
		}
	}
	return 0, false
}

func deterministicAgentID(prefix string, values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x1f")))
	return prefix + hex.EncodeToString(sum[:16])
}

func agentEventBlocked(decision, status string) bool {
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "block", "blocked", "deny", "denied":
		return true
	}
	return strings.EqualFold(strings.TrimSpace(status), "blocked")
}

func agentEventSeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	default:
		return 0 // low 或空
	}
}

func normalizeSeverity(s string) string {
	switch agentEventSeverityRank(s) {
	case 3:
		return "critical"
	case 2:
		return "high"
	case 1:
		return "medium"
	default:
		return "low"
	}
}

// maxSeverity 取二者较高档；低 severity 不得掩盖高风险。
func agentEventMaxSeverity(a, b string) string {
	if agentEventSeverityRank(a) >= agentEventSeverityRank(b) {
		return normalizeSeverity(a)
	}
	return normalizeSeverity(b)
}

// agentEventIsBlockDecision 仅按有效决策判断阻断（block/blocked/deny/denied）。
// 注意：不参考工具 status——status=blocked 但有效决策为 allow 时不应判定为阻断告警。
func agentEventIsBlockDecision(d string) bool {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "block", "blocked", "deny", "denied":
		return true
	}
	return false
}

// agentEventSecurityEventDecision 决定端点事件是否写入 security_events 并接入既有告警聚合。
// 触发条件（P0-2 规格 + 修正"合并 severity 触发"与"误用工具 status 触发"两处越界）：
//   - would_block / would-block：无条件排除，仅计数（计数已在端点/会话计数器完成），不写 security_events。
//   - 有效决策为 block/blocked/deny/denied：写，action_taken=block，severity 至少 high。
//   - 有效决策为 confirm：写，action_taken=confirm，severity 至少 high（确保落入告警桥收件箱底线）。
//   - 否则仅当 risk_level 为 high/critical（且非 would_block）：写，action_taken=flag。
//   - 其它（低/中风险且无 block/confirm）：不写。
//
// 判定只看已解析的有效决策 record.Decision（agentEventDecision 已按 server>local>event>payload、
// effective_decision>decision>raw_decision 优先级解析），不参考工具 status。
// severity 取 authored 与 risk 的高者存储，确保低 authored severity 不掩盖高 risk；
// 但"是否告警"只取决于有效决策与 risk_level——authored severity 高但 risk 低且未阻断/确认时不得误告警。
func agentEventSecurityEventDecision(record *agentEventRecord) (severity, actionTaken string, shouldWrite bool) {
	decision := record.Decision
	severity = agentEventMaxSeverity(record.Severity, record.RiskLevel)
	switch {
	case decision == "would_block" || decision == "would-block":
		return severity, "", false
	case agentEventIsBlockDecision(decision):
		if agentEventSeverityRank(severity) < 2 {
			severity = "high"
		}
		return severity, "block", true
	case decision == "confirm":
		if agentEventSeverityRank(severity) < 2 {
			severity = "high"
		}
		return severity, "confirm", true
	case agentEventSeverityRank(record.RiskLevel) >= 2:
		return severity, "flag", true
	default:
		return severity, "", false
	}
}

// Acknowledgments echo the producer's ID; storage uses the canonical UUID.
func agentEventAckID(record *agentEventRecord) string {
	if record.Native != nil {
		return agentEventString(record.Native["event_id"])
	}
	return record.ID
}

func (r *AgentEndpointRepository) AcceptEventBatch(ctx context.Context, tenant, endpoint string, request AgentEventBatchRequest) (*AgentEventBatchResult, error) {
	result := &AgentEventBatchResult{Accepted: []string{}, Duplicates: []string{}, Rejected: []string{}, Rejections: []AgentEventRejection{}}
	if request.SchemaVersion != "events.v1" || len(request.Events) == 0 || len(request.Events) > maxAgentEventBatchSize {
		return nil, &AgentEventBatchError{Code: "invalid_batch", Err: fmt.Errorf("invalid event batch")}
	}
	records := make([]*agentEventRecord, 0, len(request.Events))
	allIDs := make([]string, 0, len(request.Events))
	for _, raw := range request.Events {
		var envelope map[string]any
		_ = json.Unmarshal(raw, &envelope)
		allIDs = append(allIDs, agentEventString(envelope["event_id"]))
	}
	for i, raw := range request.Events {
		record, err := decodeAgentEvent(raw, endpoint)
		if errors.Is(err, errAgentEventInvalidSession) {
			// Per-event rejection: hookd acks and drops it, the rest of the batch still lands.
			result.reject(allIDs[i], "invalid_session")
			continue
		}
		if err != nil {
			return nil, &AgentEventBatchError{Code: "invalid_event", EventIDs: allIDs, Err: err}
		}
		records = append(records, record)
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,858))`, tenant+"\x1f"+endpoint); err != nil {
		return nil, err
	}
	rejectedSessions := map[*agentEventRecord]bool{}
	for _, record := range records {
		var existingEndpoint string
		var samePayload bool
		err = tx.QueryRow(ctx, `SELECT endpoint_id,payload=$3::jsonb FROM agent_events WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, record.ID, record.Payload).Scan(&existingEndpoint, &samePayload)
		if err == nil {
			if existingEndpoint != endpoint || !samePayload {
				return nil, &AgentEventBatchError{Code: "event_conflict", EventIDs: allIDs, Err: fmt.Errorf("event_id %q conflicts with stored content", record.ID)}
			}
			result.Duplicates = append(result.Duplicates, agentEventAckID(record))
			continue
		}
		if err != pgx.ErrNoRows {
			return nil, err
		}
		if record.SessionID != "" {
			foreign, ownErr := agentSessionOwnedElsewhere(ctx, tx, tenant, endpoint, record.SessionID)
			if ownErr != nil {
				return nil, ownErr
			}
			if foreign {
				// Checked before any write, so the rejected event leaves no row or projection.
				result.reject(agentEventAckID(record), "session_ownership_conflict")
				rejectedSessions[record] = true
				continue
			}
		}
		severity := record.Severity
		if severity == "" {
			severity = record.RiskLevel
		}
		if severity == "" {
			severity = "low"
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_events(
			id,tenant_id,endpoint_id,session_id,prompt_id,tool_use_id,event_type,occurred_at,
			tool_name,tool_type,mcp_server,payload,local_decision,server_decision,severity)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb,$14::jsonb,$15)`,
			record.ID, tenant, endpoint, record.SessionID, record.PromptID, record.ToolUseID, record.EventType,
			record.OccurredAt, record.ToolName, record.ToolType, record.MCPServer, record.Payload,
			record.LocalDecision, record.ServerDecision, severity)
		if err != nil {
			return nil, fmt.Errorf("insert agent event %s: %w", record.ID, err)
		}
		if record.SessionID != "" {
			if err = upsertAgentSessionEvent(ctx, tx, tenant, endpoint, record); err != nil {
				if errors.Is(err, errAgentSessionOwnershipConflict) {
					// Lost a race with another endpoint creating this session after the pre-check.
					// 4xx, nothing committed; hookd resends and the pre-check then rejects per event.
					return nil, &AgentEventBatchError{Code: "session_ownership_conflict", EventIDs: allIDs, Err: err}
				}
				return nil, err
			}
		}
		if record.Native != nil && record.SessionID != "" {
			if err = upsertNestedSessionMetadata(ctx, tx, tenant, endpoint, record); err != nil {
				return nil, err
			}
		}
		if record.SessionID != "" && record.PromptID != "" {
			if err = upsertAgentTurnEvent(ctx, tx, tenant, record); err != nil {
				return nil, err
			}
		}
		if record.Native != nil && record.SessionID != "" && record.PromptID != "" {
			if err = upsertNestedTurnMetadata(ctx, tx, tenant, record); err != nil {
				return nil, err
			}
		}
		toolLogID, toolErr := upsertAgentToolLifecycle(ctx, tx, tenant, record)
		if toolErr != nil {
			return nil, toolErr
		}
		if toolLogID != "" {
			if _, err = tx.Exec(ctx, `UPDATE agent_events SET tool_call_log_id=$3 WHERE tenant_id=$1 AND id=$2`, tenant, record.ID, toolLogID); err != nil {
				return nil, fmt.Errorf("link tool call log: %w", err)
			}
			if record.EventType == "tool.post" || record.EventType == "tool.failure" || record.EventType == "tool.denied" {
				if err = attachT16TerminalFromAcceptedEvent(ctx, tx, tenant, endpoint, record.ID, toolLogID); err != nil {
					return nil, fmt.Errorf("attach endpoint intent result: %w", err)
				}
			}
		}
		assets := record.Assets
		if record.Asset != nil {
			assets = append(assets, record.Asset)
		}
		for _, asset := range assets {
			projection := *record
			projection.Asset = asset
			if err = upsertAgentEndpointAsset(ctx, tx, tenant, endpoint, &projection); err != nil {
				return nil, err
			}
		}
		if severity, actionTaken, shouldWrite := agentEventSecurityEventDecision(record); shouldWrite {
			if err = insertAgentSecurityEvent(ctx, tx, tenant, endpoint, severity, actionTaken, record); err != nil {
				return nil, err
			}
		}
		result.Accepted = append(result.Accepted, agentEventAckID(record))
	}
	if len(result.Accepted) > 0 {
		if _, err = tx.Exec(ctx, `UPDATE agent_endpoints SET
			last_event_at=GREATEST(COALESCE(last_event_at,to_timestamp(0)),(SELECT max(occurred_at) FROM agent_events WHERE tenant_id=$1 AND endpoint_id=$2)),
			event_count=(SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND endpoint_id=$2),
			tool_call_count=(SELECT count(DISTINCT (session_id,COALESCE(NULLIF(payload->>'tool_call_id',''),NULLIF(tool_use_id,'')))) FROM agent_events WHERE tenant_id=$1 AND endpoint_id=$2 AND event_type IN ('tool.pre','tool.post','tool.failure','tool.denied') AND COALESCE(NULLIF(payload->>'tool_call_id',''),NULLIF(tool_use_id,'')) IS NOT NULL),
			blocked_count=(SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND endpoint_id=$2 AND (COALESCE(server_decision->>'effective_decision',local_decision->>'effective_decision',payload->>'decision','') IN ('block','blocked','deny','denied') OR payload->>'status'='blocked' OR event_type='tool.denied')),
			would_block_count=(SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND endpoint_id=$2 AND COALESCE(server_decision->>'effective_decision',local_decision->>'effective_decision',payload->>'decision','') IN ('would_block','would-block')),
			updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, endpoint); err != nil {
			return nil, fmt.Errorf("update endpoint counters: %w", err)
		}
		sessions := map[string]struct{}{}
		for _, record := range records {
			if record.SessionID != "" && !rejectedSessions[record] {
				sessions[record.SessionID] = struct{}{}
			}
		}
		for sessionID := range sessions {
			if err = refreshAgentSessionCounters(ctx, tx, tenant, sessionID); err != nil {
				return nil, err
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

// errAgentSessionOwnershipConflict: the session id is already owned by another tenant or endpoint.
var errAgentSessionOwnershipConflict = errors.New("belongs to another tenant or endpoint")

// agentSessionOwnedElsewhere mirrors the ownership guard of upsertAgentSessionEvent without writing.
func agentSessionOwnedElsewhere(ctx context.Context, tx pgx.Tx, tenant, endpoint, sessionID string) (bool, error) {
	var foreign bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_sessions WHERE session_id=$1
		AND NOT (tenant_id=$2 AND (endpoint_id IS NULL OR endpoint_id=$3)))`, sessionID, tenant, endpoint).Scan(&foreign)
	if err != nil {
		return false, fmt.Errorf("check agent session owner: %w", err)
	}
	return foreign, nil
}

func upsertAgentSessionEvent(ctx context.Context, tx pgx.Tx, tenant, endpoint string, record *agentEventRecord) error {
	id := deterministicAgentID("as_", tenant, record.SessionID)
	var storedID string
	err := tx.QueryRow(ctx, `INSERT INTO agent_sessions(
		id,tenant_id,session_id,endpoint_id,source,status,started_at,first_request_at,last_request_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,'endpoint_hook','active',$5,$5,$5,now(),now())
		ON CONFLICT(session_id) DO UPDATE SET
			endpoint_id=COALESCE(agent_sessions.endpoint_id,EXCLUDED.endpoint_id),
			started_at=LEAST(COALESCE(agent_sessions.started_at,EXCLUDED.started_at),EXCLUDED.started_at),
			first_request_at=LEAST(COALESCE(agent_sessions.first_request_at,EXCLUDED.first_request_at),EXCLUDED.first_request_at),
			last_request_at=GREATEST(COALESCE(agent_sessions.last_request_at,EXCLUDED.last_request_at),EXCLUDED.last_request_at),updated_at=now()
		WHERE agent_sessions.tenant_id=EXCLUDED.tenant_id AND (agent_sessions.endpoint_id IS NULL OR agent_sessions.endpoint_id=EXCLUDED.endpoint_id)
		RETURNING id`, id, tenant, record.SessionID, endpoint, record.OccurredAt).Scan(&storedID)
	if err == pgx.ErrNoRows {
		return fmt.Errorf("session %q: %w", record.SessionID, errAgentSessionOwnershipConflict)
	}
	if err != nil {
		return fmt.Errorf("upsert agent session: %w", err)
	}
	return nil
}

func upsertAgentTurnEvent(ctx context.Context, tx pgx.Tx, tenant string, record *agentEventRecord) error {
	id := deterministicAgentID("at_", tenant, record.SessionID, record.PromptID)
	var storedID string
	err := tx.QueryRow(ctx, `INSERT INTO agent_turns(id,tenant_id,session_id,prompt_id,started_at)
		VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(session_id,prompt_id) DO UPDATE SET started_at=LEAST(COALESCE(agent_turns.started_at,EXCLUDED.started_at),EXCLUDED.started_at)
		WHERE agent_turns.tenant_id=EXCLUDED.tenant_id RETURNING id`, id, tenant, record.SessionID, record.PromptID, record.OccurredAt).Scan(&storedID)
	if err == pgx.ErrNoRows {
		return fmt.Errorf("turn belongs to another tenant")
	}
	if err != nil {
		return fmt.Errorf("upsert agent turn: %w", err)
	}
	return nil
}

// agentToolLifecycleFacts distinguishes an observed completion from a supplied
// result body. Late proposal events cannot downgrade either fact during the merge.
func agentToolLifecycleFacts(record *agentEventRecord) (string, bool, bool) {
	if record.EventType != "tool.post" && record.EventType != "tool.failure" {
		return "invocation_proposed", false, false
	}
	if record.Native == nil || record.HasResult {
		return "result_observed", true, true
	}
	return "execution_forwarded", true, false
}

func endpointToolLifecycleIdentity(tenant, endpoint, session, toolCallID string) string {
	return strings.Join([]string{tenant, endpoint, session, toolCallID}, string(rune(31)))
}

// lockEndpointToolLifecycleIdentity serializes decide proposals and /events
// projections on the same authenticated endpoint, session, and tool call tuple.
func lockEndpointToolLifecycleIdentity(ctx context.Context, tx pgx.Tx, tenant, endpoint, session, toolCallID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,854))`, endpointToolLifecycleIdentity(tenant, endpoint, session, toolCallID))
	return err
}

// UpsertEndpointToolProposal merges an authenticated /decide audit with the
// matching endpoint-hook event row. A proposal is never execution or result
// evidence; the identity lock is shared with /events ingestion.
func (r *ToolCallLogRepository) UpsertEndpointToolProposal(ctx context.Context, log *ToolCallLog) error {
	if log == nil || strings.TrimSpace(log.TenantID) == "" || strings.TrimSpace(log.EndpointID) == "" || strings.TrimSpace(log.SessionID) == "" || strings.TrimSpace(log.ToolCallID) == "" {
		return fmt.Errorf("tenant_id, endpoint_id, session_id, and tool_call_id are required")
	}
	if log.AttributionMode != "endpoint_hook" || log.Provenance != "agent_endpoint" || log.EventKind != "invocation_proposed" || log.ExecutionObserved || log.ResultObserved || log.ExecutionForwarded {
		return fmt.Errorf("invalid endpoint proposal lifecycle facts")
	}
	log.RequestID = ""
	if log.Status == "" {
		log.Status = "audited"
	}
	if log.Status != "audited" && log.Status != "blocked" {
		return fmt.Errorf("invalid endpoint proposal status %q", log.Status)
	}
	if log.Parameters == nil {
		log.Parameters = map[string]interface{}{}
	}
	parametersJSON, err := json.Marshal(log.Parameters)
	if err != nil {
		return fmt.Errorf("marshal endpoint proposal parameters: %w", err)
	}
	paramsPresent := len(log.Parameters) > 0

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin endpoint proposal upsert: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockEndpointToolLifecycleIdentity(ctx, tx, log.TenantID, log.EndpointID, log.SessionID, log.ToolCallID); err != nil {
		return fmt.Errorf("lock endpoint proposal identity: %w", err)
	}

	var existingCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM tool_call_logs
		WHERE tenant_id=$1 AND endpoint_id=$2 AND COALESCE(session_id,'')=$3 AND tool_call_id=$4 AND attribution_mode='endpoint_hook'`,
		log.TenantID, log.EndpointID, log.SessionID, log.ToolCallID).Scan(&existingCount); err != nil {
		return fmt.Errorf("count endpoint proposal identity: %w", err)
	}

	var id string
	if existingCount == 0 {
		if log.ID == "" {
			log.ID = newToolCallLogID()
		}
		evidence, _, evidenceErr := prepareEndpointProposalEvidence(log, log.ID, nil, nil, false, true)
		if evidenceErr != nil {
			return fmt.Errorf("bind endpoint proposal evidence: %w", evidenceErr)
		}
		if evidence != nil {
			log.EvidenceJSON = evidence
		}
		query, args, buildErr := buildToolCallLogInsert(log)
		if buildErr != nil {
			return buildErr
		}
		if err := tx.QueryRow(ctx, query, args...).Scan(&id); err != nil {
			return fmt.Errorf("insert endpoint proposal: %w", err)
		}
		log.ID = id
	} else {
		var currentEvidence, currentParameters []byte
		var storedToolName, storedToolType string
		err = tx.QueryRow(ctx, `SELECT id,COALESCE(evidence_json,'[]'::jsonb)::text,COALESCE(parameters,'{}'::jsonb)::text,
				COALESCE(tool_name,''),COALESCE(tool_type,'')
			FROM tool_call_logs WHERE tenant_id=$1 AND endpoint_id=$2 AND COALESCE(session_id,'')=$3
				AND tool_call_id=$4 AND attribution_mode='endpoint_hook'
			ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE`,
			log.TenantID, log.EndpointID, log.SessionID, log.ToolCallID).Scan(&id, &currentEvidence, &currentParameters, &storedToolName, &storedToolType)
		if err != nil {
			return fmt.Errorf("find endpoint proposal identity: %w", err)
		}
		legacyRequestID := deterministicAgentID("aer_", log.TenantID, log.EndpointID, log.SessionID, log.ToolCallID)
		_, err = tx.Exec(ctx, `UPDATE tool_call_logs AS t SET
			tool_name=COALESCE(NULLIF(t.tool_name,''),NULLIF($8,''),t.tool_name),
			tool_type=COALESCE(NULLIF(t.tool_type,''),NULLIF($9,''),t.tool_type),
			risk_level=CASE
				WHEN LOWER(t.risk_level)='critical' OR LOWER($10)='critical' THEN 'critical'
				WHEN LOWER(t.risk_level)='high' OR LOWER($10)='high' THEN 'high'
				WHEN LOWER(t.risk_level)='medium' OR LOWER($10)='medium' THEN 'medium'
				WHEN LOWER(t.risk_level)='low' OR LOWER($10)='low' THEN 'low'
				WHEN NULLIF($10,'') IS NOT NULL THEN $10
				ELSE t.risk_level END,
			parameters=CASE WHEN $6 AND (t.parameters IS NULL OR t.parameters='{}'::jsonb) THEN $7::jsonb ELSE t.parameters END,
			raw_decision=COALESCE(NULLIF(t.raw_decision,''),NULLIF($11,'')),
			effective_decision=COALESCE(NULLIF(t.effective_decision,''),NULLIF($12,'')),
			mode=COALESCE(NULLIF(t.mode,''),NULLIF($13,'')),
			effective_reason=COALESCE(NULLIF(t.effective_reason,''),NULLIF($14,'')),
			policy_version=COALESCE(NULLIF(t.policy_version,''),NULLIF($15,'')),
			trace_id=COALESCE(NULLIF(t.trace_id,''),NULLIF($16,'')),
			request_id=CASE WHEN t.request_id=$18 THEN '' ELSE t.request_id END,
			status=CASE WHEN COALESCE(t.execution_observed,FALSE) OR COALESCE(t.result_observed,FALSE) OR t.event_kind IN ('execution_forwarded','result_observed') OR t.status IN ('blocked','failed') THEN t.status ELSE $17 END,
			event_kind=CASE WHEN COALESCE(t.execution_observed,FALSE) OR COALESCE(t.result_observed,FALSE) OR t.event_kind IN ('execution_forwarded','result_observed') THEN t.event_kind ELSE 'invocation_proposed' END,
			execution_observed=COALESCE(t.execution_observed,FALSE) OR FALSE,
			result_observed=COALESCE(t.result_observed,FALSE) OR FALSE,
			execution_forwarded=COALESCE(t.execution_forwarded,FALSE) OR FALSE,
			provenance=COALESCE(NULLIF(t.provenance,''),'agent_endpoint'),
			attribution_confidence=COALESCE(t.attribution_confidence,1)
			WHERE t.id=$1 AND t.tenant_id=$2 AND t.endpoint_id=$3 AND COALESCE(t.session_id,'')=$4 AND t.tool_call_id=$5 AND t.attribution_mode='endpoint_hook'`,
			id, log.TenantID, log.EndpointID, log.SessionID, log.ToolCallID, paramsPresent, string(parametersJSON),
			log.ToolName, log.ToolType, log.RiskLevel, log.RawDecision, log.EffectiveDecision, log.Mode,
			log.EffectiveReason, log.PolicyVersion, log.TraceID, log.Status, legacyRequestID)
		if err != nil {
			return fmt.Errorf("merge endpoint proposal: %w", err)
		}
		log.ID = id

		if existingCount == 1 {
			if storedToolName == "" {
				storedToolName = log.ToolName
			}
			if storedToolType == "" {
				storedToolType = log.ToolType
			}
			log.ToolName, log.ToolType = storedToolName, storedToolType
		}
		updatedEvidence, evidenceChanged, evidenceErr := prepareEndpointProposalEvidence(log, id, currentParameters, currentEvidence, true, existingCount == 1)
		if evidenceErr != nil {
			return fmt.Errorf("merge endpoint proposal evidence: %w", evidenceErr)
		}
		if evidenceChanged {
			if _, err := tx.Exec(ctx, `UPDATE tool_call_logs SET evidence_json=$1::jsonb WHERE id=$2 AND tenant_id=$3
				AND endpoint_id=$4 AND COALESCE(session_id,'')=$5 AND tool_call_id=$6 AND attribution_mode='endpoint_hook'`,
				updatedEvidence, id, log.TenantID, log.EndpointID, log.SessionID, log.ToolCallID); err != nil {
				return fmt.Errorf("update endpoint proposal evidence: %w", err)
			}
		}
	}

	if err := bindIntentTaskProposal(ctx, tx, log, id); err != nil {
		return fmt.Errorf("bind approved task step: %w", err)
	}
	if err := reconcileT16TerminalEventsForProposal(ctx, tx, log.TenantID, log.EndpointID, log.SessionID, id); err != nil {
		return fmt.Errorf("reconcile terminal endpoint events: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit endpoint proposal upsert: %w", err)
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	return nil
}

func upsertAgentToolLifecycle(ctx context.Context, tx pgx.Tx, tenant string, record *agentEventRecord) (string, error) {
	if (record.EventType != "tool.pre" && record.EventType != "tool.post" && record.EventType != "tool.failure" && record.EventType != "tool.denied") || record.ToolCallID == "" {
		return "", nil
	}
	if record.ToolUseID != "" && record.ToolCallID != "" && record.ToolUseID != record.ToolCallID {
		// Contradictory endpoint identities must not select or mutate a server log row.
		return "", nil
	}
	if err := lockEndpointToolLifecycleIdentity(ctx, tx, tenant, record.EndpointID, record.SessionID, record.ToolCallID); err != nil {
		return "", err
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM tool_call_logs WHERE tenant_id=$1 AND tool_call_id=$2 AND endpoint_id=$3 AND COALESCE(session_id,'')=$4 AND attribution_mode='endpoint_hook' ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE`, tenant, record.ToolCallID, record.EndpointID, record.SessionID).Scan(&id)
	kind, executionObserved, resultObserved := agentToolLifecycleFacts(record)
	status := record.Status
	if status == "" && agentEventBlocked(record.Decision, record.Status) {
		status = "blocked"
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE tool_call_logs SET
			tool_name=CASE WHEN $3<>'' THEN $3 ELSE tool_name END,
			tool_type=CASE WHEN $4<>'' THEN $4 ELSE tool_type END,
			session_id=COALESCE(NULLIF(session_id,''),NULLIF($5,'')),
			risk_level=CASE
                WHEN LOWER(risk_level)='critical' OR LOWER($6)='critical' THEN 'critical'
                WHEN LOWER(risk_level)='high' OR LOWER($6)='high' THEN 'high'
                WHEN LOWER(risk_level)='medium' OR LOWER($6)='medium' THEN 'medium'
                WHEN LOWER(risk_level)='low' OR LOWER($6)='low' THEN 'low'
                WHEN NULLIF($6,'') IS NOT NULL THEN $6
                ELSE risk_level END,
			result=CASE WHEN $7<>'' THEN $7 ELSE result END,
			status=CASE WHEN COALESCE(execution_observed,false) AND NOT $10 THEN status WHEN $8<>'' THEN $8 ELSE status END,
			event_kind=CASE WHEN $9='result_observed' OR event_kind IS NULL OR event_kind='' OR ($9='execution_forwarded' AND event_kind='invocation_proposed') THEN $9 ELSE event_kind END,
			execution_observed=COALESCE(execution_observed,false) OR $10,
			result_observed=COALESCE(result_observed,false) OR $11,
			attribution_confidence=COALESCE(attribution_confidence,1),
			request_id=CASE WHEN request_id=$12 THEN '' ELSE request_id END
			WHERE tenant_id=$1 AND id=$2`, tenant, id, record.ToolName, record.ToolType, record.SessionID,
			record.RiskLevel, record.Result, status, kind, executionObserved, resultObserved,
			deterministicAgentID("aer_", tenant, record.EndpointID, record.SessionID, record.ToolCallID))
		if err != nil {
			return "", fmt.Errorf("merge endpoint tool lifecycle: %w", err)
		}
		return id, nil
	}
	if err != pgx.ErrNoRows {
		return "", err
	}
	if record.ToolName == "" || record.ToolType == "" {
		return "", nil
	}
	id = deterministicAgentID("tc_", tenant, record.EndpointID, record.SessionID, record.ToolCallID)
	risk := record.RiskLevel
	if risk == "" {
		risk = "low"
	}
	if status == "" {
		status = "success"
	}
	_, err = tx.Exec(ctx, `INSERT INTO tool_call_logs(
		id,request_id,session_id,tenant_id,tool_name,tool_type,risk_level,parameters,result,status,
		event_kind,execution_observed,result_observed,tool_call_id,attribution_mode,attribution_confidence,provenance,created_at,endpoint_id)
		VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7,'{}'::jsonb,$8,$9,$10,$11,$12,$13,'endpoint_hook',1,'agent_endpoint',$14,$15)`,
		id, "", record.SessionID, tenant, record.ToolName, record.ToolType, risk, record.Result, status,
		kind, executionObserved, resultObserved, record.ToolCallID, record.OccurredAt, record.EndpointID)
	if err != nil {
		return "", fmt.Errorf("insert endpoint tool lifecycle: %w", err)
	}
	return id, nil
}

func upsertAgentEndpointAsset(ctx context.Context, tx pgx.Tx, tenant, endpoint string, record *agentEventRecord) error {
	if err := lockUnifiedAssetTenantWrite(ctx, tx, tenant); err != nil {
		return fmt.Errorf("lock unified asset tenant: %w", err)
	}
	asset := record.Asset
	id := deterministicAgentID("aea_", tenant, endpoint, asset.AssetType, asset.Name, asset.Hash)
	_, err := tx.Exec(ctx, `INSERT INTO agent_endpoint_assets(
		id,tenant_id,endpoint_id,asset_type,name,version,source,hash,evidence,first_seen,last_seen,present,scan_status,scan_decision)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$10,$11,$12,$13)
		ON CONFLICT(endpoint_id,asset_type,name,hash) DO UPDATE SET
			version=CASE WHEN EXCLUDED.version<>'' THEN EXCLUDED.version ELSE agent_endpoint_assets.version END,
			source=CASE WHEN EXCLUDED.source<>'' THEN EXCLUDED.source ELSE agent_endpoint_assets.source END,
			evidence=CASE WHEN EXCLUDED.evidence<>'{}'::jsonb THEN EXCLUDED.evidence ELSE agent_endpoint_assets.evidence END,
			first_seen=LEAST(agent_endpoint_assets.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(agent_endpoint_assets.last_seen,EXCLUDED.last_seen),
			present=EXCLUDED.present,
			scan_status=CASE WHEN EXCLUDED.scan_status<>'' THEN EXCLUDED.scan_status ELSE agent_endpoint_assets.scan_status END,
			scan_decision=CASE WHEN EXCLUDED.scan_decision<>'' THEN EXCLUDED.scan_decision ELSE agent_endpoint_assets.scan_decision END
		WHERE agent_endpoint_assets.tenant_id=EXCLUDED.tenant_id`, id, tenant, endpoint, asset.AssetType, asset.Name,
		asset.Version, asset.Source, asset.Hash, asset.Evidence, record.OccurredAt, asset.Present, asset.ScanStatus, asset.ScanDecision)
	if err != nil {
		return fmt.Errorf("upsert endpoint asset: %w", err)
	}
	if err := upsertUnifiedEndpointAsset(ctx, tx, tenant, endpoint, record); err != nil {
		return fmt.Errorf("upsert unified endpoint asset: %w", err)
	}
	return nil
}

// insertAgentSecurityEvent 在同事务内将端点风险/阻断事件写入 security_events，接入既有告警聚合
// （SecEventBridge）。agent_endpoint 源允许 request_id/project_id 为 NULL（迁移 859，不伪造请求/项目）；
// 端点身份、会话、工具元数据放入 matched_summary，读查询据此做源限定 SessionID 回退。
// 旧 agent_alerts 表（迁移 858 创建）按约定保留，但本路径不再写入。
func insertAgentSecurityEvent(ctx context.Context, tx pgx.Tx, tenant, endpoint, severity, actionTaken string, record *agentEventRecord) error {
	id := deterministicAgentID("ase_", tenant, record.ID)
	summary := map[string]any{
		"source":      "agent_endpoint",
		"endpoint_id": endpoint,
		"event_type":  record.EventType,
	}
	if record.SessionID != "" {
		summary["session_id"] = record.SessionID
	}
	if record.EventType == "tool.pre" || record.EventType == "tool.post" || record.EventType == "tool.failure" || record.EventType == "tool.denied" {
		summary["stage"] = "tool"
	}
	if record.ToolUseID != "" {
		summary["tool_use_id"] = record.ToolUseID
	}
	if record.ToolName != "" {
		summary["tool_name"] = record.ToolName
	}
	if record.MCPServer != "" {
		summary["mcp_server"] = record.MCPServer
	}
	if record.RiskLevel != "" {
		summary["risk_level"] = record.RiskLevel
	}
	if record.Decision != "" {
		summary["decision"] = record.Decision
	}
	// Keep the endpoint origin and observed event type even when the alert bridge
	// uses the existing tool-risk lifecycle for the security event projection.
	summary["server_id"] = endpoint
	summary["raw_decision"] = record.Decision
	summary["agent_event_id"] = record.ID
	summary["occurred_at"] = record.OccurredAt.Format(time.RFC3339)
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	// Endpoint events must retain their actual kind; only tool events may use
	// the tool_execution_risk bridge lifecycle.
	securityType := "agent_endpoint_risk"
	if record.EventType == "tool.pre" || record.EventType == "tool.post" || record.EventType == "tool.failure" || record.EventType == "tool.denied" {
		securityType = "tool_execution_risk"
	}
	_, err = tx.Exec(ctx, `INSERT INTO security_events(
		id, request_id, tenant_id, project_id, user_id, event_type, severity, rule_id,
		action_taken, matched_summary, evidence_ref, principal_key, conversation_key)
		VALUES($1, NULL, $2, NULL, NULL, $3, $4, NULL, $5, $6::jsonb, NULL, NULL, NULL)
		ON CONFLICT (id) DO NOTHING`,
		id, tenant, securityType, severity, actionTaken, summaryJSON)
	if err != nil {
		return fmt.Errorf("insert endpoint security event: %w", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_events SET security_event_id=$3 WHERE tenant_id=$1 AND id=$2`, tenant, record.ID, id); err != nil {
		return fmt.Errorf("link endpoint security event: %w", err)
	}
	return nil
}

func refreshAgentSessionCounters(ctx context.Context, tx pgx.Tx, tenant, sessionID string) error {
	_, err := tx.Exec(ctx, `UPDATE agent_sessions SET
		event_count=(SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND session_id=$2),
		turn_count=(SELECT count(*) FROM agent_turns WHERE tenant_id=$1 AND session_id=$2),
		tool_call_count=(SELECT count(DISTINCT COALESCE(NULLIF(payload->>'tool_call_id',''),NULLIF(tool_use_id,''))) FROM agent_events WHERE tenant_id=$1 AND session_id=$2 AND event_type IN ('tool.pre','tool.post','tool.failure','tool.denied') AND COALESCE(NULLIF(payload->>'tool_call_id',''),NULLIF(tool_use_id,'')) IS NOT NULL),
		blocked_count=(SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND session_id=$2 AND (COALESCE(server_decision->>'effective_decision',local_decision->>'effective_decision',payload->>'decision','') IN ('block','blocked','deny','denied') OR payload->>'status'='blocked' OR event_type='tool.denied')),
		would_block_count=(SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND session_id=$2 AND COALESCE(server_decision->>'effective_decision',local_decision->>'effective_decision',payload->>'decision','') IN ('would_block','would-block')),
		last_request_at=GREATEST(COALESCE(last_request_at,to_timestamp(0)),(SELECT max(occurred_at) FROM agent_events WHERE tenant_id=$1 AND session_id=$2)),updated_at=now()
		WHERE tenant_id=$1 AND session_id=$2`, tenant, sessionID)
	if err != nil {
		return fmt.Errorf("refresh agent session counters: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE agent_turns t SET
		tool_call_count=(SELECT count(DISTINCT COALESCE(NULLIF(e.payload->>'tool_call_id',''),NULLIF(e.tool_use_id,''))) FROM agent_events e WHERE e.tenant_id=t.tenant_id AND e.session_id=t.session_id AND e.prompt_id=t.prompt_id AND e.event_type IN ('tool.pre','tool.post','tool.failure','tool.denied') AND COALESCE(NULLIF(e.payload->>'tool_call_id',''),NULLIF(e.tool_use_id,'')) IS NOT NULL),
		blocked_count=(SELECT count(*) FROM agent_events e WHERE e.tenant_id=t.tenant_id AND e.session_id=t.session_id AND e.prompt_id=t.prompt_id AND (COALESCE(e.server_decision->>'effective_decision',e.local_decision->>'effective_decision',e.payload->>'decision','') IN ('block','blocked','deny','denied') OR e.payload->>'status'='blocked' OR e.event_type='tool.denied'))
		WHERE t.tenant_id=$1 AND t.session_id=$2`, tenant, sessionID)
	if err != nil {
		return fmt.Errorf("refresh agent turn counters: %w", err)
	}
	return nil
}

type AgentRetentionResult struct {
	Events, Turns, Sessions, Assets int64
}

func (r *AgentEndpointRepository) DeleteRetainedData(ctx context.Context, retentionDays int) (AgentRetentionResult, error) {
	return r.deleteRetainedDataAt(ctx, retentionDays, time.Now().UTC())
}

// deleteRetainedDataAt keeps the retention cutoff deterministic in database tests.
func (r *AgentEndpointRepository) deleteRetainedDataAt(ctx context.Context, retentionDays int, now time.Time) (AgentRetentionResult, error) {
	var result AgentRetentionResult
	if retentionDays < 1 {
		return result, fmt.Errorf("retention days must be positive")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('jjdguard:agent-retention',858))`); err != nil {
		return result, err
	}
	cutoff := now.UTC().AddDate(0, 0, -retentionDays)
	cmd, err := tx.Exec(ctx, `DELETE FROM agent_events e WHERE e.occurred_at<$1 AND NOT EXISTS(
		SELECT 1 FROM agent_sessions s WHERE s.tenant_id=e.tenant_id AND s.session_id=e.session_id AND s.status='active')`, cutoff)
	if err != nil {
		return result, fmt.Errorf("delete retained agent events: %w", err)
	}
	result.Events = cmd.RowsAffected()
	cmd, err = tx.Exec(ctx, `DELETE FROM agent_turns t USING agent_sessions s
		WHERE t.tenant_id=s.tenant_id AND t.session_id=s.session_id AND s.status<>'active'
		AND COALESCE(t.ended_at,t.started_at,s.ended_at,s.last_request_at,s.updated_at,s.created_at)<$1`, cutoff)
	if err != nil {
		return result, fmt.Errorf("delete retained agent turns: %w", err)
	}
	result.Turns = cmd.RowsAffected()
	cmd, err = tx.Exec(ctx, `DELETE FROM agent_sessions s WHERE s.status<>'active'
		AND COALESCE(s.ended_at,s.last_request_at,s.updated_at,s.created_at)<$1
		AND NOT EXISTS(SELECT 1 FROM agent_turns t WHERE t.tenant_id=s.tenant_id AND t.session_id=s.session_id)
		AND NOT EXISTS(SELECT 1 FROM agent_events e WHERE e.tenant_id=s.tenant_id AND e.session_id=s.session_id)`, cutoff)
	if err != nil {
		return result, fmt.Errorf("delete retained agent sessions: %w", err)
	}
	result.Sessions = cmd.RowsAffected()
	cmd, err = tx.Exec(ctx, `DELETE FROM agent_endpoint_assets WHERE present=false AND last_seen<$1`, cutoff)
	if err != nil {
		return result, fmt.Errorf("delete retained endpoint assets: %w", err)
	}
	result.Assets = cmd.RowsAffected()
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}

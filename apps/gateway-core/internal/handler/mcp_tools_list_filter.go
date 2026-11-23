package handler

// W1 1.3：tools/list 响应按已批准资产过滤。
//
// 两次同步之间上游可以悄悄改工具描述/Schema（rug-pull），客户端读 tools/list 就会当场
// 拿到投毒内容。网关对每个 tools/list 响应逐条比对「已批准快照」的 schema hash
// （与 control-plane mcpToolSchemaHash 同算法），不一致/未知/未批准的条目剔除并告警。
//
// 出口走 securityexit：防护模式剔除；记录模式不改响应只留痕；准入集拿不到
// （DetectionFailure）时放行并记覆盖缺口，不自作主张拦。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpadmission"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// 与 control-plane handler/mcp_manifest_fetch.go 的归一化上限保持一致：超过上限时
// 控制面入库的是截断值，其哈希不覆盖客户端实际看到的内容，网关因此直接剔除。
const (
	mcpAdmissionToolNameMaxLen     = 512
	mcpAdmissionToolDescMaxLen     = 8192
	mcpAdmissionToolSchemaMaxBytes = 65536
	mcpToolsListDropEvidenceLimit  = 50
)

const (
	mcpToolsListDropUnknown       = "mcp_tool_unknown"
	mcpToolsListDropRemoved       = "mcp_tool_removed"
	mcpToolsListDropNotApproved   = "mcp_tool_not_approved"
	mcpToolsListDropServer        = "mcp_server_not_approved"
	mcpToolsListDropSchemaChanged = "schema_hash_mismatch"
	mcpToolsListDropBounds        = "exceeds_admission_bounds"
	mcpToolsListDropMalformed     = "malformed_tool"
	mcpToolsListDropNoncanonical  = "noncanonical_field"
	mcpToolsListDropAmbiguous     = "ambiguous_response"
	// mcpToolsListDropAdministrator：管理员手动隔离或撤销的服务/工具，照拦（管理员自己的配置）。
	mcpToolsListDropAdministrator = "mcp_admission_blocked_by_administrator"
)

var errMCPApprovedToolsUnavailable = errors.New("MCP 已批准工具集不可用")

type mcpApprovedTool struct {
	Status             string
	ApprovedSchemaHash string
	Removed            bool
	// Reason 是隔离原因或未准入工具上的发现；Source 是处置来源（system/administrator，见 mcpadmission）。
	Reason string
	Source string
}

// mcpApprovedToolSet 是某 server 的准入快照：服务器是否已批准 + 按工具名的已批准哈希。
type mcpApprovedToolSet struct {
	ServerApproved bool
	ServerStatus   string
	ServerReason   string
	ServerSource   string
	Tools          map[string]mcpApprovedTool
	// Limits 是 mcp.oversize 的三个上限；零值用默认（512/8192/65536）。
	Limits mcpToolBounds
}

// mcpToolBounds 是工具名、描述、Schema 的长度上限（mcp.oversize 参数）。
type mcpToolBounds struct{ Name, Description, Schema int }

func mcpToolBoundsFor(settings protection.Settings) mcpToolBounds {
	return mcpToolBounds{
		Name:        settings.IntParam(protection.KeyMCPOversize, "max_name_bytes"),
		Description: settings.IntParam(protection.KeyMCPOversize, "max_description_bytes"),
		Schema:      settings.IntParam(protection.KeyMCPOversize, "max_schema_bytes"),
	}
}

func (b mcpToolBounds) orDefault() mcpToolBounds {
	if b.Name <= 0 {
		b.Name = mcpAdmissionToolNameMaxLen
	}
	if b.Description <= 0 {
		b.Description = mcpAdmissionToolDescMaxLen
	}
	if b.Schema <= 0 {
		b.Schema = mcpAdmissionToolSchemaMaxBytes
	}
	return b
}

// mcpListedDropReasons 把未批准的服务/工具归到原因：管理员处置单独一类（照剔除）；系统隔离按隔离原因
// 对应的项（原因没登记照剔除）；其余未准入按通用原因（mcp.unadmitted），带已登记发现时再按发现对应的项
// 判一次，两者取更严（与调用路径一致）。
func mcpListedDropReasons(status, reason, source, generic string) []string {
	if mcpAdministratorAdmission(status, source) {
		return []string{mcpToolsListDropAdministrator}
	}
	finding, registered := protection.ItemForReason(reason)
	if status == "quarantined" {
		if !registered {
			return []string{mcpToolsListDropAdministrator}
		}
		return []string{reason}
	}
	reasons := []string{generic}
	if unadmitted, ok := protection.ItemForReason(generic); registered && (!ok || finding.Key != unadmitted.Key) {
		reasons = append(reasons, reason)
	}
	return reasons
}

type mcpApprovedToolsLoader func(ctx context.Context, tenantID, serverID string) (*mcpApprovedToolSet, error)

// setApprovedToolsLoader 供测试注入准入快照来源。
func (h *MCPProxyHandler) setApprovedToolsLoader(loader mcpApprovedToolsLoader) {
	h.approvedToolsLoader = loader
}

type mcpToolsListDrop struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// mcpGatewayToolSchemaHash 必须与 control-plane mcpToolSchemaHash 逐字节一致：
// sha256(description + "\x00" + json.Marshal(inputSchema))，inputSchema 为
// map[string]interface{}（数字按 float64、键按字典序、HTML 字符按默认转义）。
func mcpGatewayToolSchemaHash(description string, inputSchema map[string]interface{}) string {
	schemaBytes, _ := json.Marshal(inputSchema)
	sum := sha256.Sum256(append([]byte(description+"\x00"), schemaBytes...))
	return hex.EncodeToString(sum[:])
}

// loadMCPApprovedTools 每次 tools/list 实时查库（低频操作，不缓存，避免批准/隔离后的陈旧窗口）。
func (h *MCPProxyHandler) loadMCPApprovedTools(ctx context.Context, tenantID, serverID string) (*mcpApprovedToolSet, error) {
	if h.approvedToolsLoader != nil {
		return h.approvedToolsLoader(ctx, tenantID, serverID)
	}
	if h.db == nil {
		return nil, errMCPApprovedToolsUnavailable
	}
	rows, err := h.db.Query(ctx, `
		SELECT s.admission_status, COALESCE(s.quarantine_reason, ''), COALESCE(s.admission_reviewed_by, ''),
		       COALESCE(t.tool_name, ''), COALESCE(t.admission_status, ''),
		       COALESCE(t.approved_schema_hash, ''), COALESCE(t.removed, FALSE), COALESCE(t.quarantine_reason, ''),
		       COALESCE(t.admission_reviewed_by, '')
		FROM mcp_servers s
		LEFT JOIN mcp_tools t ON t.tenant_id = s.tenant_id AND t.server_id = s.id
		WHERE s.tenant_id = $1 AND s.id = $2`, tenantID, serverID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errMCPApprovedToolsUnavailable, err)
	}
	defer rows.Close()
	set := &mcpApprovedToolSet{Tools: make(map[string]mcpApprovedTool)}
	for rows.Next() {
		var serverStatus, serverReason, serverReviewedBy, name, status, approvedHash, reason, reviewedBy string
		var removed bool
		if err := rows.Scan(&serverStatus, &serverReason, &serverReviewedBy, &name, &status, &approvedHash, &removed, &reason, &reviewedBy); err != nil {
			return nil, fmt.Errorf("%w: %v", errMCPApprovedToolsUnavailable, err)
		}
		set.ServerApproved = serverStatus == "approved"
		set.ServerStatus, set.ServerReason, set.ServerSource = serverStatus, serverReason, mcpadmission.Source(serverReviewedBy)
		if name != "" {
			set.Tools[name] = mcpApprovedTool{Status: status, ApprovedSchemaHash: approvedHash, Removed: removed, Reason: reason, Source: mcpadmission.Source(reviewedBy)}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", errMCPApprovedToolsUnavailable, err)
	}
	return set, nil
}

// mcpHasNoncanonicalKey：对象里存在与已知字段仅大小写不同的键（如 "Tools"、"Description"）。
// 大小写不敏感的客户端会读它，网关按精确键判定会漏看，因此视为歧义。
func mcpHasNoncanonicalKey(obj map[string]json.RawMessage, canonical ...string) bool {
	for key := range obj {
		for _, want := range canonical {
			if key != want && strings.EqualFold(key, want) {
				return true
			}
		}
	}
	return false
}

// judgeMCPListedTool 判定一条 tools/list 条目是否与已批准快照一致；一致返回空列表。
// 返回多条原因时按每条对应的项各判一次（见 mcpListedDropReasons）。
func judgeMCPListedTool(raw json.RawMessage, set *mcpApprovedToolSet) (string, []string) {
	one := func(reason string) []string { return []string{reason} }
	obj, ok := mcpExactObject(raw)
	if !ok {
		return "", one(mcpToolsListDropMalformed)
	}
	name, present, err := mcpExactString(obj, "name")
	if err != nil || !present || name == "" {
		return name, one(mcpToolsListDropMalformed)
	}
	if mcpHasNoncanonicalKey(obj, "name", "title", "description", "inputSchema", "outputSchema", "annotations", "_meta", "icons") {
		return name, one(mcpToolsListDropNoncanonical)
	}
	description, _, err := mcpExactString(obj, "description")
	if err != nil {
		return name, one(mcpToolsListDropMalformed)
	}
	var schema map[string]interface{}
	if rawSchema, ok := obj["inputSchema"]; ok {
		if err := json.Unmarshal(rawSchema, &schema); err != nil {
			return name, one(mcpToolsListDropMalformed)
		}
	}
	// 管理员手动隔离、撤销优先于其他原因判定（超长、服务未批准等不能抢先命中而让它留在列表里）。
	if mcpAdministratorAdmission(set.ServerStatus, set.ServerSource) {
		return name, one(mcpToolsListDropAdministrator)
	}
	if tool, ok := set.Tools[name]; ok && mcpAdministratorAdmission(tool.Status, tool.Source) {
		return name, one(mcpToolsListDropAdministrator)
	}
	bounds := set.Limits.orDefault()
	if len(name) > bounds.Name || len(description) > bounds.Description {
		return name, one(mcpToolsListDropBounds)
	}
	if schemaBytes, err := json.Marshal(schema); err != nil || len(schemaBytes) > bounds.Schema {
		return name, one(mcpToolsListDropBounds)
	}
	if !set.ServerApproved {
		return name, mcpListedDropReasons(set.ServerStatus, set.ServerReason, set.ServerSource, mcpToolsListDropServer)
	}
	approved, ok := set.Tools[name]
	switch {
	case !ok:
		return name, one(mcpToolsListDropUnknown)
	case approved.Removed:
		return name, one(mcpToolsListDropRemoved)
	case approved.Status != "approved" || approved.ApprovedSchemaHash == "":
		return name, mcpListedDropReasons(approved.Status, approved.Reason, approved.Source, mcpToolsListDropNotApproved)
	case mcpGatewayToolSchemaHash(description, schema) != approved.ApprovedSchemaHash:
		return name, one(mcpToolsListDropSchemaChanged)
	}
	return name, nil
}

// mcpToolsListFilter 绑定一次 POST 的 tools/list 请求 ID 与判定上下文。
type mcpToolsListFilter struct {
	decisions []mcpToolCallDecision
	indexByID map[string]int
	set       *mcpApprovedToolSet
	enforce   bool
	serverID  string
	// tenant 是租户的防护项设置与例外：剔除与否按每条原因对应的 mcp.* 项动作，指向该项的例外可放开。
	tenant mcpTenantContext
}

// listedAction 是 tools/list 上一条不一致的处置：协议格式问题、管理员手动处置和没登记的原因照剔除
// （block）；已登记的发现按对应 mcp.* 防护项（默认告警放行，只留证），指向该项的例外把它降为仅记录，
// 与调用路径同口径。
func (f *mcpToolsListFilter) listedAction(reason, toolName string) protection.Action {
	switch reason {
	case mcpToolsListDropMalformed, mcpToolsListDropNoncanonical, mcpToolsListDropAmbiguous, mcpToolsListDropAdministrator:
		return protection.ActionBlock
	}
	item, ok := protection.ItemForReason(reason)
	if !ok {
		return protection.ActionBlock
	}
	target := mcpExceptionTarget(f.tenant.ServerName, toolName)
	if agentguard.MatchingMCPException(f.tenant.Exceptions, []string{item.Key, reason}, target, time.Now()) != nil {
		return protection.ActionRecord
	}
	return f.tenant.Protections.ActionFor(item.Key)
}

// dropsFromList 判断一条不一致是否要从列表里剔除（设为阻断、没有例外）。
func (f *mcpToolsListFilter) dropsFromList(reason, toolName string) bool {
	return f.listedAction(reason, toolName) == protection.ActionBlock
}

// prepareMCPToolsListFilter：请求中含 tools/list 时构造过滤器，否则返回 nil。
func (h *MCPProxyHandler) prepareMCPToolsListFilter(ctx context.Context, server *mcpServerRoute, tenantID string, decisions []mcpToolCallDecision, auditOnly bool, tenant mcpTenantContext) *mcpToolsListFilter {
	indexByID := make(map[string]int)
	for i := range decisions {
		d := &decisions[i]
		if d.TargetKind != mcpTargetMethod || d.ToolName != "tools/list" {
			continue
		}
		if key, ok := mcpRPCIDKey(d.Message.ID); ok {
			indexByID[key] = i
		}
	}
	if len(indexByID) == 0 {
		return nil
	}
	mode := securityexit.ModeFromAuditOnly(auditOnly)
	set, err := h.loadMCPApprovedTools(ctx, tenantID, server.ID)
	if err != nil {
		// 覆盖缺口：拿不到准入快照就不做比对，放行并留痕，不自作主张拦。
		outcome := securityexit.Decide(mode, "block", securityexit.DetectionFailure)
		log.Printf("MCP tools/list 准入快照不可用，本次未比对 (server=%s gap=%v): %v", server.ID, outcome.Gap, err)
		for _, i := range indexByID {
			decisions[i].Decision.Evidence = append(decisions[i].Decision.Evidence, agentguard.Evidence{
				RuleID: "mcp_tools_list_unverified", Category: "coverage_gap",
			})
		}
		return nil
	}
	bounded := *set
	bounded.Limits = mcpToolBoundsFor(tenant.Protections)
	return &mcpToolsListFilter{
		decisions: decisions, indexByID: indexByID, set: &bounded, serverID: server.ID,
		enforce: securityexit.Decide(mode, "block", securityexit.ToolPolicy).Enforce,
		tenant:  tenant,
	}
}

func (f *mcpToolsListFilter) record(index int, drops []mcpToolsListDrop, enforced ...bool) {
	if len(drops) == 0 {
		return
	}
	d := &f.decisions[index]
	d.ToolsListDrops = append(d.ToolsListDrops, drops...)
	// enforced 省略时（整包协议问题）按执行模式；逐条判定时由调用方给出是否真的剔除了。
	d.ToolsListEnforced = f.enforce
	if len(enforced) > 0 {
		d.ToolsListEnforced = enforced[0]
	}
	f.recordEvidence(index, drops)
}

// recordEvidence 只把不一致记进这次 tools/list 的证据（进工具日志），不算告警：仅记录的发现走这里。
func (f *mcpToolsListFilter) recordEvidence(index int, drops []mcpToolsListDrop) {
	d := &f.decisions[index]
	for _, drop := range drops {
		if len(d.Decision.Evidence) >= mcpToolsListDropEvidenceLimit {
			break
		}
		preview := drop.Name
		if len(preview) > 64 {
			preview = truncateMCPUTF8(preview, 64)
		}
		d.Decision.Evidence = append(d.Decision.Evidence, agentguard.Evidence{
			RuleID: "mcp_tools_list_" + drop.Reason, Category: "mcp_tools_list_drift",
			SourceField: "result.tools[].name", MaskedPreview: preview,
		})
	}
	names := make([]string, 0, len(drops))
	for _, drop := range drops {
		names = append(names, drop.Name+":"+drop.Reason)
	}
	log.Printf("MCP tools/list 与已批准快照不一致 (server=%s enforced=%v): %s", f.serverID, f.enforce, strings.Join(names, ","))
}

// rewritePayload 处理一条 JSON-RPC 响应载荷（非流式 body 或单个 SSE data）。
// 未命中 tools/list 请求 ID 或无需改动时原样返回。
func (f *mcpToolsListFilter) rewritePayload(payload []byte) []byte {
	if f == nil {
		return payload
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return payload
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return payload
	}
	key, ok := mcpRPCIDKey(obj["id"])
	if !ok {
		return payload
	}
	index, ok := f.indexByID[key]
	if !ok {
		return payload
	}
	if _, isRequest := obj["method"]; isRequest {
		return payload
	}
	emptied := func() []byte {
		out, err := mcpMarshalNoEscape(map[string]json.RawMessage{
			"jsonrpc": json.RawMessage(`"2.0"`), "id": obj["id"], "result": json.RawMessage(`{"tools":[]}`),
		})
		if err != nil {
			return payload
		}
		return out
	}
	// 响应本身有歧义（重复键/仅大小写不同的键/非法 UTF-8）：网关无法确定客户端会读到哪份工具清单。
	if mcpStrictValidate(trimmed) != nil || mcpHasNoncanonicalKey(obj, "jsonrpc", "id", "result", "error") {
		f.record(index, []mcpToolsListDrop{{Name: "*", Reason: mcpToolsListDropAmbiguous}})
		if !f.enforce {
			return payload
		}
		return emptied()
	}
	rawResult, hasResult := obj["result"]
	if !hasResult {
		return payload
	}
	result, ok := mcpExactObject(rawResult)
	if !ok {
		return payload
	}
	if mcpHasNoncanonicalKey(result, "tools", "nextCursor", "_meta") {
		f.record(index, []mcpToolsListDrop{{Name: "*", Reason: mcpToolsListDropAmbiguous}})
		if !f.enforce {
			return payload
		}
		return emptied()
	}
	var tools []json.RawMessage
	if rawTools, ok := result["tools"]; ok {
		if err := json.Unmarshal(rawTools, &tools); err != nil {
			f.record(index, []mcpToolsListDrop{{Name: "*", Reason: mcpToolsListDropMalformed}})
			if !f.enforce {
				return payload
			}
			return emptied()
		}
	}
	kept := make([]json.RawMessage, 0, len(tools))
	var drops, recorded []mcpToolsListDrop
	removedAny := false
	for _, tool := range tools {
		name, reasons := judgeMCPListedTool(tool, f.set)
		if len(reasons) == 0 {
			kept = append(kept, tool)
			continue
		}
		if name == "" {
			name = "?"
		}
		// 一条工具可能同时按几项判（未准入 + 发现）：任一项要剔除就剔除，证据逐项记；
		// 仅记录（含例外放开）的发现只进证据，不算不一致告警。
		remove := false
		for _, reason := range reasons {
			drop := mcpToolsListDrop{Name: name, Reason: reason}
			switch f.listedAction(reason, name) {
			case protection.ActionBlock:
				remove = true
				drops = append(drops, drop)
			case protection.ActionRecord:
				recorded = append(recorded, drop)
			default:
				drops = append(drops, drop)
			}
		}
		if remove {
			removedAny = true
		} else {
			// 只告警：留在列表里，证据照记。
			kept = append(kept, tool)
		}
	}
	f.recordEvidence(index, recorded)
	if len(drops) == 0 {
		return payload
	}
	f.record(index, drops, f.enforce && removedAny)
	if !f.enforce || !removedAny {
		return payload
	}
	keptJSON, err := mcpMarshalNoEscape(kept)
	if err != nil {
		return emptied()
	}
	result["tools"] = keptJSON
	resultJSON, err := mcpMarshalNoEscape(result)
	if err != nil {
		return emptied()
	}
	obj["result"] = resultJSON
	out, err := mcpMarshalNoEscape(obj)
	if err != nil {
		return emptied()
	}
	return out
}

// rewriteSSEEvent 改写一个完整 SSE 事件（含结尾空行），见 mcpRewriteSSEEvent。
func (f *mcpToolsListFilter) rewriteSSEEvent(event []byte) []byte {
	if f == nil {
		return event
	}
	return mcpRewriteSSEEvent(event, f.rewritePayload)
}

func (f *mcpToolsListFilter) payloadRewriter() func([]byte) []byte {
	if f == nil {
		return nil
	}
	return f.rewritePayload
}

// mcpPayloadRewriters 按顺序串联多个 JSON-RPC 载荷改写器（nil 项跳过）。
type mcpPayloadRewriters []func([]byte) []byte

func (rs mcpPayloadRewriters) active() mcpPayloadRewriters {
	var out mcpPayloadRewriters
	for _, r := range rs {
		if r != nil {
			out = append(out, r)
		}
	}
	return out
}

func (rs mcpPayloadRewriters) payload(p []byte) []byte {
	for _, r := range rs {
		p = r(p)
	}
	return p
}

func (rs mcpPayloadRewriters) sseEvent(event []byte) []byte {
	if len(rs) == 0 {
		return event
	}
	return mcpRewriteSSEEvent(event, rs.payload)
}

// mcpRewriteSSEEvent 改写一个完整 SSE 事件：非 data 行原样保留，多行 data 拼接后交给
// rewrite，改动时以单行 data 回写到首个 data 行位置；未改动则原字节返回。
func mcpRewriteSSEEvent(event []byte, rewrite func([]byte) []byte) []byte {
	normalized := strings.ReplaceAll(string(event), "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(normalized, "\n"), "\n")
	var dataLines []string
	firstData := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "data:") {
			if firstData < 0 {
				firstData = i
			}
			dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if firstData < 0 {
		return event
	}
	payload := []byte(strings.Join(dataLines, "\n"))
	rewritten := rewrite(payload)
	if bytes.Equal(rewritten, payload) {
		return event
	}
	var out strings.Builder
	for i, line := range lines {
		if strings.HasPrefix(line, "data:") {
			if i == firstData {
				out.WriteString("data: ")
				out.Write(rewritten)
				out.WriteString("\n")
			}
			continue
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	out.WriteString("\n")
	return []byte(out.String())
}

// copyMCPSSEEvents 与 validateAndCopyMCPSSE 同样的容量上限，但按完整事件缓冲后再经
// transform 写出（SSE 客户端本就只在事件结束后处理，按事件缓冲不改变语义）。
func copyMCPSSEEvents(dst io.Writer, flush func(), src io.Reader, transform func([]byte) []byte) error {
	var pending bytes.Buffer
	emit := func() error {
		if pending.Len() == 0 {
			return nil
		}
		out := pending.Bytes()
		if transform != nil {
			out = transform(out)
		}
		_, err := dst.Write(out)
		pending.Reset()
		if flush != nil {
			flush()
		}
		return err
	}
	collector := mcpSSEEventCollector{emit: emit, pending: &pending}
	if err := validateAndCopyMCPSSE(&collector, nil, src); err != nil {
		return err
	}
	return emit()
}

// mcpSSEEventCollector 接收 validateAndCopyMCPSSE 按行写出的片段，遇空行即一个事件结束。
type mcpSSEEventCollector struct {
	pending *bytes.Buffer
	emit    func() error
}

func (c *mcpSSEEventCollector) Write(p []byte) (int, error) {
	c.pending.Write(p)
	if bytes.Equal(p, []byte("\n")) || bytes.Equal(p, []byte("\r\n")) {
		if err := c.emit(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func truncateMCPUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// 脱敏原文留证：命中脱敏或被阻断的输入/输出，另存一份加密原文，供管理员溯源。
// 铁律：
//   - 只留证，不改变发往上游/客户端的任何内容；
//   - 明文原文只出现在本文件的调用栈里，加密后落 content_raw_evidence，
//     绝不写入 content_logs、security_events、缓存、语义裁判、规则包或日志；
//   - 加密失败/开关关闭/写库失败都只丢留证，不影响请求（日志里不带原文）。

const (
	rawEvidenceInput    = "input"
	rawEvidenceOutput   = "output"
	rawEvidenceMasked   = "masked"
	rawEvidenceBlocked  = "blocked"
	rawEvidenceMaxRunes = 512 * 1024
)

// RawEvidenceRecord 是一条待留证的原文。Index：输入为客户端协议里的消息序号（-1 表示
// system/instructions 这类没有协议序号的消息），输出为 choice 序号。
type RawEvidenceRecord struct {
	Direction   string
	Role        string
	Index       int
	Disposition string
	Text        string
	BlockID     string
	RuleIDs     []string
	RuleNames   []string
	Categories  []string
}

// rawEvidenceWriter 是审计写入器的可选能力（与 retentionTurnContextWriter 同一做法，不扩大必选接口）。
type rawEvidenceWriter interface {
	WriteRawEvidence(context.Context, *modelrouter.RequestEnvelope, RawEvidenceRecord)
}

const rawEvidenceInsertSQL = `
	INSERT INTO content_raw_evidence (tenant_id, request_id, session_id, user_id, direction, role, message_index, disposition,
		block_id, rule_ids, rule_names, categories, content_ciphertext, content_hmac, content_chars, content_truncated, original_chars, environment_scope)
	SELECT $1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8, NULLIF($9, ''), $10::text[], $11::text[], $12::text[], $13, $14, $15, $16, $17, $18
	WHERE COALESCE((SELECT value FROM system_settings WHERE key = 'raw_evidence_enabled'), 'true') <> 'false'
	ON CONFLICT DO NOTHING`

// rawEvidenceRefInsertSQL 写一行引用：不含密文，ref_evidence_id 指向同租户、同会话、同方向与处置下
// 同一原文（HMAC 相同）的首条留证；找不到首条（开关关闭、首条已过保留期）时写 0 行。
const rawEvidenceRefInsertSQL = `
	INSERT INTO content_raw_evidence (tenant_id, request_id, session_id, user_id, direction, role, message_index, disposition,
		block_id, rule_ids, rule_names, categories, content_ciphertext, content_hmac, content_chars, content_truncated, original_chars,
		environment_scope, ref_evidence_id)
	SELECT $1::text, $2, $3::text, NULLIF($4, ''), $5::text, $6, $7, $8::text, NULLIF($9, ''), $10::text[], $11::text[], $12::text[], NULL, o.content_hmac,
		o.content_chars, o.content_truncated, o.original_chars, $13, o.id
	FROM content_raw_evidence o
	WHERE o.tenant_id = $1::text AND o.session_id = $3::text AND o.direction = $5::text AND o.disposition = $8::text AND o.content_hmac = $14
	  AND o.ref_evidence_id IS NULL
	  AND COALESCE((SELECT value FROM system_settings WHERE key = 'raw_evidence_enabled'), 'true') <> 'false'
	LIMIT 1
	ON CONFLICT DO NOTHING`

// truncateRawEvidence 把超长原文截到 rawEvidenceMaxRunes，返回截断后文本、是否截断与原始字符数。
func truncateRawEvidence(text string) (string, bool, int) {
	n := utf8.RuneCountInString(text)
	if n <= rawEvidenceMaxRunes {
		return text, false, n
	}
	return string([]rune(text)[:rawEvidenceMaxRunes]), true, n
}

// ---- 写入：请求热路径只入队，后台协程加密、去重、落库 ----
//
// 留证不能拖慢业务请求：每条被改写的消息在发给上游前串行加密 + INSERT（最长 10 秒的审计时限）
// 会直接叠加到首字延迟上（审查 B-3）。这里改为进程内有界队列：
//   - WriteRawEvidence 只做参数校验并入队，立即返回；队列满（条数或字节）时丢弃并记日志，不阻塞；
//   - 后台协程逐条加密、计算 HMAC、写库，单条写库时限 rawEvidenceWriteTimeout（短于普通审计）；
//   - 失败（无密钥、写库超时/出错）只记日志，日志里不带原文。
//
// 不走现有 outbox：outbox 事件是明文 JSON 落库，原文不能经过它。
//
// 去重：同一租户、同一会话（无会话时为请求编号）、同一方向与处置下，原文 HMAC 相同只存一份。
// 智能体多轮对话每轮都会把同一段含个人信息的 tool_result 重新发来并重新脱敏，不去重时每轮各存一份。
// 进程内记住最近写入成功的去重键，省掉重复的加密；库里的唯一索引兜底多实例并发。
// 去重后的后续请求写一行不含密文的引用行（ref_evidence_id 指向首条），按它的请求 ID 仍能定位与查看。

var (
	// rawEvidenceWriteTimeout 是后台单条留证写库的时限。var 便于测试调小。
	rawEvidenceWriteTimeout = 3 * time.Second
	// rawEvidenceQueueCap / rawEvidenceQueueMaxBytes 限制排队中的留证条数与原文总字节，防止写库变慢时占满内存。
	rawEvidenceQueueCap            = 512
	rawEvidenceQueueMaxBytes int64 = 64 << 20
)

const (
	rawEvidenceWorkers     = 2
	rawEvidenceSeenMaxKeys = 8192
)

type rawEvidenceJob struct {
	ctx      context.Context
	envelope modelrouter.RequestEnvelope
	rec      RawEvidenceRecord
	bytes    int64
}

// rawEvidenceQueue 的零值可用（RealAuditWriter 以结构体字面量构造时也能工作）：首次入队时启动后台协程。
type rawEvidenceQueue struct {
	once    sync.Once
	ch      chan rawEvidenceJob
	bytes   atomic.Int64
	pending sync.WaitGroup

	seenMu sync.Mutex
	seen   map[string]struct{}
}

func (w *RealAuditWriter) WriteRawEvidence(ctx context.Context, envelope *modelrouter.RequestEnvelope, rec RawEvidenceRecord) {
	if w == nil || w.db == nil || envelope == nil || envelope.TenantID == "" || envelope.RequestID == "" || rec.Text == "" {
		return
	}
	if rec.Direction != rawEvidenceInput && rec.Direction != rawEvidenceOutput {
		return
	}
	if rec.Disposition != rawEvidenceMasked && rec.Disposition != rawEvidenceBlocked {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	q := &w.rawEvidence
	q.once.Do(func() {
		q.ch = make(chan rawEvidenceJob, rawEvidenceQueueCap)
		for i := 0; i < rawEvidenceWorkers; i++ {
			go w.rawEvidenceLoop()
		}
	})
	size := int64(len(rec.Text))
	if q.bytes.Add(size) > rawEvidenceQueueMaxBytes {
		q.bytes.Add(-size)
		log.Printf("raw evidence dropped for request %s: queue byte budget exhausted", envelope.RequestID)
		return
	}
	q.pending.Add(1)
	job := rawEvidenceJob{ctx: context.WithoutCancel(ctx), envelope: *envelope, rec: rec, bytes: size}
	select {
	case q.ch <- job:
	default:
		q.bytes.Add(-size)
		q.pending.Done()
		log.Printf("raw evidence dropped for request %s: queue full", envelope.RequestID)
	}
}

func (w *RealAuditWriter) rawEvidenceLoop() {
	q := &w.rawEvidence
	for job := range q.ch {
		if err := w.storeRawEvidence(job.ctx, &job.envelope, job.rec); err != nil {
			log.Printf("raw evidence not stored for request %s: %v", job.envelope.RequestID, err)
		}
		q.bytes.Add(-job.bytes)
		q.pending.Done()
	}
}

// flushRawEvidence 等待已入队的留证全部处理完（测试用；关停用带时限的 DrainRawEvidence）。
func (w *RealAuditWriter) flushRawEvidence() {
	if w != nil {
		w.rawEvidence.pending.Wait()
	}
}

func (q *rawEvidenceQueue) seenKey(key string) bool {
	q.seenMu.Lock()
	defer q.seenMu.Unlock()
	_, ok := q.seen[key]
	return ok
}

// DrainRawEvidence 在进程关停时调用（必须在关闭连接池之前）：等待已入队的留证写完，最多等 timeout。
// 返回 false 表示到时限仍有未写完的留证（会丢失，调用方记日志）。
func (w *RealAuditWriter) DrainRawEvidence(timeout time.Duration) bool {
	if w == nil {
		return true
	}
	done := make(chan struct{})
	go func() {
		w.rawEvidence.pending.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func (q *rawEvidenceQueue) forget(key string) {
	q.seenMu.Lock()
	defer q.seenMu.Unlock()
	delete(q.seen, key)
}

func (q *rawEvidenceQueue) remember(key string) {
	q.seenMu.Lock()
	defer q.seenMu.Unlock()
	if q.seen == nil || len(q.seen) >= rawEvidenceSeenMaxKeys {
		q.seen = make(map[string]struct{}, 256)
	}
	q.seen[key] = struct{}{}
}

// rawEvidenceSessionID 是留证的会话键：有会话 ID 用会话 ID；没有时用会话归组键（Claude Code 等走 API
// 直连的客户端不带会话 ID，退回请求编号会让同一段原文每次重试都算新会话，去重从不生效）；两者都没有才用请求编号。
// 写进 session_id 列，也进 AAD 与去重键；查看引用行时按同一列核对首条留证。
func rawEvidenceSessionID(envelope *modelrouter.RequestEnvelope) string {
	if envelope.SessionID != "" {
		return envelope.SessionID
	}
	if key := strings.TrimSpace(envelope.ConversationKey); key != "" {
		return "conv:" + key
	}
	return envelope.RequestID
}

// storeRawEvidence 加密并写入一条留证（后台协程调用）。错误信息里绝不带原文。
func (w *RealAuditWriter) storeRawEvidence(ctx context.Context, envelope *modelrouter.RequestEnvelope, rec RawEvidenceRecord) error {
	text, truncated, originalChars := truncateRawEvidence(rec.Text)
	sessionID := rawEvidenceSessionID(envelope)
	mac, err := secrets.RawEvidenceContentMAC(envelope.TenantID, []byte(text))
	if err != nil {
		// 没有数据加密密钥时宁可不留证，也不落明文。
		return fmt.Errorf("content mac unavailable: %w", err)
	}
	dedupKey := strings.Join([]string{envelope.TenantID, sessionID, rec.Direction, rec.Disposition, hex.EncodeToString(mac)}, "\x00")
	ctx, cancel := detachAuditContextFor(ctx, rawEvidenceWriteTimeout)
	defer cancel()
	// 引用行：同一会话里已经存过同一原文时，只给本请求写一行不含密文、指向首条留证的引用，
	// 按本请求的请求 ID / 阻断编号 / 规则照样能定位并查看（查看时解密首条）。
	writeRef := func() (int64, error) {
		res, err := w.db.Exec(ctx, rawEvidenceRefInsertSQL,
			envelope.TenantID, envelope.RequestID, sessionID, envelope.UserID,
			rec.Direction, rec.Role, rec.Index, rec.Disposition, rec.BlockID,
			nonNilStrings(rec.RuleIDs), nonNilStrings(rec.RuleNames), nonNilStrings(rec.Categories),
			retentionartifact.NormalizeEnvironmentScope(envelope.EnvironmentScope), mac)
		if err != nil {
			return 0, fmt.Errorf("reference write failed: %w", err)
		}
		if res == nil {
			return 0, nil
		}
		return res.RowsAffected(), nil
	}
	if w.rawEvidence.seenKey(dedupKey) {
		n, err := writeRef()
		if err != nil || n > 0 {
			return err
		}
		// 引用写了 0 行：首条已不在（过保留期被删）或开关已关。缓存失真，清掉键退回完整插入，
		// 不能让这条留证悄悄丢失（完整插入同样受开关约束）。
		w.rawEvidence.forget(dedupKey)
	}
	cipher, err := secrets.EncryptRawEvidence([]byte(text), secrets.RawEvidenceAAD(envelope.TenantID, envelope.RequestID, envelope.UserID, sessionID, rec.Direction, rec.Index, rec.Disposition))
	if err != nil {
		return fmt.Errorf("encryption unavailable: %w", err)
	}
	res, err := w.db.Exec(ctx, rawEvidenceInsertSQL,
		envelope.TenantID, envelope.RequestID, sessionID, envelope.UserID,
		rec.Direction, rec.Role, rec.Index, rec.Disposition, rec.BlockID,
		nonNilStrings(rec.RuleIDs), nonNilStrings(rec.RuleNames), nonNilStrings(rec.Categories),
		cipher, mac, utf8.RuneCountInString(text), truncated, originalChars, retentionartifact.NormalizeEnvironmentScope(envelope.EnvironmentScope))
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}
	// 只在真正写入后记住：开关关闭时（0 行）不记，重新打开后同一原文仍能留证。
	if res != nil && res.RowsAffected() > 0 {
		w.rawEvidence.remember(dedupKey)
		return nil
	}
	// 0 行：库里已有同一原文（另一台网关先写了）、同槽位重试、或开关关闭。前两种写引用行，
	// 引用 SQL 自带开关判断与槽位唯一约束，开关关闭/重试时同样写 0 行。
	_, err = writeRef()
	return err
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func (w *AsyncAuditWriter) WriteRawEvidence(ctx context.Context, e *modelrouter.RequestEnvelope, rec RawEvidenceRecord) {
	if w == nil {
		return
	}
	if writer, ok := w.syncWriter.(rawEvidenceWriter); ok {
		writer.WriteRawEvidence(ctx, e, rec)
	}
}

func (w *BillingAuditWriter) WriteRawEvidence(ctx context.Context, e *modelrouter.RequestEnvelope, rec RawEvidenceRecord) {
	if w == nil {
		return
	}
	if writer, ok := w.inner.(rawEvidenceWriter); ok {
		writer.WriteRawEvidence(ctx, e, rec)
	}
}

// ---- 请求级收集：把脱敏/阻断事件的命中规则带到留证记录上 ----

type rawEvidenceCollectorKey struct{}

// rawEvidenceHit 是一次脱敏或阻断事件里的一条命中：position 是网关检测列表里的消息位置
// （-1 表示事件不是在逐条检测里写的，只能看 MessageIndex），blocking 区分阻断与脱敏。
type rawEvidenceHit struct {
	finding  SecurityFinding
	position int
	blocking bool
}

type rawEvidenceCollector struct {
	mu   sync.Mutex
	hits []rawEvidenceHit
}

type rawEvidencePositionKey struct{}

// withRawEvidencePosition 由 applyInputSecurity 的逐条检测循环设置：让本条消息写出的事件命中
// 带上网关位置。system/instructions/工具定义的协议序号是 -1、引擎回来的命中不带 message_index，
// 只能靠位置知道命中的是哪一段。
func withRawEvidencePosition(ctx context.Context, position int) context.Context {
	if _, ok := ctx.Value(rawEvidenceCollectorKey{}).(*rawEvidenceCollector); !ok {
		return ctx
	}
	return context.WithValue(ctx, rawEvidencePositionKey{}, position)
}

func withRawEvidenceCollector(ctx context.Context) (context.Context, *rawEvidenceCollector) {
	if existing, ok := ctx.Value(rawEvidenceCollectorKey{}).(*rawEvidenceCollector); ok {
		return ctx, existing
	}
	c := &rawEvidenceCollector{}
	return context.WithValue(ctx, rawEvidenceCollectorKey{}, c), c
}

// noteRawEvidenceFindings 由 writeSecurityEvent 调用：只记录脱敏与阻断类事件的命中（规则、消息序号）。
func noteRawEvidenceFindings(ctx context.Context, actionTaken string, findings []SecurityFinding) {
	if len(findings) == 0 {
		return
	}
	if actionTaken != "security_masked" && !isBlockingSecurityAction(actionTaken) {
		return
	}
	c, _ := ctx.Value(rawEvidenceCollectorKey{}).(*rawEvidenceCollector)
	if c == nil {
		return
	}
	position := -1
	if p, ok := ctx.Value(rawEvidencePositionKey{}).(int); ok {
		position = p
	}
	blocking := isBlockingSecurityAction(actionTaken)
	c.mu.Lock()
	for _, f := range findings {
		c.hits = append(c.hits, rawEvidenceHit{finding: f, position: position, blocking: blocking})
	}
	c.mu.Unlock()
}

func (c *rawEvidenceCollector) snapshot() []rawEvidenceHit {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]rawEvidenceHit(nil), c.hits...)
}

// ruleAttribution 汇总某条消息（index>=0 时按命中序号过滤；找不到则取全部）的规则标识。
func ruleAttribution(findings []SecurityFinding, index int) (ids, names, categories []string) {
	collect := func(match func(SecurityFinding) bool) {
		seenIDs, seenNames, seenCats := map[string]bool{}, map[string]bool{}, map[string]bool{}
		add := func(dst *[]string, seen map[string]bool, v string) {
			v = strings.TrimSpace(v)
			if v != "" && !seen[v] {
				seen[v] = true
				*dst = append(*dst, v)
			}
		}
		for _, f := range findings {
			if match(f) {
				add(&ids, seenIDs, f.RuleID)
				add(&names, seenNames, f.RuleName)
				add(&categories, seenCats, f.Category)
			}
		}
	}
	collect(func(f SecurityFinding) bool { return f.MessageIndex != nil && *f.MessageIndex == index })
	if len(ids)+len(names)+len(categories) == 0 {
		collect(func(SecurityFinding) bool { return true })
	}
	sort.Strings(ids)
	sort.Strings(names)
	sort.Strings(categories)
	return
}

// ---- 输入：对比脱敏前后的消息文本；被阻断时留存命中的那几条 ----

// rawEvidenceNoProtocolIndex 表示网关消息没有协议消息序号（Anthropic system、Responses instructions）。
const rawEvidenceNoProtocolIndex = -1

// rawEvidenceToolDefIndex 是工具定义（工具名、描述、参数 schema）的留证序号：与 system 分开，
// system 被脱敏时不会把工具定义拼进留证；同一请求里命中的多段工具定义合成一条。
const rawEvidenceToolDefIndex = -2

// rawInputSnapshot 记录脱敏前每条网关检测消息的原文，以及它在客户端协议里的消息序号与角色。
// 安全命中（SecurityFinding.MessageIndex）带的是协议序号：Anthropic Messages / Responses 前面
// 多一条 system，tool_result 块被拆成多条网关消息，协议序号与网关数组位置并不一致。
// 位置与 applyInputSecurity 的检测列表（inspectionMessagesWithTools）一一对应。
type rawInputSnapshot struct {
	texts      []string
	roles      []string
	proto      []int    // 协议消息序号；rawEvidenceNoProtocolIndex 表示没有
	protoRoles []string // 协议消息角色（tool_result 拆出的 tool 消息仍归属协议里的 user 消息）
	toolDef    []bool   // 工具定义（请求 tools 或原生 /tools 路径）
}

// rawEvidenceProtocolIndex 与 gatewayInputInspectionPlan 的取法逐项一致：没有来源路径的
// 消息（OpenAI chat 原生消息）协议序号就是数组位置；有来源路径的取 SecurityMessageIndex。
func rawEvidenceProtocolIndex(m Message, position int) int {
	if m.SecuritySourcePath == "" {
		return position
	}
	if m.SecurityMessageIndex != nil {
		return *m.SecurityMessageIndex
	}
	return rawEvidenceNoProtocolIndex
}

func snapshotRawInput(messages []Message) rawInputSnapshot {
	n := len(messages)
	s := rawInputSnapshot{texts: make([]string, n), roles: make([]string, n), proto: make([]int, n), protoRoles: make([]string, n), toolDef: make([]bool, n)}
	for i := range messages {
		s.texts[i] = messageText(messages[i].Content)
		s.roles[i] = messages[i].Role
		s.proto[i] = rawEvidenceProtocolIndex(messages[i], i)
		s.protoRoles[i] = messages[i].SecurityMessageRole
		if s.protoRoles[i] == "" {
			s.protoRoles[i] = messages[i].Role
		}
		s.toolDef[i] = messages[i].SecuritySource == "tool_def" || strings.HasPrefix(messages[i].SecuritySourcePath, "/tools")
	}
	return s
}

// snapshotRawInputForInspection 按检测列表的同一顺序快照：请求消息之后追加 tools 定义
// （与 inspectionMessagesWithTools 的追加方式一致；未开启"检查内置上下文"时这些位置不会被检测）。
func snapshotRawInputForInspection(req *ChatCompletionRequest) rawInputSnapshot {
	all := inspectionMessagesWithTools(req, inspectionscope.Policy{InspectBuiltinContext: true})
	return snapshotRawInput(all)
}

// group 是留证单位：协议消息序号（>=0）、system 段（-1）、工具定义段（-2）。
func (s rawInputSnapshot) group(position int) int {
	if position < 0 || position >= len(s.proto) {
		return rawEvidenceNoProtocolIndex
	}
	if s.proto[position] >= 0 {
		return s.proto[position]
	}
	if s.toolDef[position] {
		return rawEvidenceToolDefIndex
	}
	return rawEvidenceNoProtocolIndex
}

// members 返回一个留证单位的网关位置。协议消息与 system 段取全部；工具定义段只取 only 中给出的
// （命中或被改写的那几段），不把无关工具定义拼进来。
func (s rawInputSnapshot) members(group int, only map[int]bool) []int {
	var out []int
	for i := range s.proto {
		if s.group(i) != group {
			continue
		}
		if group == rawEvidenceToolDefIndex && !only[i] {
			continue
		}
		out = append(out, i)
	}
	return out
}

// protocolText 拼出一条留证的原文（多条网关消息按顺序以换行连接，跳过空文本）。
func (s rawInputSnapshot) protocolText(positions []int) string {
	parts := make([]string, 0, len(positions))
	for _, i := range positions {
		if s.texts[i] != "" {
			parts = append(parts, s.texts[i])
		}
	}
	return strings.Join(parts, "\n")
}

func ledgerBlock(ctx context.Context) (blockID string, fallback []SecurityFinding) {
	ledger := blockLedgerFromContext(ctx)
	if ledger == nil {
		return "", nil
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.entry == nil {
		return "", nil
	}
	return ledger.entry.BlockID, []SecurityFinding{{RuleID: ledger.entry.RuleID, RuleName: ledger.entry.RuleName, Category: ledger.entry.Category}}
}

// hitGroup：有网关位置按位置归组；没有位置（不是逐条检测里写的事件）按命中带回的协议序号。
func (s rawInputSnapshot) hitGroup(hit rawEvidenceHit) (int, bool) {
	if hit.position >= 0 && hit.position < len(s.proto) {
		return s.group(hit.position), true
	}
	if hit.finding.MessageIndex != nil && *hit.finding.MessageIndex >= 0 {
		return *hit.finding.MessageIndex, true
	}
	return 0, false
}

// retainRawInput 在输入安全检查结束后调用。
//   - 被阻断：只有阻断类命中所在的那几段按 blocked 留证（带阻断编号）；阻断命中没有落在任何消息上
//     （如附件清单、外部策略）时留存最后一条用户消息。
//   - 同一请求里其他文本被脱敏改写的消息，不论是否阻断都按 masked 留证，规则只取脱敏类命中。
func (h *ChatCompletionsHandler) retainRawInput(ctx context.Context, envelope *modelrouter.RequestEnvelope, before rawInputSnapshot, after []Message, blocked bool, collector *rawEvidenceCollector) {
	if h == nil || h.auditWriter == nil || envelope == nil {
		return
	}
	writer, ok := h.auditWriter.(rawEvidenceWriter)
	if !ok {
		return
	}
	hits := collector.snapshot()
	blockID, ledgerFindings := ledgerBlock(ctx)

	attribution := func(group int, blocking bool) (ids, names, cats []string) {
		var matched, sameClass []SecurityFinding
		for _, hit := range hits {
			if hit.blocking != blocking {
				continue
			}
			sameClass = append(sameClass, hit.finding)
			if g, ok := before.hitGroup(hit); ok && g == group {
				matched = append(matched, hit.finding)
			}
		}
		switch {
		case len(matched) > 0:
			return ruleAttribution(matched, -1)
		case len(sameClass) > 0:
			return ruleAttribution(sameClass, -1)
		case blocking:
			return ruleAttribution(ledgerFindings, -1)
		}
		return nil, nil, nil
	}
	emit := func(group int, only map[int]bool, disposition string) bool {
		positions := before.members(group, only)
		if len(positions) == 0 {
			return false
		}
		text := before.protocolText(positions)
		if text == "" {
			return false
		}
		ids, names, cats := attribution(group, disposition == rawEvidenceBlocked)
		rec := RawEvidenceRecord{Direction: rawEvidenceInput, Role: before.protoRoles[positions[0]], Index: group, Disposition: disposition,
			Text: text, RuleIDs: ids, RuleNames: names, Categories: cats}
		if disposition == rawEvidenceBlocked {
			rec.BlockID = blockID
		}
		writer.WriteRawEvidence(ctx, envelope, rec)
		return true
	}

	blockedGroups := map[int]bool{}
	if blocked {
		toolHits := map[int]bool{}
		for _, hit := range hits {
			if !hit.blocking {
				continue
			}
			if g, ok := before.hitGroup(hit); ok {
				blockedGroups[g] = true
				if g == rawEvidenceToolDefIndex {
					toolHits[hit.position] = true
				}
			}
		}
		emitted := false
		for _, group := range sortedIntKeys(blockedGroups) {
			emitted = emit(group, toolHits, rawEvidenceBlocked) || emitted
		}
		if !emitted {
			// 阻断命中没有落在本请求的任何消息上：留存最后一条用户消息。
			for i := len(before.texts) - 1; i >= 0; i-- {
				if strings.EqualFold(before.roles[i], "user") && before.texts[i] != "" {
					blockedGroups[before.group(i)] = true
					emit(before.group(i), nil, rawEvidenceBlocked)
					break
				}
			}
		}
	}
	changed := map[int]bool{}
	changedTools := map[int]bool{}
	for i := range after {
		if i < len(before.texts) && before.texts[i] != "" && messageText(after[i].Content) != before.texts[i] {
			g := before.group(i)
			changed[g] = true
			if g == rawEvidenceToolDefIndex {
				changedTools[i] = true
			}
		}
	}
	for _, group := range sortedIntKeys(changed) {
		if blockedGroups[group] {
			continue
		}
		emit(group, changedTools, rawEvidenceMasked)
	}
}

func sortedIntKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// ---- 输出：对比脱敏前后的 choice 文本；被阻断时留存原始回复 ----

type rawOutputChoice struct {
	text      string
	toolCalls int
}

func rawOutputChoices(body []byte) []rawOutputChoice {
	var resp ChatCompletionResponse
	if len(body) == 0 || json.Unmarshal(body, &resp) != nil {
		return nil
	}
	out := make([]rawOutputChoice, len(resp.Choices))
	for i, choice := range resp.Choices {
		text := choice.Message.Content
		if choice.Message.ReasoningContent != "" {
			if text != "" {
				text += "\n"
			}
			text += choice.Message.ReasoningContent
		}
		out[i] = rawOutputChoice{text: text, toolCalls: len(choice.Message.ToolCalls)}
	}
	return out
}

func (h *ChatCompletionsHandler) retainRawOutput(ctx context.Context, envelope *modelrouter.RequestEnvelope, rawBody, securedBody []byte, audit *AuditResult, blocked bool) {
	if h == nil || h.auditWriter == nil || envelope == nil {
		return
	}
	writer, ok := h.auditWriter.(rawEvidenceWriter)
	if !ok {
		return
	}
	raw := rawOutputChoices(rawBody)
	if len(raw) == 0 {
		return
	}
	secured := rawOutputChoices(securedBody)
	var findings []SecurityFinding
	if audit != nil {
		for _, f := range audit.OutputFindings {
			finding := SecurityFinding{}
			finding.RuleID, _ = f["rule_id"].(string)
			finding.RuleName, _ = f["rule_name"].(string)
			finding.Category, _ = f["category"].(string)
			findings = append(findings, finding)
		}
	}
	blockID, ledgerFindings := ledgerBlock(ctx)
	if len(findings) == 0 && blocked {
		findings = ledgerFindings
	}
	for i, choice := range raw {
		text := choice.text
		if text == "" {
			continue
		}
		disposition := rawEvidenceMasked
		if blocked {
			disposition = rawEvidenceBlocked
		} else if i >= len(secured) || secured[i].text == text {
			continue
		} else if choice.toolCalls > 0 && secured[i].toolCalls == 0 {
			// 破坏性工具调用全部被拦、正文换成了拦截提示：这是工具拦截，不是脱敏改写。
			continue
		}
		ids, names, cats := ruleAttribution(findings, -1)
		rec := RawEvidenceRecord{Direction: rawEvidenceOutput, Role: "assistant", Index: i, Disposition: disposition, Text: text,
			RuleIDs: ids, RuleNames: names, Categories: cats}
		if blocked {
			rec.BlockID = blockID
		}
		writer.WriteRawEvidence(ctx, envelope, rec)
	}
}

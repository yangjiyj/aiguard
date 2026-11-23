import { renderToStaticMarkup } from "react-dom/server"
import { describe, expect, it } from "vitest"
import { buildRuleEvidences, findRelatedLogs, formatEvidenceLocation, renderEvidenceContext } from "../utils/contentAuditEvidence"

describe("content audit structured evidence anchors", () => {
  it("keeps each finding's own severity and does not borrow an event maximum", () => {
    const evidence = buildRuleEvidences([{ id: 'mixed', severity: 'critical', matched_summary: {
      summary: 'summary of a different critical finding', findings: [
        { category: 'secret', severity: 'critical' },
        { category: 'pii_email', severity: 'low', reason: 'email only' },
        { category: 'pii_phone' },
        { category: 'pii_email', severity: 'critical', effective_severity: 'low' },
      ],
    } }])
    expect(evidence.map((item) => item.severity)).toEqual(['critical', 'low', '', 'low'])
    expect(evidence[1].summary).toBe('email only')
    expect(evidence[2].summary).toBe('')
  })

  it("leaves null and missing indexes unknown instead of inventing the first message", () => {
    const evidence = buildRuleEvidences([{ id: 'legacy', matched_summary: { findings: [
      { category: 'pii_email', message_index: null, attachment_index: null },
      { category: 'pii_email', message_index: '', attachment_index: '' },
    ] } }])
    for (const item of evidence) {
      expect(item.messageIndex).toBeUndefined()
      expect(item.attachmentIndex).toBeUndefined()
    }
  })
  it("uses the actual gateway action instead of the rule suggested action", () => {
    const evidence = buildRuleEvidences([{ id: "audit-event", action_taken: "audit", matched_summary: { findings: [{ type: "secret", category: "secret", severity: "high", action: "block" }] } } as any])
    expect(evidence[0].action).toBe("audit")
    const unknown = buildRuleEvidences([{ id: "unknown-event", matched_summary: { findings: [{ type: "secret", action: "block" }] } } as any])
    expect(unknown[0].action).toBe("")
  })
  it("carries event-owned unredacted context when ordinary retention is absent", () => {
    const evidences = buildRuleEvidences([{
      id: "evt-context",
      request_id: "req-context",
      matched_summary: {
        findings: [{
          type: "secret",
          category: "openai_key",
          rule_id: "secret-openai",
          raw_evidence: "sk-live-value",
          evidence_context: "tool output before sk-live-value after",
        }],
      },
    } as any])

    expect(evidences[0].preview).toBe("sk-live-value")
    expect(evidences[0].evidenceContext).toBe("tool output before sk-live-value after")
  })

  it("preserves zero indexes and links only the exact first message", () => {
    const evidences = buildRuleEvidences([{
      id: "evt-1",
      request_id: "req-1",
      matched_summary: { findings: [{
        category: "file_content_uninspected",
        message_index: 0,
        message_role: "user",
        attachment_index: 0,
        matched_location: "attachment[0]:image.png",
      }] },
    } as any])
    const logs = [
      { id: "cl-1", request_id: "req-1", message_index: 0, role: "user", content: "first", created_at: "2026-08-23T00:00:00Z" },
      { id: "cl-2", request_id: "req-1", message_index: 1, role: "assistant", content: "second", created_at: "2026-08-23T00:00:01Z" },
      { id: "cl-3", request_id: "req-1", message_index: 2, role: "user", content: "third", created_at: "2026-08-23T00:00:02Z" },
    ]

    expect(evidences[0].messageIndex).toBe(0)
    expect(evidences[0].attachmentIndex).toBe(0)
    expect(findRelatedLogs(evidences[0], logs as any).map((item) => item.id)).toEqual(["cl-1"])
    expect(formatEvidenceLocation(evidences[0])).toContain("第 1 条 user消息 / 附件 1")
  })

  it("does not point at an unanchored log when the finding has index zero", () => {
    const evidence = { requestId: "req-1", messageIndex: 0, messageRole: "user" } as any
    const logs = [
      { id: "legacy-cl", request_id: "req-1", role: "user", content: "same request but no anchor", created_at: "2026-08-23T00:00:00Z" },
    ]
    expect(findRelatedLogs(evidence, logs as any)).toEqual([])
  })

  it("does not expand an anchored finding to every log in the request", () => {
    const evidence = { requestId: "req-1", messageIndex: 1, messageRole: "assistant" } as any
    const logs = [
      { id: "cl-1", request_id: "req-1", message_index: 0, role: "user", content: "first", created_at: "2026-08-23T00:00:00Z" },
      { id: "cl-2", request_id: "req-1", message_index: 1, role: "assistant", content: "second", created_at: "2026-08-23T00:00:01Z" },
    ]
    expect(findRelatedLogs(evidence, logs as any).map((item) => item.id)).toEqual(["cl-2"])
  })

  it("returns empty when a structured anchor has no exact role match", () => {
    const evidence = { requestId: "req-1", messageIndex: 1, messageRole: "user", preview: "second" } as any
    const logs = [
      { id: "cl-1", request_id: "req-1", message_index: 0, role: "user", content: "first", created_at: "2026-08-23T00:00:00Z" },
      { id: "cl-2", request_id: "req-1", message_index: 1, role: "assistant", content: "second", created_at: "2026-08-23T00:00:01Z" },
    ]
    expect(findRelatedLogs(evidence, logs as any)).toEqual([])
  })

  it("constrains a location-derived index to the same request and role", () => {
    const evidence = { requestId: "req-1", location: "第 2 条 tool消息 / content[0:4]" } as any
    const logs = [
      { id: "other-0", request_id: "req-other", role: "user", content: "other", created_at: "2026-08-23T00:00:00Z" },
      { id: "other-1", request_id: "req-other", role: "tool", content: "wrong request", created_at: "2026-08-23T00:00:01Z" },
      { id: "req-1-user", request_id: "req-1", role: "user", content: "first", created_at: "2026-08-23T00:00:02Z" },
      { id: "req-1-tool", request_id: "req-1", role: "tool", content: "target", created_at: "2026-08-23T00:00:03Z" },
    ]
    expect(findRelatedLogs(evidence, logs as any).map((item) => item.id)).toEqual(["req-1-tool"])
  })

  it("links an anchored finding to whole-segment retained content instead of reporting a broken chain", () => {
    // 留存详情由整段 request_content 拼接而成,没有逐消息 message_index。
    // 之前这里会硬 return [],导致明明有留存正文却报"证据链不完整"。
    const evidence = { requestId: "req-1", messageIndex: 1, messageRole: "user", preview: "git@gitee.com" } as any
    const logs = [
      { id: "req-1-request", request_id: "req-1", role: "user", content: "contact git@gitee.com now", created_at: "2026-08-23T00:00:00Z", whole_segment: true },
      { id: "req-1-response", request_id: "req-1", role: "assistant", content: "ok", created_at: "2026-08-23T00:00:01Z", whole_segment: true },
    ]
    expect(findRelatedLogs(evidence, logs as any).map((item) => item.id)).toEqual(["req-1-request"])
  })

  it("falls back to the whole retained segment when the anchored role does not match", () => {
    const evidence = { requestId: "req-1", messageIndex: 2, messageRole: "tool" } as any
    const logs = [
      { id: "req-1-request", request_id: "req-1", role: "user", content: "tool output embedded here", created_at: "2026-08-23T00:00:00Z", whole_segment: true },
    ]
    expect(findRelatedLogs(evidence, logs as any).map((item) => item.id)).toEqual(["req-1-request"])
  })

  it("still refuses to guess when a per-message log is missing its anchor", () => {
    // 逐消息留存缺锚点属于数据异常,必须保持严格匹配,不能借整段降级把证据指向错误消息。
    const evidence = { requestId: "req-1", messageIndex: 1, messageRole: "user" } as any
    const logs = [
      { id: "cl-1", request_id: "req-1", role: "user", content: "no anchor", created_at: "2026-08-23T00:00:00Z" },
    ]
    expect(findRelatedLogs(evidence, logs as any)).toEqual([])
  })

  it("renders an actual mark only for a confirmed evidence context", () => {
    const evidence = { location: "第 1 条 user消息 / content[7:13]" } as any
    const html = renderToStaticMarkup(renderEvidenceContext("prefix target suffix", evidence) as any)
    expect(html).toContain("<mark")
    expect(html).toContain(">target</mark>")
  })

  it("does not expose semantic runtime telemetry as dangerous evidence", () => {
    const evidences = buildRuleEvidences([{
      id: "evt-runtime",
      request_id: "req-1",
      matched_summary: {
        findings: [{
          type: "semantic_telemetry",
          category: "semantic_unavailable",
          rule_id: "semantic_runtime_unavailable",
          counts_as_security_finding: false,
          message_index: 1,
          message_role: "user",
        }],
      },
    } as any])
    expect(evidences).toEqual([])
  })

  it("does not link dangerous evidence to WorkBuddy internal user-context", () => {
    const evidence = { requestId: "req-1", messageIndex: 1, messageRole: "user" } as any
    const logs = [{
      id: "cl-context",
      request_id: "req-1",
      message_index: 1,
      role: "user",
      content: '<system-reminder data-role="user-context"><user_info>internal</user_info></system-reminder>',
      created_at: "2026-08-29T03:20:17Z",
    }]
    expect(findRelatedLogs(evidence, logs as any)).toEqual([])
  })
})

import { describe, expect, it } from 'vitest'
import { securityModeLabel } from '../services/securityExecutionMode'
import type { AlertOccurrence } from '../services/alertOccurrences'
import { notificationActionLabel } from '../utils/alertInboxDisplay'
import { getFindingCategoryLabel } from '../utils/alertOccurrenceDisplay'
import {
  alertActionResult, alertHitText, alertCaseLine, alertCaseSource, alertRuleDisplayName, alertRuleActionLabel, alertRuleActionDiffers, alertCaseTitle, alertEvidenceSummary,
  GATEWAY_REASON_LABELS, readableHitText, readableReasonCode, stripSeverityExplanation,
} from '../utils/alertReadable'
import { getReadableToolReason, getRiskCategoryLabel } from '../utils/risk'

const item = (overrides: Partial<AlertOccurrence>) => ({
  type: 'custom', category: 'customer_sensitive_data', rule_name: '密钥相关', rule_name_count: 1,
  redacted_evidence: 'PA****RD (sha256:0be64ae8)', evidence_status: 'available', event_action_taken: 'security_audit',
  ...overrides,
}) as AlertOccurrence

describe('alert readable text', () => {
  it('drops the severity explanation the 2.9.16 engine appended as 策略基准 / 本次风险', () => {
    expect(stripSeverityExplanation('命中口令字段；策略基准：高危；本次风险：中风险（规则风险分级；是否有效、是否复核请查看判定依据）')).toBe('命中口令字段')
    expect(stripSeverityExplanation('策略基准：高危；本次风险：高危（规则风险分级；是否有效、是否复核请查看判定依据）')).toBe('')
    expect(stripSeverityExplanation('命中口令字段；策略级别：高危；告警级别：中危（只命中字段名，未见真实值）')).toBe('命中口令字段')
    expect(stripSeverityExplanation('说明里提到本次风险：较低，但没有策略基准')).toBe('说明里提到本次风险：较低，但没有策略基准')
  })

  it('titles a case by its rule name', () => {
    expect(alertCaseTitle(item({}))).toBe('密钥相关')
    expect(alertCaseTitle(item({ rule_name_count: 3 }))).toBe('密钥相关 等 3 条')
  })

  it('falls back to the category for generic names and tool events', () => {
    expect(alertCaseTitle(item({ rule_name: '自定义' }))).toBe('客户敏感数据')
    expect(alertCaseTitle(item({ type: 'tool_destructive_intent', category: 'destructive_change', rule_name: 'Bash' }))).toBe('删除与破坏操作')
    expect(alertCaseTitle(item({ rule_name: '' }))).toBe('客户敏感数据')
  })

  it('keeps the suspicion marker for model-judged findings', () => {
    expect(alertCaseTitle(item({ type: 'catalog_policy', category: 'code_xss_generation', rule_name: 'XSS 代码生成' }))).toBe('疑似XSS 代码生成')
  })

  it('never titles a case with a bare tool name', () => {
    const cases: Array<[Partial<AlertOccurrence>, string]> = [
      [{ type: 'tool_policy_alert', category: 'agent_behavior_policy', rule_name: 'Bash' }, '智能体行为策略告警'],
      [{ type: 'security_audit', category: 'restricted_file_access', rule_name: 'Read' }, '受限文件访问'],
      [{ type: 'security_audit', category: 'agentguard_confirmation', rule_name: 'Bash' }, '人工确认后放行一次'],
      [{ type: 'coverage_gap', category: 'agent_permission_governance', rule_name: 'Bash' }, '智能体权限治理'],
    ]
    for (const [overrides, title] of cases) expect(alertCaseTitle(item(overrides))).toBe(title)
  })

  it('keeps block-reason rule names for blocked tool attempts', () => {
    expect(alertCaseTitle(item({ type: 'tool_attempt_blocked', category: 'tool_attempt_blocked', rule_name: '删除与破坏' }))).toBe('删除与破坏')
  })

  it('does not show internal ids as a rule name', () => {
    expect(alertCaseTitle(item({ rule_name: 'block_model_egress' }))).toBe('客户敏感数据')
    expect(alertCaseTitle(item({ rule_name: 'disable_mcp' }))).toBe('客户敏感数据')
    expect(alertCaseTitle(item({ rule_name: 'rule_9f3a1c' }))).toBe('客户敏感数据')
    expect(alertCaseTitle(item({ rule_name: 'Rule 1' }))).toBe('Rule 1')
  })

  it('never shows spliced English for unknown agent and semantic categories', () => {
    expect(alertCaseTitle(item({ rule_name: '', category: 'agent_brand_new' }))).toBe('其他风险')
    expect(alertCaseTitle(item({ rule_name: '', category: 'semantic_brand_new' }))).toBe('疑似其他风险')
    expect(getRiskCategoryLabel('agent_brand_new')).toContain('brand')
  })

  it('never shows a raw category code in the title', () => {
    expect(alertCaseTitle(item({ rule_name: '', category: 'brand_new_category' }))).toBe('其他风险')
    expect(alertCaseTitle(item({ rule_name: '', category: '' , type: 'brand_new_type' }))).toBe('其他风险')
    expect(alertCaseTitle(item({ rule_name: '', category: 'agent_tool_failure_loop' }))).toBe('智能体工具连续失败')
  })

  describe('hit text', () => {
    it('translates the tool and target summary once', () => {
      expect(readableHitText('filesystem_overwrite:1-targets')).toBe('覆盖文件（1 个目标）')
      expect(readableHitText('Bash · filesystem_overwrite:1-targets')).toBe('Bash · 覆盖文件（1 个目标）')
      expect(readableHitText('Bash · filesystem_delete:target-incomplete')).toBe('Bash · 删除文件（目标未解析）')
      expect(readableHitText('Bash · mystery_op:2-targets')).toBe('Bash · 破坏性操作（2 个目标）')
    })

    it('leaves everything else untouched', () => {
      expect(readableHitText('覆盖文件：cat a > b')).toBe('覆盖文件：cat a > b')
      expect(readableHitText('Bash · rm -rf /tmp/x')).toBe('Bash · rm -rf /tmp/x')
      expect(readableHitText('用户输入 · explicit_block')).toBe('用户输入 · explicit_block')
      expect(readableHitText('C:/a/b:target-incomplete')).toBe('C:/a/b:target-incomplete')
      expect(readableHitText('a · b · filesystem_delete:1-targets')).toBe('a · b · filesystem_delete:1-targets')
      expect(readableHitText(undefined)).toBe('')
      expect(readableHitText(null as unknown as string)).toBe('')
      expect(readableHitText(42 as unknown as string)).toBe('42')
    })
  })

  describe('reason codes', () => {
    it('states the real outcome for fail-closed and confirmation codes', () => {
      // 2.9.22：文案改为防护项名称，处置结果由防护项动作决定。
      expect(readableReasonCode('confirm_without_channel_fail_closed')).toBe('需要确认但无法确认')
      expect(readableReasonCode('destructive_confirmation_extension_required')).toBe('需人工确认，但客户端不支持确认扩展，已阻断')
      expect(readableReasonCode('analyzer_high_risk_block')).toBe('判定为高风险调用，已阻断')
      expect(readableReasonCode('destructive_alert_allow')).toBe('按策略仅告警，已放行')
      expect(readableReasonCode('agentguard_policy_load_failed')).toBe('策略加载失败')
    })

    it('names policy sources consistently', () => {
      expect(readableReasonCode('explicit_block')).toBe('智能体行为策略要求阻断')
      expect(readableReasonCode('explicit_confirm')).toBe('智能体行为策略要求人工确认')
      expect(readableReasonCode('explicit_audit')).toBe('智能体行为策略要求放行并留痕')
      expect(readableReasonCode('explicit_allow')).toBe('智能体行为策略要求放行')
      expect(readableReasonCode('would-block')).toBe('按策略应阻断，当前模式仅记录')
      expect(readableReasonCode('would-confirm')).toBe('按策略应人工确认，当前模式仅记录')
      expect(readableReasonCode('destructive_global_audit_only_recorded')).toBe(`${securityModeLabel('record')}模式，仅记录`)
      expect(readableReasonCode('analyzer_default')).toBe('按风险分析默认处置')
      expect(readableReasonCode('analyzer_result')).toBe('按风险分析结果处置')
    })

    it('covers the codes the gateway writes into alert reasons', () => {
      for (const code of ['human_approved_confirmation_consumed', 'tool_policy_recorded', 'blocked_cloud_metadata', 'destructive_command_requires_confirm', 'analyzer_high_risk_recorded', 'approval_context_drift', 'policy_fail_closed', 'skill_admission_floor', 'exception_downgrade', 'restricted_file_explicit_block', 'global_default', 'analyzer_unconfigured_alert_only', 'destructive_parse_rejected_fail_safe']) {
        expect(GATEWAY_REASON_LABELS[code], code).toBeTruthy()
        expect(readableReasonCode(code), code).toMatch(/[\u4e00-\u9fa5]/)
      }
    })

    it('states exact outcomes and facts without a verdict', () => {
      expect(readableReasonCode('approval_context_drift')).toBe('确认后调用内容有变化，已阻断')
      expect(readableReasonCode('mcp_confirmation_policy_recorded')).toBe('当前策略要求阻断，当前模式仅记录')
      expect(readableReasonCode('tool_policy_recorded')).toBe('按策略应阻断或确认，当前模式仅记录')
      expect(readableReasonCode('policy_runtime_unavailable')).toBe('策略运行时不可用，已阻断')
      expect(readableReasonCode('analyzer_unconfigured_alert_only')).toBe('未配置阻断规则，告警放行')
      expect(readableReasonCode('scoped_mutation_requires_confirm')).toBe('带条件的数据修改')
      expect(readableReasonCode('shell_interpolation_requires_confirm')).toBe('命令含变量或命令替换')
      expect(readableReasonCode('unknown_sql_requires_audit')).toBe('无法识别的 SQL 语句')
      for (const code of Object.keys(GATEWAY_REASON_LABELS)) {
        if (/requires_(confirm|audit)/.test(code)) expect(GATEWAY_REASON_LABELS[code], code).not.toMatch(/需人工确认|需留痕/)
      }
      expect(GATEWAY_REASON_LABELS).not.toHaveProperty('policy_block')
    })

    it('translates composite codes by prefix', () => {
      expect(readableReasonCode('would-block:tool_name_policy_block')).toBe('按策略应阻断，当前模式仅记录（命中工具名称阻断策略）')
      expect(readableReasonCode('would-confirm:some_future_reason')).toBe('按策略应人工确认，当前模式仅记录')
      expect(readableReasonCode('mcp_redline_block:rm_rf,drop_table')).toBe('命中 MCP 红线阻断规则')
      expect(readableReasonCode('semantic_capability:vision,tools')).toBe('线路不支持本次请求所需的能力')
      expect(readableReasonCode('mystery_prefix:inner')).toBe('')
      expect(getReadableToolReason('would-block:tool_name_policy_block')).toBe('按策略应阻断，当前模式仅记录（命中工具名称阻断策略）')
    })

    it('translates the gateway confirmation replay sentence', () => {
      expect(readableReasonCode('human approved; execution awaits client retry')).toBe('人工确认通过，等待客户端重试执行')
    })

    it('shows nothing for unknown codes and keeps plain text', () => {
      expect(readableReasonCode('some_future_reason')).toBe('')
      expect(readableReasonCode('Some.Future-reason:1,2')).toBe('')
      expect(getReadableToolReason('some_future_reason')).toBe('按工具安全策略命中')
      expect(readableReasonCode('命中自定义规则')).toBe('命中自定义规则')
      expect(readableReasonCode('')).toBe('')
      expect(readableReasonCode(undefined)).toBe('')
    })

    it('is the one dictionary behind the tool reason helper', () => {
      for (const code of Object.keys(GATEWAY_REASON_LABELS)) expect(getReadableToolReason(code), code).toBe(GATEWAY_REASON_LABELS[code])
      for (const code of Object.keys(GATEWAY_REASON_LABELS)) expect(readableReasonCode(code), code).toBe(GATEWAY_REASON_LABELS[code])
    })
  })

  describe('action result', () => {
    it('uses completed-state wording with one word for block', () => {
      for (const value of ['block', 'blocked', 'deny', 'security_blocked', 'stream_blocked', 'tool_attempt_blocked', 'tool_blocked', 'mcp_tool_result_blocked', 'mcp_server_request_blocked']) expect(alertActionResult(value), value).toBe('已阻断')
      for (const value of ['mask', 'redact', 'security_masked']) expect(alertActionResult(value), value).toBe('已脱敏')
      for (const value of ['reply', 'security_replied']) expect(alertActionResult(value), value).toBe('安全代答')
      for (const value of ['audit', 'security_audit', 'tool_audited', 'tool_audit_only']) expect(alertActionResult(value), value).toBe('仅记录')
      expect(alertActionResult('confirm')).toBe('要求人工确认')
      expect(alertActionResult('rewrite')).toBe('已改写')
      for (const value of ['alert', 'flag', 'flagged']) expect(alertActionResult(value), value).toBe('告警放行')
      expect(alertActionResult('quarantine')).toBe('已隔离')
      expect(alertActionResult('security_check_failed')).toBe('检测异常')
      expect(alertActionResult('security_output_check_failed')).toBe('输出检测异常')
      expect(alertActionResult('mcp_tools_list_filtered')).toBe('已过滤工具列表')
      expect(alertActionResult('agentguard_policy_load_failed')).toBe('策略加载失败')
    })

    it('tells empty from unknown', () => {
      expect(alertActionResult('')).toBe('未记录处置结果')
      expect(alertActionResult(undefined)).toBe('未记录处置结果')
      expect(alertActionResult('unknown')).toBe('未记录处置结果')
      expect(alertActionResult('brand_new_action')).toBe('其他处置')
    })

    it('is what the message center shows', () => {
      for (const value of ['block', 'mask', 'audit', 'allow', 'security_blocked', 'security_replied', 'something_else']) expect(notificationActionLabel(value)).toBe(alertActionResult(value))
      expect(notificationActionLabel('')).toBe('未记录')
    })
  })

  describe('rule action', () => {
    it('names the configured rule action, not a completed result', () => {
      expect(alertRuleActionLabel('block')).toBe('阻断')
      expect(alertRuleActionLabel('deny')).toBe('阻断')
      expect(alertRuleActionLabel('redact')).toBe('脱敏')
      expect(alertRuleActionLabel('security_audit')).toBe('仅记录')
      expect(alertRuleActionLabel('flag')).toBe('告警放行')
      expect(alertRuleActionLabel('allow')).toBe('放行')
      expect(alertRuleActionLabel('confirm')).toBe('人工确认')
      expect(alertRuleActionLabel('reply')).toBe('安全代答')
      expect(alertRuleActionLabel('rewrite')).toBe('改写')
      expect(alertRuleActionLabel('')).toBe('')
      expect(alertRuleActionLabel('unknown')).toBe('')
    })

    it('compares the rule action with the actual outcome by meaning', () => {
      expect(alertRuleActionDiffers('block', 'tool_attempt_blocked')).toBe(false)
      expect(alertRuleActionDiffers('block', 'audit')).toBe(true)
      expect(alertRuleActionDiffers('audit', 'security_audit')).toBe(false)
      expect(alertRuleActionDiffers('', 'block')).toBe(false)
      expect(alertRuleActionDiffers('alert', 'audit')).toBe(true)
      expect(alertRuleActionDiffers('audit', 'alert')).toBe(true)
      expect(alertRuleActionDiffers('confirm', 'block')).toBe(true)
      expect(alertRuleActionDiffers('block', 'confirm')).toBe(true)
      expect(alertRuleActionDiffers('confirm', 'confirm')).toBe(false)
      expect(alertRuleActionDiffers('audit', 'security_audit_only')).toBe(false)
      expect(alertRuleActionDiffers('block', 'security_audit_only')).toBe(true)
    })

    it('hides the audit rule action of agent tool alerts, which is ambiguous with alert-and-pass', () => {
      expect(alertRuleActionLabel('audit', 'agentguard')).toBe('')
      expect(alertRuleActionLabel('block', 'agentguard')).toBe('阻断')
      expect(alertRuleActionLabel('audit', 'regex')).toBe('仅记录')
      expect(alertRuleActionDiffers('audit', 'alert', 'agentguard')).toBe(false)
    })
  })

  describe('integration policy categories', () => {
    it('names the unapproved model egress and MCP policy categories', () => {
      expect(getRiskCategoryLabel('unapproved_model_egress')).toBe('未批准的模型调用')
      expect(getRiskCategoryLabel('mcp_policy')).toBe('MCP 禁用策略命中')
    })
  })

  describe('source and hit rule name', () => {
    it('reads the source from content source, then the hit location, then the message role', () => {
      const o = (x: Record<string, unknown>) => ({ content_source: '', message_role: '', matched_location: '', ...x }) as never
      expect(alertCaseSource(o({ content_source: 'tool_result' }))).toBe('工具返回')
      expect(alertCaseSource(o({ content_source: 'mystery' }))).toBe('')
      expect(alertCaseSource(o({ message_role: 'assistant' }))).toBe('模型输出')
      expect(alertCaseSource(o({ message_role: 'tool' }))).toBe('工具返回')
      // Claude Messages 协议下工具返回的原始角色是 user，没有来源字段和位置时不能断定是用户输入。
      expect(alertCaseSource(o({ message_role: 'user' }))).toBe('')
      expect(alertCaseSource(o({ message_role: 'system' }))).toBe('内置上下文')
      expect(alertCaseSource(o({ message_role: 'user', matched_location: 'tool_call[0]' }))).toBe('工具调用')
      expect(alertCaseSource(o({ content_source: 'tool_result', message_role: 'user' }))).toBe('工具返回')
      expect(alertCaseSource(o({ matched_location: 'tool_call[0]' }))).toBe('工具调用')
      expect(alertCaseSource(o({ matched_location: 'tool_result[0]' }))).toBe('工具返回')
    })

    it('names the hit rule: cleaned rule name, then the link label, then the category', () => {
      const f = (x: Record<string, unknown>) => alertRuleDisplayName({ type: 'custom', category: 'agent_behavior_policy', rule_name: '', ...x } as never)
      expect(f({ rule_name: '密钥相关', category: 'customer_sensitive_data' })).toBe('密钥相关')
      expect(f({ rule_name: 'Bash' })).toBe('智能体行为策略告警')
      expect(f({ rule_name: 'Bash', policy_link: { kind: 'agent_behavior', path: '/x', label: '删除与破坏' } })).toBe('删除与破坏')
      expect(f({ rule_name: 'block_model_egress', policy_link: { kind: 'none', label: 'block_model_egress' } })).not.toContain('block_model_egress')
      expect(f({ rule_name: '自定义', category: 'customer_sensitive_data', policy_link: { kind: 'policy', path: '/x', label: '客户敏感数据策略' } })).toBe('客户敏感数据策略')
    })
  })

  describe('one line reason', () => {
    it('says what was matched, what happened and where', () => {
      expect(alertEvidenceSummary(item({ evidence_status: 'restricted' }))).toBe('无权查看命中内容')
      expect(alertEvidenceSummary(item({ redacted_evidence: '' }))).toBe('未记录命中内容')
      expect(alertEvidenceSummary(item({ redacted_evidence: undefined as unknown as string }))).toBe('未记录命中内容')
    })

    it('drops empty segments on the card line instead of writing "not recorded"', () => {
      const tool = (o: Partial<AlertOccurrence>) => item({ redacted_evidence: '', event_action_taken: 'alert', content_source: '', stage: '', matched_location: 'tool_call[0]', ...o } as never)
      expect(alertCaseLine(tool({}))).toBe('告警放行 · 工具调用')
      expect(alertCaseLine(tool({ stage: 'tool' }))).toBe('告警放行 · 工具调用 · 工具检测')
      expect(alertCaseLine(tool({ event_action_taken: 'tool_attempt_blocked' }))).toBe('已阻断 · 工具调用')
      expect(alertCaseLine(tool({ event_action_taken: 'confirm' }))).toBe('要求人工确认 · 工具调用')
      expect(alertCaseLine(tool({ event_action_taken: 'agentguard_policy_load_failed' }))).toBe('策略加载失败 · 工具调用')
      expect(alertCaseLine(tool({ evidence_status: 'restricted' }))).toBe('无权查看命中内容 · 告警放行 · 工具调用')
      expect(alertCaseLine(tool({ event_action_taken: '', matched_location: '', content_source: 'unknown' }))).toBe('')
      expect(alertCaseLine(tool({ content_source: 'mystery_source', matched_location: '' }))).toBe('告警放行')
      expect(alertCaseLine(tool({ matched_location: 'tool_result[0]' }))).toBe('告警放行 · 工具返回')
      expect(alertCaseLine(item({ content_source: 'tool_result', stage: 'input', matched_location: '' } as never))).toBe('PA****RD (sha256:0be64ae8) · 仅记录 · 工具返回 · 输入检测')
    })

    it('cuts by character, not by code unit', () => {
      const text = '😀'.repeat(10)
      expect(alertEvidenceSummary(item({ redacted_evidence: text }), 10)).toBe(text)
      expect(alertEvidenceSummary(item({ redacted_evidence: text }), 4)).toBe(`${'😀'.repeat(4)}…`)
    })

    it('only needs the fields it reads', () => {
      expect(alertEvidenceSummary({ redacted_evidence: 'x', evidence_status: 'available' })).toBe('x')
    })
  })

  it('keeps one category wording across dictionaries', () => {
    for (const category of ['agent_behavior_policy', 'restricted_file_access', 'agentguard_confirmation', 'agent_permission_governance', 'agent_tool_failure_loop']) {
      expect(getRiskCategoryLabel(category)).toBe(getFindingCategoryLabel(category))
      expect(getRiskCategoryLabel(category)).not.toContain('其他风险')
    }
  })
})

describe('可读命中内容原样显示', () => {
  it.each([
    '-----BEGIN RSA PRIVATE KEY-----（后续正文 1,675 字已隐藏）',
    'password=ab****23（8 位）',
    'postgres://app:****@db.internal:5432/app',
    'sk-ab****9f（50 位）',
    '110105********1234',
  ])('%s', (text) => {
    expect(alertHitText({ redacted_evidence: text, evidence_status: 'available' } as never, 120)).toBe(text)
  })
})

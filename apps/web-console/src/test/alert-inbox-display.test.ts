import { describe, it, expect } from 'vitest'
import { INBOX_TYPE_LABELS, inboxTypeLabel, normalizeInboxItem, severityLabel, sourceLabel } from '../utils/alertInboxDisplay'
import { isConsoleAdministratorRole } from '../utils/access'

// 消息中心是客户直接可见的页面：现网实测会泄露英文的行（type=alert / governor 事件 / quota.admission.* / model_route_*）
// 必须全部转成中文标题与详情，且不得露出原始 reason、type 码或技术 id。
const ENGLISH_LEAK = /governor|reservation_overrun|runtime_fault|fail-open|model not allowed|timeout|quota error|soft quota|conservative|prov_/i

const row = (type: string, body: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  id: `id-${type}`, severity: 'warning', type, title: `governor 事件：${type}`, body_json: body, read_at: null,
  created_at: '2026-10-10T15:58:10Z', ...extra,
})

describe('normalizeInboxItem 中文化补漏', () => {
  it('安全事件类型的历史工具连续失败：用工具连续失败标题与证据，不带处置尾巴', () => {
    const n = normalizeInboxItem(row('security_event', { event_type: 'security_check', severity: 'low', rule_name: 'Bash', action: 'tool_failure_loop', category: 'agent_tool_failure_loop', primary_finding: { category: 'agent_tool_failure_loop', redacted_evidence: 'Bash 在窗口内失败 5 次' } }))
    expect(n.title).toBe('智能体工具连续失败')
    expect(n.detail).toBe('Bash 在窗口内失败 5 次')
  })

  it('安全事件的处置值不在字典里时省略整段处置，不写其他处置', () => {
    const n = normalizeInboxItem(row('security_event', { event_type: 'security_check', severity: 'low', rule_name: 'Bash', action: 'some_new_action' }))
    expect(n.title).not.toMatch(/处置/)
    expect(n.title).not.toMatch(/其他处置/)
    expect(normalizeInboxItem(row('security_event', { event_type: 'security_check', severity: 'low', action: 'block' })).title).toMatch(/处置：已阻断/)
  })

  it('未知严重度叫未分级，与告警卡片一致', () => {
    expect(severityLabel('whatever')).toBe('未分级')
    expect(severityLabel('')).toBe('未分级')
    expect(severityLabel('info')).toBe('提示')
  })

  it('type=alert + model not allowed for team：中文标题，仅告警时说明未阻断，来源/风险域归访问与额度治理', () => {
    const n = normalizeInboxItem(row('alert', { reason: 'model not allowed for team', alert_only: true }))
    expect(n.title).toBe('模型访问策略通知')
    expect(n.detail).toBe('当前团队模型策略仅告警，未阻断请求')
    expect(n.domain).toBe('access')
    expect(sourceLabel(n.source)).toBe('访问与额度治理')
  })

  it('model not allowed 且不是仅告警：说明当前团队不允许使用该模型', () => {
    const n = normalizeInboxItem(row('alert', { reason: 'model not allowed for team', alert_only: false }))
    expect(n.title).toBe('模型访问策略通知')
    expect(n.detail).toBe('当前团队不允许使用该模型')
  })

  it('旧的 governor.alert 行保持原有标题与详情', () => {
    const n = normalizeInboxItem(row('governor.alert', { reason: 'model not allowed for team', alert_only: true }))
    expect(n.title).toBe('模型访问策略通知')
    expect(n.detail).toBe('当前团队模型策略仅告警，未阻断请求')
    expect(n.domain).toBe('access')
    expect(sourceLabel(n.source)).toBe('访问与额度治理')
  })

  it.each([
    'fail-open: quota error: timeout: context deadline exceeded',
    'fail-open: timeout',
  ])('额度检查超时（%s）：标题说明已放行请求，不露英文', (reason) => {
    const n = normalizeInboxItem(row('alert', { reason }))
    expect(n.title).toBe('额度检查超时，已放行请求')
    expect(n.detail).toBe('额度检查超时，请求按放行处理')
    expect(`${n.title}${n.detail}`).not.toMatch(ENGLISH_LEAK)
    expect(n.domain).toBe('access')
  })

  it('quota.admission.reservation_overrun：额度预占不足通知，仅告警未阻断', () => {
    const n = normalizeInboxItem(row('quota.admission.reservation_overrun', { reason: 'actual token usage exceeded the conservative reservation' }))
    expect(n.title).toBe('额度预占不足通知')
    expect(n.detail).toBe('实际用量超过了预占额度（仅告警，未阻断）')
    expect(`${n.title}${n.detail}`).not.toMatch(ENGLISH_LEAK)
    expect(n.domain).toBe('access')
    expect(sourceLabel(n.source)).toBe('访问与额度治理')
  })

  it.each([
    'soft quota observation unavailable',
    'quota admission runtime fault',
  ])('quota.admission.runtime_fault（%s）：额度观测不可用', (reason) => {
    const n = normalizeInboxItem(row('quota.admission.runtime_fault', { reason }))
    expect(n.title).toBe('额度观测不可用')
    expect(`${n.title}${n.detail}`).not.toMatch(ENGLISH_LEAK)
    expect(n.domain).toBe('access')
    expect(sourceLabel(n.source)).toBe('访问与额度治理')
  })

  it('type=alert 但 reason 无法识别：只给通用中文标题，不回显英文 reason', () => {
    const n = normalizeInboxItem(row('alert', { reason: 'some brand new english reason' }))
    expect(n.title).toBe('访问与额度治理通知')
    expect(`${n.title}${n.detail}`).not.toMatch(/english|reason|governor/i)
  })

  it.each([
    ['model_route_degraded', '模型仅剩一条健康线路'],
    ['model_route_circuit_opened', '上游线路已熔断'],
    ['model_route_unavailable', '模型无可用线路'],
    ['model_route_recovered', '上游线路已恢复'],
  ])('%s：详情带上 model_name，不露 provider_ref', (type, title) => {
    const n = normalizeInboxItem(row(type, { model_name: 'gpt-5.6-sol', provider_ref: 'prov_ab12cd' }, { title }))
    expect(n.title).toBe(title)
    expect(n.detail).toBe('模型：gpt-5.6-sol')
    expect(`${n.title}${n.detail}`).not.toMatch(/prov_/)
  })

  it('model_route_* 没有 model_name 时详情为空；标题缺失/为英文时用中文兜底', () => {
    const noModel = normalizeInboxItem(row('model_route_degraded', {}, { title: '模型仅剩一条健康线路' }))
    expect(noModel.detail).toBe('')
    const englishTitle = normalizeInboxItem(row('model_route_circuit_opened', { model_name: 'm1' }, { title: 'model route circuit opened' }))
    expect(englishTitle.title).toBe('上游线路已熔断')
  })

  it('未识别的 type：标题含英文/类型码时统一显示「其它事件」，来源显示「其它来源」', () => {
    const n = normalizeInboxItem(row('some.weird_type', { reason: 'weird english reason' }))
    expect(n.title).toBe('其它事件')
    expect(sourceLabel(n.source)).toBe('其它来源')
    expect(`${n.title}${n.detail}`).not.toMatch(/weird|governor/i)
  })

  it('未识别的 type 但后端给了干净的中文标题：保留该中文标题', () => {
    const n = normalizeInboxItem(row('custom_notice', {}, { title: '自定义业务通知' }))
    expect(n.title).toBe('自定义业务通知')
  })

  it('已知类型的既有行为不变：成本异常等带中文标题的行原样显示', () => {
    const n = normalizeInboxItem(row('cost_anomaly', {}, { title: '成本异常：昨日费用激增' }))
    expect(n.title).toBe('成本异常：昨日费用激增')
    expect(sourceLabel(n.source)).toBe('成本异常')
  })
})

describe('INBOX_TYPE_LABELS 与 inboxTypeLabel', () => {
  it('按需求给出各类别中文名', () => {
    expect(INBOX_TYPE_LABELS).toMatchObject({
      alert: '访问与额度治理事件',
      'quota.admission.reservation_overrun': '额度预占超出',
      'quota.admission.runtime_fault': '额度观测故障',
      model_route_degraded: '模型线路退化（仅剩一条健康线路）',
      model_route_circuit_opened: '上游线路已熔断',
      model_route_unavailable: '模型无可用线路',
      model_route_recovered: '上游线路已恢复',
      runtime_fault: '运行告警',
      security_event: '安全事件',
      security_event_daily_summary: '安全事件日聚合',
    })
  })

  it('billing_* 复用 SOURCE_LABELS；未知类别显示「其它类别」并标记 known=false', () => {
    expect(inboxTypeLabel('billing_finalize_failed')).toEqual({ label: '计费结算失败', known: true })
    expect(inboxTypeLabel('alert')).toEqual({ label: '访问与额度治理事件', known: true })
    expect(inboxTypeLabel('governor.alert')).toEqual({ label: '访问与额度治理事件', known: true })
    expect(inboxTypeLabel('mystery.kind')).toEqual({ label: '其它类别', known: false })
  })
})

describe('isConsoleAdministratorRole（与后端 roles.IsConsoleAdministrator 对齐）', () => {
  it.each(['platform_admin', 'admin', 'tenant_owner', 'tenant_admin'])('%s 是控制台管理员', (role) => {
    expect(isConsoleAdministratorRole(role)).toBe(true)
  })

  it.each(['security_officer', 'auditor', 'viewer', 'dept_manager', 'developer', 'chat_user', '', undefined])('%s 不是控制台管理员', (role) => {
    expect(isConsoleAdministratorRole(role as string | undefined)).toBe(false)
  })
})

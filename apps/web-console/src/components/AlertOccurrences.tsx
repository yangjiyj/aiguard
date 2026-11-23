import { CORE_SEVERITY_LABELS, SEVERITY_LABELS } from '../utils/risk'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Alert, Avatar, Button, Checkbox, Collapse, Descriptions, Drawer, Empty, Grid, Input, Modal, Pagination, Select, Space, Tabs, Tag, Tooltip, Typography, message } from 'antd'
import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { alertOccurrencesApi, type AlertLane, type AlertOccurrence, type AlertOccurrenceParams } from '../services/alertOccurrences'
import { accessRetentionApi, auditDispositionApi, contentAuditApi, contentSecurityApi } from '../services/api'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { useAuthStore } from '../stores/auth'
import { formatAgentType } from '../utils/agents'
import { alertAccountName, alertIdentityLabel, alertIdentityBasis, alertConnectionLabel, alertIdentityDetails } from '../utils/alertIdentity'
import { getFindingCategoryLabel } from '../utils/alertOccurrenceDisplay'
import type { ContentAuditLog } from '../utils/contentAuditEvidence'
import './AlertOccurrences.css'
import AlertCaseDetail from './AlertCaseDetail'
import { RAW_EVIDENCE_OMITTED_TEXT, rawEvidenceDisplay } from '../utils/alertEvidence'
import RawEvidenceText from './RawEvidenceText'
import { alertActionResult, alertCaseLine, alertCaseSource, alertCaseTitle, alertRuleActionDiffers, alertRuleActionLabel, readableHitText, readableReasonCode, STAGE_LABELS as DETAIL_STAGES } from '../utils/alertReadable'

const { Text, Paragraph } = Typography
const SEVERITIES: Record<string, { label: string; color: string }> = {
  critical: { label: CORE_SEVERITY_LABELS.critical, color: 'red' }, high: { label: CORE_SEVERITY_LABELS.high, color: 'orange' },
  medium: { label: CORE_SEVERITY_LABELS.medium, color: 'gold' }, low: { label: CORE_SEVERITY_LABELS.low, color: 'green' },
  unknown: { label: '未分级', color: 'default' },
}
const SEVERITY_BAR: Record<string, string> = {
  critical: 'var(--status-danger)', high: 'var(--status-high)', medium: 'var(--status-warn)', low: 'var(--status-ok)', unknown: 'var(--text-tertiary)',
}
const MESSAGE_ROLES: Record<string, string> = {
  user: '用户', assistant: '模型', system: '系统', developer: '开发者', tool: '工具', function: '函数', other: '其他',
}
const STAGES: Record<string, string> = {
  ...DETAIL_STAGES, request: '请求阶段', response: '响应阶段',
  tool_call: '工具调用', tool_result: '工具结果', retrieval: '检索阶段', rag: '检索阶段',
}
const stageLabel = (stage: string) => STAGES[stage] || (stage && stage !== 'unknown' ? '未知阶段' : '阶段未记录')

const STATUSES: Record<string, string> = {
  open: '待处置', resolved: '已处理', false_positive: '误报', accepted: '已接受风险',
  escalated: '已升级', closed: '已关闭', acknowledged: '已确认',
  unknown: '状态未记录',
}
const REVIEW_STATES: Record<string, string> = {
  review_pending: '待复核', confirmed: '已确认', suspected: '疑似风险',
  benign: '复核为正常', suppressed: '已抑制', false_positive: '误报',
  confirmed_risk: '已确认风险', likely_false_positive: '疑似误报',
}
// 字典外的来源值不显示原始码。
const sourceLabel = (item: AlertOccurrence) => alertCaseSource(item) || '未记录消息来源'
// 检测理由：网关原因码翻成中文；不认识的码整行不显示，非码文本原样。
const detectionReasonRow = (item: AlertOccurrence) => {
  if (item.reason_status === 'restricted') return [{ label: '检测理由', children: '无权查看检测理由' }]
  const raw = (item.reason || '').trim()
  if (!raw) return []
  const text = readableReasonCode(raw)
  return text ? [{ label: '检测理由', children: text }] : []
}
// 有内容证据权限时接口带回命中原文，先显示原文；历史事件没存原文时显示当时的打码片段。
const maskedText = (item: AlertOccurrence) => item.evidence_status === 'restricted'
  ? '无权查看命中片段'
  : readableHitText(item.redacted_evidence) || (item.raw_evidence_omitted ? RAW_EVIDENCE_OMITTED_TEXT : '未记录命中片段')
const previewText = (item: AlertOccurrence) => (item.evidence_status !== 'restricted' && rawEvidenceDisplay(item.raw_evidence, item.raw_evidence_truncated)) || maskedText(item)
const severityTag = (severity: string) => <Tag color={SEVERITIES[severity]?.color || 'default'}>{SEVERITIES[severity]?.label || SEVERITY_LABELS[String(severity).toLowerCase()] || '未分级'}</Tag>
const actionLabel = alertActionResult
const ruleActionLabel = (item: AlertOccurrence) => alertRuleActionLabel(item.action_taken, item.rule_type)
const statusLabel = (item: AlertOccurrence) => item.suppressed
  ? '已抑制'
  : STATUSES[item.disposition_status] || item.disposition_status || '状态未记录'
const conversationLabel = (item: AlertOccurrence) => item.conversation_id || item.session_id || item.conversation_key || ''
const hasConversationLink = (item: AlertOccurrence) => Boolean(item.session_id || item.request_id)
const indexLabel = (item: AlertOccurrence) => Number.isInteger(item.message_index) && item.message_index !== null
  ? `第 ${item.message_index + 1} 条消息（消息索引 ${item.message_index}）`
  : '消息位置未记录'
const actorDepartment = (item: AlertOccurrence) => item.actor_department_name || '部门未关联'
const whoLabel = (item: AlertOccurrence) => {
  const account = alertAccountName(item) || item.source_ip?.trim()
  const client = item.agent_type ? formatAgentType(item.agent_type) : ''
  return [account, client, alertConnectionLabel(item)].filter((part, index, all) => part && all.indexOf(part) === index && part !== '接入方式未记录').join(' · ') || '身份与接入方式未记录'
}
const withoutRawEvidence = (item: AlertOccurrence): AlertOccurrence => ({ ...item, raw_evidence: undefined, matched_text_preview: undefined, evidence_context: undefined, raw_evidence_status: 'not_requested' })

const actorDisplay = alertIdentityLabel
const caseActorDisplay = alertIdentityLabel
const identityUnknown = (item: AlertOccurrence) => !alertAccountName(item) && !item.source_ip?.trim()
const avatarText = (item: AlertOccurrence) => alertAccountName(item).slice(0, 1) || (item.source_ip?.trim() ? 'IP' : '?')
// 一句话叙事：谁 在 什么场景 触发了 什么风险
const storyHeadline = (item: AlertOccurrence) => {
  const risk = getFindingCategoryLabel(item.category || item.type)
  if (item.case_id && item.hit_count) return `${caseActorDisplay(item) || '账户与来源 IP 未记录'}${item.actor_department_name ? ' · ' + item.actor_department_name : ''} · ${(item.type === 'semantic_attack' || item.type === 'catalog_policy' || item.category.startsWith('semantic_')) ? '疑似' : ''}${risk}`
  const source = sourceLabel(item)
  if (identityUnknown(item)) return `账户与来源 IP 未记录的流量在「${source}」中触发了「${risk}」`
  const who = actorDisplay(item) + (item.actor_department_name ? ` · ${item.actor_department_name}` : '')
  return `${who}的「${source}」触发了「${risk}」`
}

export function AlertOccurrenceSummary({ occurrence: item }: { occurrence: AlertOccurrence }) {
  const rawAvailable = item.raw_evidence_status === 'available'
  const endpointEvidence = item.agent_endpoint_evidence
  const localDecision = endpointEvidence?.local_decision
  const summaryRuleAction = ruleActionLabel(item)
  const localDecisionValue = localDecision?.effective_decision || localDecision?.decision || localDecision?.raw_decision || ''
  return (
    <section aria-label="本次告警">
      <Space wrap style={{ marginBottom: 12 }}>
        {severityTag(item.severity)}
        <Tag color="purple">{getFindingCategoryLabel(item.category || item.type)}</Tag>
        <Tag>{statusLabel(item)}</Tag>
        {summaryRuleAction ? <Tag>规则动作：{summaryRuleAction}</Tag> : null}
      </Space>
      <Descriptions size="small" column={1} items={[
        { label: '发生时间', children: item.created_at ? new Date(item.created_at).toLocaleString() : '未记录' },
        ...alertIdentityDetails(item),
        { label: '账户部门', children: actorDepartment(item) },
        { label: '内容来源', children: sourceLabel(item) },
        { label: '消息位置', children: indexLabel(item) },
        { label: '消息角色 / 检测阶段', children: `${MESSAGE_ROLES[item.message_role] || (item.message_role && item.message_role !== 'unknown' ? '未知角色' : '角色未记录')} / ${stageLabel(item.stage)}` },
        { label: '命中位置', children: item.matched_location || '未记录精确位置' },
        ...(Number.isInteger(item.attachment_index) && item.attachment_index !== null
          ? [{ label: '附件位置', children: `第 ${item.attachment_index + 1} 个附件（索引 ${item.attachment_index}）` }] : []),
        { label: '检测规则', children: item.rule_name || item.rule_id || '未记录' },
        ...detectionReasonRow(item),
        { label: '复核状态', children: REVIEW_STATES[item.review_state] || item.review_state || '未记录' },
        { label: '请求动作', children: actionLabel(item.event_action_taken) },
        ...(item.suppressed ? [{ label: '抑制原因', children: item.suppression_reason || '未记录' }] : []),
        { label: '事件 / 命中', children: `${item.event_id} / ${item.finding_index == null ? '历史事件证据' : `命中索引 ${item.finding_index}`}` },
        { label: '请求 / 项目', children: `${item.request_id || '请求未关联'} / ${item.project_id || '项目未关联'}` },
        { label: '关联对话', children: conversationLabel(item) || '对话未关联' },
        { label: '对话关联依据', children: [item.conversation_source, item.conversation_reliability].filter(Boolean).join(' / ') || '未记录，无法确认完整对话' },
        ...(endpointEvidence ? [
          { label: '原生端点事件关联', children: endpointEvidence.status === 'matched' ? '已按租户、端点、会话和工具事件身份核验' : '未找到身份完整匹配的端点事件记录' },
          ...(endpointEvidence.status === 'matched' ? [
            { label: '端点 / 事件', children: [endpointEvidence.endpoint_id, endpointEvidence.event_type, endpointEvidence.agent_event_id].filter(Boolean).join(' / ') || '未记录' },
            { label: '端点会话', children: item.agent_session_id && item.agent_session_id === endpointEvidence.session_id
              ? <Link to={'/agent/sessions/' + encodeURIComponent(item.agent_session_id)}>{item.agent_session_id}</Link>
              : '未记录或未核验' },
            { label: '端点工具', children: [endpointEvidence.tool_name, endpointEvidence.tool_type, endpointEvidence.tool_use_id].filter(Boolean).join(' / ') || '未记录' },
            { label: '端侧本地判定', children: localDecisionValue || '未记录' },
            { label: '本地决策来源 / 模式', children: [localDecision?.source, localDecision?.mode].filter(Boolean).join(' / ') || '未记录' },
            { label: '本地策略 / 风险', children: [localDecision?.policy_version != null ? '版本 ' + String(localDecision.policy_version) : '', localDecision?.policy_checksum, localDecision?.risk_level ? '风险 ' + localDecision.risk_level : '风险未记录'].filter(Boolean).join(' / ') },
          ] : []),
        ] : []),
      ]} />
      <div style={{ marginTop: 16 }}>
        {rawAvailable && item.raw_evidence ? <>
          <Text strong>本次事件原始命中</Text>
          <RawEvidenceText raw={item.raw_evidence} truncated={item.raw_evidence_truncated} rows={8} style={{ marginTop: 8, marginBottom: '1em' }} />
        </> : <>
          <Text type="secondary">命中片段</Text>
          <Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', marginTop: 8 }}>{maskedText(item)}</Paragraph>
        </>}
        {['available', 'missing'].includes(item.raw_evidence_status) && item.matched_text_preview && !item.raw_evidence ? <>
          <Text strong>历史命中预览（非完整原文）</Text>
          <Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', marginTop: 8 }}>{item.matched_text_preview}</Paragraph>
        </> : null}
        {rawAvailable && item.evidence_context ? <>
          <Text strong>本次事件上下文</Text>
          <Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', marginTop: 8 }}>{item.evidence_context}</Paragraph>
        </> : <Text type="secondary">{item.raw_evidence_status === 'restricted' ? '无权查看原始上下文' : '未提供本次命中的独立上下文'}</Text>}
      </div>
    </section>
  )
}

type Props = {
  onIncludeDevChange?: (include: boolean) => void
  // 车道由页面通过 URL 持有（刷新/分享链接不丢）；缺省为"需行动"。
  lane?: AlertLane
  onLaneChange?: (lane: AlertLane) => void
  params: AlertOccurrenceParams
  page: number
  onPageChange: (page: number) => void
  canReadContent: boolean
  onOpenConversation: (occurrence: AlertOccurrence) => void
}

// ─── 处理车道 ───────────────────────────────────────────────────────────────
const LANES: { key: AlertLane; label: string; hint: string }[] = [
  { key: 'action', label: '需行动', hint: '真实风险与无法排除的命中，默认先看这里' },
  { key: 'watch', label: '观察', hint: '低危、中危命中，以及编程助手流量里的内容规则命中，留痕但不需要立即处理' },
  { key: 'eval', label: '测评流量', hint: '升级自检请求，以及管理员标记为测评的凭据产生的攻击样本，不是真实攻击' },
]
const laneCount = (counts: { lane_action?: number; lane_watch?: number; lane_eval?: number } | undefined, lane: AlertLane) =>
  counts?.[`lane_${lane}` as 'lane_action']
function LaneTabs({ lane, counts, loading, onChange }: {
  lane: AlertLane; counts?: { lane_action?: number; lane_watch?: number; lane_eval?: number }; loading: boolean; onChange: (lane: AlertLane) => void
}) {
  return <div className="alert-lane-bar" data-testid="alert-lane-bar">
    <Tabs size="large" activeKey={lane} onChange={(key) => onChange(key as AlertLane)} items={LANES.map(({ key, label, hint }) => {
      const n = laneCount(counts, key)
      return { key, label: <Tooltip title={hint}><span className={`alert-lane-tab is-${key}`}>{label}<b>{loading || n == null ? '' : n.toLocaleString()}</b></span></Tooltip> }
    })} />
    {lane === 'eval' ? <Alert className="alert-lane-note" type="info" showIcon
      message="管理员已将这些凭据标记为测评：下面是测评平台主动发出的攻击样本及网关的检测记录，不代表真实攻击。"
      description="样本照常检测、留证、可追溯；测评凭据里一旦出现真实密钥格式或硬底线命中，会自动回到「需行动」。" /> : null}
    {lane === 'watch' ? <Alert className="alert-lane-note" type="info" showIcon
      message="观察：低危、中危命中，以及编程助手流量里的内容规则命中。照常留痕，不需要逐条处理。"
      description="凭据格式、硬底线与蜜签泄露不会进入这里，始终在「需行动」。" /> : null}
  </div>
}

// ─── 事件卡 ─────────────────────────────────────────────────────────────────
function AlertCard({ item, canReadContent, onOpen, onOpenConversation, selected = false }: {
  selected?: boolean
  item: AlertOccurrence
  canReadContent: boolean
  onOpen: () => void
  onOpenConversation: () => void
}) {
  const unknownIdentity = identityUnknown(item)
  if (item.hit_count) {
    const repeat = item.hit_count > 1
    const caseLine = alertCaseLine(item)
    return <div role="button" aria-pressed={selected} tabIndex={0} data-severity={item.severity}
      className={`alert-workbench-card alert-workbench-card-compact is-sev-${item.severity}${selected ? ' is-selected' : ''}`}
      data-testid={`alert-card-${item.id}`} onClick={() => canReadContent && onOpen()}
      onKeyDown={event => { if ((event.key === 'Enter' || event.key === ' ') && canReadContent) { event.preventDefault(); onOpen() } }}>
      <div className="alert-card-head">
        <span className="alert-card-what" data-testid="alert-card-what">{alertCaseTitle(item)}</span>
        {severityTag(item.severity)}
      </div>
      {caseLine ? <div className="alert-card-where" data-testid="alert-card-where">{caseLine}</div> : null}
      <div className="alert-card-foot">
        <span className="alert-card-who" data-testid="alert-card-who"><Avatar size={18}>{avatarText(item)}</Avatar><span>{whoLabel(item)}</span></span>
        <Text type="secondary">{item.last_seen ? new Date(item.last_seen).toLocaleString() : '时间未记录'}</Text>
        {repeat ? <span className="alert-card-repeat" data-testid="alert-card-repeat" title={`同一问题合并了 ${item.hit_count} 次命中，涉及 ${item.request_count || 0} 个请求`}>×{item.hit_count.toLocaleString()}<i>{item.request_count || 0} 个请求</i></span> : <Text type="secondary">1 次命中</Text>}
        <Tag>{statusLabel(item)}</Tag>
        {canReadContent ? <Button type="link" size="small" onClick={event => { event.stopPropagation(); onOpen() }}>查看</Button> : <Text type="secondary">仅元数据</Text>}
      </div>
    </div>
  }
  return (
    <div
      role="button"
      aria-pressed={selected}
      className={`alert-workbench-card${selected ? ' is-selected' : ''}`}
      tabIndex={0}
      onClick={() => canReadContent && onOpen()}
      onKeyDown={(event) => { if ((event.key === 'Enter' || event.key === ' ') && canReadContent) { event.preventDefault(); onOpen() } }}
      style={{ display: 'flex', gap: 12, padding: '12px 14px', marginBottom: 10, borderRadius: 10, border: '1px solid rgba(128,128,128,0.25)', cursor: canReadContent ? 'pointer' : 'default', background: selected ? 'var(--bg-hover)' : 'var(--bg-card)' }}
      data-testid={`alert-card-${item.id}`}
    >
      <div style={{ width: 4, borderRadius: 4, background: SEVERITY_BAR[item.severity] || SEVERITY_BAR.unknown, flex: 'none' }} />
      <Avatar size={32} style={{ flex: 'none', background: unknownIdentity ? 'rgba(128,128,128,0.3)' : undefined }}>{avatarText(item)}</Avatar>
      <div style={{ flex: 1, minWidth: 0 }}>
        <Space wrap size={[8, 4]} style={{ width: '100%' }}>
          <Text strong>{storyHeadline(item)}</Text>
          {severityTag(item.severity)}
          <Tag>{statusLabel(item)}</Tag>
          {item.hit_count ? <Text type="secondary">{item.hit_count} 次命中 · {item.request_count ? `${item.request_count} 个请求` : '请求未关联'}</Text> : <Text type="secondary">{actionLabel(item.event_action_taken)}</Text>}
          {!item.hit_count && alertRuleActionDiffers(item.action_taken, item.event_action_taken, item.rule_type) ? <Text type="secondary" style={{ fontSize: 12 }}>规则建议：{ruleActionLabel(item)}</Text> : null}
          <Text type="secondary" style={{ fontSize: 12 }}>{item.last_seen ? `${item.time_known === false ? '检测记录' : '最近发生'} ${new Date(item.last_seen).toLocaleString()}` : item.created_at ? new Date(item.created_at).toLocaleString() : '未记录'}</Text>
        </Space>
        <Space wrap size={[8, 4]} style={{ marginTop: 6 }}>
          {!item.hit_count ? <Tag>{getFindingCategoryLabel(item.category || item.type)}</Tag> : null}
          <Text type="secondary" style={{ fontSize: 12 }}>{sourceLabel(item)}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>{item.hit_count ? (item.grouping_basis === 'conversation' ? '会话内同类风险已合并' : '同源同日风险已合并') : indexLabel(item)}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>{alertConnectionLabel(item)}</Text>
          {!item.hit_count && conversationLabel(item) ? <Text type="secondary" style={{ fontSize: 12 }}>会话 {conversationLabel(item)}</Text> : null}
          {item.agent_endpoint_evidence?.status === 'matched' ? <Text type="secondary" style={{ fontSize: 12 }}>端点 {item.agent_endpoint_evidence.endpoint_id || '未记录'} · 工具 {item.agent_endpoint_evidence.tool_name || item.agent_endpoint_evidence.tool_use_id || '未记录'}</Text> : null}
          {item.agent_session_id ? <Link to={'/agent/sessions/' + encodeURIComponent(item.agent_session_id)} onClick={(event) => event.stopPropagation()}>端点会话 {item.agent_session_id}</Link> : null}
          {unknownIdentity ? <Tag color="warning">账户与来源 IP 未记录</Tag> :
            <Tooltip title={!item.actor_name?.trim() && item.key_owner_name?.trim() ? '这是接入凭据绑定的账户；共享凭据不能确认本次实际操作者。' : item.actor_name?.trim() ? '按本次请求记录关联的用户账户展示。' : '账户未关联时显示来源 IP；代理或 NAT 地址可能由多人共用。'}>
              <Tag>{alertIdentityBasis(item)}</Tag>
            </Tooltip>}

        </Space>
        <Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', margin: '8px 0 0', fontSize: 12.5 }} type="secondary" ellipsis={{ rows: 2, expandable: false }}>
          {previewText(item)}
        </Paragraph>
        <Space wrap size={[8, 4]} style={{ marginTop: 8 }}>
          {canReadContent ? <Button size="small" onClick={(event) => { event.stopPropagation(); onOpen() }}>{item.hit_count ? '查看问题' : '查看告警'}</Button> : <Text type="secondary">仅元数据</Text>}
          {canReadContent && !item.hit_count && hasConversationLink(item) ? <Button size="small" type="link" onClick={(event) => { event.stopPropagation(); onOpenConversation() }}>查看关联对话</Button> : null}
        </Space>
      </div>
    </div>
  )
}

// ─── 详情抽屉：事实 / 命中规则 / 对话上下文 / 处置 ─────────────────────────────
function AlertStory({ item, onOpenConversation, onDispositionSaved, canManage, timeWindow }: {
  timeWindow: { from: string; to: string }
  canManage: boolean
  item: AlertOccurrence
  onOpenConversation: () => void
  onDispositionSaved: (status: string, note: string) => Promise<void>
}) {
  const [status, setStatus] = useState(item.disposition_status || 'open')
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)
  const identity = useAuditQueryIdentity()
  const sessionId = item.session_id || item.conversation_id || ''
  const timelineQ = useQuery({
    queryKey: ['alert-occurrence-timeline', identity, item.request_id, sessionId, timeWindow],
    queryFn: ({ signal }) => contentAuditApi.getSession(sessionId, { ...timeWindow, view: 'manager', limit: 50, signal }),
    enabled: Boolean(sessionId),
    retry: false,
  })
  const logs = useMemo(() => {
    const payload = timelineQ.data?.data as unknown
    const arr = Array.isArray(payload)
      ? payload
      : ((payload as { logs?: unknown; data?: unknown } | undefined)?.logs
        ?? (payload as { data?: unknown } | undefined)?.data
        ?? [])
    return Array.isArray(arr) ? (arr as ContentAuditLog[]) : []
  }, [timelineQ.data])
  const retainedQ = useQuery({
    queryKey: ['alert-request-context', identity, item.request_id, timeWindow],
    queryFn: ({ signal }) => accessRetentionApi.getContent(item.request_id, undefined, { ...timeWindow, signal }),
    enabled: Boolean(item.request_id) && (!sessionId || (timelineQ.isSuccess && logs.length === 0)), retry: false,
  })
  const retained = retainedQ.data?.data
  const hitIndex = Number.isInteger(item.message_index) && item.message_index !== null ? item.message_index : null
  const isHitLog = (log: ContentAuditLog) => hitIndex !== null && log.message_index === hitIndex
    && (!log.request_id || log.request_id === item.request_id)
  const hitPosition = logs.findIndex(isHitLog)
  const visibleLogs = logs.slice(Math.max(0, hitPosition - 2), hitPosition >= 0 ? hitPosition + 4 : 6)
  const ruleName = item.rule_name || item.rule_id || '未记录'
  const ruleActionTitle = ruleActionLabel(item)
  const save = async () => {
    setSaving(true)
    try {
      await onDispositionSaved(status, note)
      setNote('')
    } finally {
      setSaving(false)
    }
  }
  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <section aria-label="事实" className="alert-workbench-facts">
        <Text type="secondary">事实</Text>
        <Descriptions column={1} size="small" items={[
          { label: '身份 / 部门', children: actorDisplay(item) + (item.actor_department_name ? ` · ${item.actor_department_name}` : '') },
          { label: '时间', children: new Date(item.created_at).toLocaleString() },
          { label: '请求动作', children: actionLabel(item.event_action_taken) },
          { label: '目标', children: item.model_name || (item.target_host?.startsWith('model_') ? '' : item.target_host) || '未记录模型或目标' },
          { label: '来源', children: [item.source_ip, item.agent_type && formatAgentType(item.agent_type), alertConnectionLabel(item)].filter(Boolean).join(' · ') },
          { label: '会话 / 请求', children: <Text copyable={{ text: item.request_id }}>{conversationLabel(item) || '未关联会话'} / {item.request_id}</Text> },
        ]} />
      </section>

      {/* 命中规则 */}
      <section aria-label="命中规则">
        <Text strong>命中规则</Text>
        <div style={{ border: '1px solid rgba(128,128,128,0.25)', borderRadius: 8, padding: '10px 12px', marginTop: 8 }}>
          <Space wrap size={[8, 4]}>
            <Text strong>{ruleName}</Text>
            <Tag color="purple">{getFindingCategoryLabel(item.category || item.type)}</Tag>
            {ruleActionTitle ? <Text type="secondary">{ruleActionTitle}</Text> : null}
          </Space>
          <div style={{ marginTop: 6 }}>
            <Text type="secondary" style={{ fontSize: 12 }}>
              规则 {item.rule_id || '未记录'} · 命中位置 {item.matched_location || '未记录'} · 检测阶段 {stageLabel(item.stage)}
            </Text>
          </div>
          <div style={{ marginTop: 8 }}>
            <Text type="secondary" style={{ fontSize: 12 }}>命中片段</Text>
            <Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', marginTop: 4, marginBottom: 0 }} ellipsis={{ rows: 6, expandable: true, symbol: '展开' }}>{previewText(item)}</Paragraph>
          </div>
        </div>
      </section>

      {/* 对话上下文 */}
      <section aria-label="对话上下文">
        <Text strong>对话上下文</Text>
        <div style={{ marginTop: 8 }}>
          {logs.length > 0 ? (
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              {visibleLogs.map((log, index) => {
                const isHit = isHitLog(log)
                const content = String(log.content ?? '').replace(/\s+/g, ' ').trim()
                return (
                  <div key={log.id || index} style={{ border: `1px solid ${isHit ? 'var(--status-danger)' : 'rgba(128,128,128,0.25)'}`, borderRadius: 8, padding: '8px 10px', background: isHit ? 'var(--status-danger-bg)' : 'transparent' }}>
                    <div style={{ fontSize: 11, color: 'rgba(140,140,140,0.9)', marginBottom: 2 }}>
                      {MESSAGE_ROLES[log.role] || log.role || '未记录'}
                      {log.created_at ? ` · ${new Date(log.created_at).toLocaleString()}` : ''}
                      {isHit ? <Text type="danger" style={{ fontSize: 11, marginLeft: 6 }}>⚑ 命中轮</Text> : null}
                    </div>
                    <div style={{ fontSize: 12.5, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{content.length > 180 ? `${content.slice(0, 180)}…` : content || '（无文本内容）'}</div>
                  </div>
                )
              })}
            </Space>
          ) : retained?.user_input || retained?.request_content || retained?.model_output || retained?.response_content ? (
            <Space direction="vertical" style={{ width: '100%' }}>
              <Text type="secondary">本次请求留存内容（未记录原消息索引时不推测命中轮次）</Text>
              {(retained.user_input || retained.request_content) ? <div className="alert-retained-turn"><Text type="secondary">用户 / 请求</Text><Paragraph ellipsis={{ rows: 5, expandable: true }}>{retained.user_input || retained.request_content}</Paragraph></div> : null}
              {(retained.model_output || retained.response_content) ? <div className="alert-retained-turn"><Text type="secondary">模型 / 响应</Text><Paragraph ellipsis={{ rows: 5, expandable: true }}>{retained.model_output || retained.response_content}</Paragraph></div> : null}
            </Space>
          ) : (
            <Text type="secondary">
              {timelineQ.isLoading || retainedQ.isFetching ? '正在读取会话上下文…' : '该告警的会话上下文未留存，或不在当前范围。'}
            </Text>
          )}
          {logs.length > 0 && hitPosition < 0 ? <Text type="secondary">命中轮次不在已加载的上下文中，可查看完整关联对话。</Text> : null}
          {hasConversationLink(item) ? (
            <Button size="small" style={{ marginTop: 8 }} onClick={onOpenConversation}>查看完整关联对话</Button>
          ) : null}
          {item.agent_session_id ? <Link style={{ marginLeft: 8 }} to={`/agent/sessions/${encodeURIComponent(item.agent_session_id)}`}>查看会话</Link> : null}
        </div>
      </section>

      <Collapse ghost items={[{ key: 'evidence', label: '查看完整身份、检测理由与原始证据', children: <AlertOccurrenceSummary occurrence={item} /> }]} />

      {/* 处置 */}
      {canManage ? <section aria-label="处置">
        <Text strong>处置</Text>
        <Space wrap size={[8, 8]} style={{ marginTop: 8 }}>
          <Text type="secondary">状态</Text>
          <Select
            aria-label="处置状态"
            style={{ width: 150 }}
            value={status}
            onChange={setStatus}
            options={[
              { value: 'open', label: '待处置' },
              { value: 'resolved', label: '已处理' },
              { value: 'false_positive', label: '误报' },
              { value: 'accepted', label: '已接受风险' },
              { value: 'escalated', label: '已升级' },
            ]}
          />
          <Text type="secondary">批注</Text>
          <Input aria-label="处置批注" placeholder="处置备注（可选）" value={note} onChange={(event) => setNote(event.target.value)} style={{ width: 240 }} />
          <Button type="primary" size="small" loading={saving} onClick={() => void save()}>保存处置</Button>
        </Space>
      </section> : null}
    </Space>
  )
}

const downloadAlertFile = (name: string, text: string, type: string) => {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const anchor = document.createElement('a')
  anchor.href = url; anchor.download = name; anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
const csvCell = (value: unknown) => {
  const text = String(value ?? '')
  return '"' + (/^[=+@\-\t\r]/.test(text) ? "'" + text : text).replace(/"/g, '""') + '"'
}

export default function AlertOccurrences({ params, page, onPageChange, canReadContent: roleCanReadContent, onOpenConversation, onIncludeDevChange, lane = 'action', onLaneChange }: Props) {
  const identity = useAuditQueryIdentity()
  const role = useAuthStore((state) => state.user?.role)
  const canManage = ['platform_admin', 'tenant_owner', 'tenant_admin'].includes(role || '')
  const listScroll = useRef<HTMLDivElement>(null)
  useEffect(() => { if (listScroll.current) listScroll.current.scrollTop = 0 }, [page, params])
  const screens = Grid.useBreakpoint()
  const wide = screens.lg !== false
  const queryClient = useQueryClient()
  const exactHitKey = [params.event_id?.trim() || '', params.request_id?.trim() || ''].join('|')
  const exactLinkedHit = exactHitKey !== '|'
  const [disposition, setDisposition] = useState<'pending' | 'all' | 'handled' | 'false_positive'>(() => exactLinkedHit ? 'all' : 'pending')
  useEffect(() => { setDisposition(exactHitKey !== '|' ? 'all' : 'pending') }, [exactHitKey])
  const [selected, setSelected] = useState<AlertOccurrence | null>(null)
  const [exporting, setExporting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [exceptionOpen, setExceptionOpen] = useState(false)
  const [exceptionReason, setExceptionReason] = useState('')
  // A customer-provided request/event key identifies historical evidence. Do
  // not let the ordinary recent/pending case defaults hide that exact hit.
  const scopedParams = useMemo<AlertOccurrenceParams>(() => exactLinkedHit
    ? { ...params, recent_limit: undefined, start_time: undefined, end_time: undefined }
    : params, [params, exactLinkedHit])
  // 精确深链（按编号/请求）是审计视图，永远看全部命中，不套车道；其余走车道分流。
  const listParams = { ...scopedParams, grouping: exactLinkedHit ? 'hits' as const : 'cases' as const, disposition, include_suppressed: true, ...(exactLinkedHit ? {} : { lane }) }
  const selectedOccurrenceTime = selected?.occurred_at || selected?.created_at
  // 单条命中的留存上下文只看这条命中发生时间前后各 1 天；过去没有起始时间时默认查 90 天，留存视图要扫全窗口。
  const timeWindow = useMemo(() => {
    const occurredAt = selectedOccurrenceTime ? Date.parse(selectedOccurrenceTime) : NaN
    if (Number.isFinite(occurredAt)) {
      return { from: new Date(occurredAt - 86400000).toISOString(), to: new Date(occurredAt + 86400000).toISOString() }
    }
    return { from: params.start_time || new Date(Date.now() - 86400000).toISOString(), to: params.end_time || new Date().toISOString() }
  }, [selectedOccurrenceTime, params.start_time, params.end_time])
  const scopeKey = JSON.stringify(scopedParams)
  useEffect(() => { setSelected(null); setExceptionOpen(false) }, [scopeKey, disposition, lane])
  const listKey = ['alert-occurrences', identity, listParams, roleCanReadContent]
  // 列表“是哪一份”：分组、车道、处置状态。翻页、改筛选仍是同一份。
  const listScope = [listParams.grouping, listParams.lane ?? '', listParams.disposition].join('|')
  const listQ = useQuery({
    queryKey: listKey,
    queryFn: ({ signal }) => alertOccurrencesApi.list({ ...listParams, include_raw: roleCanReadContent, signal }).then((response) => ({ ...response, scope: listScope })),
    refetchOnWindowFocus: false, retry: false, staleTime: 15000,
    // 翻页、改筛选时留着上一页避免闪烁；换车道或处置状态是另一份列表，先显示加载中，不拿上一份冒充。
    placeholderData: (previous) => previous?.scope === listScope ? keepPreviousData(previous) : undefined,
  })
  // 角色名只是初判；以后端在响应里给的内容证据权限为准（应急模式、旧角色等与角色名不一致的账号）。
  const canReadContent = roleCanReadContent && listQ.data?.data.evidence_readable !== false
  const items = listQ.data?.data.items || []
  const total = listQ.data?.data.total || 0
  useEffect(() => {
    if (listQ.isFetching || !listQ.data) return
    const rows = listQ.data.data.items
    const current = selected && rows.find(row => (row.case_id || row.id) === (selected.case_id || selected.id))
    if (selected && !current) setSelected(wide && canReadContent ? rows[0] || null : null)
    else if (!selected && wide && canReadContent) setSelected(rows[0] || null)
    else if (current && current !== selected) setSelected(current)
  }, [wide, canReadContent, selected, listQ.data, listQ.isFetching])
  const evidenceQ = useQuery({
    queryKey: ['alert-occurrence-evidence', identity, selected?.id, scopedParams],
    queryFn: ({ signal }) => alertOccurrencesApi.getEvidence(selected!, { ...scopedParams, signal }),
    enabled: canReadContent && selected !== null && !selected.hit_count, retry: false,
  })
  const detail = evidenceQ.data || (selected ? withoutRawEvidence(selected) : null)
  const openConversation = (item: AlertOccurrence) => { if (!wide) setSelected(null); onOpenConversation(item) }
  const counts = listQ.data?.data.counts
  const number = (value?: number) => value == null || listQ.isError ? '—' : value.toLocaleString()
  const saveDisposition = async (status: string, note: string) => {
    if (!detail || !canManage) return
    await auditDispositionApi.upsert({ subject_type: selected?.hit_count ? 'alert_case' : 'security_event', subject_id: selected?.hit_count ? selected.case_id! : detail.event_id, case_seen_through: selected?.hit_count ? selected.last_detected_at : undefined,
      status: status as 'open' | 'resolved' | 'false_positive' | 'accepted' | 'escalated', note: note || undefined })
    message.success('处置状态已保存')
    setSelected(null)
    await refreshAfterDisposition()
  }
  const refreshAfterDisposition = async () => {
    await Promise.all(['alert-occurrences', 'alert-case-summary', 'alert-occurrence-evidence', 'alert-case-members']
      .map((key) => queryClient.invalidateQueries({ queryKey: [key], refetchType: 'none' })))
    await queryClient.refetchQueries({ queryKey: listKey, exact: true })
  }
  const quickDisposition = async (status: string) => {
    setSaving(true)
    try { await saveDisposition(status, status === 'resolved' ? '已标记为已处理' : '已人工复核为误报') }
    catch (error) {
      const status=(error as {response?:{status?:number}})?.response?.status
      if (status===409 || status===404) {message.warning(status===409?'该问题有新证据，请刷新后再处置':'该问题已撤回或不在当前权限范围，正在刷新'); await refreshAfterDisposition()}
      else message.error('处置失败，请重试')
    } finally { setSaving(false) }
  }
  const exportAlerts = async () => {
    if (total > 5000) { message.info('当前结果超过 5000 条，请缩小时间或筛选范围后导出'); return }
    setExporting(true)
    try {
      const all: AlertOccurrence[] = []
      for (let offset = 0; offset < total; offset += 100) {
        const result = await alertOccurrencesApi.list({ ...listParams, limit: 100, offset, include_raw: false })
        all.push(...result.data.items)
        if (!result.data.items.length) break
      }
      const fields = ['首次发生', '最近发生', '身份', '风险', '最高等级', '命中次数', '已关联请求数', '处置状态', '问题ID']
      const rows = all.map((item) => [item.first_seen || item.created_at, item.last_seen || item.created_at, actorDisplay(item), getFindingCategoryLabel(item.category), SEVERITIES[item.severity]?.label || item.severity, item.hit_count || 1, item.request_count || 1, statusLabel(item), item.case_id || item.id])
      downloadAlertFile('安全告警.csv', '\uFEFF' + [fields, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n'), 'text/csv;charset=utf-8')
      message.success(`已导出 ${all.length} 条告警`)
    } catch { message.error('导出失败，未生成不完整文件') } finally { setExporting(false) }
  }
  const createException = async () => {
    if (!detail || !detail.rule_id || !exceptionReason.trim()) return
    setSaving(true)
    try {
      // 没有项目的命中（如未归属应用的请求）按全单位范围加例外，任何命中都能加。
      await contentSecurityApi.createException({ scope_type: detail.project_id ? 'project' : 'tenant', scope_ref: detail.project_id || '', rule_id: detail.rule_id,
        decision: 'audit', reason: exceptionReason.trim(), expires_at: new Date(Date.now() + 24 * 3600000).toISOString() })
      setExceptionOpen(false); setExceptionReason(''); message.success(detail.project_id ? '已添加仅适用于本项目、本规则的 24 小时审计例外' : '已添加适用于全单位、本规则的 24 小时审计例外')
    } catch { message.error('例外创建失败，请核对权限与规则范围') } finally { setSaving(false) }
  }
  const detailPanel = selected?.hit_count && canReadContent ? <AlertCaseDetail key={selected.case_id} item={selected} params={scopedParams} canReadContent={canReadContent} identityLabel={caseActorDisplay(selected) + (selected.actor_department_name ? ' · ' + selected.actor_department_name : '')} canManage={canManage} saving={saving} onDisposition={(status)=>void quickDisposition(status)} /> : detail && canReadContent ? <>
    <div className="alert-workbench-detail-actions">
      <Space wrap>{severityTag(detail.severity)}<Tag>{statusLabel(detail)}</Tag><Text>{actionLabel(detail.event_action_taken)}</Text></Space>
      <Space wrap>
        {canManage ? <><Button type="primary" loading={saving} onClick={() => void quickDisposition('resolved')}>标为已处理</Button>
          <Button loading={saving} onClick={() => void quickDisposition('false_positive')}>标为误报</Button>
          <Button disabled={!detail.rule_id} onClick={() => setExceptionOpen(true)}>加为例外</Button></> : null}
        <Button disabled={!evidenceQ.data} onClick={() => downloadAlertFile(`告警证据-${detail.event_id}.json`, JSON.stringify(detail, null, 2), 'application/json')}>导出证据</Button>
      </Space>
    </div>
    <div className="alert-workbench-detail-body">
      {evidenceQ.isLoading ? <Text type="secondary">正在读取本次事件证据…</Text> : null}
      {evidenceQ.isError ? <Alert type="warning" showIcon message="本次告警原始证据加载失败" action={<Button onClick={() => void evidenceQ.refetch()}>重试证据</Button>} /> : null}
      {evidenceQ.isSuccess && !evidenceQ.data ? <Alert type="info" showIcon message="本次告警已不在当前查询范围，未获取独立上下文" /> : null}
      <AlertStory key={detail.id} item={detail} onOpenConversation={() => openConversation(detail)} onDispositionSaved={saveDisposition} canManage={canManage} timeWindow={timeWindow} />
    </div>
  </> : <Empty description={canReadContent ? '选择左侧告警查看事实、证据和对话上下文' : '当前角色只能查看告警的元数据（时间、类别、处置状态），不能查看证据和对话内容。如需查看，请联系安全保密管理员、审计员或租户管理员。'} />
  return <div className="alert-workbench">
    <Space wrap style={{ marginBottom: 12 }}>
      <Checkbox checked={params.include_dev === true} onChange={event => { onIncludeDevChange?.(event.target.checked); onPageChange(1) }}>显示开发作用域语义/运行告警</Checkbox>
      <Text type="secondary">{listQ.data?.data.folded_development_groups == null ? '开发作用域折叠数量正在统计' : params.include_dev ? `已显示 ${number(listQ.data.data.folded_development_groups)} 个开发作用域组` : `已折叠 ${number(listQ.data.data.folded_development_groups)} 个开发作用域组`}；其他风险类别始终显示。</Text>
    </Space>
    <div className="alert-case-guide">
      <strong>{exactLinkedHit ? '编号 → 关联命中 → 原请求留存' : '问题 → 命中明细 → 原请求留存'}</strong>
      <span>{exactLinkedHit ? <>按编号精确查询，共 {number(listQ.data?.data.total)} 条命中记录；{disposition === 'all' ? '包含所有处置状态' : '已按当前处置状态筛选'}，每条命中均可追溯到原请求留存。</> : <>{scopedParams.recent_limit ? '最近 100 条范围内，' : ''}所选问题累计 {number(counts?.raw_hits)} 条命中记录，合并为 {number(counts?.total)} 项问题；每次检测均可追溯。</>}</span>
    </div>
    {exactLinkedHit ? null : <LaneTabs lane={lane} counts={counts} loading={listQ.isFetching && !listQ.data} onChange={(next) => { onLaneChange?.(next); onPageChange(1) }} />}
    <div className="alert-workbench-tabs">
      <Tabs activeKey={disposition} onChange={(key) => { setDisposition(key as typeof disposition); onPageChange(1) }} items={[
        { key: 'pending', label: `待处置${counts?.pending == null ? '' : `（${number(counts.pending)}）`}` },
        { key: 'all', label: '全部告警' }, { key: 'handled', label: '已处置' }, { key: 'false_positive', label: '误报' },
      ]} />
      <Button loading={exporting} disabled={listQ.isFetching || listQ.isError || total === 0} onClick={() => void exportAlerts()}>导出告警</Button>
    </div>
    {listQ.isError ? <Alert type="error" showIcon message="告警加载失败" action={<Button aria-label="重试告警" onClick={() => void listQ.refetch()}>重试</Button>} /> : <div className="alert-workbench-columns">
      <div className="alert-workbench-list"><div className="alert-workbench-column-title">{exactLinkedHit ? '关联命中' : '风险问题'}（{listQ.isFetching && !listQ.data ? '加载中' : `${total.toLocaleString()} ${exactLinkedHit ? '条' : '项'}`}）{listQ.isFetching ? ' · 正在更新…' : ''}</div>
        {items.length === 0 && !listQ.isFetching ? <Empty description="暂无安全告警" /> : null}
        <div className="alert-workbench-list-items" ref={listScroll}>{items.map((item) => <AlertCard key={item.id} item={item} selected={selected?.id === item.id} canReadContent={canReadContent} onOpen={() => setSelected(item)} onOpenConversation={() => openConversation(item)} />)}</div>
        {listQ.data ? <Pagination current={page} pageSize={params.limit || 10} total={total} showSizeChanger={false} onChange={onPageChange} showTotal={(value) => exactLinkedHit ? `共 ${value} 条命中` : `共 ${value} 项问题`} /> : null}
      </div>
      {wide ? <div className="alert-workbench-detail"><div className="alert-workbench-column-title">告警详情{detail ? ` · ${actorDisplay(detail)}` : ''}</div><section aria-label="告警详情" className="alert-workbench-detail-panel">{detailPanel}</section></div> : null}
    </div>}
    {!wide ? <Drawer title="告警详情" open={Boolean(selected) && canReadContent} onClose={() => setSelected(null)} width="min(960px, 100vw)" destroyOnClose>{detailPanel}</Drawer> : null}
    <Modal title="添加策略例外" open={exceptionOpen} onCancel={() => setExceptionOpen(false)} onOk={() => void createException()} okText="创建 24 小时审计例外" confirmLoading={saving} okButtonProps={{ disabled: !exceptionReason.trim() }}>
      <p>项目：{detail?.project_id || '全单位'}；规则：{detail?.rule_name || detail?.rule_id}。仅该范围改为审计，仍保留检测记录，24 小时后自动到期。</p>
      <Input.TextArea aria-label="例外原因" placeholder="填写经过复核的例外原因" value={exceptionReason} onChange={(event) => setExceptionReason(event.target.value)} maxLength={2000} />
    </Modal>
  </div>
}

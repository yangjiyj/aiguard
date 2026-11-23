import { type ReactNode, useEffect, useMemo, useState } from 'react'
import { Alert, Button, Card, Drawer, Empty, Input, Select, Space, Table, Tabs, Tag, Tooltip, Typography, message } from 'antd'
import type { TableProps } from 'antd'
import { AppstoreOutlined, CheckCircleOutlined, CopyOutlined, DownloadOutlined, ExportOutlined, EyeOutlined, FileTextOutlined, LinkOutlined, PaperClipOutlined, RobotOutlined, StopOutlined, WarningOutlined } from '@ant-design/icons'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import { accessRetentionApi, auditDispositionApi, contentAuditApi, llmProviderCatalogApi, type AccessRetentionArtifact, type AccessRetentionContent, type AccessRetentionTurn, type AccessRetentionMessage, type AccessRetentionRecord, type AccessRetentionSummary, type AccessRetentionWindow, type ContentAuditUserOption, type EvidenceRunRecord } from '../services/api'
import { EnterprisePageHeader, MetricCard, SectionPanel, StatusPill } from '../components/EnterpriseUI'
import LeakTraceDrawer from '../components/LeakTraceDrawer'
import RawEvidenceDrawer from '../components/RawEvidenceDrawer'
import { useAuthStore } from '../stores/auth'
import { canViewRawEvidenceRole } from '../utils/access'
import CollapsibleFilters from '../components/CollapsibleFilters'
import RetentionTurnList from '../components/RetentionTurnList'
import RetentionKeywordText from '../components/RetentionKeywordText'
import { TrendArea } from '../components/Charts'
import { getRiskCategoryLabel, responsibilityDisplay } from '../utils/risk'
import { AGENT_DEFINITIONS, formatAgentType, getAgentColor } from '../utils/agents'
import { compactNumber } from '../utils/format'
import { minimumKeywordLength } from '../utils/keywordSearch'
import { collapseSystemSections } from '../utils/retentionCollapse'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { RECORD_MODE_PASS_LABEL } from '../utils/ws8ActionLabels'

const { Text } = Typography

const riskLabels: Record<string, string> = {
  normal: '正常放行',
  risk: '审计线索',
  blocked: '拒绝记录',
}

const riskTone: Record<string, 'blue' | 'green' | 'orange' | 'red' | 'gray'> = {
  normal: 'green',
  risk: 'orange',
  blocked: 'red',
}

const riskReasonLabels: Record<string, string> = {
  bank_card_cn: '银行卡号',
  regex_bank_card_cn: '银行卡号',
  phone_cn: '手机号',
  id_card_cn: '身份证号',
  email: '邮箱地址',
  secret: '敏感凭据',
  generic_api_key: 'API Key',
  openai_key: 'OpenAI Key',
  github_token: 'GitHub Token',
  jwt_token: 'JWT Token',
  private_key: '私钥',
  prompt_injection: 'Prompt 注入',
  data_leak: '数据泄露',
  content_safety: '内容安全',
  encoding_zero_width: '零宽字符',
}

function riskReasonLabel(value?: string) {
  if (!value) return ''
  return riskReasonLabels[value] || getRiskCategoryLabel(value)
}

function riskReasonList(record: AccessRetentionRecord) {
  return Array.from(new Set((record.risk_reasons || []).map(riskReasonLabel).filter(Boolean)))
}

function isAuditAction(action?: string) {
  const normalized = String(action || '').toLowerCase()
  return normalized === 'audit' || normalized.includes('audit')
}

function riskStatusPill(record: AccessRetentionRecord) {
  const state = record.risk_state || 'normal'
  const reasons = riskReasonList(record)
  let label = riskLabels[state] || state || '正常放行'
  let tone = riskTone[state] || 'gray'
  let tooltip = ''

  if (state === 'blocked') {
    label = '请求被拒绝'
    tooltip = '记录包含请求拒绝或安全回复；具体原因请核对调用结果与安全事件，审计命中不等于内容策略阻断。'
  } else if (isAuditAction(record.action_taken) && state !== 'normal') {
    label = `审计线索${reasons[0] ? `：${reasons[0]}` : ''}`
    tone = 'blue'
    tooltip = '当前为审计放行记录，仅保留证据，不代表已经阻断客户访问。'
  } else if (state !== 'normal') {
    label = `${label}：${reasons[0] || '待复核'}`
    tooltip = '规则已命中但未形成阻断结论，请结合详情复核。'
  }

  const node = <StatusPill tone={tone}>{label}</StatusPill>
  const title = [tooltip, reasons.length > 1 ? `命中分类：${reasons.join('、')}` : ''].filter(Boolean).join(' ')
  return title ? <Tooltip title={title}>{node}</Tooltip> : node
}

const actionLabels: Record<string, string> = {
  allow: '放行',
  audit: '审计放行',
  block: '阻断',
  reply: '安全回复',
  security_audit_only: RECORD_MODE_PASS_LABEL,
  security_audit: '审计记录',
  security_blocked: '阻断',
  security_replied: '安全回复',
  tool_audit_only: RECORD_MODE_PASS_LABEL,
  tool_audited: '工具审计',
}

const accessTypeLabels: Record<string, string> = {
  llm: '大模型访问',
  ai_ide: 'AI 开发工具访问',
  normal_public: '普通公网访问',
  unknown_ai_candidate: '待识别 AI 访问',
}

const emptySummary: AccessRetentionSummary = {
  total: 0,
  normal_count: 0,
  risk_count: 0,
  blocked_count: 0,
  llm_count: 0,
  ai_ide_count: 0,
  normal_public_count: 0,
  retained_content_count: 0,
  undetected_count: 0,
  forward_count: 0,
  reverse_count: 0,
  data_fresh_until: undefined,
  device_count: 0,
  agent_request_count: 0,
  identified_agent_count: 0,
  unidentified_agent_count: 0,
  unique_model_count: 0,
  evidence_quality: {
    complete_count: 0,
    request_only_count: 0,
    response_only_count: 0,
    metadata_only_count: 0,
  },
  timeline: [],
  top_risk_categories: [],
  top_providers: [],
  top_targets: [],
  top_agents: [],
}

const directionMeta: Record<string, { label: string; color: string }> = {
  reverse: { label: '反向代理', color: 'blue' },
  forward: { label: '正向代理', color: 'green' },
  chat_completion: { label: '模型中转', color: 'purple' },
  device: { label: '经过设备', color: 'default' },
}

const accessRetentionWindowOptions = [
  { label: '近 24h', value: 1 },
  { label: '近 7 天', value: 7 },
  { label: '近 30 天', value: 30 },
  { label: '近 90 天', value: 90 },
  { label: '近 180 天', value: 180 },
]

function accessRetentionTimeWindow(days: number) {
  const to = new Date()
  const from = new Date(to.getTime() - days * 24 * 60 * 60 * 1000)
  return {
    from: from.toISOString(),
    to: to.toISOString(),
  }
}

type ExplicitTimeWindow = { from: string; to: string }

function linkedAccessRetentionTimeWindow(searchParams: URLSearchParams): ExplicitTimeWindow | null {
  const from = searchParams.get('from')
  const to = searchParams.get('to')
  if (!from || !to) return null
  const fromTime = Date.parse(from)
  const toTime = Date.parse(to)
  if (Number.isNaN(fromTime) || Number.isNaN(toTime) || toTime <= fromTime) return null
  return { from, to }
}

function timeWindowDaysFromRange(window: ExplicitTimeWindow | null) {
  if (!window) return 1
  const durationDays = Math.round((Date.parse(window.to) - Date.parse(window.from)) / (24 * 60 * 60 * 1000))
  return accessRetentionWindowOptions.some((option) => option.value === durationDays) ? durationDays : 1
}

function displayProvider(record: AccessRetentionRecord) {
  const v = record.provider_cn || record.provider
  if (!v || v === 'unknown' || v === '其它') return '直连调用'
  return v
}

function accessIdentityDisplay(record: AccessRetentionRecord) {
  const identityKind = record.identity_kind || (record.user_id ? 'key_owner' : record.client_id ? 'api_key' : 'unknown')
  const source = record.source_ip ? `来源 ${record.source_ip}` : ''
  if (identityKind === 'key_owner') {
    const owner = record.key_owner || record.username || record.user_id || '未命名归属用户'
    return {
      primary: `Key 归属：${owner}`,
      secondary: [record.client_name ? `Key：${record.client_name}` : '', source].filter(Boolean).join(' · '),
    }
  }
  if (identityKind === 'api_key') {
    return {
      primary: record.client_name ? `API Key：${record.client_name}` : 'API Key',
      secondary: source,
    }
  }
  const fallback = responsibilityDisplay({
    clientName: record.client_name,
    sourceIp: record.source_ip,
    direction: record.access_direction,
  })
  return {
    primary: `身份未知 · ${fallback.primary}`,
    secondary: fallback.secondary,
  }
}

function displayProduct(record: AccessRetentionRecord) {
  return record.product_cn || record.product || displayProvider(record)
}

function formatBytes(value?: number) {
  const n = value || 0
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${n} B`
}

function formatDateTime(value?: string) {
  return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '-'
}

function formatTimelineBucket(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  const hour = String(date.getHours()).padStart(2, '0')
  const minute = String(date.getMinutes()).padStart(2, '0')
  return `${month}-${day} ${hour}:${minute}`
}

type EvidenceView = 'agent_tasks' | 'ai_conversations' | 'requests'

function runtimeDisplayName(runtime?: string) {
  if (runtime === 'vscode') return 'VS Code'
  if (runtime === 'electron') return 'Electron'
  return runtime || ''
}

function formatRunDuration(milliseconds?: number) {
  const totalSeconds = Math.max(0, Math.round((milliseconds || 0) / 1000))
  if (totalSeconds < 60) return `${totalSeconds} 秒`
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  if (minutes < 60) return seconds ? `${minutes} 分 ${seconds} 秒` : `${minutes} 分钟`
  const hours = Math.floor(minutes / 60)
  const remainingMinutes = minutes % 60
  return remainingMinutes ? `${hours} 小时 ${remainingMinutes} 分` : `${hours} 小时`
}

function evidenceStatusLabel(status?: string) {
  if (status === 'complete') return '证据完整'
  if (status === 'partial') return '部分留证'
  return '仅元数据'
}

function percentage(value: number, total: number) {
  return total > 0 ? Math.round(value * 1000 / total) / 10 : 0
}

function retentionTag(record: AccessRetentionRecord) {
  if (record.content_retained) return <Tag color="blue">已留证内容</Tag>
  if (record.retention_level === 'content') return <Tag color="default">暂无可审计内容</Tag>
  if (record.retention_level === 'summary') return <Tag color="default">仅留存概要</Tag>
  return <Tag>{record.retention_level || '未设置留存策略'}</Tag>
}

function usesFullAccessPath(record: AccessRetentionRecord) {
  return record.access_type === 'llm' || record.access_type === 'ai_ide'
}

function displayAccessObject(record: AccessRetentionRecord) {
  if (record.access_direction === 'chat_completion') {
    return record.target_host || '模型已下线'
  }
  return usesFullAccessPath(record) ? displayProduct(record) : record.target_host
}

// 访问路径对客户只展示「方法 + 干净路径」。豆包等网页大模型的 target_path 带巨长 query
// （msToken / a_bogus 等反爬签名 token），既不可读又含敏感凭证，审计界面一律剥掉 ? 之后的 query。
// 完整 URL 仍保留在后端 request_logs.proxy_target_path 供取证导出，只是不在界面暴露。
const METHOD_LABELS: Record<string, string> = {
  CONNECT: '代理连接',
  GET: '获取',
  POST: '提交',
  PUT: '更新',
  DELETE: '删除',
  PATCH: '修改',
  OPTIONS: '预检',
}

function displayAccessPath(record: AccessRetentionRecord) {
  const rawMethod = (record.method || '').toUpperCase()
  const raw = usesFullAccessPath(record) ? (record.target_path || '/') : (record.path_template || '/')
  const clean = raw.split('?')[0] || '/'
  // CONNECT 是正向代理建立隧道的请求，目标域名就是访问对象，不是路径
  if (rawMethod === 'CONNECT') {
    const target = clean.replace(/^\//, '').split(':')[0] || '未知目标'
    return `${METHOD_LABELS.CONNECT} ${target}`
  }
  const methodLabel = METHOD_LABELS[rawMethod] || rawMethod || '访问'
  return `${methodLabel} ${clean}`
}

function accessTypeTagColor(record: AccessRetentionRecord) {
  if (record.access_type === 'llm') return 'blue'
  if (record.access_type === 'ai_ide') return 'purple'
  return 'default'
}

type RetainedFileMetadata = NonNullable<ReturnType<typeof normalizeFileMetadata>[number]>

type RawFileMetadata = {
  source?: string
  stage?: string
  field_name?: string
  file_name?: string
  reference_id?: string
  content_type?: string
  size?: number
  sha256?: string
  text_preview?: string
  retained_text?: string
  data_base64?: string
  download_url?: string
  object_key?: string
  findings?: Array<{ category?: string; rule_name?: string; action?: string }>
}

type RetainedDisplayBlock =
  | { type: 'text'; content: string }
  | { type: 'code'; language: string; content: string }

const retainedProtocolNoise = new Set(['default', 'assistant', 'user', 'system', 'wip', 'think', 'thinking', 'analysis', 'final', 'append', 'replace', 'done', 'content'])
const fileReferenceLinePattern = /^\[([^\]]*(?:file|files|attachment|upload|document)[^\]]*)\]\s+(.+)$/i
const fileReferenceIDPattern = /\b(?:file|upload|attachment)-[A-Za-z0-9][A-Za-z0-9._-]{5,}\b/g
const retainedUploadHeaderPattern = /^\[file:(.+?)(?:\s+type=([^\s\]]+))?(?:\s+size=(\d+))?(?:\s+sha256=([^\s\]]+))?\]\s*$/i
const retainedPartHeaderPattern = /^\[(?:field|file|embedded|multipart_error):/i
const retainedFieldLinePattern = /^\[field:[^\]]+\]\s*(.*)$/i
const standaloneUUIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const retainedStreamPathPattern = /^(?:response|request|message)(?:\/|\.|$)/i
const retainedAgentFilesHeaderPattern = /^#\s*Files\s+(?:mentioned|pasted|attached|provided|selected|referenced)\s+by\s+the\s+user\s*:\s*$/im
const retainedMyRequestHeaderPattern = /^##\s*My\s+request(?:\s+for\s+Codex)?\s*:\s*$/gim
const retainedUserQueryPattern = /<user_query(?:\s[^>]*)?>([\s\S]*?)<\/user_query>/gi
const retainedImagePathBlockPattern = /[\t ]*\r?\n?<image_local_path(?:\s[^>]*)?>.*?<\/image_local_path>[\t ]*\r?\n?/gis
const retainedImagePathOpenPattern = /[\t ]*<image_local_path(?:\s[^>]*)?>[^\r\n<]*(?:<\/image_local_path>)?/gi
const retainedAgentImageRefPattern = /@image#[0-9]+:[^\s]+[\t ]*/gi
const retainedCodeBuddyImagePathPattern = /^[\t ]*@image(?:#[0-9]+)?:(?:[A-Z]:\\|\/)[^\r\n]*$/gim
const retainedVSCodeRuntimePrefixPattern = /^\s*<current_datetime(?:\s[^>]*)?>[0-9TZ:+.-]+<\/current_datetime>/i
const retainedCurrentDateTimeBlockPattern = /[\t ]*\r?\n?<current_datetime(?:\s[^>]*)?>[0-9TZ:+.-]+<\/current_datetime>[\t ]*\r?\n?/gis
const retainedSystemReminderBlockPattern = /[\t ]*\r?\n?<system_reminder(?:\s[^>]*)?>.*?<\/system_reminder>[\t ]*\r?\n?/gis
const retainedToolsChangedNoticeBlockPattern = /[\t ]*\r?\n?<tools_changed_notice(?:\s[^>]*)?>.*?<\/tools_changed_notice>[\t ]*\r?\n?/gis
const retainedToolsChangedNoticeTailPattern = /[\t ]*<tools_changed_notice(?:\s[^>]*)?>\s*Tools no longer available\b/i
const retainedVSCodeLocalImagePathPattern = /^[\t ]*Image file at path[\t ]+(?:[A-Z]:\\|\/)[^\r\n]*$/gim
const retainedWorkBuddyLoopNoticeBlockPattern = /^[\t ]*\[[\t ]*\n[\t ]*Loop detected: the tool ["'][^"'\r\n]+["'] has been called [1-9]\d* consecutive times with identical arguments\.[\t ]*\n[\t ]*\n[\t ]*STOP calling tools immediately\. Do NOT make any more tool calls\.[\t ]*\n[\t ]*Instead, tell the user what happened and suggest they switch models or modify their prompt to retry\.[\t ]*\n[\t ]*\][\t ]*\n[\t ]*\n[\t ]*\[LOOP_DETECTED\][\t ]*$/i
const retainedWebModelProtocolLinePattern = /^(?:SCENARIO_[A-Z0-9_]+|TOOL_TYPE_[A-Z0-9_]+|MESSAGE_STATUS_[A-Z0-9_]+|local_[A-Za-z0-9_-]+|chat\.[A-Za-z0-9_.-]+|block\.[A-Za-z0-9_.!-]+|patch_op\.[A-Za-z0-9_.-]+|\d{8,}|\d{4}-\d{2}-\d{2}T[^\s]+Z?|未命名会话)$/i
const webModelTokenStreamSignalPattern = /(?:block\.text\.content|SCENARIO_[A-Z0-9_]+|TOOL_TYPE_[A-Z0-9_]+|MESSAGE_STATUS_[A-Z0-9_]+)/i
const webModelProtocolUUIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const retainedWebModelJSONProtocolPattern = /"(?:ack_cost_time|first_packet_cost_time|agent_id|agent_name|bot_id|bot_name|intent_agent_name|llm_intention|plugin_intention|plugin_generalize_intention|vlm_intention|browsing_intention|rich_media_intention|branch_intention|creation_detail_intention|deep_think_intention|freshness|appended_system_prompt|origin_plugin_name|intention_ori_score|block_type|block_id|text_block|[A-Za-z]+RawValue)"/i
const retainedWebModelBrandLinePattern = /^(?:豆包|Kimi|DeepSeek|ChatGPT|腾讯元宝)$/i
const setResponsePattern = /^\s*SET\s+RESPONSE\b[:：]?\s*/i
const finalAnswerMarkerPattern = /^\s*(?:FINAL|FINAL ANSWER|ANSWER|MODEL ANSWER|最终回答|模型回答)\s*[:：]?\s*$/i
const retainedImageReferencePattern = /\[(message\.(?:refs|references)[^\]]*(?:image|images)[^\]]*)\]\s*(https?:\/\/[^\s\]]+)/gi
const retainedFileURLReferencePattern = /\[([^\]]*(?:file|files|attachment|upload|document)[^\]]*(?:url|signurl|previewurl|downloadurl|fullsizeurl|originurl|originalurl)[^\]]*)\]\s*(https?:\/\/[^\s\]]+)/gi
const retainedFileURLReferenceLinePattern = /^\[[^\]]*(?:file|files|attachment|upload|document)[^\]]*(?:url|signurl|previewurl|downloadurl|fullsizeurl|originurl|originalurl)[^\]]*\]\s*https?:\/\/\S+$/i
const retainedFileTypeMarkerPattern = /\[[^\]]*(?:file|files|attachment|upload|document)[^\]]*(?:type|meta)[^\]]*\]\s*FILE_TYPE_[A-Z0-9_]+/gi
const retainedFileTypeMarkerLinePattern = /^\[[^\]]*(?:file|files|attachment|upload|document)[^\]]*(?:type|meta)[^\]]*\]\s*FILE_TYPE_[A-Z0-9_]+$/i
const retainedImageReferenceMarkerPattern = /\[message\.(?:refs|references)[^\]]*(?:image|images)[^\]]*\]/gi
const retainedGenericImageMarkerPattern = /\[(?:image_url|image|img|generated_image|output_image)\]/gi
const retainedPrivateBlockPattern = /[\t ]*\r?\n?<(?:think|memory|memory_and_skills_reminder|oai-mem-citation|citation_entries|rollout_ids|tool_call|tool_result|tool_use|function_call|internal_recap)(?:\s[^>]*)?>.*?<\/(?:think|memory|memory_and_skills_reminder|oai-mem-citation|citation_entries|rollout_ids|tool_call|tool_result|tool_use|function_call|internal_recap)>[\t ]*\r?\n?/gis
const retainedPrivateClosePattern = /<\/(?:think|memory|memory_and_skills_reminder|oai-mem-citation|citation_entries|rollout_ids|tool_call|tool_result|tool_use|function_call|internal_recap)>/gi
const retainedPrivateOpenPattern = /[\t ]*\r?\n?<(?:think|memory|memory_and_skills_reminder|oai-mem-citation|citation_entries|rollout_ids|tool_call|tool_result|tool_use|function_call|internal_recap)(?:\s[^>]*)?>/i
const retainedPrivateLinePattern = /^\s*\[(?:tool|tool_use(?::[^\]\r\n]*)?|tool_result(?::[^\]\r\n]*)?|reasoning|thinking|analysis|chain_of_thought|cot)\][^\r\n]*(?:\r?\n|$)/gim
const retainedRuntimeDocStartPattern = /(?:^|\n)\s*(?:Waits on a yielded `exec` cell|This tool only accepts string inputs|Tools for spawning and managing sub-agents|Available model overrides|Request user input for one to three short questions|Identifier of the running exec cell)\b/i
const retainedJSONURLFieldPattern = /"([^"]*(?:image|img|url|uri|src)[^"]*)"\s*:\s*"([^"]+)"/gi
const retainedImageJSONProtocolPattern = /"(?:image|images|img|image_url|imageUrl|mime_type|content_type|type)"\s*:\s*"?(?:image\/|[^"]*image)|"(?:url|uri|src)"\s*:\s*"\s*"/i
const standaloneURLPattern = /https?:\/\/[^\s<>"')\]}]+/gi

function tlsVisibilityText(record: AccessRetentionRecord) {
  if (record.tls_inspected) return '已解密，可检测 prompt、代码片段和文件内容'
  return '仅元数据可见，无法检测 prompt、代码片段或文件内容'
}

function normalizeFileMetadata(items?: RawFileMetadata[]) {
  return (items || []).filter(Boolean).map((item) => ({
    ...item,
    source: item.source || '',
    stage: item.stage || '',
    field_name: item.field_name || '',
    file_name: item.file_name || '',
    reference_id: item.reference_id || '',
    content_type: item.content_type || '',
    size: Number(item.size || 0),
    sha256: item.sha256 || '',
    text_preview: item.text_preview || '',
    retained_text: item.retained_text || '',
    data_base64: item.data_base64 || '',
    download_url: item.download_url || '',
    findings: item.findings || [],
  }))
}

function fileMetadataKey(item: RetainedFileMetadata) {
  return item.reference_id || item.sha256 || item.file_name || `${item.field_name}-${item.content_type}`
}

function isReferenceFile(item: RetainedFileMetadata) {
  return item.source === 'json_file_reference' || (!!item.reference_id && !item.file_name)
}

function referenceFilesFromText(text?: string): RetainedFileMetadata[] {
  const out: RetainedFileMetadata[] = []
  for (const line of (text || '').split(/\r?\n/)) {
    const match = line.trim().match(fileReferenceLinePattern)
    if (!match) continue
    const ids = match[2].match(fileReferenceIDPattern) || []
    ids.forEach((id) => out.push({
      source: 'text_file_reference',
      stage: '',
      field_name: match[1],
      file_name: '',
      reference_id: id,
      content_type: 'reference/file-id',
      size: 0,
      sha256: '',
      text_preview: '',
      retained_text: '',
      data_base64: '',
      download_url: '',
      findings: [],
    }))
  }
  return out
}

function uniqueFiles(items: RetainedFileMetadata[]) {
  const byKey = new Map<string, RetainedFileMetadata>()
  items.forEach((item) => {
    const key = fileMetadataKey(item)
    if (!key) return
    const existing = byKey.get(key)
    byKey.set(key, existing ? {
      ...item,
      ...existing,
      retained_text: existing.retained_text || item.retained_text,
      text_preview: existing.text_preview || item.text_preview,
      data_base64: existing.data_base64 || item.data_base64,
      download_url: existing.download_url || item.download_url,
    } : item)
  })
  return Array.from(byKey.values())
}

function isImageMetadata(item: RetainedFileMetadata) {
  return item.content_type.toLowerCase().startsWith('image/')
}

function isConversationUploadedFileMetadata(item: RetainedFileMetadata) {
  const field = item.field_name.toLowerCase()
  if ((item.source === 'json_file_url' || item.source === 'text_file_url') && /(?:^|\.)(?:chat|message|conversation)s?\.files?(?:\.|$)/i.test(field)) {
    return true
  }
  // ChatGPT 网页版发「图片+文字」时，SSE 流会把用户那条 input_message 原样回放，导致同一张上传
  // 图片在对话行里出现两次：stage=request 的 messages.metadata.attachments（真上传）与 stage=response
  // 的 input_message.metadata.attachments（流里回放，仍是用户上传）。两条都是 source=json_file_object。
  // 把后者也认作「用户上传」，避免被 stage=response 误判进「模型返回图片」。
  if (item.source === 'json_file_object' && /metadata\.attachments\b/i.test(field)) {
    return true
  }
  return false
}

function isModelReturnedImage(item: RetainedFileMetadata) {
  return item.stage === 'response' && isImageMetadata(item) && !isConversationUploadedFileMetadata(item)
}

function isModelReturnedFile(item: RetainedFileMetadata) {
  return item.stage === 'response' && !isImageMetadata(item) && !isReferenceFile(item) && !isConversationUploadedFileMetadata(item)
}

function isUploadedFileMetadata(item: RetainedFileMetadata) {
  if (isConversationUploadedFileMetadata(item)) return true
  return item.stage !== 'response' && !isReferenceFile(item)
}

function isDoubaoAttachmentMetadata(item: RetainedFileMetadata) {
  return item.stage !== 'response' && /messages\.content_block\.content\.attachment_block\.attachments\.(?:file|image)\b/i.test(item.field_name)
}

function doubaoAttachmentFallbackLine(item: RetainedFileMetadata) {
  const field = item.field_name.toLowerCase()
  if (field.includes('.image') || isImageMetadata(item)) {
    return item.file_name ? `[图片] ${item.file_name}` : '[图片]'
  }
  return `[附件] ${retainedFileDisplayName(item)}`
}

function requestAttachmentFallbackText(text: string, fileMetadata: RetainedFileMetadata[]) {
  if (text.trim()) return text
  const lines = uniqueFiles(fileMetadata.filter(isDoubaoAttachmentMetadata))
    .map(doubaoAttachmentFallbackLine)
    .filter(Boolean)
  return lines.join('\n')
}

function retainedImageSrc(item: RetainedFileMetadata, requestId?: string, members?: string) {
  // 小图已由详情接口内联 data_base64：直接用 data URL 渲染，省掉一次 /blob 网络往返，图随正文一起出现。
  // 大图无 data_base64，走下面 /blob 懒加载（带 immutable 缓存，二次秒开）。object_key 始终保留作兜底。
  // SP4：合并 turn 视图下带 members，让 /blob 与 /image-proxy 按整 turn 成员鉴权（图可能来自其它成员）。
  const memberSuffix = members ? `&members=${encodeURIComponent(members)}` : ''
  if (item.data_base64) return `data:${item.content_type || 'image/png'};base64,${item.data_base64}`
  if (item.object_key && requestId) {
    return `/admin/v1/audit/access-retention/${encodeURIComponent(requestId)}/blob?key=${encodeURIComponent(item.object_key)}${memberSuffix}`
  }
  if (item.download_url) {
    if (requestId) {
      return `/admin/v1/audit/access-retention/${encodeURIComponent(requestId)}/image-proxy?url=${encodeURIComponent(item.download_url)}${memberSuffix}`
    }
    return item.download_url
  }
  return ''
}

function imageURLPath(value: string) {
  try {
    return new URL(value).pathname
  } catch {
    return value.split(/[?#]/)[0]
  }
}

function isImageLikeURL(value: string) {
  return /\.(?:png|jpe?g|gif|webp|bmp|svg)(?:$|[~._-])/i.test(imageURLPath(value))
}

function imageContentTypeFromURL(value: string) {
  const ext = imageURLPath(value).split('.').pop()?.toLowerCase()
  if (ext === 'jpg' || ext === 'jpeg') return 'image/jpeg'
  if (ext === 'png') return 'image/png'
  if (ext === 'gif') return 'image/gif'
  if (ext === 'webp') return 'image/webp'
  if (ext === 'bmp') return 'image/bmp'
  if (ext === 'svg') return 'image/svg+xml'
  return 'image/*'
}

function imageFileNameFromURL(value: string) {
  try {
    const name = decodeURIComponent(new URL(value).pathname.split('/').filter(Boolean).pop() || '')
    return name || 'model-image'
  } catch {
    return value.split(/[?#]/)[0].split('/').filter(Boolean).pop() || 'model-image'
  }
}

function fileURLPath(value: string) {
  try {
    return decodeURIComponent(new URL(value).pathname)
  } catch {
    try {
      return decodeURIComponent(value.split(/[?#]/)[0])
    } catch {
      return value.split(/[?#]/)[0]
    }
  }
}

function fileContentTypeFromName(name: string) {
  const ext = name.split('.').pop()?.toLowerCase() || ''
  if (ext === 'pdf') return 'application/pdf'
  if (ext === 'doc') return 'application/msword'
  if (ext === 'docx') return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  if (ext === 'xls') return 'application/vnd.ms-excel'
  if (ext === 'xlsx') return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  if (ext === 'ppt') return 'application/vnd.ms-powerpoint'
  if (ext === 'pptx') return 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
  if (ext === 'txt' || ext === 'md' || ext === 'log') return 'text/plain'
  if (ext === 'csv') return 'text/csv'
  if (ext === 'json') return 'application/json'
  if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return 'application/octet-stream'
  return 'application/octet-stream'
}

function retainedFileNameFromURL(value: string) {
  try {
    const url = new URL(value)
    const queryName = url.searchParams.get('filename') || url.searchParams.get('fileName') || url.searchParams.get('name')
    if (queryName?.trim()) return queryName.trim().split(/[/\\]/).filter(Boolean).pop() || queryName.trim()
  } catch {
    // Fall through to path parsing below.
  }
  const name = fileURLPath(value).split('/').filter(Boolean).pop() || ''
  return name.includes('.') ? name : ''
}

function retainedFileReferenceIDFromURL(value: string) {
  const path = fileURLPath(value).replace(/^\/+/, '')
  for (const marker of ['kimi-fs/files/blob/', 'files/blob/', 'blob/']) {
    const index = path.indexOf(marker)
    if (index >= 0) return path.slice(index)
  }
  return path
}

function normalizedFileURLReferenceKey(value: string) {
  const id = retainedFileReferenceIDFromURL(value)
  if (id) return id.toLowerCase()
  try {
    const url = new URL(value)
    url.search = ''
    url.hash = ''
    return url.toString().toLowerCase()
  } catch {
    return value.replace(/[?#].*$/, '').toLowerCase()
  }
}

function isDownloadableFileLikeURL(value: string, fieldName = '') {
  const lowerField = fieldName.toLowerCase()
  const lowerPath = fileURLPath(value).toLowerCase()
  if (!/^https?:\/\//i.test(value)) return false
  if (isImageLikeURL(value) || /(?:image|images|img|icon|avatar)/i.test(lowerField)) return false
  const name = retainedFileNameFromURL(value)
  if (/\.(?:pdf|docx?|xlsx?|pptx?|txt|md|csv|json|zip|rar|7z|tar|gz)$/i.test(name)) return true
  return /(?:file|files|attachment|upload|document|signurl|downloadurl|previewurl)/i.test(lowerField) && /(?:\/file|files|sign-obj|\/blob\/)/i.test(lowerPath)
}

function retainedFileURLPriority(fieldName: string) {
  const lower = fieldName.toLowerCase()
  if (/(?:download|signurl|sign|^url$)/i.test(lower)) return 1
  if (/(?:origin|original|fullsize|full)/i.test(lower)) return 2
  if (/preview/i.test(lower)) return 3
  if (/thumb/i.test(lower)) return 4
  return 5
}

function retainedFilesFromText(text?: string, stage: 'request' | 'response' = 'response') {
  const source = text || ''
  const byKey = new Map<string, { item: RetainedFileMetadata; priority: number }>()
  const addFile = (rawURL: string, fieldName: string) => {
    const url = rawURL.trim()
    if (!isDownloadableFileLikeURL(url, fieldName)) return
    const fileName = retainedFileNameFromURL(url) || '未命名文件'
    const key = normalizedFileURLReferenceKey(url) || url
    const item: RetainedFileMetadata = {
      source: 'text_file_url',
      stage,
      field_name: fieldName,
      file_name: fileName,
      reference_id: retainedFileReferenceIDFromURL(url),
      content_type: fileContentTypeFromName(fileName),
      size: 0,
      sha256: '',
      text_preview: '',
      retained_text: '',
      data_base64: '',
      download_url: url,
      findings: [],
    }
    const priority = retainedFileURLPriority(fieldName)
    const existing = byKey.get(key)
    if (!existing || priority < existing.priority) byKey.set(key, { item, priority })
  }

  retainedFileURLReferencePattern.lastIndex = 0
  let referenceMatch: RegExpExecArray | null
  while ((referenceMatch = retainedFileURLReferencePattern.exec(source)) !== null) addFile(referenceMatch[2], referenceMatch[1])

  retainedJSONURLFieldPattern.lastIndex = 0
  let fieldMatch: RegExpExecArray | null
  while ((fieldMatch = retainedJSONURLFieldPattern.exec(source)) !== null) addFile(fieldMatch[2], fieldMatch[1])

  standaloneURLPattern.lastIndex = 0
  let urlMatch: RegExpExecArray | null
  while ((urlMatch = standaloneURLPattern.exec(source)) !== null) addFile(urlMatch[0], 'inline_file_url')

  return Array.from(byKey.values()).map((entry) => entry.item)
}

function normalizedImageReferenceURL(value: string) {
  try {
    const url = new URL(value)
    url.search = ''
    url.hash = ''
    return url.toString()
  } catch {
    return value.replace(/[?#].*$/, '')
  }
}

function retainedImagesFromText(text?: string, stage: 'request' | 'response' = 'response') {
  const source = text || ''
  const byURL = new Map<string, RetainedFileMetadata>()
  const sourceHasImageContext = stage === 'response' && /(?:image|images|img|mime_type":"image\/|content_type":"image\/)/i.test(source)
  const addImage = (rawURL: string, fieldName: string, allowContext = true) => {
    if (/(?:sourceSite|displaySource|siteUrl|pageUrl)/i.test(fieldName)) return
    const url = rawURL.trim()
    const fieldHasImageContext = /(?:image|images|img)/i.test(fieldName)
    if (!isImageLikeURL(url) && !(allowContext && (fieldHasImageContext || sourceHasImageContext))) return
    const key = normalizedImageReferenceURL(url)
    if (byURL.has(key)) return
    byURL.set(key, {
      source: stage === 'response' ? 'response_image_url' : 'request_image_url',
      stage,
      field_name: fieldName,
      file_name: imageFileNameFromURL(url),
      reference_id: key,
      content_type: imageContentTypeFromURL(url),
      size: 0,
      sha256: '',
      text_preview: '',
      retained_text: '',
      data_base64: '',
      download_url: url,
      findings: [],
    })
  }

  retainedImageReferencePattern.lastIndex = 0
  let referenceMatch: RegExpExecArray | null
  while ((referenceMatch = retainedImageReferencePattern.exec(source)) !== null) addImage(referenceMatch[2], referenceMatch[1])

  retainedJSONURLFieldPattern.lastIndex = 0
  let fieldMatch: RegExpExecArray | null
  while ((fieldMatch = retainedJSONURLFieldPattern.exec(source)) !== null) addImage(fieldMatch[2], fieldMatch[1])

  standaloneURLPattern.lastIndex = 0
  let urlMatch: RegExpExecArray | null
  while ((urlMatch = standaloneURLPattern.exec(source)) !== null) addImage(urlMatch[0], 'inline_image_url', false)
  return Array.from(byURL.values())
}

function stripRetainedFileReferenceNoise(source: string) {
  return source
    .replace(retainedFileURLReferencePattern, ' ')
    .replace(retainedFileTypeMarkerPattern, ' ')
    .replace(retainedJSONURLFieldPattern, (match, fieldName, url) => (isDownloadableFileLikeURL(url, fieldName) ? `"${fieldName}":" "` : match))
    .replace(standaloneURLPattern, (url) => (isDownloadableFileLikeURL(url, 'inline_file_url') ? ' ' : url))
}

function stripRetainedImageReferenceNoise(source: string) {
  return source
    .replace(retainedImageReferencePattern, ' ')
    .replace(retainedImageReferenceMarkerPattern, ' ')
    .replace(retainedGenericImageMarkerPattern, ' ')
    .replace(retainedJSONURLFieldPattern, (match, fieldName, url) => {
      const sourceHasImageContext = retainedImageJSONProtocolPattern.test(match) || /(?:image|images|img)/i.test(fieldName) || isImageLikeURL(url)
      return sourceHasImageContext ? `"${fieldName}":" "` : match
    })
    .replace(standaloneURLPattern, (url) => (isImageLikeURL(url) ? ' ' : url))
}

type RetainedTextKind = 'request' | 'response' | 'reasoning'
type RetainedTextCleanOptions = { stripReasoningPrefix?: boolean }

function projectRetainedAgentRequestText(source: string) {
  let normalized = source.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim()
  retainedUserQueryPattern.lastIndex = 0
  const queryMatches = Array.from(normalized.matchAll(retainedUserQueryPattern))
  if (queryMatches.length > 0 && /<system-reminder|<user_query/i.test(normalized)) {
    const queries = queryMatches
      .map((match) => stripRetainedAgentImageMetadata(match[1] || ''))
      .map((value) => value.trim())
      .filter(Boolean)
    return queries.join('\n').trim()
  }

  if (retainedAgentFilesHeaderPattern.test(normalized)) {
    retainedMyRequestHeaderPattern.lastIndex = 0
    const headers = Array.from(normalized.matchAll(retainedMyRequestHeaderPattern))
    const last = headers[headers.length - 1]
    if (!last || last.index === undefined) return ''
    normalized = normalized.slice(last.index + last[0].length)
  }
  return stripRetainedAgentImageMetadata(normalized).trim()
}

function stripRetainedAgentImageMetadata(source: string) {
  const normalized = source.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  const stripVSCodeRuntime = retainedVSCodeRuntimePrefixPattern.test(normalized)
    && normalized.search(retainedSystemReminderBlockPattern) >= 0
  return cleanRetainedOutsideCodeFences(normalized, (chunk) => cleanRetainedRequestTransportChunk(chunk, stripVSCodeRuntime))
}

function cleanRetainedRequestTransportChunk(source: string, stripVSCodeRuntime: boolean) {
  const original = source
  let cleaned = source
    .replace(retainedImagePathBlockPattern, '\n')
    .replace(retainedImagePathOpenPattern, '\n')
    .replace(retainedAgentImageRefPattern, '')
    .replace(retainedCodeBuddyImagePathPattern, '\n')
    .replace(retainedVSCodeLocalImagePathPattern, '\n')
    .replace(retainedToolsChangedNoticeBlockPattern, '\n')
  if (retainedWorkBuddyLoopNoticeBlockPattern.test(cleaned)) cleaned = ''
  if (stripVSCodeRuntime) {
    cleaned = cleaned
      .replace(retainedCurrentDateTimeBlockPattern, '\n')
      .replace(retainedSystemReminderBlockPattern, '\n')
  }
  const toolsNoticeStart = cleaned.search(retainedToolsChangedNoticeTailPattern)
  const projected = toolsNoticeStart >= 0 ? cleaned.slice(0, toolsNoticeStart) : cleaned
  const changed = toolsNoticeStart >= 0 || projected !== original
  return {
    content: changed ? projected.trim() : projected,
    truncated: toolsNoticeStart >= 0,
  }
}

function isRetainedMarkdownFenceOpener(line: string) {
  return /^```[A-Za-z0-9_+.-]*[\t ]*$/.test(line)
}

function isRetainedMarkdownFenceClose(line: string) {
  return /^```[\t ]*$/.test(line)
}

function cleanRetainedAssistantTransportChunk(source: string) {
  let cleaned = source.replace(retainedPrivateBlockPattern, '\n')
  cleaned = cleaned.replace(retainedPrivateClosePattern, '')
  let truncated = false
  const privateStart = cleaned.search(retainedPrivateOpenPattern)
  if (privateStart >= 0) {
    cleaned = cleaned.slice(0, privateStart)
    truncated = true
  }
  const runtimeDocStart = cleaned.search(retainedRuntimeDocStartPattern)
  if (runtimeDocStart >= 0) {
    cleaned = cleaned.slice(0, runtimeDocStart)
    truncated = true
  }
  return { content: cleaned.replace(retainedPrivateLinePattern, '').trim(), truncated }
}

function cleanRetainedOutsideCodeFences(source: string, cleanChunk: (chunk: string) => { content: string; truncated: boolean }) {
  const lines = source.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')
  const output: string[] = []
  let outside: string[] = []
  let fenced: string[] = []
  let inFence = false
  let truncated = false

  const flushOutside = () => {
    if (outside.length === 0 || truncated) return
    const result = cleanChunk(outside.join('\n'))
    if (result.content) output.push(result.content)
    outside = []
    truncated = result.truncated
  }

  for (const line of lines) {
    if (truncated) break
    if (inFence) {
      fenced.push(line)
      if (isRetainedMarkdownFenceClose(line)) {
        output.push(fenced.join('\n'))
        fenced = []
        inFence = false
      }
      continue
    }
    if (isRetainedMarkdownFenceOpener(line)) {
      flushOutside()
      if (truncated) break
      inFence = true
      fenced = [line]
      continue
    }
    outside.push(line)
  }

  if (!truncated && inFence) {
    // An unterminated fence cannot make transport-private content safe to show.
    outside.push(...fenced)
  }
  flushOutside()
  return output.join('\n').trim()
}

function cleanRetainedAssistantTransportText(source: string) {
  return cleanRetainedOutsideCodeFences(source, cleanRetainedAssistantTransportChunk)
}

function cleanRetainedText(raw?: string, kind: RetainedTextKind = 'request', options: RetainedTextCleanOptions = {}) {
  const source = raw || ''
  if (kind === 'response' || kind === 'reasoning') return cleanRetainedResponseText(source, options)
  return cleanRetainedRequestText(source)
}

function cleanRetainedRequestText(source: string) {
  const projected = projectRetainedAgentRequestText(source)
  if (!projected) return ''
  if (isRetainedBackgroundWorkloadText(projected)) return ''
  const withoutUploads = stripRetainedFileReferenceNoise(stripRetainedImageReferenceNoise(stripRetainedUploadBlocks(projected)))
  const lines = trimBlankEdges(withoutUploads
    .split(/\r?\n/)
    .map(normalizeRetainedFieldLine)
    .filter((line) => !isFileReferenceLine(line) && !isStandaloneMetadataID(line) && !isRetainedUploadHeaderLine(line)))
  const withoutProtocol = trimBlankEdges(lines.filter((line) => !isRetainedProtocolLine(line)))
  return (withoutProtocol.length > 0 ? withoutProtocol : lines).join('\n')
}

function isRetainedBackgroundWorkloadText(source: string) {
  const lower = source.trim().toLowerCase()
  if (lower.startsWith('## memory writing agent:') && lower.includes('you are a memory writing agent.')) return true
  if (lower.startsWith('heartbeat poll:') || /^\[[a-z]{3} [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} gmt[+-][0-9:]+\]\s*\[openclaw heartbeat poll\]$/.test(lower)) return true
  if (lower.startsWith('critical: respond with text only. do not call any tools.') && lower.includes('summary')) return true
  if (lower.startsWith('this session is being continued from a previous conversation that ran out of context.') && lower.includes('summary')) return true
  if (!lower.startsWith('analyze this rollout')) return false
  if (lower.includes('durable memory')) return true
  const markers = ['rollout_context:', 'rendered conversation', 'raw_memory', 'rollout_summary', 'rollout_slug']
  return markers.filter((marker) => lower.includes(marker)).length >= 2
}

function retainedRunDisplayTitle(record: EvidenceRunRecord) {
  if (record.task_class === 'codex_background_memory') return 'Codex 后台记忆整理'
  const cleaned = stripRetainedAgentImageMetadata(record.title || '').replace(/\s+/g, ' ').trim()
  return cleaned || (record.kind === 'agent_task' ? '未命名任务' : '未命名对话')
}

function cleanRetainedResponseText(source: string, options: RetainedTextCleanOptions = {}) {
  const withoutThinkBlocks = cleanRetainedAssistantTransportText(source)
  const withoutImageRefs = stripRetainedImageReferenceNoise(withoutThinkBlocks)
  const withoutFileRefs = stripRetainedFileReferenceNoise(withoutImageRefs)
  const webModelText = cleanWebModelProtocolTokenStream(withoutFileRefs)
  if (webModelText) return webModelText

  const originalLines = withoutFileRefs.split(/\r?\n/)
  const setResponseLines = extractSetResponseLines(originalLines)
  if (setResponseLines) return cleanFinalResponseLines(setResponseLines).join('\n')

  const finalMarkerLines = extractAfterFinalMarker(originalLines)
  if (finalMarkerLines) return cleanFinalResponseLines(finalMarkerLines).join('\n')

  const sawFragmentProtocol = originalLines.some((line) => {
    const trimmed = line.trim()
    return retainedStreamPathPattern.test(trimmed) || ['append', 'replace', 'done'].includes(trimmed.toLowerCase())
  })
  const lines = cleanFinalResponseLines(originalLines)
  if (sawFragmentProtocol || shouldReflowFragmentedText(lines)) {
    const displayLines = options.stripReasoningPrefix ? stripLikelyReasoningPrefix(lines) : lines
    return formatReflowedModelText(reflowFragmentedText(displayLines))
  }
  return lines.join('\n')
}

function extractSetResponseLines(lines: string[]) {
  const index = lines.findIndex((line) => setResponsePattern.test(line))
  if (index < 0) return null
  const first = lines[index].replace(setResponsePattern, '')
  return [first, ...lines.slice(index + 1)]
}

function extractAfterFinalMarker(lines: string[]) {
  let index = -1
  lines.forEach((line, i) => {
    if (finalAnswerMarkerPattern.test(line.trim())) index = i
  })
  if (index < 0) return null
  return lines.slice(index + 1)
}

function cleanFinalResponseLines(lines: string[]) {
  return dedupeAdjacentRetainedLines(trimBlankEdges(stripWrappingAsciiQuote(lines)
    .filter((line) => !isFileReferenceLine(line) && !isStandaloneMetadataID(line) && !isRetainedAttachmentHeaderLine(line) && !isRetainedResponseProtocolLine(line))))
}

function isFileReferenceLine(line: string) {
  return fileReferenceLinePattern.test(line.trim())
}

function isStandaloneMetadataID(line: string) {
  return standaloneUUIDPattern.test(line.trim())
}

function isRetainedAttachmentHeaderLine(line: string) {
  return retainedPartHeaderPattern.test(line.trim())
}

function isRetainedProtocolLine(line: string) {
  const trimmed = line.trim()
  if (!trimmed) return false
  if (retainedProtocolNoise.has(trimmed.toLowerCase())) return true
  if (retainedWebModelProtocolLinePattern.test(trimmed)) return true
  return retainedStreamPathPattern.test(trimmed)
}

function isRetainedResponseProtocolLine(line: string) {
  const trimmed = line.trim()
  return isRetainedProtocolLine(trimmed) || retainedWebModelBrandLinePattern.test(trimmed) || isRetainedFileReferenceNoiseLine(trimmed) || isWebModelProtocolJSONLine(trimmed)
}

function isRetainedFileReferenceNoiseLine(line: string) {
  const trimmed = line.trim()
  return retainedFileURLReferenceLinePattern.test(trimmed) || retainedFileTypeMarkerLinePattern.test(trimmed) || /^FILE_TYPE_[A-Z0-9_]+$/i.test(trimmed)
}

function isWebModelProtocolJSONLine(line: string) {
  const trimmed = line.trim()
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return false
  if (retainedWebModelJSONProtocolPattern.test(trimmed)) return true
  if (retainedImageJSONProtocolPattern.test(trimmed)) return true
  if (retainedFilesFromText(trimmed, 'response').length > 0) return true
  return retainedImagesFromText(trimmed, 'response').length > 0
}

function cleanWebModelProtocolTokenStream(source: string) {
  if (!webModelTokenStreamSignalPattern.test(source)) return ''
  const normalized = source
    .replace(retainedFileURLReferencePattern, ' ')
    .replace(retainedFileTypeMarkerPattern, ' ')
    .replace(/\[[^\]]*(?:url|image_thumb|image_ori|icon)[^\]]*\]\s*https?:\/\/\S+/gi, ' ')
    .replace(/https?:\/\/\S+/gi, ' ')
  const tokens = normalized.split(/\s+/).map((token) => token.trim()).filter(Boolean)
  const kept: string[] = []
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]
    if (isWebModelProtocolToken(token)) {
      if (/^chat\.name$/i.test(token)) index += 1
      continue
    }
    kept.push(token)
  }
  const compact = formatReflowedModelText(reflowFragmentedText(kept))
  return /[\u4e00-\u9fff]/.test(compact) ? compact : ''
}

function isWebModelProtocolToken(token: string) {
  const trimmed = token.trim()
  const lower = trimmed.toLowerCase()
  if (!trimmed) return true
  if (retainedProtocolNoise.has(lower)) return true
  if (['set', 'message', 'chat.lastrequest', 'chat.name', '未命名会话'].includes(lower)) return true
  if (/^(?:SCENARIO_[A-Z0-9_]+|TOOL_TYPE_[A-Z0-9_]+|MESSAGE_STATUS_[A-Z0-9_]+|local_[A-Za-z0-9_-]+)$/i.test(trimmed)) return true
  if (/^\d+$/.test(trimmed)) return true
  if (/^\d{4}-\d{2}-\d{2}T[^\s]+Z?$/i.test(trimmed)) return true
  if (webModelProtocolUUIDPattern.test(trimmed)) return true
  if (/^(?:chat|message|patch_op|content_block|text_block|loading_block)(?:\.|$)/i.test(trimmed)) return true
  if (/^block(?:\.[A-Za-z0-9_-]+)+[!?！？。；;:：]*$/i.test(trimmed)) return true
  return false
}

function stripWrappingAsciiQuote(lines: string[]) {
  const out = [...lines]
  const firstIndex = out.findIndex((line) => line.trim())
  const lastIndex = out.length - 1 - [...out].reverse().findIndex((line) => line.trim())
  if (firstIndex < 0 || lastIndex < firstIndex) return out

  const first = out[firstIndex]
  const last = out[lastIndex]
  if (first.trimStart().startsWith('"') && last.trimEnd().endsWith('"')) {
    out[firstIndex] = first.replace(/^(\s*)"/, '$1')
    out[lastIndex] = out[lastIndex].replace(/"\s*$/, '')
  }
  return out
}

function trimBlankEdges(lines: string[]) {
  let start = 0
  let end = lines.length
  while (start < end && !lines[start].trim()) start += 1
  while (end > start && !lines[end - 1].trim()) end -= 1
  return lines.slice(start, end)
}

function shouldReflowFragmentedText(lines: string[]) {
  const contentLines = lines.map((line) => line.trim()).filter(Boolean)
  if (contentLines.length < 4) return false
  const shortLines = contentLines.filter((line) => line.length <= 8).length
  const averageLength = contentLines.reduce((sum, line) => sum + line.length, 0) / contentLines.length
  return averageLength <= 14 || shortLines / contentLines.length >= 0.6
}

function splitDeepSeekResponseContent(source?: string, enabled = false) {
  const empty = { reasoning: '', answer: source || '' }
  if (!source) return empty

  const reasoning: string[] = []
  const answer: string[] = []
  let sawReasoningMarker = false
  for (const line of source.split(/\r?\n/)) {
    const match = line.match(/^\s*\[reasoning\]\s*(.*)$/i)
    if (match) {
      sawReasoningMarker = true
      reasoning.push(match[1])
      continue
    }
    answer.push(line)
  }
  if (sawReasoningMarker) {
    return { reasoning: reasoning.join('\n'), answer: answer.join('\n') }
  }

  // 以下为 DeepSeek 专属的中文启发式拆分，仅对 DeepSeek 记录(enabled)生效；
  // 其他 provider 只吃上面的通用 [reasoning] 标记拆分，无标记则原样返回，
  // 避免对英文/其他语言内容误切。
  if (!enabled) return empty

  const cleanedLines = cleanFinalResponseLines(source.split(/\r?\n/))
  const contentLines = cleanedLines.map((line) => line.trim()).filter(Boolean)
  const singleLineSplit = splitSingleLineDeepSeekReasoning(contentLines)
  if (singleLineSplit) return singleLineSplit
  if (!shouldReflowFragmentedText(contentLines)) return empty
  if (!looksLikeDeepSeekReasoning(contentLines.slice(0, Math.min(40, contentLines.length)).join(''))) return empty
  const answerStart = findLikelyFinalAnswerStart(contentLines)
  if (answerStart <= 0) return empty
  return { reasoning: contentLines.slice(0, answerStart).join('\n'), answer: contentLines.slice(answerStart).join('\n') }
}

function splitSingleLineDeepSeekReasoning(lines: string[]) {
  if (lines.length !== 1) return null
  const text = lines[0].trim()
  if (!looksLikeDeepSeekReasoning(text)) return null
  const marker = findSingleLineDeepSeekAnswerStart(text)
  if (marker <= 0) return null
  return { reasoning: text.slice(0, marker).trim(), answer: text.slice(marker).trim() }
}

function looksLikeDeepSeekReasoning(text: string) {
  return text.includes('用户') && /(可能|应该|意图|打字|错误|回复|自我介绍|问题|看起来|表达)/.test(text)
}

function findSingleLineDeepSeekAnswerStart(text: string) {
  const patterns = [
    /哎呀[，,]?我(?:猜|猜你|理解)/,
    /我猜你可能是想问/,
    /你可能是想问/,
    /我是(?:一个|由)/,
    /你好[，,]/,
    /您好[，,]/,
    /当然[，,]/,
    /简单来说/,
  ]
  let best = -1
  for (const pattern of patterns) {
    const match = pattern.exec(text)
    if (!match || match.index < 16) continue
    if (best < 0 || match.index < best) best = match.index
  }
  return best
}

function isDeepSeekRecord(record?: AccessRetentionRecord | null) {
  if (!record) return false
  const values = [record.provider, record.product, record.product_cn, record.target_host].filter(Boolean).join(' ').toLowerCase()
  return values.includes('deepseek')
}

function stripLikelyReasoningPrefix(lines: string[]) {
  const contentLines = lines.map((line) => line.trim()).filter(Boolean)
  if (!shouldReflowFragmentedText(contentLines)) return lines

  const prefix = contentLines.slice(0, Math.min(40, contentLines.length)).join('')
  if (!looksLikeDeepSeekReasoning(prefix)) return lines

  const answerStart = findLikelyFinalAnswerStart(contentLines)
  return answerStart > 0 ? contentLines.slice(answerStart) : lines
}

function findLikelyFinalAnswerStart(lines: string[]) {
  const minIndex = Math.min(Math.max(8, Math.floor(lines.length * 0.25)), Math.max(lines.length - 1, 0))
  for (let index = minIndex; index < lines.length; index += 1) {
    const current = lines[index]
    const nextText = lines.slice(index, index + 12).join('')
    if (/^(?:哎呀|你好|您好|抱歉|不好意思|当然|可以|简单来说|这个|这是)$/.test(current) && /(?:我是|我可以|可以|这是|你可能|想问|助手|回答|建议|帮你)/.test(nextText)) {
      return index
    }
    if (/^(?:我猜你|你可能是想问|我是|我可以)/.test(current) && /(?:我是|我可以|助手|回答|建议|帮你)/.test(nextText)) {
      return index
    }
    if (current === '我' && lines[index + 1] === '猜' && /你可能是想问/.test(lines.slice(index, index + 8).join(''))) {
      return index
    }
  }
  return -1
}

function dedupeAdjacentRetainedLines(lines: string[]) {
  const out: string[] = []
  lines.forEach((line) => {
    const trimmed = line.trim()
    const previous = out[out.length - 1]?.trim()
    if (trimmed && previous === trimmed) return
    out.push(line)
  })
  return out
}

function restoreRetainedMarkdownBreaks(text: string) {
  return text
    .replace(/\s+(#{1,6}\s+)/g, '\n\n$1')
    .replace(/\s+(\d+\.\s+)/g, '\n$1')
    .replace(/\s+(-\s+)/g, '\n$1')
    .trim()
}

function formatReflowedModelText(text: string) {
  const compact = text
    .replace(/\s+/g, ' ')
    .replace(/\s+([，。！？、,.!?;；:：)）])/g, '$1')
    .replace(/([（(])\s+/g, '$1')
    .replace(/([\u4e00-\u9fff])\*\*\s+/g, '$1 **')
    .replace(/\*\*\s+([A-Za-z0-9\u4e00-\u9fff])/g, '**$1')
    .replace(/\s+\*\*([，。！？、,.!?;；:：)）])/g, '**$1')
    .replace(/\s*(```[A-Za-z0-9_+.-]*)\s+/g, '\n\n$1\n')
    .replace(/\s+(```)\s*/g, '\n$1\n')
    .trim()
  return restoreRetainedMarkdownBreaks(normalizeReflowedCodeBlocks(compact))
}

function normalizeReflowedCodeBlocks(text: string) {
  return text.replace(/```([A-Za-z0-9_+.-]*)\n([\s\S]*?)\n```/g, (_match, language, code) => {
    const normalizedCode = String(code)
      .replace(/#(?=[\u4e00-\u9fff])/g, '# ')
      .replace(/"\s*([^"\n]+?)\s*"/g, (_quoteMatch, inner) => `"${String(inner).replace(/\s+/g, '')}"`)
      .replace(/(\/[A-Za-z0-9_.-]+)\s+(?=\/[A-Za-z0-9_.-]+)/g, '$1')
      .trim()
    return `\`\`\`${language}\n${normalizedCode}\n\`\`\``
  })
}

function reflowFragmentedText(lines: string[]) {
  return lines.reduce((acc, rawLine) => {
    const line = rawLine.trim()
    if (!line) return acc
    if (!acc) return line
    if (line === ':' && /[\u4e00-\u9fff]$/.test(acc)) return `${acc}：`
    if (/^[，。！？、,.!?;；:：)）]/.test(line)) return `${acc}${line}`
    if (/^[（(]$/.test(line)) return `${acc}${line}`

    const last = acc[acc.length - 1]
    const prevIsCJK = /[\u4e00-\u9fff]$/.test(acc)
    const nextIsCJK = /^[\u4e00-\u9fff]/.test(line)
    const prevIsAscii = /[A-Za-z0-9]$/.test(last)
    const nextIsAsciiWord = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(line)
    if ((prevIsCJK && nextIsAsciiWord) || (prevIsAscii && nextIsCJK)) return `${acc} ${line}`
    if (prevIsCJK || nextIsCJK) return `${acc}${line}`
    return `${acc} ${line}`
  }, '').replace(/\s+([，。！？、,.!?;；:：)）])/g, '$1')
}

function isRetainedUploadHeaderLine(line: string) {
  return retainedUploadHeaderPattern.test(line.trim())
}

function normalizeRetainedFieldLine(line: string) {
  const match = line.match(retainedFieldLinePattern)
  return match ? match[1] : line
}

function stripRetainedUploadBlocks(source: string) {
  const out: string[] = []
  let skippingUploadBody = false
  for (const line of source.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (isRetainedUploadHeaderLine(line)) {
      skippingUploadBody = true
      continue
    }
    if (skippingUploadBody) {
      if (!retainedPartHeaderPattern.test(trimmed)) continue
      skippingUploadBody = false
    }
    if (!isRetainedUploadHeaderLine(line)) out.push(line)
  }
  return out.join('\n')
}

function retainedUploadedFilesFromText(text?: string): RetainedFileMetadata[] {
  const files: RetainedFileMetadata[] = []
  let current: RetainedFileMetadata | null = null
  let bodyLines: string[] = []

  const flush = () => {
    if (!current) return
    const retainedText = trimBlankEdges(bodyLines).join('\n')
    files.push({
      ...current,
      retained_text: retainedText,
      text_preview: current.text_preview || retainedText.slice(0, 500),
    })
    current = null
    bodyLines = []
  }

  for (const line of (text || '').split(/\r?\n/)) {
    const uploadMatch = line.trim().match(retainedUploadHeaderPattern)
    if (uploadMatch) {
      flush()
      current = {
        source: 'retained_request_file',
        stage: 'request',
        field_name: 'file',
        file_name: uploadMatch[1] || '',
        reference_id: '',
        content_type: uploadMatch[2] || 'application/octet-stream',
        size: Number(uploadMatch[3] || 0),
        sha256: uploadMatch[4] || '',
        text_preview: '',
        retained_text: '',
        data_base64: '',
        download_url: '',
        findings: [],
      }
      continue
    }
    if (current && retainedPartHeaderPattern.test(line.trim())) {
      flush()
    }
    if (current) bodyLines.push(line)
  }
  flush()
  return files
}

function splitRetainedTextBlocks(content?: string): RetainedDisplayBlock[] {
  const lines = (content || '').split(/\r?\n/)
  const blocks: RetainedDisplayBlock[] = []
  let textLines: string[] = []
  let codeLines: string[] = []
  let language = ''
  let inCode = false

  const flushText = () => {
    const value = textLines.join('\n')
    if (value.trim()) blocks.push({ type: 'text', content: value })
    textLines = []
  }

  lines.forEach((line) => {
    const fence = line.match(/^```([A-Za-z0-9_+.-]*)\s*$/)
    if (fence) {
      if (inCode) {
        blocks.push({ type: 'code', language: language || 'text', content: codeLines.join('\n') })
        codeLines = []
        language = ''
        inCode = false
      } else {
        flushText()
        language = fence[1] || 'text'
        inCode = true
      }
      return
    }
    if (inCode) codeLines.push(line)
    else textLines.push(line)
  })

  if (inCode) {
    blocks.push({ type: 'code', language: language || 'text', content: codeLines.join('\n') })
  } else {
    flushText()
  }
  return blocks.length > 0 ? blocks : [{ type: 'text', content: content || '' }]
}

function safeDownloadName(name: string) {
  const cleaned = name.replace(/[\\/:*?"<>|]+/g, '_').trim()
  return cleaned || 'retained-file.txt'
}

function retainedFileDisplayName(item: RetainedFileMetadata) {
  return item.file_name || item.reference_id || item.sha256 || '未命名文件'
}

function retainedFileText(item: RetainedFileMetadata) {
  return item.retained_text || item.text_preview || ''
}

function blobFromBase64(dataBase64: string, contentType: string) {
  try {
    const binary = atob(dataBase64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
    return new Blob([bytes], { type: contentType || 'application/octet-stream' })
  } catch {
    return null
  }
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = safeDownloadName(filename)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

function canDownloadRetainedFile(item: RetainedFileMetadata) {
  return !!(item.download_url || item.data_base64 || retainedFileText(item))
}

function downloadRetainedFile(item: RetainedFileMetadata) {
  const filename = safeDownloadName(retainedFileDisplayName(item))
  if (item.download_url) {
    const link = document.createElement('a')
    link.href = item.download_url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    return
  }
  if (item.data_base64) {
    const blob = blobFromBase64(item.data_base64, item.content_type)
    if (blob) {
      downloadBlob(blob, filename)
      return
    }
  }
  const text = retainedFileText(item)
  if (text) {
    const type = item.content_type || 'text/plain;charset=utf-8'
    downloadBlob(new Blob([text], { type }), filename)
    return
  }
  message.warning('暂无可下载的文件内容')
}

function copyRetainedText(value: string) {
  if (!navigator.clipboard?.writeText) {
    message.warning('当前浏览器不支持复制')
    return
  }
  navigator.clipboard.writeText(value).then(() => message.success('已复制')).catch(() => message.error('复制失败'))
}

function downloadCodeBlock(value: string, language: string, index: number) {
  const ext = language && language !== 'text' ? language.replace(/[^A-Za-z0-9]+/g, '') : 'txt'
  downloadBlob(new Blob([value], { type: 'text/plain;charset=utf-8' }), `模型回答-${index + 1}.${ext || 'txt'}`)
}

export function RetainedTurnText({ content, kind, keyword }: { content: string; kind: 'request' | 'response'; keyword?: string }) {
  const cleaned = cleanRetainedText(content, kind)
  let readable = cleaned
  if (cleaned.trimStart().startsWith('{') || cleaned.trimStart().startsWith('[')) {
    try { readable = '```json\n' + JSON.stringify(JSON.parse(cleaned), null, 2) + '\n```' } catch { /* Preserve non-JSON evidence verbatim. */ }
  }
  const blocks = splitRetainedTextBlocks(readable)
  return <div className="retention-rich-text">
    {blocks.map((block, index) => block.type === 'code'
      ? <RetainedCodeBlock key={index} language={block.language} content={block.content} index={index} keyword={keyword} />
      : <RetentionProse key={index} text={block.content} keyword={keyword} />)}
  </div>
}

function RetentionProse({ text, keyword }: { text: string; keyword?: string }) {
 const inline = (value: string): ReactNode => value.split(/(\*\*[^*]+\*\*|`[^`]+`|<br\s*\/?>)/gi).map((part, index) => /^<br\s*\/?>$/i.test(part)
  ? <br key={index} />
  : part.startsWith('**') && part.endsWith('**') ? <strong key={index}><RetentionKeywordText text={part.slice(2,-2)} keyword={keyword} /></strong>
  : part.startsWith('`') && part.endsWith('`') ? <code key={index}><RetentionKeywordText text={part.slice(1,-1)} keyword={keyword} /></code>
  : <RetentionKeywordText key={index} text={part} keyword={keyword} />)
 // Only construct React elements; retained HTML must never execute or fetch media.
 const cells = (line: string) => {
  const row = line.trim().replace(/^\|/, '').replace(/(?<!\\)\|$/, '')
  return row.split(/(?<!\\)\|/).map((cell) => cell.trim().replace(/\\\|/g, '|'))
 }
 const lines = text.split('\n')
 const nodes: ReactNode[] = []
 for (let i = 0; i < lines.length;) {
  if (!lines[i].trim()) { i++; continue }
  const head = cells(lines[i])
  const divider = i + 1 < lines.length ? cells(lines[i + 1]) : []
  if (head.length > 1 && divider.length === head.length && divider.every((cell) => /^:?-{3,}:?$/.test(cell))) {
   const key = i
   i += 2
   const rows: string[][] = []
   while (i < lines.length && lines[i].trim() && lines[i].includes('|')) {
    const row = cells(lines[i])
    if (row.length !== head.length) break
    rows.push(row); i++
   }
   const align = (column: number) => divider[column].endsWith(':') ? divider[column].startsWith(':') ? 'center' as const : 'right' as const : 'left' as const
   nodes.push(<div className="retention-table-scroll" key={key}><table><thead><tr>{head.map((cell, column) => <th scope="col" key={column} style={{textAlign: align(column)}}>{inline(cell)}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={index}>{row.map((cell, column) => <td key={column} style={{textAlign: align(column)}}>{inline(cell)}</td>)}</tr>)}</tbody></table></div>)
   continue
  }
  if (/^#{1,6} /.test(lines[i])) { nodes.push(<h4 key={i}>{inline(lines[i].replace(/^#{1,6} /,''))}</h4>); i++; continue }
  const key = i
  const paragraph = [lines[i++]]
  while (i < lines.length && lines[i].trim() && !/^#{1,6} /.test(lines[i])) {
   if (i + 1 < lines.length && cells(lines[i]).length > 1 && cells(lines[i+1]).every((cell) => /^:?-{3,}:?$/.test(cell))) break
   paragraph.push(lines[i++])
  }
  nodes.push(<p key={key}>{inline(paragraph.join('\n'))}</p>)
 }
 return <>{nodes}</>
}

// Normalize older evidence payloads into the same question/answer component.
// There is no legacy layout: old transport fields never choose a different screen.
function retainedConversation(content: AccessRetentionContent | undefined, requestId: string, input = '', output = '', reasoning = '') {
 if (content?.turn_view_version === 1) return { turns: content.turns || [], processMessages: undefined }
 const messages: AccessRetentionMessage[] = (content?.messages?.length ? content.messages : [
  ...(input ? [{id: 'user', request_id: requestId, sequence: 1, role: 'user' as const, kind: 'user_input', content: input}] : []),
  ...(output ? [{id: 'answer', request_id: requestId, sequence: 2, role: 'assistant' as const, kind: 'model_output', content: output}] : []),
 ]).filter((item) => item.role === 'user' || item.role === 'assistant').map((item) => ({...item, content: cleanRetainedText(item.content, item.role === 'user' ? 'request' : 'response')})).filter((item) => !!item.content).sort((a,b) => a.sequence - b.sequence)
 const attachmentRequests = new Set((content?.artifacts || []).filter((a) => a.direction === 'input').map((a) => a.request_id || requestId))
 for (const attachmentRequest of attachmentRequests) {
  if (messages.some((m) => m.role === 'user' && m.request_id === attachmentRequest)) continue
  const at = messages.findIndex((m) => m.request_id === attachmentRequest)
  messages.splice(at < 0 ? messages.length : at, 0, {id: 'artifact-user-' + attachmentRequest,request_id:attachmentRequest,sequence:0,role:'user',kind:'user_input',content:''})
 }
 const turns: AccessRetentionTurn[] = []
 const processMessages: Record<string, AccessRetentionMessage[]> = {}
 const newTurn = (item?: AccessRetentionMessage) => {
  const turn: AccessRetentionTurn = {id: `retained-${requestId}-${turns.length}`, index: turns.length + 1, user_input: item?.content || '', started_at: item?.created_at,
   request_ids: [item?.request_id || requestId], request_count: 1, process_count: 0, status: 'unconfirmed', finality_source: 'last_observed_response', correlation_source: 'unlinked', evidence_status: content?.evidence_status || 'complete', observed_duration_ms: 0}
  turns.push(turn); processMessages[turn.id] = []; return turn
 }
 for (const item of messages) {
  if (item.role === 'user') { newTurn(item); continue }
  const turn = turns[turns.length - 1] || newTurn()
  if (turn.answer) processMessages[turn.id].push(turn.answer)
  turn.answer = item
  if (!turn.request_ids.includes(item.request_id)) turn.request_ids.push(item.request_id)
  turn.request_count = turn.request_ids.length
  turn.process_count = processMessages[turn.id].length
 }
 if (!turns.length && content?.artifacts?.length) newTurn()
 if (reasoning && turns[0]) processMessages[turns[0].id].unshift({id:'retained-reasoning',request_id:requestId,sequence:0,role:'assistant',kind:'assistant_progress',content:reasoning})
 return {turns, processMessages}
}

function RetainedCodeBlock({ language, content, index, keyword }: { language: string; content: string; index: number; keyword?: string }) {
 const [expanded, setExpanded] = useState(false)
 useEffect(() => {
  if (keyword?.trim() && content.toLocaleLowerCase().includes(keyword.trim().toLocaleLowerCase())) setExpanded(true)
 }, [content, keyword])
 const label = language || 'text'
 const long = content.split('\n').length > 7 || content.length > 700
 return <div className="retention-code">
  <div className="retention-code-toolbar"><span>{label}</span><Space size={4}>
   <Button size="small" type="text" icon={<CopyOutlined />} onClick={() => copyRetainedText(content)}>复制代码</Button>
   <Button size="small" type="text" icon={<DownloadOutlined />} onClick={() => downloadCodeBlock(content, label, index)}>下载代码</Button>
  </Space></div>
  <pre data-testid="retained-code-block" style={{ maxHeight: long && !expanded ? 150 : undefined, overflow: 'hidden' }}><code><RetentionKeywordText text={content} keyword={keyword} /></code></pre>
  {long ? <button className="retention-code-toggle" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>{expanded ? '收起代码' : `展开完整 ${label.toUpperCase()} · ${content.split('\n').length} 行`}</button> : null}
 </div>
}

function typedArtifactRequestID(requestId: string, artifact: AccessRetentionArtifact) {
  return artifact.request_id || requestId
}

function artifactGapLabel(status: string) {
  if (status === 'reference_only') return '证据缺口：仅收到附件引用，未取得原件'
  if (status === 'oversize_unretained') return '证据缺口：附件超出留证上限'
  return '证据缺口：附件原件留存失败'
}

function TypedArtifactGroup({ title, icon, artifacts, requestId, retentionWindow }: { title: string; icon: ReactNode; artifacts: AccessRetentionArtifact[]; requestId: string; retentionWindow: AccessRetentionWindow }) {
  if (artifacts.length === 0) return null
  return (
    <div style={{ border: '1px solid var(--border-color)', background: 'var(--bg-card)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <Space size={8}>
          {icon}
          <Text strong style={{ color: 'var(--text-primary)' }}>{title}</Text>
        </Space>
        <Tag>{artifacts.length} 个</Tag>
      </div>
      <div style={{ padding: 12 }}>
        {artifacts.length ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(210px, 1fr))', gap: 12 }}>
            {artifacts.map((artifact) => <TypedArtifactCard key={artifact.id} title={title} artifact={artifact} requestId={requestId} retentionWindow={retentionWindow} />)}
          </div>
        ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="本次无此类附件" />}
      </div>
    </div>
  )
}

function TypedArtifactCard({ title, artifact, requestId, retentionWindow }: { title: string; artifact: AccessRetentionArtifact; requestId: string; retentionWindow: AccessRetentionWindow }) {
  const auditIdentity = useAuditQueryIdentity()
  const retained = artifact.retention_status === 'retained'
  const artifactRequestID = typedArtifactRequestID(requestId, artifact)
  const previewQuery = useQuery({
    queryKey: ['access-retention-artifact-preview', auditIdentity, artifactRequestID, artifact.id, retentionWindow],
    queryFn: ({ signal }) => accessRetentionApi.getArtifact(artifactRequestID, artifact.id, 'preview', { ...retentionWindow, signal }),
    enabled: retained && artifact.kind === 'image' && artifact.has_preview && !!artifactRequestID,
  })
  const [previewURL, setPreviewURL] = useState('')
  const [downloading, setDownloading] = useState(false)

  useEffect(() => {
    const blob = previewQuery.data?.data
    if (!blob) {
      setPreviewURL('')
      return
    }
    const objectURL = URL.createObjectURL(blob)
    setPreviewURL(objectURL)
    return () => URL.revokeObjectURL(objectURL)
  }, [previewQuery.data])

  const downloadArtifact = async () => {
    if (!retained || !artifactRequestID) return
    setDownloading(true)
    try {
      const response = await accessRetentionApi.getArtifact(artifactRequestID, artifact.id, 'original', retentionWindow)
      downloadBlob(response.data, artifact.display_name || 'retained-file')
    } catch {
      message.error('附件下载失败')
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div style={{ border: '1px solid var(--border-color)', borderRadius: 8, padding: 10, background: 'var(--bg-secondary)', minWidth: 0 }}>
      <Space direction="vertical" size={8} style={{ width: '100%' }}>
        {artifact.kind === 'image' ? (
          <div style={{ aspectRatio: '4 / 3', borderRadius: 6, background: 'var(--bg-card)', border: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
            {previewURL ? <img alt={`${title} ${artifact.display_name || '附件'}`} src={previewURL} style={{ width: '100%', height: '100%', objectFit: 'contain', display: 'block' }} /> : <Text type="secondary">{previewQuery.isFetching ? '预览加载中...' : '无可用预览'}</Text>}
          </div>
        ) : null}
        <Text strong style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}>{artifact.display_name || '未命名附件'}</Text>
        <Space size={[6, 6]} wrap>
          <Tag color={retained ? 'green' : 'default'}>{retained ? '已留存' : '证据缺口'}</Tag>
          {artifact.media_type ? <Tag>{artifact.media_type}</Tag> : null}
          <Tag>{formatBytes(artifact.byte_size)}</Tag>
          {artifact.reference_count && artifact.reference_count > 1 ? <Tag color="blue">引用 {artifact.reference_count} 次</Tag> : null}
        </Space>
        {artifact.sha256 ? <Text type="secondary">SHA256 {artifact.sha256.slice(0, 12)}...</Text> : null}
        {retained ? (
          <Space size={6} wrap>
            <Button size="small" icon={<EyeOutlined />} disabled={!previewURL} onClick={() => previewURL && window.open(previewURL, '_blank', 'noopener,noreferrer')}>预览</Button>
            <Button size="small" icon={<DownloadOutlined />} loading={downloading} onClick={() => { void downloadArtifact() }}>下载</Button>
          </Space>
        ) : <Text type="secondary">{artifactGapLabel(artifact.retention_status)}</Text>}
      </Space>
    </div>
  )
}

function RetainedImagesPanel({ title, icon, items, emptyText, requestId, members }: { title: string; icon: ReactNode; items: RetainedFileMetadata[]; emptyText: string; requestId?: string; members?: string }) {
  return (
    <div style={{ border: '1px solid var(--border-color)', background: 'var(--bg-card)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <Space size={8}>
          {icon}
          <Text strong style={{ color: 'var(--text-primary)' }}>{title}</Text>
        </Space>
        <Tag>{items.length} 张</Tag>
      </div>
      <div style={{ padding: 12 }}>
        {items.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 }}>
            {items.map((item, index) => <RetainedImageCard key={`${fileMetadataKey(item)}-${index}`} item={item} index={index} requestId={requestId} members={members} />)}
          </div>
        ) : (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={emptyText} />
        )}
      </div>
    </div>
  )
}

function RetainedImageCard({ item, index, requestId, members }: { item: RetainedFileMetadata; index: number; requestId?: string; members?: string }) {
  const src = retainedImageSrc(item, requestId, members)
  const displayName = retainedFileDisplayName(item)
  return (
    <div style={{ border: '1px solid var(--border-color)', borderRadius: 8, padding: 10, background: 'var(--bg-secondary)' }}>
      <Space direction="vertical" size={8} style={{ width: '100%' }}>
        <div style={{ aspectRatio: '4 / 3', borderRadius: 6, background: 'var(--bg-card)', border: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
          {src ? (
            <img alt={`模型返回图片 ${index + 1}`} src={src} style={{ width: '100%', height: '100%', objectFit: 'contain', display: 'block' }} />
          ) : (
            <Text type="secondary">仅留存图片引用</Text>
          )}
        </div>
        <Space size={[6, 6]} wrap>
          <Tag color="green">模型返回</Tag>
          {item.content_type ? <Tag>{item.content_type}</Tag> : null}
          <Tag>{formatBytes(item.size)}</Tag>
          {item.data_base64 ? <Tag color="blue">留存副本</Tag> : item.download_url ? <Tag color="blue">外链图片</Tag> : <Tag>引用</Tag>}
        </Space>
        {item.sha256 ? <Text type="secondary">SHA256 {item.sha256.slice(0, 12)}...</Text> : null}
        {item.reference_id && !src ? <Text copyable style={{ color: 'var(--text-secondary)', wordBreak: 'break-all' }}>{item.reference_id}</Text> : null}
        <Space size={6} wrap>
          {src ? <Button size="small" icon={<EyeOutlined />} onClick={() => window.open(src, '_blank', 'noopener,noreferrer')}>预览大图</Button> : null}
          {canDownloadRetainedFile(item) ? <Button size="small" icon={<DownloadOutlined />} onClick={() => downloadRetainedFile(item)}>下载留存副本</Button> : null}
          {item.download_url ? <Button size="small" icon={<CopyOutlined />} onClick={() => copyRetainedText(item.download_url)}>复制图片链接</Button> : null}
        </Space>
        {!src ? <Text type="secondary">{displayName}</Text> : null}
      </Space>
    </div>
  )
}

function RetainedFilesPanel({ title, icon, items, emptyText, requestId, members }: { title: string; icon: ReactNode; items: RetainedFileMetadata[]; emptyText: string; requestId?: string; members?: string }) {
  return (
    <div style={{ border: '1px solid var(--border-color)', background: 'var(--bg-card)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <Space size={8}>
          {icon}
          <Text strong style={{ color: 'var(--text-primary)' }}>{title}</Text>
        </Space>
        <Tag>{items.length} 个</Tag>
      </div>
      <div style={{ padding: 12 }}>
        {items.length > 0 ? (
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            {items.map((item, index) => (
              <RetainedFileCard key={`${fileMetadataKey(item)}-${index}`} item={item} index={index} requestId={requestId} members={members} />
            ))}
          </Space>
        ) : (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={emptyText} />
        )}
      </div>
    </div>
  )
}


function retainedFileRoleMeta(item: RetainedFileMetadata) {
  if (isReferenceFile(item)) return { label: '引用ID', color: 'purple' }
  if (isModelReturnedFile(item)) return { label: '模型生成', color: 'green' }
  if (item.stage === 'response') return { label: '模型返回', color: 'cyan' }
  return { label: '上传文件', color: 'blue' }
}

function RetainedFileCard({ item, index, requestId, members }: { item: RetainedFileMetadata; index: number; requestId?: string; members?: string }) {
  const displayName = retainedFileDisplayName(item)
  const isReference = isReferenceFile(item)
  const roleMeta = retainedFileRoleMeta(item)
  const previewText = retainedFileText(item)
  const downloadable = canDownloadRetainedFile(item)
  const imageSrc = isImageMetadata(item) ? retainedImageSrc(item, requestId, members) : ''
  return (
    <div style={{ border: '1px solid var(--border-color)', borderRadius: 8, padding: 12, background: 'var(--bg-secondary)' }}>
      <Space direction="vertical" size={8} style={{ width: '100%' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
          <Space size={8} wrap style={{ minWidth: 0 }}>
            <Tag color={roleMeta.color}>{roleMeta.label}</Tag>
            <Text strong copyable style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>{displayName}</Text>
          </Space>
          {imageSrc ? <Button size="small" icon={<EyeOutlined />} onClick={() => window.open(imageSrc, '_blank', 'noopener,noreferrer')}>预览大图</Button> : null}
          {downloadable ? <Button size="small" icon={<DownloadOutlined />} onClick={() => downloadRetainedFile(item)}>下载留存副本</Button> : null}
        </div>
        <Space size={[6, 6]} wrap>
          {item.field_name ? <Tag>字段：{item.field_name}</Tag> : null}
          {item.content_type ? <Tag>{item.content_type}</Tag> : null}
          {!isReference ? <Tag>{formatBytes(item.size)}</Tag> : null}
          {item.sha256 ? <Tag>SHA256 {item.sha256.slice(0, 12)}...</Tag> : null}
          {item.data_base64 ? <Tag color="green">可下载原始留存</Tag> : item.download_url ? <Tag color="green">可下载文件链接</Tag> : previewText ? <Tag color="green">可下载文本留存</Tag> : null}
        </Space>
        {imageSrc ? (
          <div style={{ width: 220, maxWidth: '100%', aspectRatio: '4 / 3', borderRadius: 6, background: 'var(--bg-card)', border: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
            <img alt={`用户上传图片 ${index + 1}`} src={imageSrc} style={{ width: '100%', height: '100%', objectFit: 'contain', display: 'block' }} />
          </div>
        ) : null}
        {previewText ? (
          <div>
            <Text type="secondary">文件正文预览</Text>
            <div className="enterprise-code-block" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', marginTop: 6, lineHeight: 1.7, maxHeight: 220, overflow: 'auto' }}>
              {previewText}
            </div>
          </div>
        ) : null}
        {(item.findings || []).length > 0 ? (
          <div>
            <Text type="secondary">命中规则</Text>
            <div style={{ marginTop: 6 }}>
              <Space size={[6, 6]} wrap>
                {(item.findings || []).map((finding, findingIndex) => (
                  <Tag key={`${finding.rule_name || finding.category}-${findingIndex}`} color="red">
                    {finding.rule_name || getRiskCategoryLabel(finding.category) || finding.category || '风险规则'}
                  </Tag>
                ))}
              </Space>
            </div>
          </div>
        ) : null}
      </Space>
    </div>
  )
}

function AccessRetention() {
  const auditIdentity = useAuditQueryIdentity()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const searchParamsKey = searchParams.toString()
  const queryClient = useQueryClient()
  const [provider, setProvider] = useState<string | undefined>()
  const [riskState, setRiskState] = useState<string | undefined>(() => searchParams.get('risk_state') || undefined)
  const [targetInput, setTargetInput] = useState('')
  const [targetHost, setTargetHost] = useState('')
  const [sourceIP, setSourceIP] = useState('')
  const [userId, setUserId] = useState('')
  const [selectedUser, setSelectedUser] = useState<ContentAuditUserOption | null>(null)
  const [userSearchInput, setUserSearchInput] = useState('')
  const [userSearch, setUserSearch] = useState('')
  const [disposition, setDisposition] = useState<string | undefined>()
  const [keywordInput, setKeywordInput] = useState('')
  const [keyword, setKeyword] = useState('')
  const [keywordScope, setKeywordScope] = useState<'all' | 'request' | 'response'>('all')
  const [selected, setSelected] = useState<AccessRetentionRecord | null>(null)
  // 普通详情默认完整会话；请求编号深链精确展示该次调用。
  const [memberView, setMemberView] = useState<'conversation' | string>(() => (searchParams.get('request_id') || '').trim() || 'conversation')
  const requestedEvidenceView = searchParams.get('view')
  const [selectedRun, setSelectedRun] = useState<EvidenceRunRecord | null>(null)
  const [direction, setDirection] = useState<string | undefined>()
  const initialLinkedWindow = linkedAccessRetentionTimeWindow(searchParams)
  const [explicitTimeWindow, setExplicitTimeWindow] = useState<ExplicitTimeWindow | null>(() => initialLinkedWindow)
  const [timeWindowDays, setTimeWindowDays] = useState(() => timeWindowDaysFromRange(initialLinkedWindow))
  const [agentType, setAgentType] = useState<string | undefined>(() => searchParams.get('agent_type') || undefined)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  // 深链直开（设计 1d-P1）：?request_id= 由告警"查看完整留证"下钻，精确定位一条记录并自动开详情抽屉
  const deepLinkRequestID = (searchParams.get('request_id') || '').trim()
  const [leakTraceOpen, setLeakTraceOpen] = useState(false)
  const canViewRawEvidence = canViewRawEvidenceRole(useAuthStore((state) => state.user?.role))
  const [rawEvidenceRequestId, setRawEvidenceRequestId] = useState<string | null>(null)
  const [rawEvidenceOpen, setRawEvidenceOpen] = useState(false)
  const openRawEvidence = (requestId: string) => { setRawEvidenceRequestId(requestId); setRawEvidenceOpen(true) }
  // 页签和明细子视图以 URL 为唯一事实源，确保刷新、复制链接和浏览器前进/后退一致。
  const evidenceView: EvidenceView = deepLinkRequestID
    ? 'requests'
    : requestedEvidenceView === 'ai_conversations' || requestedEvidenceView === 'requests'
      ? requestedEvidenceView
      : 'agent_tasks'
  const pageTab: 'overview' | 'details' = (
    deepLinkRequestID || searchParams.has('view') || searchParams.get('tab') === 'details' ? 'details' : 'overview'
  )

  useEffect(() => {
    const currentParams = new URLSearchParams(searchParamsKey)
    const nextWindow = linkedAccessRetentionTimeWindow(currentParams)
    setExplicitTimeWindow(nextWindow)
    if (nextWindow) setTimeWindowDays(timeWindowDaysFromRange(nextWindow))
    setRiskState(currentParams.get('risk_state') || undefined)
    setAgentType(currentParams.get('agent_type') || undefined)
    setPage(1)
  }, [searchParamsKey])

  const catalogQuery = useQuery({
    queryKey: ['llm-provider-catalog'],
    queryFn: () => llmProviderCatalogApi.list(),
  })

  const usersQuery = useInfiniteQuery({
    queryKey: ['access-retention', auditIdentity, 'user-selector', userSearch],
    initialPageParam: { cursor: undefined as string | undefined, offset: 0 },
    queryFn: ({ pageParam, signal }) => contentAuditApi.listUsers({
      q: userSearch || undefined,
      limit: 50,
      cursor: pageParam.cursor,
      offset: pageParam.cursor ? undefined : pageParam.offset,
      signal,
    }),
    getNextPageParam: (lastPage) => {
      if (!lastPage.data.has_more) return undefined
      return lastPage.data.next_cursor
        ? { cursor: lastPage.data.next_cursor, offset: 0 }
        : { cursor: undefined, offset: lastPage.data.offset + lastPage.data.limit }
    },
    enabled: pageTab === 'details',
    staleTime: 5 * 60 * 1000,
  })
  const userOptions = useMemo(() => {
    const byID = new Map<string, ContentAuditUserOption>()
    if (selectedUser) byID.set(selectedUser.id, selectedUser)
    usersQuery.data?.pages.forEach((pageData) => pageData.data.data.forEach((user) => byID.set(user.id, user)))
    return Array.from(byID.values())
  }, [selectedUser, usersQuery.data?.pages])

  const frozenTimeWindow = useMemo(
    () => explicitTimeWindow || accessRetentionTimeWindow(timeWindowDays),
    [explicitTimeWindow, timeWindowDays],
  )

  // 本页定位：仅大模型流量（llm + ai_ide，后端在 access_type 为空时默认排除普通公网/CDN/遥测噪声）
  // 且仅展示已留存正文内容的记录。access_type 与 content_only 不再随标签切换，固定为「大模型 + 有内容」。
  const accessRetentionParams = useMemo(() => {
    const params: {
      access_type: string | undefined
      provider: string | undefined
      risk_state: string | undefined
      target_host: string | undefined
      keyword: string | undefined
      keyword_scope: typeof keywordScope
      direction: string | undefined
      agent_type: string | undefined
      content_only: boolean | undefined
      limit: number
      offset: number
      skip_summary: boolean
      skip_total: boolean
      from: string
      to: string
      source_ip?: string
      user_id?: string
      disposition?: string
      request_id?: string
    } = {
      access_type: undefined,
      provider,
      risk_state: riskState,
      target_host: targetHost || undefined,
      keyword: keyword || undefined,
      keyword_scope: keywordScope,
      direction: direction || undefined,
      agent_type: agentType,
      content_only: true,
      limit: pageSize,
      offset: (page - 1) * pageSize,
      skip_summary: true,
      skip_total: true,
      ...frozenTimeWindow,
      // 深链定位：带 request_id 时保留完整 UTC 留证窗口并解除 access_type 默认限制，直达目标行；
      // 同时解除 content_only（目标告警行可能是任意留证级别/未回填 has_retained_content），
      // 否则详情抽屉会因 has_retained_content=true 硬过滤命不中而静默不开。
      ...(deepLinkRequestID ? { request_id: deepLinkRequestID, content_only: undefined } : {}),
    }
    const trimmedSourceIP = sourceIP.trim()
    if (trimmedSourceIP) params.source_ip = trimmedSourceIP
    if (userId) params.user_id = userId
    if (disposition) params.disposition = disposition
    return params
  }, [provider, riskState, targetHost, keyword, keywordScope, direction, agentType, sourceIP, userId, disposition, frozenTimeWindow, deepLinkRequestID, page, pageSize])

  const accessRetentionSummaryParams = useMemo(() => ({
    ...accessRetentionParams,
    // 正文关键词只属于留证明细；概览接口不按正文关键字聚合，不能因此停查并显示假 0。
    keyword: undefined,
    limit: undefined,
    offset: undefined,
    skip_summary: false,
    skip_total: false,
  }), [accessRetentionParams])

  const accessRetentionExportParams = useMemo(() => ({
    ...accessRetentionParams,
    limit: 100000,
    offset: 0,
  }), [accessRetentionParams])

  const loadRawRequests = pageTab === 'details' && (evidenceView === 'requests' || !!deepLinkRequestID)
  const recordsQuery = useQuery({
    queryKey: ['access-retention', auditIdentity, accessRetentionParams],
    queryFn: ({ signal }) => accessRetentionApi.list({ ...accessRetentionParams, signal }),
    enabled: loadRawRequests,
    placeholderData: (previousData) => previousData,
  })

  const evidenceRunParams = useMemo(() => ({
    ...accessRetentionParams,
    view: evidenceView === 'ai_conversations' ? 'ai_conversations' as const : 'agent_tasks' as const,
  }), [accessRetentionParams, evidenceView])

  const runsQuery = useQuery({
    queryKey: ['access-retention-runs', auditIdentity, evidenceRunParams],
    queryFn: ({ signal }) => accessRetentionApi.listRuns({ ...evidenceRunParams, signal }),
    enabled: pageTab === 'details' && evidenceView !== 'requests' && !deepLinkRequestID,
    retry: false,
  })

  // 概览只发一次完整汇总，KPI 计数也从中取（完整汇总的风险原因与正文有无已预算成列，不再需要先发
  // 一个快速计数请求垫底）。
  const summaryQuery = useQuery({
    queryKey: ['access-retention-summary', auditIdentity, accessRetentionSummaryParams],
    queryFn: ({ signal }) => accessRetentionApi.getSummary({ ...accessRetentionSummaryParams, signal }),
    // 概览与列表并行请求。完整概览较重，但不能再等列表完成后才开始。
    enabled: pageTab === 'overview',
    retry: false,
  })

  const dispositionMutation = useMutation({
    mutationFn: (payload: { subject_type: string; subject_id: string; status: 'false_positive' | 'escalated' | 'resolved'; note: string }) => auditDispositionApi.upsert(payload),
    onSuccess: () => {
      message.success('处置状态已更新')
      queryClient.invalidateQueries({ queryKey: ['access-retention'] })
    },
    onError: () => message.error('处置失败'),
  })

  const listResponse = recordsQuery.data?.data
  const runResponse = runsQuery.data?.data
  const independentSummaryResponse = summaryQuery.data?.data
  const records = useMemo(() => recordsQuery.isError ? [] : (listResponse?.data || []), [listResponse?.data, recordsQuery.isError])
  const evidenceRuns = useMemo(() => runsQuery.isError ? [] : (runResponse?.data || []), [runResponse?.data, runsQuery.isError])
  // 分页签后两条数据链相互独立：概览绝不能被已缓存的明细错误/summary_error 污染。
  const detailedSummaryData = pageTab === 'overview'
    ? independentSummaryResponse?.summary
    : (recordsQuery.isError ? undefined : listResponse?.summary)
  const summaryData = detailedSummaryData
  const summary: AccessRetentionSummary = {
    ...emptySummary,
    ...(summaryData || {}),
    evidence_quality: {
      ...emptySummary.evidence_quality,
      ...(summaryData?.evidence_quality || {}),
    },
    timeline: summaryData?.timeline || [],
    top_risk_categories: summaryData?.top_risk_categories || [],
  }
  const summaryError = (pageTab === 'overview'
    ? independentSummaryResponse?.summary_error
    : listResponse?.summary_error)
    || (pageTab === 'overview' && summaryQuery.isError ? 'summary_unavailable' : undefined)
  const listTotal = typeof listResponse?.total === 'number' ? listResponse.total : records.length
  const listTotalKnown = listResponse?.total_known !== false
  const runTotalKnown = runResponse?.total_known !== false
  const summaryTotal = !summaryError && typeof detailedSummaryData?.total === 'number'
    ? detailedSummaryData.total
    : undefined
  const tableTotal = pageTab === 'details' ? listTotal : (summaryTotal ?? listTotal)
  const showRunTable = evidenceView !== 'requests' && !deepLinkRequestID
  const activeTableTotal = showRunTable ? (runResponse?.total ?? evidenceRuns.length) : tableTotal

  // 深链直开（设计 1d-P1）：?request_id= 命中即自动打开详情抽屉
  useEffect(() => {
    if (!deepLinkRequestID) return
    const hit = records.find((r) => (
      r.request_id === deepLinkRequestID || r.member_request_ids?.includes(deepLinkRequestID)
    ))
    if (hit) {
      setMemberView(deepLinkRequestID)
      setSelected(hit)
    }
  }, [deepLinkRequestID, records])

  const closeDetailDrawer = () => {
    setSelected(null)
    setMemberView('conversation')

    if (!deepLinkRequestID) return
    const next = new URLSearchParams(searchParams)
    next.delete('request_id')
    next.set('tab', 'details')
    next.set('view', 'requests')
    setSearchParams(next, { replace: true })
  }

  const changePageTab = (value: 'overview' | 'details') => {
    const next = new URLSearchParams(searchParams)
    if (value === 'details') {
      next.set('tab', 'details')
      if (keyword) next.set('view', 'requests')
    } else {
      next.delete('tab')
      next.delete('view')
      next.delete('request_id')
      setSelected(null)
      setSelectedRun(null)
      setMemberView('conversation')
    }
    // 显式页签切换写入历史，浏览器后退可回到此前页签。
    setSearchParams(next)
  }

  const handleExport = async () => {
    try {
      const res = await accessRetentionApi.export(accessRetentionExportParams)
      const url = URL.createObjectURL(res.data)
      const link = document.createElement('a')
      link.href = url
      link.download = `内容留证-${new Date().toISOString().slice(0, 10)}.csv`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)
      message.success('导出成功')
    } catch (err) {
      console.error('导出失败', err)
      message.error('导出失败')
    }
  }
  // 会话详情默认合并全部轮次和模型物理请求；也保留单次调用下钻。
  const conversationMembers = selected?.member_request_ids && selected.member_request_ids.length > 1
    ? selected.member_request_ids
    : undefined
  const contentRequestId = memberView === 'conversation' ? selected?.request_id : memberView
  const contentMembers = memberView === 'conversation' ? conversationMembers : undefined
  const detailTimeWindow = useMemo(
    () => explicitTimeWindow || accessRetentionTimeWindow(timeWindowDays),
    [explicitTimeWindow, timeWindowDays],
  )
  const contentQuery = useQuery({
    queryKey: ['access-retention-content', auditIdentity, contentRequestId, contentMembers, detailTimeWindow, keyword, keywordScope],
    queryFn: ({ signal }) => accessRetentionApi.getContent(contentRequestId!, contentMembers, { ...detailTimeWindow, signal, view: 'turns', keyword: keyword || undefined, keyword_scope: keywordScope }),
    enabled: !!contentRequestId && !!selected?.content_retained,
  })
  const retainedContent = contentQuery.data?.data
  const selectedRunRequestID = selectedRun?.representative_request_id
  const selectedRunMembers = selectedRun?.member_request_ids || []
  const runContentQuery = useQuery({
    queryKey: ['access-retention-run-content', auditIdentity, selectedRunRequestID, selectedRunMembers, detailTimeWindow, keyword, keywordScope],
    queryFn: ({ signal }) => accessRetentionApi.getContent(selectedRunRequestID!, selectedRunMembers, { ...detailTimeWindow, signal, view: 'turns', keyword: keyword || undefined, keyword_scope: keywordScope }),
    enabled: !!selectedRunRequestID,
  })
  const runContent = runContentQuery.data?.data
  const runView = retainedConversation(runContent, selectedRunRequestID || '', runContent?.user_input || '', runContent?.model_output || '')
  const detailRequestId = contentRequestId
  const detailMembers = memberView === 'conversation' && conversationMembers ? conversationMembers.join(',') : undefined
  const providerLabelByValue = useMemo(() => {
    return new Map((catalogQuery.data?.data?.providers || []).map((item) => [item.value, item.label] as const))
  }, [catalogQuery.data?.data?.providers])
  const providerOptions = summary.top_providers.map((item) => ({
    value: item.name,
    label: `${providerLabelByValue.get(item.name) || item.name} (${item.count})`,
  }))
  const freshUntilText = summary.data_fresh_until ? formatDateTime(summary.data_fresh_until) : ''
  const agentRecognitionPercent = summary.agent_request_count > 0
    ? percentage(summary.identified_agent_count, summary.agent_request_count)
    : 0
  const agentRecognitionRate = summary.agent_request_count > 0 ? `${agentRecognitionPercent}%` : '—'
  const identifiedAgents = summary.top_agents.filter((agent) => agent.name !== 'agent-tool-call')
  const evidenceCompletePercent = summary.total > 0
    ? percentage(summary.evidence_quality.complete_count, summary.total)
    : 0
  const evidenceCompleteRate = summary.total > 0 ? `${evidenceCompletePercent}%` : '—'
  const riskRecordCount = summary.risk_count + summary.blocked_count
  const evidenceQualityItems = [
    { key: 'complete', label: '请求与响应完整', value: summary.evidence_quality.complete_count, color: 'var(--brand-green)' },
    { key: 'request', label: '仅请求正文', value: summary.evidence_quality.request_only_count, color: 'var(--brand-blue)' },
    { key: 'response', label: '仅响应正文', value: summary.evidence_quality.response_only_count, color: 'var(--brand-orange)' },
    { key: 'metadata', label: '仅元数据', value: summary.evidence_quality.metadata_only_count, color: 'var(--text-tertiary)' },
  ]
  const timelineData = summary.timeline.map((item) => ({
    date: formatTimelineBucket(item.bucket),
    total_count: item.total_count,
    risk_count: item.risk_count,
    blocked_count: item.blocked_count,
  }))
  const riskStatusItems = [
    { key: 'normal', label: '正常放行', value: summary.normal_count, color: 'var(--brand-green)' },
    { key: 'risk', label: '审计线索', value: summary.risk_count, color: 'var(--brand-orange)' },
    { key: 'blocked', label: '拒绝记录', value: summary.blocked_count, color: 'var(--brand-red)' },
  ]
  const normalStop = percentage(summary.normal_count, summary.total)
  const riskStop = Math.min(100, normalStop + percentage(summary.risk_count, summary.total))
  const riskStructureBackground = `conic-gradient(var(--brand-green) 0 ${normalStop}%, var(--brand-orange) ${normalStop}% ${riskStop}%, var(--brand-red) ${riskStop}% 100%)`
  const maxTargetCount = Math.max(1, ...summary.top_targets.map((item) => item.count))
  const riskCategoryCounts = new Map<string, number>()
  summary.top_risk_categories.forEach((item) => {
    const label = riskReasonLabel(item.name)
    riskCategoryCounts.set(label, (riskCategoryCounts.get(label) || 0) + item.count)
  })
  const riskCategoryRows = Array.from(riskCategoryCounts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
  const maxRiskCategoryCount = Math.max(1, ...riskCategoryRows.map((item) => item.count))

  const applyAgentType = (value?: string) => {
    const drillingFromOverview = pageTab === 'overview'
    if (drillingFromOverview) setSelectedRun(null)
    setPage(1)
    setAgentType(value)
    const next = new URLSearchParams(searchParams)
    next.set('tab', 'details')
    if (drillingFromOverview) next.set('view', 'requests')
    if (value) next.set('agent_type', value)
    else next.delete('agent_type')
    setSearchParams(next, { replace: !drillingFromOverview })
  }

  const applyRiskState = (value?: string) => {
    const drillingFromOverview = pageTab === 'overview'
    if (drillingFromOverview) setSelectedRun(null)
    setPage(1)
    setRiskState(value)
    const next = new URLSearchParams(searchParams)
    next.set('tab', 'details')
    if (drillingFromOverview) next.set('view', 'requests')
    if (value) next.set('risk_state', value)
    else next.delete('risk_state')
    setSearchParams(next, { replace: !drillingFromOverview })
  }

  const applyTargetHost = (value: string) => {
    const drillingFromOverview = pageTab === 'overview'
    if (drillingFromOverview) setSelectedRun(null)
    setPage(1)
    const next = value.trim()
    setTargetInput(next)
    setTargetHost(next)
    const nextParams = new URLSearchParams(searchParams)
    nextParams.set('tab', 'details')
    if (drillingFromOverview) nextParams.set('view', 'requests')
    setSearchParams(nextParams, { replace: !drillingFromOverview })
  }

  const applyEvidenceKeyword = (value: string) => {
    const next = value.trim()
    if (!next) {
      setKeywordInput('')
      setKeyword('')
      setPage(1)
      return
    }
    const runeCount = Array.from(next).length
    const minimum = minimumKeywordLength(next)
    if (runeCount < minimum || runeCount > 128) {
      message.warning('中文关键词至少 2 个字符、英文至少 3 个字符，最多 128 个字符')
      return
    }
    setKeywordInput(next)
    setKeyword(next)
    setPage(1)
    const nextParams = new URLSearchParams(searchParams)
    nextParams.set('tab', 'details')
    nextParams.set('view', 'requests')
    setSearchParams(nextParams, { replace: true })
  }

  const changeEvidenceView = (value: EvidenceView) => {
    setSelectedRun(null)
    setPage(1)
    const next = new URLSearchParams(searchParams)
    next.set('tab', 'details')
    if (value === 'agent_tasks') next.delete('view')
    else next.set('view', value)
    setSearchParams(next, { replace: true })
  }

  const showAttentionRecords = () => {
    const drillingFromOverview = pageTab === 'overview'
    setRiskState('attention')
    setSelectedRun(null)
    setPage(1)
    const next = new URLSearchParams(searchParams)
    next.set('risk_state', 'attention')
    next.set('view', 'requests')
    next.set('tab', 'details')
    setSearchParams(next, { replace: !drillingFromOverview })
  }

  const columns: TableProps<AccessRetentionRecord>['columns'] = useMemo(() => [
    {
      title: '访问时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 150,
      render: (value: string) => formatDateTime(value),
    },
    {
      title: '身份 / 来源',
      key: 'source',
      width: 140,
      render: (_, record) => {
        const actor = accessIdentityDisplay(record)
        return (
          <Space direction="vertical" size={0}>
            <Text strong>{actor.primary}</Text>
            <Text type="secondary" style={{ fontSize: 12 }}>{actor.secondary}</Text>
            {(record.turn_count || 1) > 1 ? <Tag color="blue" style={{ marginTop: 4 }}>{record.turn_count} 轮对话</Tag> : null}
          </Space>
        )
      },
    },
    {
      title: '模型 / 外部服务',
      key: 'target',
      render: (_, record) => (
        <Space direction="vertical" size={0}>
          <Space size={6} wrap>
            <Text strong>{displayAccessObject(record)}</Text>
            <Tag color={accessTypeTagColor(record)}>{accessTypeLabels[record.access_type] || record.access_type}</Tag>
          </Space>
          {record.access_direction !== 'chat_completion' && record.target_host ? (
            <Text type="secondary" style={{ fontSize: 12 }}>{record.target_host}</Text>
          ) : null}
          <Text type="secondary" ellipsis style={{ maxWidth: '100%', fontSize: 12 }}>{displayAccessPath(record)}</Text>
        </Space>
      ),
    },
    {
      title: '流量方向',
      key: 'access_direction',
      width: 100,
      render: (_, record) => {
        const meta = directionMeta[record.access_direction || 'chat_completion'] || directionMeta.chat_completion
        return <Tag color={meta.color}>{meta.label}</Tag>
      },
    },
    {
      title: '智能体',
      key: 'agent',
      width: 115,
      render: (_, record) => {
        if (!record.agent_type) {
          const label = record.access_direction === 'chat_completion' ? '普通对话（非智能体）' : '非智能体调用'
          return <Tag color="default" style={{ fontSize: 12 }}>{label}</Tag>
        }
        return <Tag color={getAgentColor(record.agent_type)}>{record.agent_label || formatAgentType(record.agent_type)}</Tag>
      },
    },
    {
      title: '服务商',
      key: 'provider',
      width: 120,
      render: (_, record) => <Tag color={record.provider ? 'geekblue' : 'default'}>{displayProvider(record)}</Tag>,
    },
    {
      title: '内容留存',
      key: 'retention',
      width: 96,
      render: (_, record) => retentionTag(record),
    },
    {
      title: '流量 / 时长',
      key: 'traffic',
      width: 120,
      render: (_, record) => (
        <Space direction="vertical" size={0}>
          <Text style={{ fontSize: 12 }}>上行 {formatBytes(record.request_bytes)}</Text>
          <Text style={{ fontSize: 12 }}>下行 {formatBytes(record.response_bytes)}</Text>
          {(record.tunnel_duration_ms || 0) > 0 ? (
            <Text type="secondary" style={{ fontSize: 12 }}>时长 {formatRunDuration(record.tunnel_duration_ms)}</Text>
          ) : null}
        </Space>
      ),
    },
    {
      title: '结论',
      dataIndex: 'risk_state',
      key: 'risk_state',
      width: 130,
      render: (_, record) => riskStatusPill(record),
    },
    {
      title: '处置',
      key: 'action',
      width: 170,
      render: (_, record) => (
        <Space size={4} wrap>
          <Button size="small" icon={<EyeOutlined />} onClick={() => { setMemberView('conversation'); setSelected(record) }}>详情</Button>
          {record.request_id && record.risk_state && record.risk_state !== 'normal' ? (
            <Button
              size="small"
              onClick={() => navigate(`/security/alerts?${new URLSearchParams({ request_id: record.request_id }).toString()}`)}
            >
              查看告警
            </Button>
          ) : null}
          {record.risk_state !== 'normal' ? (
            <Button
              size="small"
              type="primary"
              danger={record.risk_state === 'blocked'}
              onClick={() => dispositionMutation.mutate({
                subject_type: 'request',
                subject_id: record.request_id,
                status: 'escalated',
                note: '内容留证风险访问已升级为安全事件',
              })}
            >
              升级事件
            </Button>
          ) : null}
        </Space>
      ),
    },
  ], [dispositionMutation, navigate])

  const runColumns: TableProps<EvidenceRunRecord>['columns'] = useMemo(() => [
    {
      title: evidenceView === 'agent_tasks' ? '任务 / 时间' : '对话 / 时间',
      key: 'title',
      width: 240,
      render: (_, record) => (
        <Space direction="vertical" size={2}>
          <Space size={[6, 6]} wrap>
            <Text strong>{retainedRunDisplayTitle(record)}</Text>
            {record.task_class === 'codex_background_memory' ? <Tag color="purple">后台任务</Tag> : null}
          </Space>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {formatDateTime(record.started_at)} · 持续 {formatRunDuration(record.duration_ms)}
          </Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {record.username || record.client_name || record.source_ip || '来源未标识'}
          </Text>
        </Space>
      ),
    },
    {
      title: evidenceView === 'agent_tasks' ? '智能体身份' : '对话主体',
      key: 'agent',
      width: 150,
      render: (_, record) => evidenceView === 'agent_tasks' ? (
        <Space direction="vertical" size={3}>
          <Tag color={record.agent_type ? getAgentColor(record.agent_type) : 'default'}>
            {record.agent_label || (record.agent_type ? formatAgentType(record.agent_type) : '未识别产品')}
          </Tag>
          {record.agent_runtime ? (
            <Text type="secondary" style={{ fontSize: 12 }}>运行环境：{runtimeDisplayName(record.agent_runtime)}</Text>
          ) : null}
          {record.agent_detection_confidence ? (
            <Text type="secondary" style={{ fontSize: 12 }}>识别置信度 {Math.round(record.agent_detection_confidence * 100)}%</Text>
          ) : null}
        </Space>
      ) : (
        <Space direction="vertical" size={3}>
          <Tag color="blue">普通 AI 对话（非智能体）</Tag>
          <Text>{record.username || record.client_name || '对话用户未标识'}</Text>
          {record.source_ip ? <Text type="secondary" style={{ fontSize: 12 }}>来源 {record.source_ip}</Text> : null}
        </Space>
      ),
    },
    {
      title: evidenceView === 'agent_tasks' ? '模型与通道' : '模型与接入',
      key: 'models',
      render: (_, record) => (
        <Space direction="vertical" size={5}>
          <Space size={[4, 4]} wrap>{record.models.map((model) => <Tag key={model}>{model}</Tag>)}</Space>
          <Space size={[4, 4]} wrap>{record.access_directions.map((item) => <Tag color="purple" key={item}>{directionMeta[item]?.label || item}</Tag>)}</Space>
        </Space>
      ),
    },
    {
      title: evidenceView === 'agent_tasks' ? '智能体行为' : '对话概览',
      key: 'behavior',
      width: 140,
      render: (_, record) => evidenceView === 'agent_tasks' ? (
        <Space direction="vertical" size={2}>
          <Text>{record.request_count} 次模型交互</Text>
          <Text type="secondary">工具与附件明细点击任务后加载</Text>
        </Space>
      ) : (
        <Space direction="vertical" size={2}>
          <Text>{record.request_count} 个对话片段</Text>
          <Text type="secondary">用户输入与模型回答按会话归集</Text>
        </Space>
      ),
    },
    {
      title: evidenceView === 'agent_tasks' ? '关联与证据' : '内容证据',
      key: 'evidence',
      width: 130,
      render: (_, record) => (
        <Space direction="vertical" size={4}>
          <Tag color={record.correlation_confidence === 'exact' ? 'green' : record.correlation_confidence === 'derived' ? 'blue' : 'default'}>
            {record.correlation_confidence === 'exact'
              ? (evidenceView === 'agent_tasks' ? '精确关联' : '会话精确关联')
              : record.correlation_confidence === 'derived'
                ? '内容链关联'
                : record.correlation_confidence === 'inferred' ? '推断关联' : '单次请求留证'}
          </Tag>
          <Tag color={record.evidence_status === 'complete' ? 'blue' : 'orange'}>{evidenceStatusLabel(record.evidence_status)}</Tag>
        </Space>
      ),
    },
    {
      title: '结论',
      key: 'risk',
      width: 88,
      render: (_, record) => <StatusPill tone={riskTone[record.risk_state] || 'gray'}>{record.risk_state === 'blocked' ? '含拒绝记录' : riskLabels[record.risk_state] || record.risk_state}</StatusPill>,
    },
    {
      title: '操作',
      key: 'action',
      width: 110,
      render: (_, record) => (
        <Button size="small" icon={<EyeOutlined />} onClick={() => setSelectedRun(record)}>
          查看{record.kind === 'agent_task' ? '任务' : '对话'}
        </Button>
      ),
    },
  ], [evidenceView])

  return (
    <div>
      {searchParams.get('alert_case') && deepLinkRequestID ? <Alert style={{ marginBottom: 12 }} type="info" showIcon message="正在核对告警关联的单个请求留存" description={<Space wrap><span>当前请求：{deepLinkRequestID}。本页保留请求当时的记录，缺失会明确提示；最新复核状态请返回风险问题查看。</span><Link to={'/security/alerts?case_id=' + encodeURIComponent(searchParams.get('alert_case')!)}>返回对应风险问题</Link></Space>} /> : null}
      <EnterprisePageHeader
        eyebrow="审计合规"
        title="内容留证"
        description="仅聚焦大模型流量中已留存正文内容的记录——查看经网关解密和内容抽取后的请求、响应、文件与审计处置证据。普通公网/CDN/遥测噪声已默认排除，统一使用下方筛选器过滤。"
        meta={freshUntilText ? <StatusPill tone="blue">数据更新至 {freshUntilText}</StatusPill> : undefined}
        actions={(
          <Space>
            <Tooltip title="粘贴疑似泄露的 AI 回复，查找原始请求">
              <Button onClick={() => setLeakTraceOpen(true)}>泄露溯源</Button>
            </Tooltip>
            {canViewRawEvidence ? (
              <Tooltip title="按请求编号、阻断编号或命中规则定位脱敏前的原文（全程审计）">
                <Button onClick={() => { setRawEvidenceRequestId(null); setRawEvidenceOpen(true) }}>原文留证</Button>
              </Tooltip>
            ) : null}
            {pageTab === 'details' ? (
              <Tooltip title="导出当前筛选的内容留证记录">
                <Button icon={<ExportOutlined />} onClick={handleExport}>导出留证</Button>
              </Tooltip>
            ) : null}
          </Space>
        )}
      />
      <LeakTraceDrawer open={leakTraceOpen} onClose={() => setLeakTraceOpen(false)} />
      {canViewRawEvidence ? (
        <RawEvidenceDrawer open={rawEvidenceOpen} requestId={rawEvidenceRequestId} onClose={() => setRawEvidenceOpen(false)} />
      ) : null}

      <Tabs
        className="retention-page-tabs"
        activeKey={pageTab}
        onChange={(key) => changePageTab(key as 'overview' | 'details')}
        items={[
          { key: 'overview', label: '概览' },
          { key: 'details', label: '留证明细' },
        ]}
      />

      {pageTab === 'details' && recordsQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="留证列表加载失败"
          description="暂时无法读取内容留证，不会将同步或查询失败显示为 0 条。请检查服务状态后重试。"
          action={<Button onClick={() => { void recordsQuery.refetch() }}>重试</Button>}
          style={{ marginBottom: 16 }}
        />
      ) : pageTab === 'overview' && summaryError ? (
        <Alert type="warning" showIcon message="留证概览统计加载失败，留证明细仍可使用" action={<Button size="small" onClick={() => { void summaryQuery.refetch() }}>重试</Button>} style={{ marginBottom: 16 }} />
      ) : pageTab === 'overview' && summaryQuery.isFetching ? (
        <Alert type="info" showIcon message={'基础统计已加载，详细概览正在加载'} style={{ marginBottom: 16 }} />
      ) : null}

      {pageTab === 'overview' && !summaryError ? <Card
        size="small"
        title="内容留证概览"
        extra={<Text type="secondary" style={{ fontSize: 12 }}>统计随下方筛选和时间范围联动</Text>}
        className="retention-overview-card"
      >
        <div className="retention-kpi-grid">
          <MetricCard
            label="留证请求"
            valueNumber={summary.total}
            unit="条"
            tone="blue"
            icon={<FileTextOutlined />}
            hint="当前筛选窗口内的留证请求"
          />
          <MetricCard
            label="证据完整率"
            value={evidenceCompleteRate}
            tone="green"
            icon={<CheckCircleOutlined />}
            hint={summary.total > 0 ? '请求与响应均完整 ' + compactNumber(summary.evidence_quality.complete_count) + ' 条' : '暂无可评估证据'}
          />
          <MetricCard
            label="需关注记录"
            valueNumber={riskRecordCount}
            unit="条"
            tone={riskRecordCount > 0 ? 'orange' : 'green'}
            icon={<WarningOutlined />}
            hint="审计线索与拒绝记录记录"
            onClick={showAttentionRecords}
            ariaLabel="筛选需关注留证记录"
          />
          <MetricCard
            label="拒绝记录"
            valueNumber={summary.blocked_count}
            unit="条"
            tone={summary.blocked_count > 0 ? 'red' : 'green'}
            icon={<StopOutlined />}
            hint="网关已实际阻断"
          />
          <MetricCard
            label="模型 / 外部服务"
            valueNumber={summary.unique_model_count}
            unit="个"
            tone="blue"
            icon={<AppstoreOutlined />}
            hint="当前留证覆盖的公开模型或外部服务"
          />
          <MetricCard
            label="智能体识别率"
            value={agentRecognitionRate}
            tone="green"
            icon={<RobotOutlined />}
            hint={summary.agent_request_count > 0 ? '明确识别 ' + compactNumber(summary.identified_agent_count) + ' / ' + compactNumber(summary.agent_request_count) : '暂无智能体请求'}
          />
        </div>

        <div className="retention-overview-grid retention-overview-grid-primary">
          <section className="retention-overview-panel retention-overview-panel-wide">
            <div className="retention-overview-panel-header">
              <div>
                <div className="retention-overview-panel-title">留证与处置趋势</div>
                <div className="retention-overview-panel-description">按时间观察留证量、风险线索和实际阻断</div>
              </div>
            </div>
            {timelineData.length > 0 ? (
              <TrendArea
                data={timelineData}
                height={236}
                series={[
                  { key: 'total_count', label: '留证请求', color: 'var(--brand-blue)' },
                  { key: 'risk_count', label: '审计线索', color: 'var(--brand-orange)' },
                  { key: 'blocked_count', label: '拒绝记录', color: 'var(--brand-red)' },
                ]}
              />
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无趋势数据" className="retention-overview-empty" />
            )}
          </section>

          <section className="retention-overview-panel">
            <div className="retention-overview-panel-header">
              <div>
                <div className="retention-overview-panel-title">证据完整性</div>
                <div className="retention-overview-panel-description">四类证据状态互斥统计</div>
              </div>
              <span className="retention-overview-panel-value">{evidenceCompleteRate}</span>
            </div>
            {evidenceQualityItems.some((item) => item.value > 0) ? (
              <>
                <div className="retention-evidence-track" aria-label="证据完整性分布">
                  {evidenceQualityItems.map((item) => (
                    item.value > 0 ? (
                      <span
                        key={item.key}
                        title={item.label + ' ' + item.value + ' 条'}
                        style={{ width: percentage(item.value, summary.total) + '%', background: item.color }}
                      />
                    ) : null
                  ))}
                </div>
                <div className="retention-evidence-list">
                  {evidenceQualityItems.map((item) => (
                    <div className="retention-evidence-item" key={item.key}>
                      <span className="retention-legend-dot" style={{ background: item.color }} />
                      <span>{item.label}</span>
                      <strong>{compactNumber(item.value)}</strong>
                      <span className="retention-overview-rate">{percentage(item.value, summary.total)}%</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无证据完整性统计" className="retention-overview-empty" />
            )}
          </section>

          <section className="retention-overview-panel">
            <div className="retention-overview-panel-header">
              <div>
                <div className="retention-overview-panel-title">审计与处置结构</div>
                <div className="retention-overview-panel-description">点击状态筛选下方留证记录</div>
              </div>
            </div>
            {summary.total > 0 ? (
              <div className="retention-risk-structure">
                <div className="retention-risk-ring" style={{ background: riskStructureBackground }}>
                  <div className="retention-risk-ring-center">
                    <strong>{compactNumber(riskRecordCount)}</strong>
                    <span>线索 / 阻断</span>
                  </div>
                </div>
                <div className="retention-risk-status-list">
                  {riskStatusItems.map((item) => (
                    <button
                      type="button"
                      key={item.key}
                      aria-label={'筛选处置状态 ' + item.label}
                      aria-pressed={riskState === item.key}
                      className="retention-filter-row retention-risk-status-tile"
                      onClick={() => applyRiskState(item.key)}
                    >
                      <span className="retention-risk-status-label">
                        <span className="retention-legend-dot" style={{ background: item.color }} />
                        <span>{item.label}</span>
                      </span>
                      <span className="retention-risk-status-metrics">
                        <strong>{compactNumber(item.value)}</strong>
                        <span className="retention-overview-rate">{percentage(item.value, summary.total)}%</span>
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无审计处置统计" className="retention-overview-empty" />
            )}
          </section>
        </div>

        <div className="retention-overview-grid retention-overview-grid-secondary">
          <section className="retention-overview-panel retention-overview-panel-models">
            <div className="retention-overview-panel-header">
              <div>
                <div className="retention-overview-panel-title">模型 / 外部服务需关注记录</div>
                <div className="retention-overview-panel-description">无命中与线索/阻断量堆叠，点击模型筛选留证记录</div>
              </div>
              <div className="retention-inline-legend" aria-label="模型审计处置图例">
                <span><i className="retention-legend-dot retention-legend-dot-normal" />无命中</span>
                <span><i className="retention-legend-dot retention-legend-dot-risk" />线索/阻断</span>
              </div>
            </div>
            {summary.top_targets.length > 0 ? (
              <div className="retention-ranking-list">
                {summary.top_targets.slice(0, 8).map((item) => {
                  const riskCount = Math.min(item.count, Math.max(0, item.risk_count))
                  const ordinaryCount = Math.max(0, item.count - riskCount)
                  return (
                    <button
                      type="button"
                      key={item.name}
                      aria-label={'筛选模型 ' + item.name}
                      className="retention-ranking-row"
                      onClick={() => applyTargetHost(item.name)}
                    >
                      <span className="retention-ranking-label" title={item.name}>{item.name}</span>
                      <span className="retention-stacked-track">
                        <i className="retention-stacked-normal" style={{ width: ordinaryCount / maxTargetCount * 100 + '%' }} />
                        <i className="retention-stacked-risk" style={{ width: riskCount / maxTargetCount * 100 + '%' }} />
                      </span>
                      <span className="retention-ranking-total">{compactNumber(item.count)} 条</span>
                      <span className="retention-ranking-rate">需关注占比 {percentage(riskCount, item.count)}%</span>
                    </button>
                  )
                })}
              </div>
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无模型或外部服务统计" className="retention-overview-empty" />
            )}
          </section>

          <section className="retention-overview-panel">
            <div className="retention-overview-panel-header">
              <div>
                <div className="retention-overview-panel-title">规则命中 TOP</div>
                <div className="retention-overview-panel-description">同一请求可命中多类</div>
              </div>
            </div>
            {riskCategoryRows.length > 0 ? (
              <div className="retention-risk-category-list">
                {riskCategoryRows.slice(0, 6).map((item) => (
                  <div className="retention-risk-category-row" key={item.name}>
                    <div>
                      <span title={item.name}>{item.name}</span>
                      <strong>{compactNumber(item.count)}</strong>
                    </div>
                    <span className="retention-risk-category-track">
                      <i style={{ width: item.count / maxRiskCategoryCount * 100 + '%' }} />
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无规则命中统计" className="retention-overview-empty" />
            )}
          </section>

          <section className="retention-overview-panel">
            <div className="retention-overview-panel-header">
              <div>
                <div className="retention-overview-panel-title">智能体归因</div>
                <div className="retention-overview-panel-description">识别覆盖与主要调用客户端</div>
              </div>
              <span className="retention-overview-panel-value">{agentRecognitionRate}</span>
            </div>
            {summary.agent_request_count > 0 ? (
              <>
                <div className="retention-agent-coverage">
                  <span style={{ width: agentRecognitionPercent + '%' }} />
                </div>
                <div className="retention-agent-coverage-caption">
                  <span>明确识别 {compactNumber(summary.identified_agent_count)}</span>
                  <span>待识别 {compactNumber(summary.unidentified_agent_count)}</span>
                </div>
                {identifiedAgents.length > 0 ? (
                  <div className="retention-agent-list">
                    {identifiedAgents.slice(0, 5).map((agent) => (
                      <button
                        type="button"
                        key={agent.name}
                        aria-label={'筛选智能体 ' + (agent.label || formatAgentType(agent.name))}
                        className="retention-agent-row"
                        onClick={() => applyAgentType(agent.name)}
                      >
                        <Tag color={getAgentColor(agent.name)}>{agent.label || formatAgentType(agent.name)}</Tag>
                        <span>{compactNumber(agent.count)} 条</span>
                        <span className={agent.risk_count > 0 ? 'retention-agent-risk' : ''}>需关注 {compactNumber(agent.risk_count)}</span>
                      </button>
                    ))}
                  </div>
                ) : (
                  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无已识别智能体" className="retention-overview-empty retention-overview-empty-compact" />
                )}
              </>
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无智能体归因统计" className="retention-overview-empty" />
            )}
          </section>
        </div>
      </Card> : null}

      {pageTab === 'details' && (keyword || riskState) ? <Alert style={{ marginBottom: 12 }} type="info" showIcon message={<Space wrap>{keyword ? <span>已搜索：{keywordScope === 'response' ? '模型输出' : keywordScope === 'request' ? '用户输入' : '全部正文 / 文件'}「{keyword}」</span> : null}{riskState ? <Tag closable onClose={() => applyRiskState(undefined)}>风险筛选：{riskState === 'attention' ? '仅需关注记录' : riskState === 'blocked' ? '拒绝记录' : riskState === 'risk' ? '有风险' : '正常'}</Tag> : null}<Text type="secondary">搜索在当前时间及筛选条件内生效；内容不正确的回答不一定被标记为安全风险。</Text></Space>} /> : null}
      {pageTab === 'details' ? <SectionPanel
        className="retention-details-panel"
        title="留证内容"
        description="本页聚焦解密后可审计的客户内容、模型响应、文件引用与审计处置证据；无请求/响应正文的访问元数据请在态势总览和智能体统计中查看。"
        extra={(
            <CollapsibleFilters
            id="access-retention-advanced-filters"
            advancedActiveCount={[agentType, provider, direction, riskState, disposition].filter(Boolean).length}
            primary={(
              <>
                <Select
                  aria-label="时间范围"
                  style={{ width: 120 }}
                  value={timeWindowDays}
                  onChange={(value) => {
                    setExplicitTimeWindow(null)
                    setTimeWindowDays(Number(value))
                    setPage(1)
                  }}
                  options={accessRetentionWindowOptions}
                />
                <Button icon={<WarningOutlined />} onClick={showAttentionRecords} aria-label="查看需关注留证记录">
                  查看需关注留证记录
                </Button>
                <Select
                  aria-label="人员筛选"
                  allowClear
                  showSearch
                  filterOption={false}
                  placeholder="选择 Key 归属人员"
                  style={{ width: 220 }}
                  value={userId || undefined}
                  searchValue={userSearchInput}
                  onSearch={setUserSearchInput}
                  onInputKeyDown={(event) => {
                    if (event.key === 'Enter' && !event.nativeEvent.isComposing) {
                      event.preventDefault()
                      event.stopPropagation()
                      setUserSearch(userSearchInput.trim())
                    }
                  }}
                  onOpenChange={(open) => {
                    if (!open) {
                      setUserSearchInput('')
                      setUserSearch('')
                    }
                  }}
                  onChange={(value, option) => {
                    const nextID = value || ''
                    setUserId(nextID)
                    setSelectedUser(nextID ? userOptions.find((user) => user.id === nextID) || {
                      id: nextID,
                      username: String((option as { label?: unknown })?.label || nextID),
                      identity_kind: 'key_owner',
                    } : null)
                    setPage(1)
                  }}
                  onClear={() => {
                    setUserSearchInput('')
                    setUserSearch('')
                  }}
                  onPopupScroll={(event) => {
                    const target = event.currentTarget
                    if (target.scrollTop + target.clientHeight >= target.scrollHeight - 24 && usersQuery.hasNextPage && !usersQuery.isFetchingNextPage) {
                      void usersQuery.fetchNextPage()
                    }
                  }}
                  loading={usersQuery.isLoading || usersQuery.isFetchingNextPage}
                  options={userOptions.map((user) => ({
                    value: user.id,
                    label: user.department_name ? `${user.username} · ${user.department_name}` : user.username,
                  }))}
                  notFoundContent={usersQuery.isLoading ? '加载中' : '未找到有权限查看的人员'}
                />
                <Input.Search
                  allowClear
                  placeholder="搜索模型 / 域名"
                  style={{ width: 220 }}
                  value={targetInput}
                  onChange={(event) => {
                    const next = event.target.value
                    setTargetInput(next)
                    if (!next) {
                      setTargetHost('')
                      setPage(1)
                    }
                  }}
                  onSearch={applyTargetHost}
                />
                <Select aria-label="正文搜索范围" value={keywordScope} onChange={(value) => { setKeywordScope(value); setPage(1) }} style={{ width: 145 }} options={[{ value: 'all', label: '全部正文 / 文件' }, { value: 'request', label: '仅用户输入' }, { value: 'response', label: '仅模型输出' }]} />
                <Input.Search
                  allowClear
                  enterButton="搜索"
                  placeholder="搜索留证正文 / 文件名"
                  aria-label="留证正文关键词"
                  style={{ width: 300 }}
                  value={keywordInput}
                  onChange={(event) => {
                    const next = event.target.value
                    setKeywordInput(next)
                    if (!next) setKeyword('')
                    if (!next) setPage(1)
                  }}
                  onSearch={applyEvidenceKeyword}
                />
                <Input
                  allowClear
                  placeholder="搜索来源 IP / 应用 / 入口"
                  style={{ width: 280 }}
                  value={sourceIP}
                  onChange={(event) => {
                    setSourceIP(event.target.value)
                    setPage(1)
                  }}
                />

              </>
            )}
            advanced={(
              <>
                <Select
                  aria-label="智能体"
                  allowClear
                  showSearch
                  placeholder="智能体"
                  style={{ width: 180 }}
                  value={agentType}
                  onChange={applyAgentType}
                  optionFilterProp="label"
                  options={AGENT_DEFINITIONS.map((agent) => ({ value: agent.type, label: agent.label }))}
                />
                <Select
                  aria-label="服务商"
                  allowClear
                  showSearch
                  placeholder="服务商"
                  style={{ width: 160 }}
                  value={provider}
                  onChange={(value) => {
                    setProvider(value)
                    setPage(1)
                  }}
                  options={providerOptions}
                />
                <Select
                  aria-label="访问方向"
                  allowClear
                  placeholder="访问方向"
                  style={{ width: 140 }}
                  value={direction}
                  onChange={(value) => {
                    setDirection(value)
                    setPage(1)
                  }}
                  options={[
                    { value: 'reverse', label: '反向代理' },
                    { value: 'forward', label: '正向代理' },
                    { value: 'chat_completion', label: '模型中转' },
                    { value: 'device', label: '经过设备' },
                  ]}
                />
                <Select
                  aria-label="风险状态"
                  placeholder="风险状态"
                  allowClear
                  style={{ width: 140 }}
                  value={riskState}
                  onChange={applyRiskState}
                  options={[
                    { value: 'normal', label: '正常' },
                    { value: 'risk', label: '风险' },
                    { value: 'blocked', label: '阻断' },
                    { value: 'attention', label: '需关注' },
                  ]}
                />
                <Select
                  aria-label="处置状态"
                  placeholder="处置状态"
                  allowClear
                  style={{ width: 140 }}
                  value={disposition}
                  onChange={(value) => {
                    setDisposition(value)
                    setPage(1)
                  }}
                  options={[
                    { value: 'open', label: '待处置' },
                    { value: 'resolved', label: '已解决' },
                    { value: 'false_positive', label: '误报' },
                    { value: 'accepted', label: '已接受风险' },
                    { value: 'escalated', label: '已升级' },
                  ]}
                />
              </>
            )}
            />
        )}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
          <Space.Compact>
            <Button type={evidenceView === 'agent_tasks' ? 'primary' : 'default'} onClick={() => changeEvidenceView('agent_tasks')}>智能体任务</Button>
            <Button type={evidenceView === 'ai_conversations' ? 'primary' : 'default'} onClick={() => changeEvidenceView('ai_conversations')}>AI 对话</Button>
            <Button type={evidenceView === 'requests' ? 'primary' : 'default'} onClick={() => changeEvidenceView('requests')}>原始请求</Button>
          </Space.Compact>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {evidenceView === 'agent_tasks'
              ? `当前时间范围内按任务归并；后台记忆整理与心跳轮询已隐藏。本页 ${evidenceRuns.length} 个任务，包含 ${evidenceRuns.reduce((sum, run) => sum + run.request_count, 0)} 次模型调用。`
              : '当前时间范围内展示已留存正文的记录；可调整上方时间范围查看更早内容。'}
          </Text>
        </div>
        {showRunTable ? (
          <>
            {runsQuery.isError ? (
              <Alert
                type="error"
                showIcon
                style={{ marginBottom: 12 }}
                message={evidenceView === 'agent_tasks' ? '智能体任务视图加载失败' : 'AI 对话视图加载失败'}
                description={evidenceView === 'agent_tasks'
                  ? '任务聚合接口暂不可用，请稍后重试；不会退回原始请求视图。'
                  : 'AI 对话聚合接口暂不可用，请稍后重试；不会退回原始请求视图。'}
                action={(
                  <Button size="small" onClick={() => { void runsQuery.refetch() }}>
                    重试
                  </Button>
                )}
              />
            ) : null}
            <Table
            rowKey="run_id"
            columns={runColumns}
            dataSource={evidenceRuns}
            loading={runsQuery.isLoading || runsQuery.isFetching}
            scroll={{ x: 'max-content' }}
            pagination={{
              current: page,
              pageSize,
              total: activeTableTotal,
              pageSizeOptions: ['20', '50', '100'],
              showSizeChanger: true,
              showTotal: (total) => `${runTotalKnown ? '共' : '至少'} ${total} 个${evidenceView === 'agent_tasks' ? '任务' : '对话'}`,
              onChange: (nextPage, nextPageSize) => {
                setPage(nextPage)
                setPageSize(nextPageSize)
              },
            }}
            />
          </>
        ) : (
          <Table
            rowKey="request_id"
            columns={columns}
            dataSource={records}
            loading={recordsQuery.isLoading}
            locale={{ emptyText: direction === 'device' ? '暂无经过设备的流量接入' : undefined }}
            scroll={{ x: 'max-content' }}
            pagination={{
              current: page,
              pageSize,
              total: activeTableTotal,
              pageSizeOptions: ['20', '50', '100'],
              showSizeChanger: true,
              showTotal: (total) => `${listTotalKnown ? '共' : '至少'} ${total} 条`,
              onChange: (nextPage, nextPageSize) => {
                setPage(nextPage)
                setPageSize(nextPageSize)
              },
            }}
          />
        )}
      </SectionPanel> : null}


      <Drawer
        title={selectedRun?.kind === 'agent_task' ? '智能体任务留证' : 'AI 对话留证'}
        open={!!selectedRun}
        onClose={() => setSelectedRun(null)}
        width={1040}
        rootClassName="retention-drawer"
      >
        {selectedRun ? (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <details className="retention-detail-meta"><summary><span className="retention-detail-meta-title">{retainedRunDisplayTitle(selectedRun)}</span><Text type="secondary">{selectedRun.request_count} 次调用 · 任务信息</Text></summary>
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                <Space align="start" style={{ width: '100%', justifyContent: 'space-between' }} wrap>
                  <div>
                    <Text strong style={{ fontSize: 18 }}>{retainedRunDisplayTitle(selectedRun)}</Text>
                    <div><Text type="secondary">{formatDateTime(selectedRun.started_at)} 至 {formatDateTime(selectedRun.ended_at)} · {formatRunDuration(selectedRun.duration_ms)}</Text></div>
                  </div>
                  <Space size={[6, 6]} wrap>
                    {selectedRun.kind === 'agent_task' ? (
                      <Tag color={selectedRun.agent_type ? getAgentColor(selectedRun.agent_type) : 'default'}>{selectedRun.agent_label || (selectedRun.agent_type ? formatAgentType(selectedRun.agent_type) : '未识别产品')}</Tag>
                    ) : <Tag color="blue">普通 AI 对话（非智能体）</Tag>}
                    {selectedRun.kind === 'agent_task' && selectedRun.agent_runtime ? <Tag>运行环境：{runtimeDisplayName(selectedRun.agent_runtime)}</Tag> : null}
                    {selectedRun.task_class === 'codex_background_memory' ? <Tag color="purple">后台任务</Tag> : null}
                    <Tag color={selectedRun.correlation_confidence === 'exact' ? 'green' : selectedRun.correlation_confidence === 'derived' ? 'blue' : 'default'}>
                      {selectedRun.correlation_confidence === 'exact' ? '精确关联' : selectedRun.correlation_confidence === 'derived' ? '内容链关联' : selectedRun.correlation_confidence === 'inferred' ? '推断关联' : '单次请求留证'}
                    </Tag>
                    <Tag color={selectedRun.evidence_status === 'complete' ? 'blue' : 'orange'}>{evidenceStatusLabel(selectedRun.evidence_status)}</Tag>
                  </Space>
                </Space>
                <Space size={[8, 8]} wrap>
                  <Tag>{selectedRun.request_count} {selectedRun.kind === 'agent_task' ? '次模型交互' : '个对话片段'}</Tag>
                  {selectedRun.models.map((model) => <Tag key={model}>{model}</Tag>)}
                </Space>
              </Space>
            </details>

            {runContentQuery.isLoading ? <Text type="secondary">内容证据加载中...</Text> : runContentQuery.isError ? <Alert type="warning" message="内容证据加载失败" action={<Button onClick={() => void runContentQuery.refetch()}>重试</Button>} /> : (
              <RetentionTurnList
                key={JSON.stringify([auditIdentity, selectedRunRequestID, detailTimeWindow])}
                turns={runView.turns}
                processMessages={runView.processMessages}
                requestId={selectedRun.representative_request_id}
                members={selectedRunMembers}
                onViewRawEvidence={canViewRawEvidence ? openRawEvidence : undefined}
                identity={auditIdentity}
                window={detailTimeWindow}
                agentLabel={selectedRun.agent_label || (selectedRun.agent_type ? formatAgentType(selectedRun.agent_type) : 'AI')}
                riskState={selectedRun.risk_state}
                artifacts={(runContent?.artifacts || []).map((artifact) => ({...artifact, request_id: artifact.request_id || selectedRunRequestID}))}
                searchKeyword={keyword}
                searchHits={runContent?.search_hits}
                searchHitsTruncated={runContent?.search_hits_truncated}
                renderText={(content, kind) => <RetainedTurnText content={content} kind={kind} keyword={keywordScope === 'all' || keywordScope === kind ? keyword : undefined} />}
                renderArtifacts={(artifacts, direction) => artifacts.length > 0 ? <TypedArtifactGroup title={direction === 'input' ? '输入附件' : '输出产物'} icon={<PaperClipOutlined />} artifacts={artifacts} requestId={selectedRun.representative_request_id} retentionWindow={detailTimeWindow} /> : null}
              />
            )}
          </Space>
        ) : null}
      </Drawer>


      <Drawer title="对话留证" open={!!selected} onClose={closeDetailDrawer} width={1040} rootClassName="retention-drawer">
        {selected ? (() => {
          const typedDetail = Array.isArray(retainedContent?.artifacts)
          const typedArtifacts = typedDetail ? retainedContent?.artifacts || [] : []
          const fileMetadata = normalizeFileMetadata(retainedContent?.file_metadata)
          const responseURLImages = retainedImagesFromText(retainedContent?.response_content, 'response')
          const requestURLImages = retainedImagesFromText(retainedContent?.request_content, 'request')
          const responseURLFiles = retainedFilesFromText(retainedContent?.response_content, 'response')
          const requestURLFiles = retainedFilesFromText(retainedContent?.request_content, 'request')
          const modelReturnedImages = uniqueFiles([...fileMetadata.filter(isModelReturnedImage), ...responseURLImages])
          const modelReturnedFiles = uniqueFiles([...fileMetadata.filter(isModelReturnedFile), ...responseURLFiles.filter(isModelReturnedFile)])
          const referencedFiles = uniqueFiles([...fileMetadata.filter(isReferenceFile), ...referenceFilesFromText(retainedContent?.request_content)])
          const uploadedFiles = uniqueFiles([...fileMetadata.filter(isUploadedFileMetadata), ...retainedUploadedFilesFromText(retainedContent?.request_content), ...requestURLImages, ...requestURLFiles, ...responseURLFiles.filter(isConversationUploadedFileMetadata)])
          const requestContentText = contentQuery.isLoading ? '加载中...' : cleanRetainedText(retainedContent?.request_content, 'request')
          const requestText = contentQuery.isLoading ? requestContentText : requestAttachmentFallbackText(requestContentText, fileMetadata)
          const requestCollapse = contentQuery.isLoading
            ? { head: '', body: requestText, collapsedCount: 0 }
            : collapseSystemSections(requestText)
          const isDeepSeek = isDeepSeekRecord(selected)
          const responseParts = splitDeepSeekResponseContent(retainedContent?.response_content, isDeepSeek)
          const reasoningText = contentQuery.isLoading ? '' : cleanRetainedText(responseParts.reasoning, 'reasoning')
          const responseText = contentQuery.isLoading ? '加载中...' : cleanRetainedText(responseParts.answer, 'response', { stripReasoningPrefix: isDeepSeek })
          const responseCollapse = contentQuery.isLoading
            ? { head: '', body: responseText, collapsedCount: 0 }
            : collapseSystemSections(responseText)

          const detailView = retainedConversation(retainedContent, detailRequestId || selected.request_id,
            typedDetail ? retainedContent?.user_input || '' : requestCollapse.body,
            typedDetail ? retainedContent?.model_output || '' : responseCollapse.body, reasoningText)

          return (
            <Space direction="vertical" size={14} style={{ width: '100%' }}>
              <details className="retention-detail-meta"><summary><strong>{selected.agent_label || selected.target_host || 'AI 对话'}</strong><Text type="secondary">{formatDateTime(selected.created_at)} · 调用信息</Text></summary>
                <Space direction="vertical" size={10} style={{ width: '100%' }}>
                  <div>
                    <Text type="secondary">访问对象</Text>
                    <div><Text strong style={{ fontSize: 16 }}>{usesFullAccessPath(selected) ? displayProduct(selected) : selected.target_host}</Text></div>
                    <Text type="secondary">{selected.target_host}</Text>
                  </div>
                  <div>
                    <Text type="secondary">访问路径</Text>
                    <div><Text copyable>{displayAccessPath(selected)}</Text></div>
                  </div>
                  <Space size={[8, 8]} wrap>
                    {riskStatusPill(selected)}
                    {selected.risk_state !== 'normal' && riskReasonList(selected).length > 0 ? <Tag color={selected.risk_state === 'blocked' ? 'red' : 'orange'}>风险原因：{riskReasonList(selected).join('、')}</Tag> : null}
                    <Tag>{actionLabels[selected.action_taken] || selected.action_taken}</Tag>
                    <Tag>{selected.security_event_count || 0} 条风险线索</Tag>
                    {retentionTag(selected)}
                    <Tag>{directionMeta[selected.access_direction || 'chat_completion']?.label || '模型中转'}</Tag>
                    {retainedContent?.retention_until ? <Tag color="purple">内容保留至 {formatDateTime(retainedContent.retention_until)}</Tag> : null}
                  </Space>
                  <Text style={{ color: 'var(--text-secondary)' }}>
                    {selected.content_retained ? '已保存解密后的请求、响应、文件引用和上传文件内容，可用于内容安全、数据安全和智能体安全复核。' : '当前仅保留访问时间、来源、目标域名、路径模板、状态码和字节数，不保存完整 URL query、请求体或响应体。'}
                  </Text>
                  {selected.content_retained && (selected.member_count || 1) > 1 && (selected.member_request_ids?.length || 0) > 1 ? (
                    <div style={{ marginTop: 4 }}>
                      <Space size={[8, 8]} wrap align="center">
                        <Text type="secondary" style={{ fontSize: 12 }}>
                          已聚合为一个完整会话：{selected.turn_count || 1} 轮对话，{selected.member_count} 次模型调用。默认按轮次展示，可下钻单次调用：
                        </Text>
                        <Button size="small" type={memberView === 'conversation' ? 'primary' : 'default'} onClick={() => setMemberView('conversation')}>完整会话</Button>
                        {selected.member_request_ids!.map((memberId, idx) => (
                          <Button
                            key={memberId}
                            size="small"
                            type={memberView === memberId ? 'primary' : 'default'}
                            onClick={() => setMemberView(memberId)}
                            title={memberId}
                          >
                            调用 {idx + 1}{memberId === selected.request_id ? '（最新）' : ''}
                          </Button>
                        ))}
                      </Space>
                    </div>
                  ) : null}
                </Space>
              </details>

              {selected.content_retained ? (
                <>
                  {contentQuery.isLoading ? <Text type="secondary">内容证据加载中...</Text> : contentQuery.isError ? <Alert type="warning" message="内容证据加载失败" action={<Button onClick={() => void contentQuery.refetch()}>重试</Button>} /> : (
                    <RetentionTurnList
                      key={JSON.stringify([auditIdentity, detailRequestId, contentMembers, detailTimeWindow])}
                      turns={detailView.turns}
                      processMessages={detailView.processMessages}
                      requestId={detailRequestId || selected.request_id}
                      members={contentMembers || [detailRequestId || selected.request_id]}
                      onViewRawEvidence={canViewRawEvidence ? openRawEvidence : undefined}
                      identity={auditIdentity}
                      window={detailTimeWindow}
                      agentLabel={selected.agent_label || (selected.agent_type ? formatAgentType(selected.agent_type) : 'AI')}
                      riskState={selected.risk_state}
                      artifacts={typedArtifacts.map((artifact) => ({...artifact, request_id: artifact.request_id || detailRequestId || selected.request_id}))}
                      searchKeyword={keyword}
                      searchHits={retainedContent?.search_hits}
                      searchHitsTruncated={retainedContent?.search_hits_truncated}
                      renderText={(content, kind) => <RetainedTurnText content={content} kind={kind} keyword={keywordScope === 'all' || keywordScope === kind ? keyword : undefined} />}
                      renderArtifacts={(artifacts, direction) => artifacts.length > 0 ? <TypedArtifactGroup title={direction === 'input' ? '输入附件' : '输出产物'} icon={<PaperClipOutlined />} artifacts={artifacts} requestId={detailRequestId || selected.request_id} retentionWindow={detailTimeWindow} /> : null}
                    />
                  )}
                  {!typedDetail ? <>
                   {uploadedFiles.length > 0 ? <RetainedFilesPanel title="用户上传文件" icon={<PaperClipOutlined />} items={uploadedFiles} emptyText="本次请求未直接上传文件" requestId={detailRequestId} members={detailMembers} /> : null}
                   {referencedFiles.length > 0 ? <RetainedFilesPanel title="引用文件" icon={<LinkOutlined />} items={referencedFiles} emptyText="本次请求未引用已上传文件" requestId={detailRequestId} members={detailMembers} /> : null}
                   {modelReturnedFiles.length > 0 ? <RetainedFilesPanel title="模型生成文件" icon={<FileTextOutlined />} items={modelReturnedFiles} emptyText="本次模型回答未生成文件" requestId={detailRequestId} members={detailMembers} /> : null}
                   {modelReturnedImages.length > 0 ? <RetainedImagesPanel title="模型返回图片" icon={<FileTextOutlined />} items={modelReturnedImages} emptyText="本次模型回答未返回图片" requestId={detailRequestId} members={detailMembers} /> : null}
                  </> : null}
                </>
              ) : null}

              <div style={{ border: '1px solid var(--border-color)', background: 'var(--bg-card)', borderRadius: 8, padding: 14 }}>
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  <Space size={8}>
                    <FileTextOutlined style={{ color: 'var(--text-secondary)' }} />
                    <Text strong style={{ color: 'var(--text-primary)' }}>流量与审计</Text>
                  </Space>
                  <Text style={{ color: 'var(--text-secondary)' }}>{formatBytes(selected.response_bytes)}，{tlsVisibilityText(selected)}</Text>
                </Space>
              </div>

              <Space wrap>
                {selected.risk_state && selected.risk_state !== 'normal' ? (
                  <Button onClick={() => navigate(`/security/alerts?${new URLSearchParams({ request_id: selected.request_id }).toString()}`)}>查看安全告警</Button>
                ) : null}
                {canViewRawEvidence ? (
                  <Button onClick={() => openRawEvidence(selected.request_id)}>查看原文</Button>
                ) : null}
                <Button
                  onClick={() => dispositionMutation.mutate({
                    subject_type: 'request',
                    subject_id: selected.request_id,
                    status: 'false_positive',
                    note: '内容留证风险访问已人工确认误报',
                  })}
                >
                  标记误报
                </Button>
                <Button
                  type="primary"
                  onClick={() => dispositionMutation.mutate({
                    subject_type: 'request',
                    subject_id: selected.request_id,
                    status: 'escalated',
                    note: '内容留证风险访问已升级为安全事件',
                  })}
                >
                  升级事件
                </Button>
              </Space>
            </Space>
          )
        })() : null}
      </Drawer>
    </div>
  )
}

export default AccessRetention

import { SEVERITY_LABELS } from '../utils/risk'
import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Collapse, Descriptions, Drawer, Input, Radio, Select, Space, Tag, Typography, message } from 'antd'
import { StopOutlined } from '@ant-design/icons'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import ResizableTable from '../components/ResizableTable'
import { EnterprisePageHeader, SectionPanel, StatusPill } from '../components/EnterpriseUI'
import { blockRecordsApi, ws8BlockRecordsApi, type BlockResponseMode, type SecurityBlockRecord } from '../services/api'
import { AuditDateRangeFilter, ServerExportButton } from '../components/AuditExportControls'
import type { AuditDateRange } from '../components/AuditExportControls'
import { auditRangeParams, formatInTimezone, useReportContext } from '../utils/ws8ReportRange'
import {
  BLOCK_LAYER_LABELS,
  BLOCK_NOTICE_PLACEHOLDERS,
  DEFAULT_BLOCK_NOTICE_TEMPLATE,
  blockLayerLabel,
  blockRecordSearchQuery,
  normalizeBlockNoticeTemplate,
  renderBlockNotice,
  validateBlockNoticeTemplate,
} from '../services/blockNotice'
import { useAuthStore } from '../stores/auth'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import BlockTraceEvidence from '../components/BlockTraceEvidence'
import { formatAgentType } from '../utils/agents'
import PolicyRuleLink from '../components/PolicyRuleLink'
import { categoryTitle, cleanRuleName, readableHitText, readableReasonCode } from '../utils/alertReadable'
import { RAW_EVIDENCE_OMITTED_TEXT, rawEvidenceDisplay } from '../utils/alertEvidence'
import { useBlockTrace } from '../hooks/useBlockTrace'

const { Text, Paragraph } = Typography

// 命中原文：有原文先给原文（截断时标出），否则给历史可读片段。
const blockHitText = (record: SecurityBlockRecord) => rawEvidenceDisplay(record.raw_evidence, record.raw_evidence_truncated) || readableHitText(record.detail)

const PAGE_SIZE = 20

const SEVERITY_TONES: Record<string, 'red' | 'orange' | 'blue' | 'gray'> = {
  critical: 'red',
  high: 'orange',
  medium: 'blue',
  low: 'gray',
}
const SOURCE_LABELS: Record<string, string> = {
  gateway: '模型网关',
  gateway_reverse_proxy: '接入通道（反向代理）',
  forward_proxy: '正向代理',
}

// 时间按租户时区显示（W8 8.9），与导出文件一致。
function formatTime(value: string | undefined, timezone: string) {
  if (!value) return '-'
  return Number.isNaN(new Date(value).getTime()) ? value : formatInTimezone(value, timezone)
}

// 阻断记录的规则名已是可读名：去泛称和内部编号后，依次用链接标签、类别名、阻断位置名；内部规则编号不显示。
function ruleText(record: SecurityBlockRecord) {
  const category = record.category ? categoryTitle(record.category) : ''
  // 未收录的类别名是“其他风险（编码）”，不如阻断位置名好认。
  const categoryName = category && !category.startsWith('其他风险') && category !== '未分类' ? category : ''
  return cleanRuleName(record.rule_name) || cleanRuleName(record.policy_link?.label) || categoryName || BLOCK_LAYER_LABELS[record.layer] || '未记录规则'
}

const SAMPLE_NOTICE = {
  reason: '输入内容命中安全规则',
  rule_name: '密码明文检测',
  rule_id: 'rule_525f3078',
  detail: 'pass****i996',
  block_id: 'evt_9bc36fc530b040eebe56e669',
  request_id: 'f53bc1b9-0c1e-4a57-9d5e-3b0f7f0e1a2d',
}

function BlockNoticeSettingsPanel() {
  const queryClient = useQueryClient()
  const identity = useAuditQueryIdentity()
  const settingsQuery = useQuery({ queryKey: ['block-notice-settings', identity], queryFn: blockRecordsApi.getNoticeSettings })
  const [mode, setMode] = useState<BlockResponseMode>('error')
  const [template, setTemplate] = useState(DEFAULT_BLOCK_NOTICE_TEMPLATE)

  useEffect(() => {
    const data = settingsQuery.data
    if (!data) return
    setMode(data.security_block_response_mode === 'message' ? 'message' : 'error')
    const saved = typeof data.security_block_notice_template === 'string' ? data.security_block_notice_template : ''
    setTemplate(normalizeBlockNoticeTemplate(saved))
  }, [settingsQuery.data])

  const templateError = validateBlockNoticeTemplate(template)
  const preview = useMemo(() => renderBlockNotice(template, SAMPLE_NOTICE), [template])
  const save = useMutation({
    mutationFn: () => blockRecordsApi.saveNoticeSettings({ mode, template: template.trim() === DEFAULT_BLOCK_NOTICE_TEMPLATE ? '' : template }),
    onSuccess: async () => {
      message.success('已保存，网关约 30 秒内生效')
      await queryClient.invalidateQueries({ queryKey: ['block-notice-settings'] })
    },
    onError: (error: unknown) => {
      const response = (error as { response?: { data?: { error?: { message?: string }; message?: string } } }).response
      message.error(response?.data?.error?.message || response?.data?.message || '保存失败')
    },
  })

  return (
    <SectionPanel
      title="智能体收到的阻断提示"
      description="被阻断时返回给智能体/客户端的内容。所有协议（Chat Completions、Responses、Anthropic Messages）共用这份设置。"
    >
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Radio.Group value={mode} onChange={(event) => setMode(event.target.value)} aria-label="阻断提示方式">
          <Space direction="vertical">
            <Radio value="error">返回错误（HTTP 403，错误信息为下方提示）</Radio>
            <Radio value="message">以助手消息返回（HTTP 200，提示作为模型回复展示）</Radio>
          </Space>
        </Radio.Group>
        <Text type="secondary">
          部分智能体客户端遇到 403 只显示“自定义模型错误 10000”之类的通用错误、不显示错误正文；这类客户端请选“以助手消息返回”，用户就能直接看到被哪条规则阻断、阻断编号是多少。两种方式都会在阻断记录里留存，并带上响应头 X-JJDGuard-Block-ID。
        </Text>
        <Input.TextArea
          aria-label="阻断提示模板"
          value={template}
          onChange={(event) => setTemplate(event.target.value)}
          autoSize={{ minRows: 5, maxRows: 12 }}
        />
        <Space size={[8, 4]} wrap>
          {BLOCK_NOTICE_PLACEHOLDERS.map((item) => (
            <Tag key={item.token} style={{ cursor: 'pointer' }} onClick={() => setTemplate((current) => `${current}${item.token}`)}>
              {item.token} {item.label}
            </Tag>
          ))}
        </Space>
        <Text type="secondary">某一行的占位符都没有取值时（例如非工具调用没有操作编号），这一行会自动省略。</Text>
        {templateError ? <Alert type="error" showIcon message={templateError} /> : null}
        <div>
          <Text strong>模板预览（示例数据，不是真实阻断记录）</Text>
          <pre className="block-notice-preview" data-testid="block-notice-preview" style={{ whiteSpace: 'pre-wrap', background: 'var(--surface-muted, rgba(0,0,0,0.04))', padding: 12, borderRadius: 8, marginTop: 8 }}>
            {preview}
          </pre>
        </div>
        <Space>
          <Button type="primary" loading={save.isPending} disabled={Boolean(templateError)} onClick={() => save.mutate()}>
            保存阻断提示
          </Button>
          <Button onClick={() => setTemplate(DEFAULT_BLOCK_NOTICE_TEMPLATE)}>恢复默认模板</Button>
        </Space>
      </Space>
    </SectionPanel>
  )
}

function BlockRecords() {
  const [searchParams, setSearchParams] = useSearchParams()
  const user = useAuthStore((state) => state.user)
  const identity = useAuditQueryIdentity()
  const [query, setQuery] = useState(searchParams.get('q') || '')
  const [layer, setLayer] = useState<string | undefined>(searchParams.get('layer') || undefined)
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<SecurityBlockRecord | null>(null)
  const submittedQuery = searchParams.get('q') || ''
  const reportCtx = useReportContext()
  const tz = reportCtx.timezone
  // W8 8.7：时间筛选；列表与导出共用同一组条件。
  const [range, setRange] = useState<AuditDateRange>(null)
  const rangeParams = auditRangeParams(range, tz)
  const exportFilters = { q: submittedQuery || undefined, layer, ...rangeParams }

  const recordsQuery = useQuery({
    queryKey: ['block-records', identity, submittedQuery, layer, rangeParams, page],
    queryFn: () => blockRecordsApi.list({
      q: submittedQuery || undefined,
      layer,
      ...rangeParams,
      limit: PAGE_SIZE,
      offset: (page - 1) * PAGE_SIZE,
    }).then((response) => response.data),
    placeholderData: (previous, previousQuery) => previousQuery?.queryKey[1] === identity ? keepPreviousData(previous) : undefined,
  })
  const items = recordsQuery.data?.items || []
  const total = recordsQuery.data?.total || 0

  useEffect(() => { setQuery(submittedQuery); setPage(1) }, [submittedQuery])
  useEffect(() => { setSelected(null); setPage(1) }, [identity])

  const search = (value: string) => {
    const normalized = blockRecordSearchQuery(value)
    if (new TextEncoder().encode(normalized).length > 256) {
      message.warning('请粘贴阻断编号或请求 ID，或输入不超过 256 字节的规则名')
      return
    }
    const next = new URLSearchParams(searchParams)
    if (normalized) next.set('q', normalized)
    else next.delete('q')
    setQuery(normalized)
    setSearchParams(next, { replace: true })
    setPage(1)
  }

  const selectedReason = selected ? readableReasonCode(selected.reason) : ''
  // 列表不带命中原文；详情的原文和前后文取溯源接口（与 BlockTraceEvidence 同一查询，按内容证据权限返回）。
  const selectedTrace = useBlockTrace(selected?.block_id)
  const tracedBlock = selectedTrace.data?.block
  const selectedHit = selected && tracedBlock && tracedBlock.block_id === selected.block_id && tracedBlock.request_id === selected.request_id
    ? { ...selected, raw_evidence: tracedBlock.raw_evidence, evidence_context: tracedBlock.evidence_context,
      raw_evidence_truncated: tracedBlock.raw_evidence_truncated, raw_evidence_omitted: tracedBlock.raw_evidence_omitted }
    : selected

  const columns = [
    { title: '时间', dataIndex: 'created_at', key: 'created_at', width: 170, render: (value: string) => formatTime(value, tz) },
    {
      title: '阻断位置',
      dataIndex: 'layer',
      key: 'layer',
      width: 140,
      render: (value: string, record: SecurityBlockRecord) => (
        <Space direction="vertical" size={2}>
          <Tag color="red">{blockLayerLabel(value)}</Tag>
          <StatusPill tone={SEVERITY_TONES[record.severity] || 'gray'}>{SEVERITY_LABELS[record.severity] || '风险'}</StatusPill>
        </Space>
      ),
    },
    {
      title: '命中规则',
      key: 'rule',
      width: 220,
      render: (_: unknown, record: SecurityBlockRecord) => {
        const reason = readableReasonCode(record.reason)
        return (
          <Space direction="vertical" size={2}>
            <Text strong><PolicyRuleLink link={record.policy_link} name={ruleText(record)} eventId={record.block_id} /></Text>
            {reason ? <Text type="secondary" style={{ fontSize: 12 }}>{reason}</Text> : null}
          </Space>
        )
      },
    },
    {
      title: '命中内容',
      dataIndex: 'detail',
      key: 'detail',
      width: 200,
      render: (value: string | undefined, record: SecurityBlockRecord) => (
        <Space direction="vertical" size={2}>
          {record.raw_evidence || value ? <Paragraph code style={{ wordBreak: 'break-all', marginBottom: 0 }} ellipsis={{ rows: 3, expandable: true, symbol: '展开' }}>{blockHitText(record)}</Paragraph> : <Text type="secondary">未记录</Text>}
          {record.explanation ? <Text type="secondary" style={{ fontSize: 12 }}>{record.explanation}</Text> : null}
        </Space>
      ),
    },
    { title: '处置依据', dataIndex: 'basis', key: 'basis', width: 240 },
    {
      title: '请求来源',
      key: 'origin',
      width: 200,
      render: (_: unknown, record: SecurityBlockRecord) => (
        <Space direction="vertical" size={2}>
          <Text>{record.model || '未记录模型'}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {[record.user_name, record.project_name, record.agent_type].filter(Boolean).join(' · ') || SOURCE_LABELS[record.source] || '-'}
          </Text>
        </Space>
      ),
    },
    {
      title: '关联编号',
      key: 'ids',
      width: 260,
      render: (_: unknown, record: SecurityBlockRecord) => (
        <Space direction="vertical" size={2}>
          <Text type="secondary" style={{ fontSize: 12 }}>阻断编号</Text>
          <Text copyable ellipsis={{ tooltip: record.block_id }} style={{ fontSize: 12, maxWidth: 235 }}>{record.block_id}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>请求 ID</Text>
          <Text copyable ellipsis={{ tooltip: record.request_id }} style={{ fontSize: 12, maxWidth: 235 }}>{record.request_id}</Text>
          {record.operation_id ? <Text copyable type="secondary" style={{ fontSize: 12 }}>{record.operation_id}</Text> : null}
        </Space>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 160,
      fixed: 'right' as const,
      render: (_: unknown, record: SecurityBlockRecord) => <Button type="link" onClick={() => setSelected(record)}>查看告警与留痕</Button>,
    },
  ]

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader
        eyebrow="风险处理"
        title="阻断记录"
        description="客户看到阻断提示后，将阻断编号或请求 ID 粘贴到下方搜索，即可定位真实记录、核查命中规则，并查看关联告警和审计留痕。"
        meta={(
          <Space size={8} wrap>
            <StatusPill tone="red"><StopOutlined /> 共 {total} 条</StatusPill>
            <StatusPill tone={reportCtx.executionMode?.effective_mode === 'protect' ? 'red' : 'blue'}>当前执行模式 {reportCtx.modeLabel}</StatusPill>
            <StatusPill tone="gray">统计时区 {tz}</StatusPill>
          </Space>
        )}
      />
      <SectionPanel
        title="阻断明细"
        description="支持阻断编号、请求 ID、操作编号、Trace ID 和规则名，也可直接粘贴客户收到的完整阻断提示。"
      >
        <Space direction="vertical" size={12} style={{ width: '100%', marginBottom: 16 }}>
          <Input.Search
            allowClear
            aria-label="检索阻断记录"
            placeholder="粘贴客户的阻断编号、请求 ID 或完整阻断提示"
            enterButton="搜索阻断记录"
            style={{ width: '100%', maxWidth: 760 }}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onSearch={search}
          />
          <Space wrap>
            <AuditDateRangeFilter value={range} onChange={(next) => { setRange(next); setPage(1) }} />
            <Select
              allowClear
              placeholder="全部阻断位置"
              style={{ width: 160 }}
              value={layer}
              onChange={(value) => { setLayer(value); setPage(1) }}
              options={Object.entries(BLOCK_LAYER_LABELS).map(([value, label]) => ({ value, label }))}
            />
            <Button onClick={() => { setQuery(''); setLayer(undefined); setRange(null); search('') }}>清除筛选</Button>
            <Button loading={recordsQuery.isFetching} onClick={() => void recordsQuery.refetch()}>刷新记录</Button>
            <ServerExportButton
              name="阻断记录"
              timezone={tz}
              run={(format) => ws8BlockRecordsApi.export(format, exportFilters)}
            />
          </Space>
        </Space>
        {recordsQuery.isError ? <Alert type="error" showIcon message="阻断记录读取失败" /> : null}
        <ResizableTable
          columnStorageKey="block-records-columns"
          columns={columns}
          dataSource={items}
          rowKey="block_id"
          loading={recordsQuery.isLoading}
          locale={{ emptyText: submittedQuery ? `没有找到与“${submittedQuery}”相关的阻断` : '暂无阻断记录' }}
          pagination={{
            current: page,
            pageSize: PAGE_SIZE,
            total,
            showSizeChanger: false,
            showTotal: (count: number) => `共 ${count} 条`,
            onChange: (next: number) => setPage(next),
          }}
        />
      </SectionPanel>
      {user?.role === 'platform_admin' ? (
        <Collapse style={{ marginTop: 16 }} items={[{
          key: 'notice-settings',
          label: '客户阻断提示设置（模板与返回方式）',
          children: <BlockNoticeSettingsPanel />,
        }]} />
      ) : null}
      <Drawer open={Boolean(selected)} width="min(860px, 100vw)" title="阻断详情 · 告警与留痕" onClose={() => setSelected(null)} destroyOnClose>
        {selected ? (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="阻断编号"><Text copyable>{selected.block_id}</Text></Descriptions.Item>
              {selected.operation_id ? <Descriptions.Item label="操作编号"><Text copyable>{selected.operation_id}</Text></Descriptions.Item> : null}
              <Descriptions.Item label="请求 ID"><Text copyable>{selected.request_id}</Text></Descriptions.Item>
              {selected.trace_id ? <Descriptions.Item label="Trace ID"><Text copyable>{selected.trace_id}</Text></Descriptions.Item> : null}
              <Descriptions.Item label="时间">{formatTime(selected.created_at, tz)}</Descriptions.Item>
              <Descriptions.Item label="阻断位置">{blockLayerLabel(selected.layer)}</Descriptions.Item>
              {selectedReason ? <Descriptions.Item label="阻断原因">{selectedReason}</Descriptions.Item> : null}
              <Descriptions.Item label="命中规则"><PolicyRuleLink link={selected.policy_link} name={ruleText(selected)} eventId={selected.block_id} /></Descriptions.Item>
              <Descriptions.Item label="命中内容">
                <Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', marginBottom: 0 }} ellipsis={{ rows: 8, expandable: true, symbol: '展开' }}>{selectedHit && (selectedHit.raw_evidence || selectedHit.detail) ? blockHitText(selectedHit) : '未记录'}</Paragraph>
                {selectedHit?.raw_evidence_omitted && !selectedHit.raw_evidence ? <Text type="secondary">{RAW_EVIDENCE_OMITTED_TEXT}</Text> : null}
              </Descriptions.Item>
              {selectedHit?.evidence_context ? <Descriptions.Item label="前后文"><Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', marginBottom: 0 }} ellipsis={{ rows: 8, expandable: true, symbol: '展开' }}>{selectedHit.evidence_context}</Paragraph></Descriptions.Item> : null}
              {selected.explanation ? <Descriptions.Item label="风险说明">{selected.explanation}</Descriptions.Item> : null}
              <Descriptions.Item label="处置依据">{selected.basis}</Descriptions.Item>
              <Descriptions.Item label="模型">{selected.model || '-'}</Descriptions.Item>
              <Descriptions.Item label="用户 / 应用">{[selected.user_name || selected.user_id, selected.project_name || selected.project_id].filter(Boolean).join(' / ') || '-'}</Descriptions.Item>
              <Descriptions.Item label="智能体">{selected.agent_type ? formatAgentType(selected.agent_type) : '-'}</Descriptions.Item>
              <Descriptions.Item label="来源">{SOURCE_LABELS[selected.source] || selected.source}{selected.source_ip ? ` · ${selected.source_ip}` : ''}</Descriptions.Item>
            </Descriptions>
            <BlockTraceEvidence blockId={selected.block_id} requestId={selected.request_id} createdAt={selected.created_at} timezone={tz} />
            <div>
              <Text strong>阻断提示示例（按默认模板重建）</Text>
              <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 8 }}>
                {renderBlockNotice(DEFAULT_BLOCK_NOTICE_TEMPLATE, selected)}
              </Paragraph>
            </div>
          </Space>
        ) : null}
      </Drawer>
    </div>
  )
}

export default BlockRecords

import { CORE_SEVERITY_LABELS } from '../utils/risk'
import { useState, useMemo } from 'react'
import { Card, Table, Tag, Select, Button, Space, Typography, Alert, Row, Col } from 'antd'
import { CheckOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { anomalyApi } from '../services/api'
import { useCurrencyStore } from '../stores/currency'
import { AnalysisFlow, EnterprisePageHeader, SectionPanel, StatusPill } from '../components/EnterpriseUI'
import { TrendLine, DistributionPie } from '../components/Charts'

const { Text } = Typography

const TYPE_OPTIONS = [
  { value: '', label: '全部类型' },
  { value: 'absolute_spike', label: '用量突增' },
  { value: 'dod', label: '环比异常' },
  { value: 'yoy', label: '同比异常' },
  { value: 'new_model', label: '新增模型用量' },
  { value: 'key_surge', label: '密钥用量激增' },
]

const RANGE_OPTIONS = [
  { value: '7', label: '近 7 天' },
  { value: '30', label: '近 30 天' },
  { value: '90', label: '近 90 天' },
]

const SEVERITY_LABELS: Record<string, string> = {
  ...CORE_SEVERITY_LABELS,
  warning: '提醒',
  info: '信息',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  warning: 'gold',
  medium: 'gold',
  low: 'blue',
  info: 'default',
}

type AnomalyRow = {
  id: string
  detectedDate: string
  type: string
  scopeType: string
  scopeId: string
  baseline: number
  actual: number
  severity: string
  detail: Record<string, any>
  ackedAt?: string | null
}

function valueOf(record: any, ...keys: string[]) {
  for (const key of keys) {
    if (record?.[key] !== undefined && record?.[key] !== null) return record[key]
  }
  return undefined
}

function numberOf(record: any, ...keys: string[]): number {
  const value = valueOf(record, ...keys)
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return 0
}

function normalizeAnomaly(raw: any): AnomalyRow {
  return {
    id: String(valueOf(raw, 'id', 'ID', 'anomaly_id') || ''),
    detectedDate: String(valueOf(raw, 'detected_date', 'DetectedDate', 'detected_at', 'created_at') || ''),
    type: String(valueOf(raw, 'dimension', 'Dimension', 'type') || ''),
    scopeType: String(valueOf(raw, 'scope_type', 'ScopeType') || ''),
    scopeId: String(valueOf(raw, 'scope_id', 'ScopeID') || valueOf(raw, 'scope') || ''),
    baseline: numberOf(raw, 'baseline', 'Baseline'),
    actual: numberOf(raw, 'actual', 'Actual'),
    severity: String(valueOf(raw, 'severity', 'Severity') || 'info'),
    detail: valueOf(raw, 'detail_json', 'DetailJSON', 'detail') || {},
    ackedAt: valueOf(raw, 'acked_at', 'AckedAt') || null,
  }
}

function typeLabel(value: string): string {
  return TYPE_OPTIONS.find((item) => item.value === value)?.label || '未知异常'
}

function scopeLabel(row: AnomalyRow): string {
  if (!row.scopeType && !row.scopeId) return '全局租户'
  const labels: Record<string, string> = {
    project: '应用',
    user: '用户',
    model: '模型',
    key: '密钥',
    tenant: '租户',
  }
  const prefix = labels[row.scopeType] || '对象'
  return row.scopeId ? `${prefix}：${row.scopeId}` : prefix
}

function formatDate(value: string): string {
  if (!value) return '-'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleDateString('zh-CN')
}

function anomalySummary(row: AnomalyRow, formatCurrency: (value: number) => string): string {
  const ratio = numberOf(row.detail, 'ratio')
  if (ratio > 0) return `当前值约为基线的 ${ratio.toFixed(1)} 倍`
  if (row.baseline > 0) return `实际值 ${formatCurrency(row.actual)}，基线 ${formatCurrency(row.baseline)}`
  if (row.type === 'new_model') return `新增模型今日请求 ${Math.round(row.actual).toLocaleString('zh-CN')} 次`
  if (row.type === 'key_surge') return `密钥费用占比较历史均值明显升高`
  return '已发现费用或用量偏离历史水平'
}

function suggestion(row: AnomalyRow): string {
  const map: Record<string, string> = {
    absolute_spike: '立即确认费用来源',
    dod: '核对昨日业务变化',
    yoy: '核对周期性任务变化',
    new_model: '确认新增模型是否经过审批',
    key_surge: '核对密钥归属和调用来源',
  }
  return map[row.type] || '确认是否为预期业务流量'
}

export default function Anomalies() {
  const [range, setRange] = useState('30')
  const [type, setType] = useState('')
  const { format } = useCurrencyStore()
  const formatCurrency = (value: number) => format(value, 2)
  const qc = useQueryClient()

  const listQ = useQuery({
    queryKey: ['anomalies', range, type],
    queryFn: () => anomalyApi.list({ range, ...(type ? { dimension: type } : {}) }),
  })

  const ackMut = useMutation({
    mutationFn: (id: string) => anomalyApi.ack(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['anomalies'] }),
  })

  const raw = listQ.data?.data
  const rawItems: any[] = Array.isArray(raw?.items) ? raw.items
    : Array.isArray(raw?.data) ? raw.data
    : Array.isArray(raw) ? raw
    : []
  const items = rawItems.map(normalizeAnomaly)

  // 前端聚合：每日异常数趋势 + 类型分布 + 严重度分布
  const trendData = useMemo(() => {
    const byDate: Record<string, number> = {}
    items.forEach((it) => {
      const d = it.detectedDate.slice(0, 10)
      byDate[d] = (byDate[d] || 0) + 1
    })
    return Object.entries(byDate).sort(([a], [b]) => a.localeCompare(b)).map(([date, count]) => ({ date, count }))
  }, [items])
  const typeDistData = useMemo(() => {
    const byType: Record<string, number> = {}
    items.forEach((it) => { byType[it.type] = (byType[it.type] || 0) + 1 })
    return Object.entries(byType).map(([type, count]) => ({ name: typeLabel(type), value: count }))
  }, [items])
  const severityDistData = useMemo(() => {
    const bySev: Record<string, number> = {}
    items.forEach((it) => { bySev[it.severity] = (bySev[it.severity] || 0) + 1 })
    return Object.entries(bySev).map(([sev, count]) => ({ name: SEVERITY_LABELS[sev] || sev, value: count }))
  }, [items])

  const columns = [
    {
      title: '发现日期',
      dataIndex: 'detectedDate',
      key: 'detectedDate',
      render: formatDate,
      width: 120,
    },
    {
      title: '异常类型',
      dataIndex: 'type',
      key: 'type',
      render: (value: string) => <Tag color="blue">{typeLabel(value)}</Tag>,
      width: 140,
    },
    {
      title: '影响对象',
      key: 'scope',
      render: (_: any, row: AnomalyRow) => scopeLabel(row),
      width: 180,
    },
    {
      title: '异常说明',
      key: 'summary',
      render: (_: any, row: AnomalyRow) => (
        <Space direction="vertical" size={2}>
          <Text>{anomalySummary(row, formatCurrency)}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>基线 {formatCurrency(row.baseline)}，实际 {formatCurrency(row.actual)}</Text>
        </Space>
      ),
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      render: (value: string) => <Tag color={SEVERITY_COLORS[value] || 'default'}>{SEVERITY_LABELS[value] || '信息'}</Tag>,
      width: 110,
    },
    {
      title: '建议动作',
      key: 'suggestion',
      render: (_: any, row: AnomalyRow) => suggestion(row),
      width: 180,
    },
    {
      title: '处置状态',
      key: 'action',
      render: (_: any, record: AnomalyRow) =>
        record.ackedAt ? (
          <Tag color="default">已确认</Tag>
        ) : (
          <Button
            size="small"
            icon={<CheckOutlined />}
            loading={ackMut.isPending && ackMut.variables === record.id}
            onClick={() => ackMut.mutate(record.id)}
          >
            确认已处理
          </Button>
        ),
      width: 140,
    },
  ]

  return (
    <div>
      <EnterprisePageHeader
        eyebrow="费用治理"
        title="异常分析"
        description="识别费用突增、环比异常、新增模型和密钥用量激增，帮助管理员快速定位异常来源。"
        meta={<StatusPill tone={items.length ? 'orange' : 'green'}>{items.length ? `${items.length} 条异常待看` : '近期平稳'}</StatusPill>}
      />

      <SectionPanel title="异常研判过程" description="系统基于历史费用、请求量和调用对象分布进行检测。">
        <AnalysisFlow
          items={[
            { label: '提取历史基线', value: items[0] ? formatCurrency(items[0].baseline) : '暂无基线', tone: 'blue', description: '按近期待选周期计算正常水位' },
            { label: '计算偏离程度', value: items[0] ? anomalySummary(items[0], formatCurrency) : '未发现偏离', tone: items[0] ? 'orange' : 'green', description: '对比实际值、基线和阈值' },
            { label: '定位影响对象', value: items[0] ? scopeLabel(items[0]) : '无异常对象', tone: items[0] ? 'purple' : 'gray', description: '聚合到应用、用户、模型或密钥' },
            { label: '给出处置建议', value: items[0] ? suggestion(items[0]) : '继续观察', tone: items[0] ? 'orange' : 'blue', description: '确认业务变化或追踪调用来源' },
          ]}
        />
      </SectionPanel>

      {items.length > 0 && (
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col xs={24} lg={12}>
            <Card size="small" title="每日异常趋势" style={{ borderRadius: 8 }}>
              <TrendLine data={trendData} series={[{ key: 'count', label: '异常数' }]} height={220} />
            </Card>
          </Col>
          <Col xs={24} lg={6}>
            <Card size="small" title="异常类型分布" style={{ borderRadius: 8 }}>
              <DistributionPie data={typeDistData} height={220} />
            </Card>
          </Col>
          <Col xs={24} lg={6}>
            <Card size="small" title="严重程度分布" style={{ borderRadius: 8 }}>
              <DistributionPie data={severityDistData} height={220} />
            </Card>
          </Col>
        </Row>
      )}

      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          value={range}
          onChange={setRange}
          options={RANGE_OPTIONS}
          style={{ width: 120 }}
        />
        <Select
          value={type}
          onChange={setType}
          options={TYPE_OPTIONS}
          style={{ width: 160 }}
          placeholder="筛选异常类型"
        />
      </Space>

      {listQ.isError ? (
        <Alert type="warning" message="异常分析数据暂不可用" description="请检查异常检测任务和控制面服务状态。" showIcon style={{ marginBottom: 16 }} />
      ) : (
        <Card title="异常事件列表">
          <Table
            size="small"
            dataSource={items}
            columns={columns}
            rowKey={(row) => row.id || `${row.detectedDate}-${row.type}-${row.scopeId || 'tenant'}`}
            loading={listQ.isLoading}
            pagination={{ defaultPageSize: 15 }}
            locale={{ emptyText: '近一段时间未发现用量异常' }}
          />
        </Card>
      )}
    </div>
  )
}

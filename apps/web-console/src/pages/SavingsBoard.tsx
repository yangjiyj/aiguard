import { useState } from 'react'
import { Card, Row, Col, Statistic, Table, Tag, Select, Space, Typography, Segmented, Spin, Alert, Tooltip, Modal, Form, InputNumber, Button } from 'antd'
import { QuestionCircleOutlined, SettingOutlined, InfoCircleOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import TwoDecimalInput from '../components/billing/TwoDecimalInput'
import { savingApi, savingsConfigApi } from '../services/api'

const { Title, Text } = Typography

const RANGE_OPTIONS = [
  { value: '30d', label: '近 30 天' },
  { value: '7d', label: '近 7 天' },
  { value: 'month', label: '本月' },
]

const GROUP_OPTIONS = [
  { value: 'source', label: '按来源' },
  { value: 'team', label: '按部门' },
  { value: 'project', label: '按应用' },
  { value: 'user', label: '按用户' },
]

// 算法口径：5 个来源，每个有颜色和说明
const ALGORITHM_SOURCES: {
  key: string
  label: string
  color: string
  tooltip?: string
}[] = [
  { key: 'cache_hit', label: '缓存命中', color: 'var(--chart-5)' },
  { key: 'model_downgraded', label: '模型降级', color: 'var(--chart-6)' },
  { key: 'negotiated_price', label: '议价折扣', color: 'var(--chart-3)' },
  { key: 'circuit_breaker', label: '熔断拦截', color: 'var(--chart-2)', tooltip: '估算值' },
  { key: 'key_mgmt_labor', label: 'Key 管理人工', color: 'var(--chart-1)' },
]

function SourceCard({
  source,
  bySource,
}: {
  source: typeof ALGORITHM_SOURCES[number]
  bySource: Record<string, { saved_cny?: number; save_rate?: number }>
}) {
  const data = bySource[source.key] || {}
  return (
    <Card size="small" bordered style={{ borderTop: `3px solid ${source.color}` }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
        <Text strong style={{ color: source.color }}>{source.label}</Text>
        {source.tooltip && (
          <Tooltip title={source.tooltip}>
            <InfoCircleOutlined style={{ color: 'var(--text-tertiary)', fontSize: 12 }} />
          </Tooltip>
        )}
        <Tag color={source.color} style={{ marginLeft: 'auto', fontSize: 10 }}>{source.key}</Tag>
      </div>
      <Statistic
        value={data.saved_cny ?? 0}
        precision={2}
        prefix="¥"
        valueStyle={{ color: source.color, fontSize: 18 }}
      />
      {data.save_rate != null && (
        <Text type="secondary" style={{ fontSize: 12 }}>
          节省率 {(data.save_rate * 100).toFixed(1)}%
        </Text>
      )}
    </Card>
  )
}

function SelfResearchCard() {
  const [configOpen, setConfigOpen] = useState(false)
  const [form] = Form.useForm()
  const qc = useQueryClient()

  const configQ = useQuery({
    queryKey: ['savings-config'],
    queryFn: () => savingsConfigApi.get(),
  })

  const setMut = useMutation({
    mutationFn: (data: any) => savingsConfigApi.set(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['savings-config'] })
      setConfigOpen(false)
    },
  })

  const _configRaw = configQ.data?.data
  const config = (_configRaw?.data && typeof _configRaw.data === 'object' && !Array.isArray(_configRaw.data))
    ? _configRaw.data
    : (_configRaw && typeof _configRaw === 'object' && !Array.isArray(_configRaw))
    ? _configRaw
    : {}
  const monthly = config.self_research_saving_monthly ?? 0

  const handleOpenConfig = () => {
    form.setFieldsValue({
      self_research_saving_monthly: config.self_research_saving_monthly,
      labor_hourly_rate: config.labor_hourly_rate,
      labor_hours_per_op: config.labor_hours_per_op,
    })
    setConfigOpen(true)
  }

  return (
    <>
      <Card
        size="small"
        bordered
        style={{ borderTop: '3px solid var(--chart-4)' }}
        extra={
          <Button size="small" icon={<SettingOutlined />} onClick={handleOpenConfig}>
            配置
          </Button>
        }
        title={
          <Space>
            <Text strong style={{ color: 'var(--chart-4)' }}>自研节省</Text>
            <Tag color="default" style={{ fontSize: 10 }}>配置项</Tag>
            <Tooltip title="客户自填，非算法计算，不计入算法节省小计">
              <QuestionCircleOutlined style={{ color: 'var(--text-tertiary)', fontSize: 12 }} />
            </Tooltip>
          </Space>
        }
      >
        <Statistic
          value={monthly}
          precision={2}
          prefix="¥"
          suffix="/ 月"
          valueStyle={{ color: 'var(--chart-4)', fontSize: 18 }}
        />
        <Text type="secondary" style={{ fontSize: 12 }}>
          客户自填节省（非算法计算，不计入算法节省小计）
        </Text>
      </Card>

      <Modal
        title="配置自研节省参数"
        open={configOpen}
        onCancel={() => setConfigOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={setMut.isPending}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={(values) => setMut.mutate(values)}
        >
          <Form.Item
            label="月度自研节省（CNY）"
            name="self_research_saving_monthly"
            help="客户自行评估的月度自研节省金额，不纳入算法节省小计"
          >
            <TwoDecimalInput min={0} style={{ width: '100%' }} prefix="¥" />
          </Form.Item>
          <Form.Item label="人工时薪（CNY/小时）" name="labor_hourly_rate">
            <TwoDecimalInput min={0} style={{ width: '100%' }} prefix="¥" />
          </Form.Item>
          <Form.Item label="每次操作人工时长（小时）" name="labor_hours_per_op">
            <InputNumber min={0} step={0.1} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  )
}

export default function SavingsBoard() {
  const [range, setRange] = useState('30d')
  const [groupBy, setGroupBy] = useState<'source' | 'team' | 'project' | 'user'>('source')

  const summaryQ = useQuery({
    queryKey: ['savings-summary', range],
    queryFn: () => savingApi.summary({ range }),
  })

  const trendQ = useQuery({
    queryKey: ['savings-trend', range, groupBy],
    queryFn: () => savingApi.trend({ range, groupBy }),
  })

  const _summaryRaw = summaryQ.data?.data
  const summary = (_summaryRaw?.data && typeof _summaryRaw.data === 'object' && !Array.isArray(_summaryRaw.data))
    ? _summaryRaw.data
    : (_summaryRaw && typeof _summaryRaw === 'object' && !Array.isArray(_summaryRaw))
    ? _summaryRaw
    : {}
  const _trendRaw = trendQ.data?.data
  const trendItems: any[] = Array.isArray(_trendRaw?.items) ? _trendRaw.items
                           : Array.isArray(_trendRaw?.data) ? _trendRaw.data
                           : Array.isArray(_trendRaw) ? _trendRaw
                           : []

  // Build by_source map from summary or trendItems (when groupBy=source)
  const bySource: Record<string, { saved_cny?: number; save_rate?: number }> = {}
  if (summary.by_source && typeof summary.by_source === 'object') {
    Object.assign(bySource, summary.by_source)
  } else if (groupBy === 'source') {
    trendItems.forEach((item: any) => {
      if (item.source) {
        bySource[item.source] = { saved_cny: item.saved_cny, save_rate: item.save_rate }
      }
    })
  }

  const trendColumns = [
    {
      title: groupBy === 'source' ? '来源' : groupBy === 'team' ? '部门' : groupBy === 'project' ? '应用' : '用户',
      dataIndex: 'name',
      key: 'name',
      ellipsis: true,
      render: (_: any, r: any) => r.name || r.source || r.id || '-',
    },
    {
      title: '节省金额',
      dataIndex: 'saved_cny',
      key: 'saved_cny',
      render: (v?: number) => v != null ? `¥${v.toFixed(2)}` : '-',
    },
    {
      title: '节省百分比',
      dataIndex: 'save_rate',
      key: 'save_rate',
      render: (v?: number) => v != null ? `${(v * 100).toFixed(1)}%` : '-',
    },
    {
      title: '来源类型',
      dataIndex: 'source',
      key: 'source_tag',
      render: (v?: string) => {
        if (!v) return '-'
        const src = ALGORITHM_SOURCES.find(s => s.key === v)
        return <Tag color={src?.color || 'default'}>{src?.label || v}</Tag>
      },
    },
  ]

  return (
    <div>
      <div className="page-header" style={{ marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>节省看板</Title>
        <Text type="secondary">成本节省来源分析（5 个算法口径 + 自研配置项）</Text>
      </div>

      <Space style={{ marginBottom: 16 }} wrap>
        <Segmented
          options={RANGE_OPTIONS}
          value={range}
          onChange={(v) => setRange(String(v))}
        />
      </Space>

      {summaryQ.isLoading ? (
        <div style={{ textAlign: 'center', padding: 40 }}><Spin size="large" /></div>
      ) : summaryQ.isError ? (
        <Alert type="warning" message="节省汇总接口暂不可用（后端 /savings/summary 待接入）" showIcon style={{ marginBottom: 16 }} />
      ) : (
        <>
          {/* 顶部汇总 */}
          <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
            <Col xs={24} sm={12} md={6}>
              <Card>
                <Statistic
                  title="算法节省小计"
                  value={summary.total_saved_cny ?? 0}
                  precision={2}
                  prefix="¥"
                  valueStyle={{ color: 'var(--chart-5)' }}
                />
              </Card>
            </Col>
            <Col xs={24} sm={12} md={6}>
              <Card>
                <Statistic
                  title="同比变化"
                  value={summary.yoy_change_pct ?? 0}
                  precision={1}
                  suffix="%"
                  valueStyle={{ color: (summary.yoy_change_pct ?? 0) >= 0 ? 'var(--status-ok)' : 'var(--status-danger)' }}
                />
              </Card>
            </Col>
            <Col xs={24} sm={12} md={6}>
              <Card>
                <Statistic
                  title="环比变化"
                  value={summary.mom_change_pct ?? 0}
                  precision={1}
                  suffix="%"
                  valueStyle={{ color: (summary.mom_change_pct ?? 0) >= 0 ? 'var(--status-ok)' : 'var(--status-danger)' }}
                />
              </Card>
            </Col>
          </Row>

          {/* 5 算法口径分色块 */}
          <Card
            title={
              <Space>
                <span>算法节省口径</span>
                <Tag color="blue">共 5 个</Tag>
              </Space>
            }
            style={{ marginBottom: 16 }}
          >
            <Row gutter={[12, 12]}>
              {ALGORITHM_SOURCES.map(src => (
                <Col xs={24} sm={12} md={8} lg={4} key={src.key} style={{ minWidth: 160 }}>
                  <SourceCard source={src} bySource={bySource} />
                </Col>
              ))}
            </Row>
          </Card>

          {/* self_research 独立区 */}
          <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
            <Col xs={24} sm={12} md={8}>
              <SelfResearchCard />
            </Col>
            <Col xs={24} sm={12} md={16}>
              <Alert
                type="info"
                showIcon
                message="口径说明"
                description={
                  <div>
                    <div>算法节省小计 = cache_hit + model_downgraded + negotiated_price + circuit_breaker + key_mgmt_labor（共 5 个算法口径）</div>
                    <div style={{ marginTop: 4 }}>
                      <Text type="secondary">自研节省为客户自填配置项，<strong>不计入算法节省小计</strong>，仅供参考展示。</Text>
                    </div>
                  </div>
                }
              />
            </Col>
          </Row>
        </>
      )}

      {/* 节省明细表 */}
      <Card
        title="节省明细"
        extra={
          <Select
            value={groupBy}
            onChange={(v) => setGroupBy(v as any)}
            options={GROUP_OPTIONS}
            size="small"
            style={{ width: 120 }}
          />
        }
      >
        <Table
          size="small"
          dataSource={trendItems}
          columns={trendColumns}
          rowKey={(r) => r.id || r.name || r.source || Math.random().toString()}
          loading={trendQ.isLoading}
          pagination={{ defaultPageSize: 15 }}
          locale={{ emptyText: '暂无数据（后端 /savings/trend 接口待接入）' }}
        />
      </Card>
    </div>
  )
}

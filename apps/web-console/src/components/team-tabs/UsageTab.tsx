import { formatDecimalAmount } from '../../utils/money'
import { getCurrencyByCode, useCurrencyStore } from '../../stores/currency'
import { useState } from 'react'
import { Select, Statistic, Row, Col, Table, Tabs, Spin } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { orgApi } from '../../services/api'
import { compactNumber } from '../../utils/format'
import { CompactNumber } from '../EnterpriseUI'

interface UsageTabProps {
  teamId: string
}

export function UsageTab({ teamId }: UsageTabProps) {
  const { currentCurrency } = useCurrencyStore()
  const [range, setRange] = useState('30d')

  const usageQ = useQuery({
    queryKey: ['team-usage', teamId, range],
    queryFn: () => orgApi.getUsage(teamId, range),
    enabled: !!teamId,
  })

  const data = usageQ.data?.data ?? {}
  const byMember = Array.isArray(data?.by_member) ? data.by_member : []
  const byApp = Array.isArray(data?.by_app) ? data.by_app : []
  const byModel = Array.isArray(data?.by_model) ? data.by_model : []

  const dimColumns = [
    { title: '名称', dataIndex: 'label', key: 'label', render: (v: string) => v || '-' },
    { title: `成本 (${data.currency || currentCurrency})`, dataIndex: 'cost', key: 'cost', render: (v: number, row: any) => `${getCurrencyByCode(row.currency || data.currency || currentCurrency).symbol}${formatDecimalAmount(v ?? 0)}` },
    { title: 'Token 数', dataIndex: 'tokens', key: 'tokens', render: (v: number) => <CompactNumber value={v} /> },
    { title: '请求次数', dataIndex: 'count', key: 'count', render: (v: number) => <CompactNumber value={v} /> },
  ]

  return (
    <Spin spinning={usageQ.isLoading}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <span style={{ fontSize: 14, color: '#666' }}>部门用量</span>
        <Select
          value={range}
          onChange={setRange}
          options={[
            { value: '7d', label: '近 7 天' },
            { value: '30d', label: '近 30 天' },
            { value: '90d', label: '近 90 天' },
          ]}
          style={{ width: 120 }}
        />
      </div>

      <Row gutter={24} style={{ marginBottom: 24 }}>
        <Col span={8}>
          <Statistic
            title={`总成本 (${data.currency || currentCurrency})`}
            value={data?.total_cost ?? 0}
            precision={2}
            prefix={getCurrencyByCode(data.currency || currentCurrency).symbol}
          />
        </Col>
        <Col span={8}>
          <Statistic
            title="总 Token"
            value={data?.total_tokens ?? 0}
            formatter={(v) => compactNumber(Number(v))}
          />
        </Col>
        <Col span={8}>
          <Statistic
            title="总请求次数"
            value={data?.request_count ?? 0}
            formatter={(v) => compactNumber(Number(v))}
          />
        </Col>
      </Row>

      <Tabs
        defaultActiveKey="member"
        items={[
          {
            key: 'member',
            label: '成员分布',
            children: (
              <Table
                dataSource={byMember}
                columns={dimColumns}
                rowKey="id"
                size="small"
                pagination={{ pageSize: 10 }}
                locale={{ emptyText: '暂无数据' }}
              />
            ),
          },
          {
            key: 'app',
            label: '应用分布',
            children: (
              <Table
                dataSource={byApp}
                columns={dimColumns}
                rowKey="id"
                size="small"
                pagination={{ pageSize: 10 }}
                locale={{ emptyText: '暂无数据' }}
              />
            ),
          },
          {
            key: 'model',
            label: '模型分布',
            children: (
              <Table
                dataSource={byModel}
                columns={dimColumns}
                rowKey="id"
                size="small"
                pagination={{ pageSize: 10 }}
                locale={{ emptyText: '暂无数据' }}
              />
            ),
          },
        ]}
      />
    </Spin>
  )
}

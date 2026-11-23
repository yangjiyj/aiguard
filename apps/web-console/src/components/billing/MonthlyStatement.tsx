import { useCurrencyStore } from '../../stores/currency'
import { useState } from 'react'
import { Alert, Button, DatePicker, Space, Table, Tag, Tooltip, Typography, message } from 'antd'
import { FileExcelOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import dayjs from 'dayjs'
import { billingAdminApi } from '../../services/api'
import { formatMoney, timezoneLabel } from './billingFormat'
import { ZhExpandIcon } from './BillingWidgets'

const { Text } = Typography

type Line = {
  model_name: string; requests: number; total_tokens: number; billed_micros: number; billed_requests: number
  unbilled_requests: number; unpriced_requests: number; usage_unknown_requests: number; failed_requests: number; estimated_requests?: number
}
type Employee = Line & { user_id: string; user_name: string; models: Line[] }
type Department = Line & { department_id: string; department_name: string; employees: Employee[] }
type Statement = { month: string; timezone: string; currency: string; total: Line; departments: Department[] }

const count = (value: number) => Number(value || 0).toLocaleString('zh-CN')

const unbilledTag = (line: Line) => line.unbilled_requests > 0
  ? <Tooltip title={`未定价 ${line.unpriced_requests} 次，用量未知 ${line.usage_unknown_requests} 次`}><Tag color="orange">{line.unbilled_requests} 次未计费</Tag></Tooltip>
  : <Text type="secondary">—</Text>

// 金额列：一笔已计费都没有、全是未计费时显示“未计费”及原因，而不是 0.00。
const estimatedCell = (line: Line) => Number(line.estimated_requests || 0) > 0
  ? <Tooltip title="流式调用未返回完整用量时，按已下发内容或预占上限保守结算，金额已计入账单"><Tag color="gold">{count(line.estimated_requests || 0)} 次估算计费</Tag></Tooltip>
  : <Text type="secondary">—</Text>

const billedCell = (line: Line, currency: string) => {
  if (line.billed_requests === 0 && line.unbilled_requests > 0) {
    const reasons = [line.unpriced_requests ? '未定价' : '', line.usage_unknown_requests ? '用量未知' : ''].filter(Boolean).join('、')
    return <Space size={4}><Tag color="orange">未计费</Tag><Text type="secondary">{reasons}</Text></Space>
  }
  return <Text strong>{formatMoney(line.billed_micros, currency)}</Text>
}

export default function MonthlyStatement({ tenantID }: { tenantID: string }) {
  const [month, setMonth] = useState(() => dayjs().format('YYYY-MM'))
  const [exporting, setExporting] = useState(false)
  const query = useQuery({ queryKey: ['billing-monthly-statement', tenantID, month], queryFn: () => billingAdminApi.monthlyStatement(tenantID, month), enabled: !!tenantID })
  const statement: Statement | undefined = query.data?.data?.data
  const currency = statement?.currency || useCurrencyStore.getState().tenantCurrency
  const exportExcel = async () => {
    setExporting(true)
    try {
      const response = await billingAdminApi.monthlyStatementXlsx(tenantID, month)
      const url = URL.createObjectURL(response.data)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `月度分账单-${month}.xlsx`
      anchor.click()
      URL.revokeObjectURL(url)
      message.success('月度分账单已导出')
    } catch {
      message.error('导出失败，请稍后重试')
    } finally {
      setExporting(false)
    }
  }
  const departmentColumns = [
    { title: '部门', dataIndex: 'department_name', render: (v: string) => <Text strong>{v}</Text> },
    { title: '调用次数', dataIndex: 'requests', align: 'right' as const, render: count },
    { title: 'Token 数', dataIndex: 'total_tokens', align: 'right' as const, render: count },
    { title: '已计费金额', key: 'billed', align: 'right' as const, render: (_: unknown, d: Department) => billedCell(d, currency) },
    { title: '估算计费', key: 'estimated', render: (_: unknown, d: Department) => estimatedCell(d) },
    { title: '未计费', key: 'unbilled', render: (_: unknown, d: Department) => unbilledTag(d) },
  ]
  const detail = (d: Department) => {
    const rows = d.employees.flatMap((e) => e.models.map((m, index) => ({ ...m, key: `${e.user_id}:${m.model_name}`, user_name: e.user_name, first: index === 0, span: e.models.length })))
    if (!rows.length) return <Text type="secondary">该部门本月没有可展开的员工明细</Text>
    return <Table size="small" pagination={false} dataSource={rows} columns={[
      { title: '员工', dataIndex: 'user_name', onCell: (r: any) => ({ rowSpan: r.first ? r.span : 0 }) },
      { title: '模型', dataIndex: 'model_name' },
      { title: '调用次数', dataIndex: 'requests', align: 'right' as const, render: count },
      { title: 'Token 数', dataIndex: 'total_tokens', align: 'right' as const, render: count },
      { title: '金额', key: 'billed', align: 'right' as const, render: (_: unknown, r: Line) => billedCell(r, currency) },
      { title: '估算计费', key: 'estimated', render: (_: unknown, r: Line) => estimatedCell(r) },
      { title: '未计费', key: 'unbilled', render: (_: unknown, r: Line) => unbilledTag(r) },
    ]} />
  }
  return <section aria-label="月度分账单">
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Space wrap style={{ justifyContent: 'space-between', width: '100%' }}>
        <Space wrap>
          <DatePicker picker="month" allowClear={false} aria-label="选择月份" value={dayjs(month + '-01')} onChange={(v) => v && setMonth(v.format('YYYY-MM'))} disabledDate={(d) => d.isAfter(dayjs(), 'month')} />
          {statement ? <Text type="secondary">账期按{timezoneLabel(statement.timezone)}的自然月统计</Text> : null}
        </Space>
        <Button icon={<FileExcelOutlined />} loading={exporting} disabled={!tenantID || query.isError} onClick={() => void exportExcel()}>导出 Excel</Button>
      </Space>
      {query.isError ? <Alert type="error" showIcon message="月度分账单读取失败" description="当前无法确认本月费用，系统不会把读取失败当成 0 元。" action={<Button onClick={() => void query.refetch()}>重试</Button>} /> : null}
      {statement ? <Space size={24} wrap>
        <Text>本月已计费 <Text strong style={{ fontSize: 18 }}>{formatMoney(statement.total.billed_micros, currency)}</Text></Text>
        <Text type="secondary">调用 {count(statement.total.requests)} 次 · Token {count(statement.total.total_tokens)}</Text>
        {Number(statement.total.estimated_requests || 0) > 0 ? estimatedCell(statement.total) : null}
        {statement.total.unbilled_requests > 0 ? <Text type="warning">未计费调用 {count(statement.total.unbilled_requests)} 次</Text> : null}
      </Space> : null}
      <Table rowKey={(d: Department) => d.department_id || 'unassigned'} loading={query.isLoading} dataSource={statement?.departments || []} columns={departmentColumns}
        pagination={false} expandable={{ expandedRowRender: detail, rowExpandable: (d: Department) => d.employees.length > 0, expandIcon: ZhExpandIcon }}
        locale={{ emptyText: query.isError ? '月度分账单读取失败，请重试' : '这个月还没有调用记录。可切换到其他月份，或在员工开始使用后再来查看。' }} scroll={{ x: 760 }} />
    </Space>
  </section>
}

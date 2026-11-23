import { Alert, Descriptions, Space, Table, Tag, Typography } from 'antd'
import { label, products } from './dict'
import { behaviorLabels, controlBoundaryRows, decideFailModeLabels, notReportedDetail, notReportedText, readControlBoundary, triggerLabels, uncontrolledLabels, yesNo, type ControlBoundaryRow } from './controlBoundaryReport'

export function ControlBoundaryPanel({ value }: { value: unknown }) {
  const report = readControlBoundary(value)
  if (!report) {
    const unsupported = value !== null && value !== undefined
    return <Alert type="warning" showIcon data-testid="control-boundary-missing" message={unsupported ? '控制边界格式无法识别 · 失效行为未知' : notReportedText} description={notReportedDetail} />
  }
  const uncontrolled = Array.isArray(report.uncontrolled) ? report.uncontrolled : []
  return <Space direction="vertical" style={{ width: '100%' }} data-testid="control-boundary">
    {report.config_error && <Alert type="error" showIcon message="hookd 无法加载钩子配置，前置钩子将全部阻断" description={report.config_error} />}
    <Descriptions bordered size="small" column={2} items={[
      { key: 'trusted', label: '要求可信授权', children: yesNo(report.require_trusted_agent_authorization) },
      { key: 'strict', label: '严格审批', children: yesNo(report.strict_approval) },
      { key: 'fail', label: '服务端判定失败时', children: report.decide_fail_mode ? decideFailModeLabels[report.decide_fail_mode] ?? report.decide_fail_mode : '未知' },
      { key: 'timeout', label: '判定超时', children: typeof report.decide_timeout_ms === 'number' ? `${report.decide_timeout_ms} 毫秒` : '未知' },
      { key: 'hookd', label: '上报 hookd 版本', children: report.hookd_version || '未记录' },
      { key: 'config', label: '配置版本', children: report.config_version ?? '未记录' },
    ]} />
    <Table<ControlBoundaryRow> size="small" rowKey="key" pagination={false} dataSource={controlBoundaryRows(report)} locale={{ emptyText: '未上报宿主路径' }} columns={[
      { title: '宿主', render: (_: unknown, x: ControlBoundaryRow) => <Space>{label(products, x.host) === '未识别' ? x.host : label(products, x.host)}{!x.pre_tool_gate && <Tag>仅观测</Tag>}</Space> },
      { title: '触发条件', render: (_: unknown, x: ControlBoundaryRow) => <Typography.Text title={x.trigger}>{triggerLabels[x.trigger] ?? x.trigger}</Typography.Text> },
      { title: '行为', render: (_: unknown, x: ControlBoundaryRow) => { const b = behaviorLabels[x.behavior]; return <Tag color={b?.color ?? 'default'}>{b?.text ?? x.behavior}</Tag> } },
      { title: '超时', render: (_: unknown, x: ControlBoundaryRow) => (typeof x.timeout_ms === 'number' ? `${x.timeout_ms} 毫秒` : '—') },
      { title: '依据', render: (_: unknown, x: ControlBoundaryRow) => <Typography.Text type="secondary" style={{ fontSize: 12 }}>{x.log ? `${x.source} · 日志“${x.log}”` : x.source}</Typography.Text> },
    ]} />
    <div><Typography.Text strong>不受控范围：</Typography.Text>{uncontrolled.length ? uncontrolled.map(item => <Tag key={item}>{uncontrolledLabels[item] ?? item}</Tag>) : <Typography.Text type="secondary">未上报</Typography.Text>}</div>
  </Space>
}

import { SEVERITY_LABELS } from '../utils/risk'
import { Alert, Button, Collapse, Descriptions, List, Space, Spin, Tag, Typography } from 'antd'
import { Link } from 'react-router-dom'
import { useBlockTrace } from '../hooks/useBlockTrace'
import RawEvidenceText from './RawEvidenceText'
import { formatInTimezone } from '../utils/ws8ReportRange'

const { Text, Paragraph } = Typography
const ACTIONS: Record<string, string> = {
  block: '阻断', security_blocked: '阻断', stream_blocked: '流式阻断', tool_attempt_blocked: '工具阻断',
  tool_blocked: '工具定义阻断', confirm: '等待确认', alert: '告警', log: '留痕', allow: '放行',
  redact: '脱敏', sanitize: '净化', quarantine: '隔离', deny: '拒绝',
}
const REQUEST_STATUSES: Record<string, string> = {
  success: '成功', security_blocked: '安全阻断', blocked: '已阻断', failed: '失败', error: '失败',
  incomplete: '未完成', cancelled: '已取消', upstream_error: '上游失败', processing: '处理中',
}
const ROLES: Record<string, string> = { user: '用户输入', assistant: '模型输出', system: '系统指令', tool: '工具结果', request_response: '请求与响应' }
const EVIDENCE_STATUSES: Record<string, string> = {
  available: '可查看', not_collected: '未采集', expired: '已过期', unavailable: '暂不可用', restricted: '无查看权限',
}

const identifier = (value: string) => <Text copyable style={{ wordBreak: 'break-all' }}>{value}</Text>

// Links from the API remain on the existing authorized console routes.
function auditLink(value: string | undefined, pathname: string, requestId: string, createdAt: string) {
  if (value) {
    try {
      const url = new URL(value, 'https://console.invalid')
      if (url.origin === 'https://console.invalid' && url.pathname === pathname && url.searchParams.get('request_id') === requestId) {
        return `${url.pathname}${url.search}`
      }
    } catch { /* Use the exact request fallback below. */ }
  }
  const params = new URLSearchParams({ request_id: requestId })
  const timestamp = Date.parse(createdAt)
  if (Number.isFinite(timestamp)) {
    params.set('from', new Date(timestamp - 86400000).toISOString())
    params.set('to', new Date(timestamp + 86400000).toISOString())
  }
  return `${pathname}?${params}`
}

export default function BlockTraceEvidence({ blockId, requestId, createdAt, timezone }: {
  blockId: string; requestId: string; createdAt: string; timezone: string
}) {
  const traceQuery = useBlockTrace(blockId)
  if (traceQuery.isPending) return <Spin aria-label="正在读取告警与留痕" />
  if (traceQuery.isError) return (
    <Alert type="error" showIcon message="告警与留痕读取失败" description="无法确认关联数据，请重试。"
      action={<Button size="small" onClick={() => void traceQuery.refetch()}>重试</Button>} />
  )
  const trace = traceQuery.data
  // Never display a response that belongs to another request or another block.
  if (!trace || trace.block.block_id !== blockId || trace.block.request_id !== requestId || trace.audit.request_id !== requestId) {
    return <Alert type="error" showIcon message="关联编号不一致，未展示告警与留痕" />
  }
  const audit = trace.audit
  const alerts = trace.alerts?.items || []
  const request = audit.request
  const events = audit.security_events || []
  const contents = audit.content_records || []
  const tools = audit.tool_records || []
  const evidence = audit.content_evidence
  const time = (value: string) => Number.isFinite(Date.parse(value)) ? formatInTimezone(value, timezone) : value || '-'
  const retentionUrl = auditLink(audit.retention_url, '/audit/access-retention', requestId, createdAt)
  return (
    <Space direction="vertical" size={20} style={{ width: '100%' }}>
      <section aria-label="关联安全告警">
        <Space wrap style={{ marginBottom: 10 }}>
          <Text strong>关联安全告警</Text>
          {trace.alerts_status === 'available' ? <Tag>{trace.alerts?.total || 0} 条</Tag> : null}
          <Link to={`/security/alerts?${new URLSearchParams({ request_id: requestId, event_id: blockId })}`}>查看本次阻断告警</Link>
        </Space>
        {trace.alerts_status === 'unavailable' ? (
          <Alert showIcon type="warning" message="关联告警暂不可用" description="阻断记录仍可核查；告警服务恢复后请刷新。" />
        ) : alerts.length === 0 ? (
          <Alert showIcon type="info" message="当前未找到本次请求的关联告警" description="以下审计留痕单独展示已保存的事件，不将缺失告警当作已找到。" />
        ) : (
          <List size="small" bordered dataSource={alerts} renderItem={(alert) => (
            <List.Item key={alert.id}>
              <Space direction="vertical" size={6} style={{ width: '100%' }}>
                <Space wrap>
                  <Text strong>{alert.rule_name || alert.rule_id || '未记录规则'}</Text>
                  <Tag color={alert.severity === 'critical' || alert.severity === 'high' ? 'red' : 'orange'}>{SEVERITY_LABELS[alert.severity] || alert.severity}</Tag>
                  <Tag>{ACTIONS[alert.event_action_taken || alert.action_taken] || alert.action_taken || '未记录处置'}</Tag>
                  {alert.suppressed ? <Tag>已抑制</Tag> : null}
                </Space>
                <Text type="secondary">发生时间：{time(alert.created_at)}</Text>
                <Text>告警编号：{identifier(alert.id)}</Text>
                <Text>事件编号：{identifier(alert.event_id)}</Text>
                {alert.reason ? <Paragraph style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }}>告警原因：{alert.reason}</Paragraph> : null}
                <RawEvidenceText prefix="命中内容：" raw={alert.raw_evidence} truncated={alert.raw_evidence_truncated} omitted={alert.raw_evidence_omitted} fallback={alert.redacted_evidence} />
                <Link to={`/security/alerts?${new URLSearchParams({ request_id: requestId, event_id: alert.event_id })}`}>查看该告警</Link>
              </Space>
            </List.Item>
          )} />
        )}
        {(trace.alerts?.total || 0) > alerts.length ? <Text type="secondary">当前展示 {alerts.length} 条，完整告警请进入安全告警页查看。</Text> : null}
      </section>

      <section aria-label="请求审计留痕">
        <Text strong>请求审计留痕</Text>
        {audit.status === 'unavailable' ? <Alert style={{ marginTop: 10 }} type="warning" showIcon message="部分审计留痕读取失败" description="以下仅展示已读取的信息，空列表不代表没有记录。请刷新后核查。" /> : null}
        {request ? (
          <Descriptions column={1} size="small" bordered style={{ marginTop: 10 }}>
            <Descriptions.Item label="留痕记录编号">{identifier(request.record_id)}</Descriptions.Item>
            <Descriptions.Item label="请求 ID">{identifier(request.request_id)}</Descriptions.Item>
            <Descriptions.Item label="记录时间">{time(request.created_at)}</Descriptions.Item>
            <Descriptions.Item label="请求状态">{REQUEST_STATUSES[request.status || ''] || request.status || '未记录'}{request.http_status ? ` · HTTP ${request.http_status}` : ''}</Descriptions.Item>
            {request.session_id ? <Descriptions.Item label="会话编号">{identifier(request.session_id)}</Descriptions.Item> : null}
            <Descriptions.Item label="Token 用量">输入 {request.input_tokens ?? 0} · 输出 {request.output_tokens ?? 0}</Descriptions.Item>
          </Descriptions>
        ) : audit.status !== 'unavailable' ? <Alert style={{ marginTop: 10 }} type="info" showIcon message="未找到关联请求日志" description="这不影响已有阻断事件的查看；历史请求或非模型代理路径可能未保存请求日志。" /> : null}
        <Alert style={{ marginTop: 12 }} type={evidence.can_view ? 'success' : 'info'} showIcon
          message={`内容留痕：${EVIDENCE_STATUSES[evidence.status] || evidence.status}`}
          description={evidence.summary || '仅展示已保存的证据状态。'} />
        <Space wrap style={{ marginTop: 12 }}>
          <Link to={retentionUrl}>{evidence.can_view ? '查看完整调用留痕' : '按请求 ID 查询留痕'}</Link>
          <Text type="secondary">原文及附件通过留痕页的现有权限核查。</Text>
        </Space>
        <Collapse style={{ marginTop: 12 }} defaultActiveKey={['events']} items={[
          {
            key: 'events', label: `安全事件留痕（${events.length} 条）`, children: (
              <List size="small" dataSource={events} locale={{ emptyText: '未返回关联安全事件' }} renderItem={(event) => (
                <List.Item key={event.id}>
                  <Space direction="vertical" size={4}>
                    <Space wrap><Text strong>{event.rule_name || event.rule_id || '安全事件'}</Text><Tag>{ACTIONS[event.action_taken] || event.action_taken}</Tag>{event.id === blockId ? <Tag color="red">本次阻断</Tag> : null}</Space>
                    <Text>事件编号：{identifier(event.id)}</Text>
                    <Text type="secondary">{time(event.created_at)} · {SEVERITY_LABELS[event.severity] || event.severity}</Text>
                  </Space>
                </List.Item>
              )} />
            ),
          },
          {
            key: 'content', label: `内容留痕索引（${audit.content_count ?? contents.length} 条）`, children: (
              <>
              <List size="small" dataSource={contents} locale={{ emptyText: '无内容留痕索引，具体原因见上方证据状态' }} renderItem={(record) => (
                <List.Item key={record.id}><Space direction="vertical" size={4}><Text>{ROLES[record.role] || record.role} · {record.tokens} Token</Text><Text>记录编号：{identifier(record.id)}</Text><Text type="secondary">{time(record.created_at)}</Text></Space></List.Item>
              )} />
              {(audit.content_count || 0) > contents.length ? <Text type="secondary">已展示 {contents.length} 条索引，完整记录请进入调用留痕页查看。</Text> : null}
              </>
            ),
          },
          {
            key: 'tools', label: `工具留痕索引（${audit.tool_count ?? tools.length} 条）`, children: (
              <>
              <List size="small" dataSource={tools} locale={{ emptyText: '无关联工具留痕' }} renderItem={(record) => (
                <List.Item key={record.id}><Space direction="vertical" size={4}><Text strong>{record.tool_name || '未记录工具'}</Text><Text>记录编号：{identifier(record.id)}</Text>{record.operation_id ? <Text>操作编号：{identifier(record.operation_id)}</Text> : null}<Text type="secondary">{time(record.created_at)} · {REQUEST_STATUSES[record.status] || ACTIONS[record.status] || record.status}</Text></Space></List.Item>
              )} />
              {(audit.tool_count || 0) > tools.length ? <Text type="secondary">已展示 {tools.length} 条索引，完整记录请进入调用留痕页查看。</Text> : null}
              </>
            ),
          },
        ]} />
      </section>
    </Space>
  )
}

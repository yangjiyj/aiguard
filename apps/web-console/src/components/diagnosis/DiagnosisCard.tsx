import { Button, Card, Collapse, Space, Tag, Typography } from 'antd'
import { Link } from 'react-router-dom'
import { diagnosticsApi, type DiagnosisReport } from '../../services/api'
import { useAuthStore } from '../../stores/auth'
import { isConsoleAdministratorRole } from '../../utils/access'

const labels = { confirmed: '确定', suspected: '疑似', unknown: '无法判断' }
export default function DiagnosisCard({ report, onOpenRequest }: {
  report: DiagnosisReport
  onOpenRequest: (requestId: string) => void
}) {
  const admin = isConsoleAdministratorRole(useAuthStore((state) => state.user?.role))
  const findings = (report.findings || []).filter((finding) => finding.severity !== 'ok')
  return <Card size="small">
    <Space direction="vertical" size="middle" style={{ width: '100%', overflowWrap: 'anywhere' }}>
      {report.degraded && <Typography.Text type="secondary">{report.degraded}</Typography.Text>}
      {findings.map((finding, index) => <section key={`${finding.check_id}-${index}`}>
        <Space size={4} wrap>
          <Tag color={finding.level === 'confirmed' ? (finding.severity === 'error' ? 'red' : 'orange') : finding.level === 'suspected' ? 'gold' : 'default'}>{labels[finding.level]}</Tag>
          <Tag>{report.tier}</Tag>
          <Typography.Text strong>{finding.title}</Typography.Text>
        </Space>
        <Typography.Paragraph style={{ marginTop: 8 }}>{finding.impact}</Typography.Paragraph>
        {!!finding.advice?.length && <ul style={{ paddingInlineStart: 20 }}>{finding.advice.map((advice, i) => <li key={i}>{advice.link ? <Link to={advice.link}>{advice.text}</Link> : advice.text}</li>)}</ul>}
        {!!finding.excluded?.length && <Typography.Text type="secondary">已排除：{finding.excluded.join('，')}</Typography.Text>}
      </section>)}
      {report.ok_count > 0 && <Typography.Text type="secondary">另有 {report.ok_count} 项正常</Typography.Text>}
      <Collapse size="small" style={{ width: '100%' }} items={[
        { key: 'steps', label: '排查过程', children: <ol style={{ paddingInlineStart: 20 }}>{(report.steps || []).map((step, i) => <li key={i}>{step.summary}</li>)}</ol> },
        { key: 'evidence', label: '证据', children: findings.flatMap((finding, i) => (finding.evidence || []).map((evidence, j) => <div key={`${i}-${j}`} style={{ marginBottom: 12 }}>
          {evidence.kind === 'request' ? <Typography.Link href={`/cost/records?request_id=${encodeURIComponent(evidence.ref)}`} onClick={(event) => { event.preventDefault(); onOpenRequest(evidence.ref) }}>{evidence.ref}</Typography.Link> : <Typography.Text>{evidence.ref}</Typography.Text>}
          <div>{evidence.summary}</div>
          {evidence.raw && <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{evidence.raw}</pre>}
        </div>)) },
      ]} />
      {admin && <div style={{ textAlign: 'right', width: '100%' }}><Button onClick={() => downloadDiagnosisBundle(report.id)}>导出诊断包</Button></div>}
    </Space>
  </Card>
}

// 控制台走 Bearer 鉴权，直链下载拿不到令牌，所以先取 blob 再触发下载。
async function downloadDiagnosisBundle(id: string) {
  const response = await diagnosticsApi.downloadBundle(id)
  const url = URL.createObjectURL(response.data)
  const link = document.createElement('a')
  link.href = url
  link.download = `diagnosis-${id}.zip`
  link.click()
  URL.revokeObjectURL(url)
}

import { Alert, Space, Typography } from 'antd'
import type { AuditChainIntegrity } from '../services/api'
import { useAuditChainIntegrity } from '../hooks/useAuditChainIntegrity'
import { formatInTimezone } from '../utils/ws8ReportRange'

const { Text } = Typography

// 审计签名密钥仍是开发默认值时的红色告警条：审计记录可被伪造，必须尽快配置。
export function AuditHmacDefaultKeyBanner({ integrity }: { integrity?: AuditChainIntegrity }) {
  if (!integrity?.hmac_default_key) return null
  return (
    <Alert
      type="error"
      showIcon
      banner
      role="alert"
      message="审计签名密钥未配置：控制面正在使用开发默认密钥，审计记录可被伪造。"
      description="请在部署配置中设置随机的审计签名密钥（UAG_AUDIT_HMAC_KEY）后重启控制面；离线安装包首次安装时会自动生成。已有审计记录的环境更换密钥前请先联系实施人员。"
    />
  )
}

// 审计日志页顶部：“最近一次完整性校验：通过 / 失败（时间）”。
export function AuditIntegrityStatusLine({ timezone }: { timezone: string }) {
  const { data, isLoading, isError } = useAuditChainIntegrity()
  if (isLoading) return null
  if (isError || !data) {
    return <Alert type="warning" showIcon message="最近一次完整性校验：状态暂不可用" />
  }
  if (!data.verified) {
    return <Alert type="info" showIcon message="最近一次完整性校验：尚未执行（控制面启动后自动校验，之后每天一次）" />
  }
  const at = data.last_verified_at ? formatInTimezone(data.last_verified_at, timezone) : ''
  if (data.ok) {
    return <Alert type="success" showIcon message={`最近一次完整性校验：通过（${at}）`} />
  }
  return (
    <Alert
      type="error"
      showIcon
      message={`最近一次完整性校验：失败（${at}）`}
      description={(
        <Space direction="vertical" size={2}>
          {data.detail ? <Text>原因：{data.detail}</Text> : null}
          {data.first_break_at_seq ? <Text>首个异常记录序号：{data.first_break_at_seq}</Text> : null}
          <Text type="secondary">已产生高危告警。请保留现场并导出审计链，联系安全负责人排查。</Text>
        </Space>
      )}
    />
  )
}

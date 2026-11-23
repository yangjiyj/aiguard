import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Descriptions, Empty, Input, Space, Spin, message } from 'antd'
import {
  ClockCircleOutlined,
  CloudUploadOutlined,
  DownloadOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { licenseApi, type LicenseStatus } from '../services/api'
import {
  EnterprisePageHeader,
  InsightStrip,
  MetricCard,
  SectionPanel,
  StatusPill,
} from '../components/EnterpriseUI'

const { TextArea } = Input

type Tone = 'blue' | 'green' | 'orange' | 'red' | 'gray'

const statusMeta: Record<LicenseStatus['status'], { tone: Tone; label: string }> = {
  active: { tone: 'green', label: '已授权' },
  trial: { tone: 'blue', label: '测试授权' },
  grace: { tone: 'orange', label: '宽限期' },
  missing: { tone: 'orange', label: '未导入' },
  expired: { tone: 'red', label: '已过期' },
  pending: { tone: 'blue', label: '未生效' },
  invalid: { tone: 'red', label: '无效' },
}

const featureLabels: Record<string, string> = {
  web_ai: '网页版 AI 审计',
  agent_audit: 'AI Agent 审计',
  agent_security: '端侧智能体安全',
  ide_proxy: 'IDE 接入',
  content_retention: '内容留存',
  sensitive_data_guard: '敏感数据拦截',
}

const ALL_FEATURES = ['web_ai', 'agent_audit', 'ide_proxy', 'content_retention', 'sensitive_data_guard', 'agent_security']

function formatDate(value?: string) {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

// 数值驱动 tone：仅在授权有效时按剩余天数切语义色，其余统一中性。
function daysTone(days: number, active: boolean): Tone {
  if (!active) return 'gray'
  if (days <= 7) return 'red'
  if (days <= 30) return 'orange'
  return 'green'
}

function License() {
  const [licenseText, setLicenseText] = useState('')
  const queryClient = useQueryClient()

  const statusQ = useQuery({
    queryKey: ['licenseStatus'],
    queryFn: () => licenseApi.status().then((res) => res.data),
  })

  const importMut = useMutation({
    mutationFn: (license: string) => licenseApi.import(license).then((res) => res.data),
    onSuccess: () => {
      message.success('授权导入成功')
      setLicenseText('')
      queryClient.invalidateQueries({ queryKey: ['licenseStatus'] })
    },
    onError: (err: any) => {
      message.error(err?.response?.data?.error?.message || '授权导入失败')
    },
  })

  const status = statusQ.data
  // 防御纵深：后端若返回前端未知的 status，回退到「未导入」中性态而非崩溃白屏。
  const meta = statusMeta[status?.status as LicenseStatus['status']] ?? statusMeta.missing
  const payload = status?.payload
  const payloadV2 = status?.payload_v2
  const licenseDetails = payload
    ? {
        customer: payload.customer,
        licenseId: payload.license_id,
        edition: payload.edition,
        notBefore: payload.not_before,
        expiresAt: payload.expires_at,
        maxUsers: payload.max_users,
      }
    : payloadV2
      ? {
          customer: payloadV2.customer.displayName,
          licenseId: payloadV2.licenseId,
          edition: payloadV2.edition,
          notBefore: payloadV2.notBefore,
          expiresAt: payloadV2.expiresAt,
          maxUsers: payloadV2.maxUsers,
        }
      : undefined
  const isActive = status?.status === 'active'
  // trial/grace 也是「当前有效运行」态，用后端 valid 统一驱动剩余天数/运行态展示。
  const isValid = status?.valid ?? false
  const isTrial =
    status?.status === 'trial' ||
    payload?.license_type === 'trial' ||
    payloadV2?.edition === 'trial' ||
    status?.key_id === 'bundle-trial-key' ||
    payloadV2?.licenseId.startsWith('lic_v2_trial_')
  // days_left 为可选字段，统一 ?? 0 守卫，避免 strict 下 TS18048。
  const daysLeft = status?.days_left ?? 0
  const dTone = daysTone(daysLeft, isValid)
  const canImport = licenseText.trim().length > 0 && !importMut.isPending
  const keyReady = !status || status.public_key_set
  const enabledFeatures = new Set(status?.features ?? payloadV2?.features ?? payload?.features ?? [])
  const enabledFeatureCount = ALL_FEATURES.filter((feature) => enabledFeatures.has(feature)).length

  // 合规态势结论。注意：授权状态项以「授权 · X」复合文本呈现，
  // 使裸 meta.label 在全页仅出现一次（当前授权 SectionPanel 的 extra），
  // 避免 screen.findByText('未导入') 命中多个精确节点。
  const insightItems: Array<{ label: string; value: string; tone: Tone; description: string }> = [
    {
      label: '授权状态',
      value: `授权 · ${meta.label}`,
      tone: meta.tone,
      description: isValid
        ? isTrial
          ? '测试授权运行中'
          : '正式授权运行中'
        : '当前不具备有效授权',
    },
    {
      label: '剩余有效期',
      value: isValid ? `${daysLeft} 天` : '—',
      tone: dTone === 'gray' ? 'blue' : dTone,
      description: isValid
        ? daysLeft <= 30
          ? '已进入临期窗口，建议尽快续期'
          : '到期前请及时续期以避免服务中断'
        : '导入有效授权后开始计算有效期',
    },
    {
      label: '能力覆盖',
      value: isValid ? `${enabledFeatureCount} / ${ALL_FEATURES.length}` : '—',
      tone: isValid ? 'blue' : 'gray',
      description: '当前授权已开通的安全审计能力数量',
    },
  ]

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader
        eyebrow="授权与合规"
        title="许可证管理"
        description="管理企业离线授权凭据、查看授权明细与平台能力开通状态"
        meta={
          <Space size={8} wrap>
            <StatusPill tone={meta.tone}>授权状态 · {meta.label}</StatusPill>
            {isValid ? <StatusPill tone={dTone}>剩余 {daysLeft} 天</StatusPill> : null}
          </Space>
        }
        actions={
          <Button icon={<ReloadOutlined />} onClick={() => statusQ.refetch()} loading={statusQ.isFetching}>
            刷新
          </Button>
        }
      />

      <Spin spinning={statusQ.isLoading}>
        {!keyReady ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
            message="授权校验尚未启用"
            description="系统尚未启用授权校验，请联系部署方完成授权配置后再导入授权凭据。"
          />
        ) : null}
        {status?.reason && status.status !== 'missing' ? (
          <Alert type="error" showIcon style={{ marginBottom: 16 }} message="授权异常" description={status.reason} />
        ) : null}

        <InsightStrip title="合规态势" items={insightItems} />

        <div className="enterprise-metric-grid" style={{ marginTop: 16 }}>
          <MetricCard
            label="剩余天数"
            value={isValid ? daysLeft : '—'}
            unit={isValid ? '天' : undefined}
            tone={dTone}
            icon={<ClockCircleOutlined />}
            footer={
              <StatusPill tone={dTone}>
                {isValid ? (daysLeft <= 7 ? '即将到期' : daysLeft <= 30 ? '建议尽快续期' : '授权有效') : '尚未授权'}
              </StatusPill>
            }
          />
          <MetricCard
            label="到期时间"
            value={licenseDetails ? formatDate(licenseDetails.expiresAt) : '—'}
            tone={isActive && daysLeft <= 30 ? 'orange' : 'blue'}
            icon={<SafetyCertificateOutlined />}
            hint={licenseDetails ? `生效于 ${formatDate(licenseDetails.notBefore)}` : '导入授权后显示有效期'}
          />
          <MetricCard
            label="用户上限"
            value={licenseDetails ? (licenseDetails.maxUsers ? licenseDetails.maxUsers : '不限') : '—'}
            unit={licenseDetails?.maxUsers ? '人' : undefined}
            tone="blue"
            hint="授权许可的最大并发用户数"
          />
          <MetricCard
            label="测试授权时长"
            value={status?.trial_days ?? 90}
            unit="天"
            tone="gray"
            hint="测试授权的默认有效期"
          />
        </div>

        <div
          className="enterprise-governance-grid"
          style={{ display: 'flex', gap: 16, marginTop: 16, alignItems: 'flex-start', flexWrap: 'wrap' }}
        >
          <div style={{ flex: '1 1 520px', minWidth: 320, display: 'flex', flexDirection: 'column', gap: 16 }}>
            <SectionPanel
              title="当前授权"
              description="平台当前生效的授权凭据与明细，状态以本地签名校验结果为准"
              extra={<StatusPill tone={meta.tone}>{meta.label}</StatusPill>}
            >
              {licenseDetails ? (
                <Descriptions column={2} size="small" bordered>
                  <Descriptions.Item label="客户名称">{licenseDetails.customer}</Descriptions.Item>
                  <Descriptions.Item label="授权类型">
                    {isTrial ? '测试授权' : '正式授权'}
                  </Descriptions.Item>
                  <Descriptions.Item label="授权编号">{licenseDetails.licenseId}</Descriptions.Item>
                  <Descriptions.Item label="产品版本">{licenseDetails.edition}</Descriptions.Item>
                  <Descriptions.Item label="生效时间">{formatDate(licenseDetails.notBefore)}</Descriptions.Item>
                  <Descriptions.Item label="到期时间">{formatDate(licenseDetails.expiresAt)}</Descriptions.Item>
                  <Descriptions.Item label="用户上限">
                    {licenseDetails.maxUsers ? licenseDetails.maxUsers : '不限'}
                  </Descriptions.Item>
                  <Descriptions.Item label="剩余天数">{daysLeft} 天</Descriptions.Item>
                </Descriptions>
              ) : (
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="尚未导入授权，平台运行于未授权状态"
                />
              )}
            </SectionPanel>

            <SectionPanel title="授权能力" description="AI Agent 审计用于网关会话；端侧智能体安全用于终端接入与行为采集，需单独授权。">
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {ALL_FEATURES.map((feature, index) => {
                  const enabled = isValid && enabledFeatures.has(feature)
                  return (
                    <div
                      key={feature}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 12,
                        padding: '10px 0',
                        borderTop: index === 0 ? 'none' : '1px solid var(--border-color)',
                      }}
                    >
                      <span style={{ color: 'var(--text-primary)', fontSize: 13 }}>
                        {featureLabels[feature] || feature}
                      </span>
                      <StatusPill tone={enabled ? 'green' : 'gray'}>{enabled ? '已启用' : '未授权'}</StatusPill>
                    </div>
                  )
                })}
              </div>
            </SectionPanel>
          </div>

          <div style={{ flex: '1 1 360px', minWidth: 300, display: 'flex', flexDirection: 'column', gap: 16 }}>
            <SectionPanel title="导出主机信息" description="续费时点此导出，发给授权方换取授权文件">
              <Space direction="vertical" size={12} style={{ width: '100%' }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.6 }}>
                  导出本机部署指纹与版本信息，发送给授权方即可换取匹配的授权文件。
                </span>
                <Button
                  block
                  icon={<DownloadOutlined />}
                  onClick={async () => {
                    const res = await licenseApi.hostInfo()
                    const info = res.data
                    const blob = new Blob([JSON.stringify(info, null, 2)], { type: 'application/json' })
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url
                    a.download = 'host-info-jjdguard.json'
                    a.click()
                    URL.revokeObjectURL(url)
                  }}
                >
                  导出主机信息
                </Button>
              </Space>
            </SectionPanel>

            <SectionPanel title="导入正式授权" description="粘贴客户授权凭据完成离线授权">
              <Space direction="vertical" size={12} style={{ width: '100%' }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.6 }}>
                  粘贴客户授权 JSON 后导入。导入前将在本地校验 Ed25519 签名，确保凭据完整可信。
                </span>
                <TextArea
                  value={licenseText}
                  onChange={(event) => setLicenseText(event.target.value)}
                  rows={8}
                  placeholder='{"algorithm":"ed25519","payload":...,"signature":"..."}'
                />
                <Button
                  type="primary"
                  block
                  icon={<CloudUploadOutlined />}
                  disabled={!canImport}
                  loading={importMut.isPending}
                  onClick={() => importMut.mutate(licenseText)}
                >
                  导入授权
                </Button>
              </Space>
            </SectionPanel>

          </div>
        </div>
      </Spin>
    </div>
  )
}

export default License

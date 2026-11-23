import { useState } from 'react'
import { Alert, Button, Input, Modal, Radio, Tag, message } from 'antd'
import {
  CheckCircleFilled,
  ClockCircleOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useSecurityExecutionMode } from '../hooks/useSecurityExecutionMode'
import {
  SECURITY_EXECUTION_MODE_QUERY_KEY,
  securityExecutionModeApi,
  securityModeLabel,
  securityModeSourceLabel,
  type SecurityExecutionModeValue,
} from '../services/securityExecutionMode'

const { TextArea } = Input

function runtimeStatusLabel(status?: string, verified = false): string {
  if (!status) return '待确认'
  if (status === 'verified' || status === 'applied') return verified ? '运行已确认' : '等待运行回执'
  if (status === 'partially_applied' || status === 'applied_with_stale_nodes') return '部分节点待同步'
  if (status === 'pending' || status === 'applying') return '正在同步'
  if (status === 'error' || status === 'failed' || status === 'degraded') return '同步异常'
  return '待确认'
}

export type SecurityExecutionModeCardProps = {
  canManage: boolean
  protectedSceneCount?: number
  totalSceneCount?: number
  runtimePolicyCount?: number
  tenantPolicyCount?: number
  blockingPolicyCount?: number
}

export default function SecurityExecutionModeCard({
  canManage,
  protectedSceneCount,
  totalSceneCount = 6,
  runtimePolicyCount,
  tenantPolicyCount,
  blockingPolicyCount,
}: SecurityExecutionModeCardProps) {
  const queryClient = useQueryClient()
  const { mode, isLoading, isError, refetch } = useSecurityExecutionMode()
  const [pendingMode, setPendingMode] = useState<SecurityExecutionModeValue>()
  const [changeReason, setChangeReason] = useState('')
  const mutation = useMutation({
    mutationFn: securityExecutionModeApi.update,
    onSuccess: async () => {
      message.success('配置已保存，正在回读运行状态')
      await queryClient.invalidateQueries({ queryKey: SECURITY_EXECUTION_MODE_QUERY_KEY })
      await refetch()
      setPendingMode(undefined)
      setChangeReason('')
    },
    onError: (error: unknown) => {
      const response = (error as { response?: { data?: { error?: { message?: string } } } }).response
      message.error(response?.data?.error?.message || '保存失败，页面将继续显示服务端原值')
      void refetch()
    },
  })
  // 2.9.22 起后端不再有部署只审计锁（不再返回 locked=true），模式只由这里配置。
  const disabled = !canManage || !mode || isError
  const requestChange = (value: SecurityExecutionModeValue) => {
    if (disabled || mutation.isPending) return
    setPendingMode(value)
    setChangeReason('')
  }
  const modified = mode?.last_modified_by && mode.last_modified_at
    ? mode.last_modified_by + ' · ' + new Date(mode.last_modified_at).toLocaleString('zh-CN')
    : '暂无记录'
  const runtimeConfirmed = mode?.runtime_verified === true && !isError
  const auditCeiling = mode?.effective_mode === 'record'
  const statusHeadline = !mode || isError
    ? '运行状态待确认'
    : runtimeConfirmed
      ? `${securityModeLabel(mode.effective_mode)}正在运行`
      : `${securityModeLabel(mode.configured_mode)}待同步`
  const statusDescription = !runtimeConfirmed
    ? '配置需等待各运行节点确认，当前实际处置状态尚未确认。'
    : mode?.effective_mode === 'protect'
      ? '已启用策略会按保存动作执行，未命中策略的正常流量不受影响。'
      : '持续检测、告警和留证，但不会执行脱敏、人工确认或阻断。'
  const dispositionCeiling = runtimeConfirmed ? auditCeiling ? '记录并告警' : '按策略执行' : '待运行确认'

  return (
    <section className={`security-execution-mode-card is-${mode?.effective_mode || 'unknown'}`} aria-label="全局防护模式">
      <div className="security-execution-mode-header">
        <div className="security-execution-mode-heading">
          <span className="security-execution-mode-icon" aria-hidden="true"><SafetyCertificateOutlined /></span>
          <div>
            <h2>全局防护模式</h2>
            <p>全局模式控制策略可执行的最高处置级别，具体动作仍由各策略决定。管理员可在此修改并保存。</p>
          </div>
        </div>
        <Button aria-label="刷新状态" className="security-execution-mode-refresh" size="small" icon={<ReloadOutlined />} loading={isLoading} onClick={() => void refetch()}>
          刷新状态
        </Button>
      </div>

      {isError ? <Alert type="error" showIcon message="全局运行状态获取失败" description="页面不会使用缓存值推断实际处置。" /> : null}
      {mode?.source === 'deployment'
        ? <Alert type="info" showIcon message="当前沿用安装时的观察留痕配置，管理员可直接在此选择并保存全局防护模式。" />
        : null}
      {!canManage ? <Alert type="info" showIcon message="当前账号可查看策略，但只有平台管理员可以修改全局模式。" /> : null}

      <div className="security-execution-mode-body">
        <div className="security-execution-mode-current" aria-live="polite">
          <span className="security-execution-mode-eyebrow">当前运行状态</span>
          <div className="security-execution-mode-status-title">
            {runtimeConfirmed ? <CheckCircleFilled /> : <ClockCircleOutlined />}
            <strong>{statusHeadline}</strong>
          </div>
          <p>{statusDescription}</p>
          <div className="security-execution-mode-facts">
            <span>
              <small>客户模式</small>
              <strong>
                {runtimeConfirmed ? securityModeLabel(mode?.effective_mode) : '待运行确认'}
              </strong>
            </span>
            <span><small>有效处置上限</small><strong>{dispositionCeiling}</strong></span>
          </div>
        </div>

        <div className="security-execution-mode-control">
          <div>
            <span className="security-execution-mode-eyebrow">运行方式</span>
            <strong>选择所有策略允许执行到的最高级别</strong>
          </div>
          <Radio.Group
            className="security-execution-mode-options"
            aria-label="全局安全执行模式选项"
            optionType="button"
            buttonStyle="solid"
            value={mode?.configured_mode}
            disabled={disabled || mutation.isPending || isLoading}
            onChange={(event) => requestChange(event.target.value)}
            options={[{ label: '观察留痕', value: 'record' }, { label: '防护阻断', value: 'protect' }]}
          />
          <Button
            disabled={disabled || mutation.isPending || isLoading}
            loading={mutation.isPending}
            onClick={() => mode && requestChange(mode.configured_mode)}
          >
            保存当前模式
          </Button>
          <p className="security-execution-mode-control-note">
            {mode?.configured_mode === 'protect' ? '按每条策略执行告警、脱敏或阻断。' : '只检测并留证，不主动改变业务请求。'}
          </p>
        </div>
      </div>

      <div className="security-execution-mode-metrics" aria-label="策略运行统计">
        <span><small>已覆盖业务场景</small><strong>{protectedSceneCount === undefined ? '待加载' : `${protectedSceneCount} / ${totalSceneCount}`}</strong></span>
        <span><small>运行中策略项</small><strong>{runtimePolicyCount ?? '待加载'}</strong></span>
        <span><small>组织自建策略</small><strong>{tenantPolicyCount ?? '待加载'}</strong></span>
        <span><small>有效处置上限</small><Tag color={!runtimeConfirmed ? 'default' : auditCeiling ? 'gold' : 'green'}>{dispositionCeiling}</Tag></span>
      </div>

      <details className="security-execution-mode-details">
        <summary>运行与配置详情</summary>
        <div className="security-execution-mode-meta">
          <span><small>配置模式</small><strong>{securityModeLabel(mode?.configured_mode)}</strong></span>
          <span><small>配置来源</small><strong>{securityModeSourceLabel(mode?.source)}</strong></span>
          <span><small>运行回执</small><strong>{runtimeStatusLabel(mode?.runtime_status, runtimeConfirmed)}</strong></span>
          <span className="security-execution-mode-meta-wide"><small>最近修改</small><strong>{modified}</strong></span>
        </div>
      </details>

      <Modal
        open={pendingMode !== undefined}
        title={pendingMode === 'protect' ? '确认启用防护阻断' : '确认切换为观察留痕'}
        okText="确认并应用"
        cancelText="取消"
        confirmLoading={mutation.isPending}
        okButtonProps={{ danger: pendingMode === 'protect', disabled: changeReason.trim().length === 0 }}
        onCancel={() => { if (!mutation.isPending) { setPendingMode(undefined); setChangeReason('') } }}
        onOk={() => !disabled && !mutation.isPending && pendingMode && changeReason.trim() && mutation.mutate({ mode: pendingMode, reason: changeReason.trim() })}
      >
        <div className="security-mode-confirmation">
          <div className="security-mode-change-summary">
            <span><small>当前模式</small><strong>{securityModeLabel(mode?.configured_mode)}</strong></span>
            <span aria-hidden="true">→</span>
            <span><small>目标模式</small><strong>{securityModeLabel(pendingMode)}</strong></span>
          </div>
          <Alert
            type={pendingMode === 'protect' ? 'warning' : 'info'}
            showIcon
            message={pendingMode === 'protect'
              ? blockingPolicyCount ? `${blockingPolicyCount} 条已启用策略可能执行脱敏或阻断` : '已启用策略将按保存动作执行'
              : '主动处置将停止，策略配置与审计证据会继续保留'}
            description={pendingMode === 'protect'
              ? '命中策略的业务请求可能被脱敏、要求人工确认或阻断。保存后覆盖安装时的初始模式，以运行回执确认生效。'
              : '保存后覆盖安装时的初始模式，等待运行回执确认生效。切换不会删除任何策略。'}
          />
          <label htmlFor="security-mode-change-reason">变更原因</label>
          <TextArea
            id="security-mode-change-reason"
            aria-label="变更原因"
            value={changeReason}
            maxLength={500}
            showCount
            rows={3}
            placeholder="填写变更单、演练或业务原因"
            onChange={(event) => setChangeReason(event.target.value)}
          />
        </div>
      </Modal>
    </section>
  )
}

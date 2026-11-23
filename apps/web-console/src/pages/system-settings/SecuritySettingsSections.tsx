import type { ReactNode } from 'react'
import { Alert, Button, Divider, Form, InputNumber, Select, Switch, Typography } from 'antd'
import { securitySystemSettingsApi } from '../../services/api'
import { useSettingsForm } from '../../hooks/useSettingsForm'
import { DEFAULT_CONFIDENCE_THRESHOLD, OUTPUT_STRICT_MAX_BYTES } from '../../utils/securityLimits'
import { settingBool, settingChoice, settingList, settingNumber } from '../../utils/settingsValue'

const { Text } = Typography

const OPEN_CLOSED = [
  { value: 'open', label: '放行并告警' },
  { value: 'closed', label: '拦截' },
]

type FailureValues = {
  guardrail_fail_closed_enabled: 'open' | 'closed'
  security_capacity_fail_mode: 'open' | 'closed'
  mcp_policy_fail_mode: 'open' | 'closed'
  retention_failure_mode: 'open' | 'closed'
}

type DetectionValues = {
  output_security_mode: 'stream_enforce' | 'strict_buffered' | 'stream_audit'
  output_strict_max_bytes?: number
  confidence_gating_enabled: boolean
  confidence_threshold?: number
  semantic_block_stages: string[]
  agent_security_monitor_disposition: 'observe' | 'follow_policy'
}

const openClosed = (value: unknown) => settingChoice(value, ['open', 'closed'] as const, 'open')

function failureValues(settings: Record<string, unknown>): FailureValues {
  return {
    guardrail_fail_closed_enabled: settingBool(settings.guardrail_fail_closed_enabled) ? 'closed' : 'open',
    security_capacity_fail_mode: openClosed(settings.security_capacity_fail_mode),
    mcp_policy_fail_mode: openClosed(settings.mcp_policy_fail_mode),
    retention_failure_mode: openClosed(settings.retention_failure_mode),
  }
}

function detectionValues(settings: Record<string, unknown>): DetectionValues {
  const stages = settingList(settings.semantic_block_stages).filter((stage) => ['input', 'output', 'agent'].includes(stage))
  return {
    output_security_mode: settingChoice(settings.output_security_mode, ['stream_enforce', 'strict_buffered', 'stream_audit'] as const, 'stream_enforce'),
    output_strict_max_bytes: settingNumber(settings.output_strict_max_bytes),
    // 键缺失时与后端默认一致：门控开、阈值 0.55。
    confidence_gating_enabled: settingBool(settings.confidence_gating_enabled, true),
    confidence_threshold: settingNumber(settings.confidence_threshold) ?? DEFAULT_CONFIDENCE_THRESHOLD,
    semantic_block_stages: settings.semantic_block_stages === undefined || settings.semantic_block_stages === '' ? ['input'] : stages,
    agent_security_monitor_disposition: settingChoice(settings.agent_security_monitor_disposition, ['observe', 'follow_policy'] as const, 'observe'),
  }
}

// 平台级安全键走安全设置接口（平台管理员与平台级安全员可写，服务端按白名单校验）。
const saveSecuritySettings = (patch: Record<string, unknown>) => securitySystemSettingsApi.update(patch)

function Section({ title, label, children }: { title: string; label: string; children: ReactNode }) {
  return (
    <section aria-label={label}>
      <Divider style={{ margin: '20px 0' }} />
      <Text strong style={{ display: 'block', marginBottom: 12, color: 'var(--text-primary)' }}>{title}</Text>
      {children}
    </section>
  )
}

const failurePatch = (values: FailureValues) => ({
  guardrail_fail_closed_enabled: values.guardrail_fail_closed_enabled === 'closed',
  security_capacity_fail_mode: values.security_capacity_fail_mode,
  mcp_policy_fail_mode: values.mcp_policy_fail_mode,
  retention_failure_mode: values.retention_failure_mode,
})

export function FailureHandlingSettings({ canManage }: { canManage: boolean }) {
  const { form, query, mutation, submit } = useSettingsForm({ toValues: failureValues, toPatch: failurePatch, save: saveSecuritySettings })
  const disabled = !canManage || !query.isSuccess || mutation.isPending
  const rows: Array<{ name: keyof FailureValues; label: string }> = [
    { name: 'guardrail_fail_closed_enabled', label: '安全检测不可用' },
    { name: 'security_capacity_fail_mode', label: '检测排队已满' },
    { name: 'mcp_policy_fail_mode', label: 'MCP 策略读取失败' },
    { name: 'retention_failure_mode', label: '日志留存不可用' },
  ]
  return (
    <Section title="故障处理" label="故障处理">
      {query.isError ? <Alert type="error" showIcon message="故障处理读取失败" style={{ marginBottom: 12 }} /> : null}
      <Form form={form} layout="vertical" disabled={disabled} initialValues={failureValues({})} onFinish={submit}>
        {rows.map(({ name, label }) => (
          <Form.Item key={name} name={name} label={label}>
            <Select aria-label={label} options={OPEN_CLOSED} style={{ width: 200 }} />
          </Form.Item>
        ))}
        <Button htmlType="submit" type="primary" disabled={disabled} loading={mutation.isPending}>保存故障处理</Button>
      </Form>
    </Section>
  )
}

const detectionPatch = (values: DetectionValues) => {
  const patch: Record<string, unknown> = {
    output_security_mode: values.output_security_mode,
    confidence_gating_enabled: Boolean(values.confidence_gating_enabled),
    semantic_block_stages: JSON.stringify(values.semantic_block_stages ?? []),
    agent_security_monitor_disposition: values.agent_security_monitor_disposition,
  }
  if (values.output_strict_max_bytes !== undefined && values.output_strict_max_bytes !== null) patch.output_strict_max_bytes = Number(values.output_strict_max_bytes)
  if (values.confidence_threshold !== undefined && values.confidence_threshold !== null) patch.confidence_threshold = Number(values.confidence_threshold)
  return patch
}

export function DetectionExecutionSettings({ canManage }: { canManage: boolean }) {
  const { form, query, mutation, submit } = useSettingsForm({ toValues: detectionValues, toPatch: detectionPatch, save: saveSecuritySettings })
  const disabled = !canManage || !query.isSuccess || mutation.isPending
  const outputMode = Form.useWatch('output_security_mode', form)
  const gating = Form.useWatch('confidence_gating_enabled', form)
  return (
    <Section title="检测执行" label="检测执行">
      {query.isError ? <Alert type="error" showIcon message="检测执行读取失败" style={{ marginBottom: 12 }} /> : null}
      <Form form={form} layout="vertical" disabled={disabled} initialValues={detectionValues({})} onFinish={submit}>
        <Form.Item name="output_security_mode" label="模型输出检测">
          <Select
            aria-label="模型输出检测"
            style={{ width: 200 }}
            options={[
              { value: 'stream_enforce', label: '流式执行' },
              { value: 'strict_buffered', label: '缓冲严格' },
              { value: 'stream_audit', label: '只审计' },
            ]}
          />
        </Form.Item>
        {outputMode === 'strict_buffered' ? (
          <Form.Item name="output_strict_max_bytes" label="缓冲上限（字节）" rules={[{ type: 'number', min: OUTPUT_STRICT_MAX_BYTES.min, max: OUTPUT_STRICT_MAX_BYTES.max, message: `需在 ${OUTPUT_STRICT_MAX_BYTES.min} 到 ${OUTPUT_STRICT_MAX_BYTES.max} 之间` }]}>
            <InputNumber aria-label="缓冲上限（字节）" precision={0} style={{ width: 200 }} />
          </Form.Item>
        ) : null}
        <Form.Item name="semantic_block_stages" label="智能分析可拦截的阶段" rules={[{ type: 'array', min: 1, message: '至少选一个阶段' }]}>
          <Select
            aria-label="智能分析可拦截的阶段"
            mode="multiple"
            style={{ maxWidth: 360 }}
            options={[{ value: 'input', label: '输入' }, { value: 'output', label: '输出' }, { value: 'agent', label: '智能体' }]}
          />
        </Form.Item>
        <Form.Item name="confidence_gating_enabled" label="低置信度降为告警" valuePropName="checked">
          <Switch aria-label="低置信度降为告警" />
        </Form.Item>
        {gating ? (
          <Form.Item name="confidence_threshold" label="置信度阈值" rules={[{ type: 'number', min: 0, max: 1, message: '需在 0 到 1 之间' }]}>
            <InputNumber aria-label="置信度阈值" min={0} max={1} step={0.05} style={{ width: 200 }} />
          </Form.Item>
        ) : null}
        <Form.Item name="agent_security_monitor_disposition" label="智能体安全监测">
          <Select aria-label="智能体安全监测" style={{ width: 200 }} options={[{ value: 'observe', label: '只留证' }, { value: 'follow_policy', label: '按策略' }]} />
        </Form.Item>
        <Button htmlType="submit" type="primary" disabled={disabled} loading={mutation.isPending}>保存检测执行</Button>
      </Form>
    </Section>
  )
}

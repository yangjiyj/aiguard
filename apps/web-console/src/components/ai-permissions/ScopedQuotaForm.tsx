import { useEffect } from 'react'
import { Alert, AutoComplete, Card, Form, InputNumber, Select, Button, Tag, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { TwoDecimalStringInput } from '../billing/TwoDecimalInput'
import { policyApi } from '../../services/api'
import { useAuthStore } from '../../stores/auth'
import { useCurrencyStore } from '../../stores/currency'
import { currencyUnitSuffix } from '../../utils/currencyUnit'
import {
  cnyStringToMicros,
  MAX_BUDGET_CNY,
  MAX_SAFE_QUOTA_INTEGER,
  microsToCNYString,
} from './quotaValues'

export type QuotaScopeType = 'tenant' | 'team' | 'project' | 'user' | 'key'
type QuotaMode = 'inherit' | 'unlimited' | 'limit' | 'blocked'
type OverageAction = 'notify' | 'rate_limit'

const OVERAGE_OPTIONS = [
  { value: 'notify', label: '仅提醒' },
  { value: 'rate_limit', label: '限速' },
]
const ENFORCEMENT_OPTIONS = [
  { value: 'soft', label: '软约束（仅记录）' },
  { value: 'enforce', label: '强制' },
  { value: 'bypass', label: '旁路' },
]
const QUOTA_TIMEZONE_OPTIONS = [
  { value: 'Asia/Shanghai', label: 'Asia/Shanghai（中国标准时间）' },
  { value: 'UTC', label: 'UTC' },
  { value: 'Asia/Hong_Kong', label: 'Asia/Hong_Kong' },
  { value: 'Asia/Singapore', label: 'Asia/Singapore' },
  { value: 'Europe/London', label: 'Europe/London' },
  { value: 'America/Los_Angeles', label: 'America/Los_Angeles' },
]
const ALLOWED_OVERAGE: OverageAction[] = ['notify', 'rate_limit']
const normalizeOverageAction = (value?: string): OverageAction =>
  value && (ALLOWED_OVERAGE as string[]).includes(value) ? value as OverageAction : 'notify'

const hasOwn = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key)

function countMode(limit: unknown, blocked: unknown): QuotaMode {
  if (blocked === true) return 'blocked'
  if (limit === null || limit === undefined) return 'inherit'
  return Number(limit) === 0 ? 'unlimited' : 'limit'
}

function moneyState(data: Record<string, any>, period: 'daily' | 'monthly'): { mode: QuotaMode; cny: string } {
  const blockedKey = period + '_budget_blocked'
  const microsKey = period + '_budget_micros'
  const legacyKey = period + '_budget_limit'
  if (data[blockedKey] === true) return { mode: 'blocked', cny: '' }

  if (hasOwn(data, microsKey)) {
    const micros = data[microsKey]
    if (micros === null || micros === undefined) return { mode: 'inherit', cny: '' }
    if (Number(micros) === 0) return { mode: 'unlimited', cny: '' }
    return { mode: 'limit', cny: microsToCNYString(micros) }
  }

  const legacy = data[legacyKey]
  if (legacy === null || legacy === undefined) return { mode: 'inherit', cny: '' }
  try {
    const micros = cnyStringToMicros(String(legacy))
    return micros === 0
      ? { mode: 'unlimited', cny: '' }
      : { mode: 'limit', cny: microsToCNYString(micros) }
  } catch {
    return { mode: 'inherit', cny: '' }
  }
}

function moneyPayload(mode: QuotaMode, cny: unknown): { micros: number | null; blocked: boolean } {
  if (mode === 'blocked') return { micros: null, blocked: true }
  if (mode === 'inherit') return { micros: null, blocked: false }
  if (mode === 'unlimited') return { micros: 0, blocked: false }
  const micros = cnyStringToMicros(cny)
  if (micros <= 0) throw new Error('限额必须大于 0')
  return { micros, blocked: false }
}

function countPayload(mode: QuotaMode, value: unknown): { limit: number | null; blocked: boolean } {
  if (mode === 'blocked') return { limit: null, blocked: true }
  if (mode === 'inherit') return { limit: null, blocked: false }
  if (mode === 'unlimited') return { limit: 0, blocked: false }
  const limit = Number(value)
  if (!Number.isSafeInteger(limit) || limit <= 0) throw new Error('限额必须为正整数')
  return { limit, blocked: false }
}

function unwrapResponse(response: any): any {
  const body = response?.data
  return body?.data ?? body
}

export function ScopedQuotaForm({
  scopeType,
  scopeId,
  readOnly = false,
  budgetReadOnly = false,
}: {
  scopeType: QuotaScopeType
  scopeId: string
  readOnly?: boolean
  // 组织/部门的月预算只在“钱包与限流”页的预算树里改：这里只读展示，保存时原值回写。
  budgetReadOnly?: boolean
}) {
  const [form] = Form.useForm()
  const queryClient = useQueryClient()
  const currentUser = useAuthStore((state) => state.user)
  const unitSuffix = currencyUnitSuffix(useCurrencyStore((state) => state.tenantCurrency))
  const identityKey = currentUser?.tenant_id + ':' + currentUser?.id
  const enabled = scopeType === 'tenant' || !!scopeId

  const dailyTokenMode = Form.useWatch('daily_token_mode', form)
  const monthlyTokenMode = Form.useWatch('monthly_token_mode', form)
  const dailyBudgetMode = Form.useWatch('daily_budget_mode', form)
  const monthlyBudgetMode = Form.useWatch('monthly_budget_mode', form)
  const rpmMode = Form.useWatch('rpm_mode', form)
  const tpmMode = Form.useWatch('tpm_mode', form)
  const concurrencyMode = Form.useWatch('concurrency_mode', form)

  const quotaQueryKey = ['quota-policy', identityKey, scopeType, scopeId]
  const quotaQuery = useQuery({
    queryKey: quotaQueryKey,
    queryFn: () => policyApi.getQuota({
      scope_type: scopeType,
      scope_id: scopeId,
      ...(scopeType === 'project' ? { project_id: scopeId } : {}),
    }),
    enabled,
  })
  useEffect(() => {
    form.resetFields()
  }, [form, scopeType, scopeId, identityKey])

  useEffect(() => {
    const data = unwrapResponse(quotaQuery.data)
    if (!data) return
    const dailyBudget = moneyState(data, 'daily')
    const monthlyBudget = moneyState(data, 'monthly')
    form.setFieldsValue({
      daily_token_mode: countMode(data.daily_token_limit, data.daily_token_blocked),
      daily_token_limit: Number(data.daily_token_limit) > 0 ? Number(data.daily_token_limit) : undefined,
      monthly_token_mode: countMode(data.monthly_token_limit, data.monthly_token_blocked),
      monthly_token_limit: Number(data.monthly_token_limit) > 0 ? Number(data.monthly_token_limit) : undefined,
      daily_budget_mode: dailyBudget.mode,
      daily_budget_cny: dailyBudget.cny,
      monthly_budget_mode: monthlyBudget.mode,
      monthly_budget_cny: monthlyBudget.cny,
      rpm_mode: countMode(data.rpm_limit, data.rpm_blocked),
      rpm_limit: Number(data.rpm_limit) > 0 ? Number(data.rpm_limit) : undefined,
      tpm_mode: countMode(data.tpm_limit, data.tpm_blocked),
      tpm_limit: Number(data.tpm_limit) > 0 ? Number(data.tpm_limit) : undefined,
      concurrency_mode: countMode(data.concurrency_limit, data.concurrency_blocked),
      concurrency_limit: Number(data.concurrency_limit) > 0 ? Number(data.concurrency_limit) : undefined,
      overage_action: normalizeOverageAction(data.overage_action),
      enforcement_mode: data.enforcement_mode || 'soft',
      quota_timezone: data.quota_timezone || 'Asia/Shanghai',
    })
  }, [quotaQuery.data, form])

  const saveMutation = useMutation({
    mutationFn: async (values: any) => {
      const dailyToken = countPayload(values.daily_token_mode, values.daily_token_limit)
      const monthlyToken = countPayload(values.monthly_token_mode, values.monthly_token_limit)
      const dailyBudget = moneyPayload(values.daily_budget_mode, values.daily_budget_cny)
      const monthlyBudget = moneyPayload(values.monthly_budget_mode, values.monthly_budget_cny)
      const rpm = countPayload(values.rpm_mode, values.rpm_limit)
      const tpm = countPayload(values.tpm_mode, values.tpm_limit)
      const concurrency = countPayload(values.concurrency_mode, values.concurrency_limit)
      const action = normalizeOverageAction(values.overage_action)

      return policyApi.setQuota({
        scope_type: scopeType,
        scope_id: scopeId,
        project_id: scopeType === 'project' ? scopeId : '',
        daily_token_limit: dailyToken.limit,
        daily_token_blocked: dailyToken.blocked,
        monthly_token_limit: monthlyToken.limit,
        monthly_token_blocked: monthlyToken.blocked,
        daily_budget_micros: dailyBudget.micros,
        daily_budget_blocked: dailyBudget.blocked,
        monthly_budget_micros: monthlyBudget.micros,
        monthly_budget_blocked: monthlyBudget.blocked,
        rpm_limit: rpm.limit,
        rpm_blocked: rpm.blocked,
        tpm_limit: tpm.limit,
        tpm_blocked: tpm.blocked,
        concurrency_limit: concurrency.limit,
        concurrency_blocked: concurrency.blocked,
        overage_action: action,
        enforcement_mode: values.enforcement_mode || 'soft',
        quota_timezone: String(values.quota_timezone || 'Asia/Shanghai').trim(),
      })
    },
    onSuccess: () => {
      message.success('配额已保存')
      queryClient.invalidateQueries({ queryKey: quotaQueryKey })
    },
    onError: () => message.error('保存失败'),
  })

  if (!enabled) return null
  if (quotaQuery.isError) {
    return (
      <Alert
        type="error"
        showIcon
        message="配额配置加载失败"
        action={<Button onClick={() => void quotaQuery.refetch()}>重试</Button>}
      />
    )
  }

  const modeOptions = [
    { value: 'inherit', label: scopeType === 'tenant' ? '未设置' : '继承上级' },
    { value: 'unlimited', label: '本级不限' },
    { value: 'limit', label: '设置限额' },
    { value: 'blocked', label: '禁止' },
  ]
  const renderCountQuota = (
    modeName: string,
    limitName: string,
    label: string,
    mode: QuotaMode | undefined,
    max = MAX_SAFE_QUOTA_INTEGER,
  ) => (
    <>
      <Form.Item name={modeName} label={label} initialValue="inherit">
        <Select options={modeOptions} disabled={readOnly} />
      </Form.Item>
      {mode === 'limit' ? (
        <Form.Item
          name={limitName}
          label={label + '数值'}
          rules={[{ required: true, type: 'number', min: 1, max, message: '请输入有效的正整数限额' }]}
        >
          <InputNumber min={1} max={max} precision={0} disabled={readOnly} style={{ width: '100%' }} />
        </Form.Item>
      ) : null}
    </>
  )
  const renderMoneyQuota = (
    modeName: string,
    valueName: string,
    label: string,
    mode: QuotaMode | undefined,
    locked = false,
  ) => (
    <>
      <Form.Item name={modeName} label={label} initialValue="inherit" extra={locked ? '月预算请在上方预算树中修改，这里仅展示。' : undefined}>
        <Select options={modeOptions} disabled={readOnly || locked} />
      </Form.Item>
      {mode === 'limit' ? (
        <Form.Item
          name={valueName}
          label={label + unitSuffix}
          rules={[
            { required: true, message: '请输入金额限额' },
            {
              validator: async (_, value) => {
                try {
                  if (cnyStringToMicros(value) <= 0) throw new Error('限额必须大于 0')
                } catch (error) {
                  throw new Error(error instanceof Error ? error.message : '金额格式无效')
                }
              },
            },
          ]}
        >
          <TwoDecimalStringInput
            min="0.000001"
            max={MAX_BUDGET_CNY}
            disabled={readOnly || locked}
            style={{ width: '100%' }}
          />
        </Form.Item>
      ) : null}
    </>
  )

  return (
    <Card title="配额上限" extra={readOnly ? <Tag>只读</Tag> : undefined} loading={quotaQuery.isLoading}>
      <Form form={form} layout="vertical" colon={false} style={{ maxWidth: 560 }}>
        {renderCountQuota('daily_token_mode', 'daily_token_limit', '每日 Token', dailyTokenMode)}
        {renderCountQuota('monthly_token_mode', 'monthly_token_limit', '每月 Token', monthlyTokenMode)}
        {renderMoneyQuota('daily_budget_mode', 'daily_budget_cny', '日费用预算', dailyBudgetMode)}
        {renderMoneyQuota('monthly_budget_mode', 'monthly_budget_cny', '月费用预算', monthlyBudgetMode, budgetReadOnly && (scopeType === 'tenant' || scopeType === 'team'))}
        {renderCountQuota('rpm_mode', 'rpm_limit', '每分钟请求数（RPM）', rpmMode, 2_147_483_647)}
        {renderCountQuota('tpm_mode', 'tpm_limit', '每分钟 Token（TPM）', tpmMode)}
        {renderCountQuota('concurrency_mode', 'concurrency_limit', '并发请求数', concurrencyMode, 2_147_483_647)}
        <Form.Item name="overage_action" label="超额处理动作" initialValue="notify">
          <Select options={OVERAGE_OPTIONS} disabled={readOnly} />
        </Form.Item>
        <Form.Item name="enforcement_mode" label="执行模式" initialValue="soft">
          <Select options={ENFORCEMENT_OPTIONS} disabled={readOnly} />
        </Form.Item>
        <Form.Item
          name="quota_timezone"
          label="日/月周期时区"
          initialValue="Asia/Shanghai"
          rules={[
            { required: true, message: '请选择或输入 IANA 时区' },
            { max: 64, message: '时区名称最多 64 个字符' },
          ]}
        >
          <AutoComplete
            options={QUOTA_TIMEZONE_OPTIONS}
            disabled={readOnly}
            filterOption={(input, option) => String(option?.value || '').toLowerCase().includes(input.toLowerCase())}
          />
        </Form.Item>
        {!readOnly ? (
          <Form.Item>
            <Button
              type="primary"
              onClick={() => form.validateFields().then((values) => saveMutation.mutate(values))}
              loading={saveMutation.isPending}
            >
              保存配置
            </Button>
          </Form.Item>
        ) : null}
      </Form>
    </Card>
  )
}

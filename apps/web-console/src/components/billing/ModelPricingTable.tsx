import { useCurrencyStore } from '../../stores/currency'
import { formatMicrosDecimal, UNKNOWN_MONEY } from '../../utils/money'
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Checkbox,
  Form,
  Input,
  Modal,
  Segmented,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { HistoryOutlined, SaveOutlined, SearchOutlined, TagsOutlined, SettingOutlined } from '@ant-design/icons'
import ModelPricingEditor from './ModelPricingEditor'
import ModelIdentity from './ModelIdentity'
import TwoDecimalInput from './TwoDecimalInput'
import PriceChangeConfirm from './PriceChangeConfirm'
import { buildPriceChange, type PriceChange } from './priceChange'
import { billingAdminApi } from '../../services/api'
import { extractApiError } from '../../utils/apiError'
import { currencyUnitLabel } from '../../utils/currencyUnit'
import {
  MICROS_PER_YUAN,
  imageQualityLabel,
  buildPricingRows,
  directPricePayload,
  ratioPricePayload,
  type EditablePriceDraft,
  type BillingModel,
  type BillingPrice,
  type PricingMode,
  type PricingRow,
} from './modelPricing'

const { Text } = Typography

interface ModelPricingTableProps {
  tenantID: string
  models: BillingModel[]
  prices: BillingPrice[]
  loading: boolean
  onRefresh: () => void | Promise<unknown>
  // 价格列表接口返回行数达到上限时，页面顶部提示可能不完整
  historyTruncated?: boolean
  effectiveTruncated?: boolean
}

type EditableDraft = EditablePriceDraft

interface BatchResult {
  successCount: number
  unchangedCount: number
  failed: { label: string; reason?: string }[]
}

interface PendingConfirm {
  id: number
  changes: PriceChange[]
  resolve: (confirmed: boolean) => void
}

// 后端对「非零价格改成 0」要求带 confirm_zero_price；前端手里的当前价过期或不全时没带，会收到 409。
const isZeroConfirmationRequired = (error: unknown) => (
  (error as { response?: { data?: { error?: { code?: unknown } } } } | undefined)?.response?.data?.error?.code === 'price_zero_confirmation_required'
)
const UNREADABLE_PRICE = '无法读取当前价格，请刷新页面后重试'
const CANCELLED_ZERO = '已取消清零确认'

interface ZeroConflictItem {
  row: PricingRow
  mode: PricingMode
  payload: Record<string, unknown>
  error: unknown
}
interface ZeroConflictResult {
  row: PricingRow
  status: 'saved' | 'cancelled' | 'failed'
  reason?: string
  response?: unknown
}

const savedNotice = (label: string, response: unknown) => (
  (response as { data?: { data?: { unchanged?: boolean } } } | undefined)?.data?.data?.unchanged === true
    ? `${label} 价格没有变化，未新增版本`
    : `${label} 定价已保存`
)

const hasChinese = (value: unknown): value is string => typeof value === 'string' && /[\u4e00-\u9fff]/.test(value)
const failureReason = (error: unknown) => (
  extractApiError(error) || (error instanceof Error && hasChinese(error.message) ? error.message : undefined)
)

const yuanFromMicros = (value?: number) => (
  typeof value === 'number' ? value / MICROS_PER_YUAN : null
)

const ratioFromPPM = (value?: number) => (
  typeof value === 'number' ? value / MICROS_PER_YUAN : null
)

const draftFromRow = (row: PricingRow): EditableDraft => {
  const price = row.current
  if (!price) {
    return {
      currency: useCurrencyStore.getState().tenantCurrency, pricingExtras: {},
      sourcePriceID: null,
      mode: 'direct',
      inputPerMillionYuan: null,
      outputPerMillionYuan: null,
      cachedInputPerMillionYuan: null,
      cacheWritePerMillionYuan: null,
      baseInputPerMillionYuan: null,
      modelRatio: 1,
      completionRatio: 1,
      cachedInputRatio: null,
      cacheWriteRatio: null,
    }
  }
  return {
    currency: price.currency ?? useCurrencyStore.getState().tenantCurrency, pricingExtras: price.pricing_extras ?? {},
    sourcePriceID: price.id,
    mode: price.pricing_mode,
    inputPerMillionYuan: yuanFromMicros(price.input_per_million_micros),
    outputPerMillionYuan: yuanFromMicros(price.output_per_million_micros),
    cachedInputPerMillionYuan: price.has_cached_input_price
      ? yuanFromMicros(price.cached_input_per_million_micros)
      : null,
    cacheWritePerMillionYuan: price.has_cache_write_price
      ? yuanFromMicros(price.cache_write_per_million_micros)
      : null,
    baseInputPerMillionYuan: yuanFromMicros(price.base_input_per_million_micros),
    modelRatio: ratioFromPPM(price.model_ratio_ppm) ?? 1,
    completionRatio: ratioFromPPM(price.completion_ratio_ppm) ?? 1,
    cachedInputRatio: price.has_cached_input_ratio ? ratioFromPPM(price.cached_input_ratio_ppm) : null,
    cacheWriteRatio: price.has_cache_write_ratio ? ratioFromPPM(price.cache_write_ratio_ppm) : null,
  }
}

const validNumber = (value: number | null): value is number => (
  typeof value === 'number' && Number.isFinite(value) && value >= 0
)

const formatMicros = (value?: number, currency: string = useCurrencyStore.getState().tenantCurrency, quantity = 1) => `${currency === 'USD' ? '$' : '¥'}${formatMicrosDecimal(value ?? 0, { quantity }) ?? UNKNOWN_MONEY}`
const unit = (currency: string) => currencyUnitLabel(currency)

const historyPrice = (price: BillingPrice) => {
  if (price.pricing_extras?.image_pricing?.mode === 'per_image') {
    const variants = price.pricing_extras.image_pricing.variants ?? []
    return `按张生图 · ${variants.length} 个尺寸与质量价格`
  }
  return price.pricing_mode === 'newapi_ratio'
    ? `基础 ${formatMicros(price.base_input_per_million_micros, price.currency)} · 模型 ${ratioFromPPM(price.model_ratio_ppm)?.toFixed(2) ?? '-'}× · 输出 ${ratioFromPPM(price.completion_ratio_ppm)?.toFixed(2) ?? '-'}×`
    : `输入 ${formatMicros(price.input_per_million_micros, price.currency)} · 输出 ${formatMicros(price.output_per_million_micros, price.currency)}`
}

export default function ModelPricingTable({
  tenantID,
  models,
  prices,
  loading,
  onRefresh,
  historyTruncated = false,
  effectiveTruncated = false,
}: ModelPricingTableProps) {
  const rows = useMemo(() => buildPricingRows(models, prices, new Date()), [models, prices])
  const [search, setSearch] = useState('')
  const [onlyUnconfigured, setOnlyUnconfigured] = useState(false)
  const [drafts, setDrafts] = useState<Record<string, EditableDraft>>({})
  const [savingKeys, setSavingKeys] = useState<Set<string>>(new Set())
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set())
  const [historyRow, setHistoryRow] = useState<PricingRow | null>(null)
  const [batchOpen, setBatchOpen] = useState(false)
  const [batchMode, setBatchMode] = useState<PricingMode>('direct')
  const [batchSaving, setBatchSaving] = useState(false)
  const [batchResult, setBatchResult] = useState<BatchResult | null>(null)
  const [saveNotice, setSaveNotice] = useState('')
  const [pendingConfirm, setPendingConfirm] = useState<PendingConfirm | null>(null)
  const confirmSeq = useRef(0)
  const [batchForm] = Form.useForm()

  useEffect(() => {
    setDrafts((previous) => {
      const next: Record<string, EditableDraft> = {}
      rows.forEach((row) => {
        const existing = previous[row.key]
        next[row.key] = existing?.sourcePriceID === (row.current?.id ?? null)
          ? existing
          : draftFromRow(row)
      })
      return next
    })
    setSelectedKeys((previous) => new Set([...previous].filter((key) => rows.some((row) => row.key === key))))
  }, [rows])

  const filteredRows = useMemo(() => {
    const keyword = search.trim().toLocaleLowerCase()
    return rows.filter((row) => {
      if (onlyUnconfigured && row.configured) return false
      if (!keyword) return true
      return [row.modelName, row.modelLabel, row.providerName]
        .some((value) => value.toLocaleLowerCase().includes(keyword))
    })
  }, [onlyUnconfigured, rows, search])

  const draftFor = (row: PricingRow) => drafts[row.key] ?? draftFromRow(row)
  const updateDraft = (row: PricingRow, values: Partial<EditableDraft>) => {
    setDrafts((previous) => ({
      ...previous,
      [row.key]: { ...(previous[row.key] ?? draftFromRow(row)), ...values },
    }))
  }

  const [advancedRow, setAdvancedRow] = useState<PricingRow | null>(null)
  const [batchCurrency, setBatchCurrency] = useState(useCurrencyStore.getState().tenantCurrency)

  // 写入前展示「旧值 → 新值」，用户确认才继续；取消返回 false。
  const askConfirm = (changes: PriceChange[]) => new Promise<boolean>((resolve) => {
    confirmSeq.current += 1
    setPendingConfirm({ id: confirmSeq.current, changes, resolve })
  })
  const settleConfirm = (confirmed: boolean) => {
    pendingConfirm?.resolve(confirmed)
    setPendingConfirm(null)
  }

  // 只有「改成 0」的提交才附带 confirm_zero_price，其他提交的 payload 里不出现这个键。
  const withZeroConfirmation = (payload: Record<string, unknown>, change: PriceChange) => (
    change.toZero ? { ...payload, confirm_zero_price: true } : payload
  )
  const submitPrice = (mode: PricingMode, payload: Record<string, unknown>) => (
    mode === 'newapi_ratio' ? billingAdminApi.createRatioPrice(payload) : billingAdminApi.createPrice(payload)
  )

  // 重新读取某个模型当前生效的价格（只取 default 客户组）；读取失败直接抛出。
  const readEffectivePrice = async (modelName: string): Promise<BillingPrice | null> => {
    const response = await billingAdminApi.prices(tenantID, { scope: 'effective', model_name: modelName, limit: 20 })
    const data = response?.data?.data
    const list: BillingPrice[] = Array.isArray(data) ? data : []
    return list
      .filter((price) => price.model_name === modelName && (!price.customer_group || price.customer_group === 'default'))
      .sort((left, right) => right.version - left.version)[0] ?? null
  }

  // 后端 409 price_zero_confirmation_required：前端手里的「当前价」过期或不全，提交时没带确认标志。
  // 重读各行当前生效价并刷新表格；仍然是「非零 → 0」的行合并成一个确认框，确认后带标志重发，取消则不发。
  const resolveZeroConflicts = async (items: ZeroConflictItem[]): Promise<ZeroConflictResult[]> => {
    const reads = await Promise.allSettled(items.map((item) => readEffectivePrice(item.row.modelName)))
    try {
      await onRefresh()
    } catch {
      // 刷新失败不影响本次确认流程，各行结果会单独汇报
    }
    const results: ZeroConflictResult[] = items.map((item) => ({ row: item.row, status: 'failed' as const }))
    const confirmable: { index: number; change: PriceChange }[] = []
    items.forEach((item, index) => {
      const read = reads[index]
      if (read.status === 'rejected') {
        results[index] = { row: item.row, status: 'failed', reason: UNREADABLE_PRICE }
        return
      }
      const change = buildPriceChange(item.row.modelName, item.row.modelLabel, read.value, item.payload)
      if (!change.toZero) {
        // 重读后并不是清零，说明状态已变：给出后端原因，不重发
        results[index] = { row: item.row, status: 'failed', reason: failureReason(item.error) }
        return
      }
      confirmable.push({ index, change })
    })
    if (confirmable.length === 0) return results
    if (!(await askConfirm(confirmable.map(({ change }) => change)))) {
      confirmable.forEach(({ index }) => { results[index] = { row: items[index].row, status: 'cancelled', reason: CANCELLED_ZERO } })
      return results
    }
    const resent = await Promise.allSettled(confirmable.map(({ index }) => (
      submitPrice(items[index].mode, { ...items[index].payload, confirm_zero_price: true })
    )))
    resent.forEach((outcome, position) => {
      const { index } = confirmable[position]
      results[index] = outcome.status === 'fulfilled'
        ? { row: items[index].row, status: 'saved', response: outcome.value }
        : { row: items[index].row, status: 'failed', reason: failureReason(outcome.reason) }
    })
    return results
  }

  const saveRow = async (row: PricingRow, overrides: Partial<EditableDraft> = {}): Promise<boolean> => {
    const draft = { ...draftFor(row), ...overrides }
    let payload: Record<string, unknown>
    try {
      if (draft.mode === 'newapi_ratio') {
        if (!validNumber(draft.baseInputPerMillionYuan)
          || !validNumber(draft.modelRatio)
          || !validNumber(draft.completionRatio)) {
          message.error('请填写完整的基础输入单价和倍率')
          return false
        }
        payload = ratioPricePayload(tenantID, row.modelName, {
          currency: draft.currency, pricingExtras: draft.pricingExtras,
          baseInputPerMillionYuan: draft.baseInputPerMillionYuan,
          modelRatio: draft.modelRatio,
          completionRatio: draft.completionRatio,
          cachedInputRatio: draft.cachedInputRatio,
          cacheWriteRatio: draft.cacheWriteRatio,
        })
      } else {
        if (!validNumber(draft.inputPerMillionYuan) || !validNumber(draft.outputPerMillionYuan)) {
          message.error('请填写完整的输入和输出单价')
          return false
        }
        payload = directPricePayload(tenantID, row.modelName, {
          currency: draft.currency, pricingExtras: draft.pricingExtras,
          inputPerMillionYuan: draft.inputPerMillionYuan,
          outputPerMillionYuan: draft.outputPerMillionYuan,
          cachedInputPerMillionYuan: draft.cachedInputPerMillionYuan,
          cacheWritePerMillionYuan: draft.cacheWritePerMillionYuan,
        })
      }
    } catch (error) {
      message.error(error instanceof Error ? error.message : '定价参数无效')
      return false
    }

    // 有变化先确认；没有变化直接提交（后端幂等返回 unchanged，不新增版本）。
    const change = buildPriceChange(row.modelName, row.modelLabel, row.current, payload)
    if (change.changed && !(await askConfirm([change]))) return false

    setSavingKeys((previous) => new Set(previous).add(row.key))
    try {
      let response: unknown
      try {
        response = await submitPrice(draft.mode, withZeroConfirmation(payload, change))
      } catch (error) {
        if (!isZeroConfirmationRequired(error) || change.toZero) throw error
        const [result] = await resolveZeroConflicts([{ row, mode: draft.mode, payload, error }])
        if (result.status === 'cancelled') return false
        if (result.status === 'failed') {
          message.error(result.reason || `${row.modelLabel} 定价保存失败`)
          return false
        }
        response = result.response
      }
      setSaveNotice(savedNotice(row.modelLabel, response))
      await onRefresh()
      return true
    } catch (error) {
      message.error(extractApiError(error) || `${row.modelLabel} 定价保存失败`)
      return false
    } finally {
      setSavingKeys((previous) => {
        const next = new Set(previous)
        next.delete(row.key)
        return next
      })
    }
  }

  const openBatch = () => {
    setBatchResult(null)
    setBatchMode('direct')
    batchForm.resetFields()
    batchForm.setFieldsValue({ mode: 'direct', model_ratio: 1, completion_ratio: 1 })
    setBatchOpen(true)
  }

  const applyBatch = async (values: Record<string, number | PricingMode | null>) => {
    const targets = rows.filter((row) => selectedKeys.has(row.key))
    setBatchSaving(true)
    try {
      // 每行独立构造 payload：某一行参数非法只让该行失败，不拖垮整批，也不让弹窗卡死。
      const built: { row: PricingRow; payload: Record<string, unknown>; change: PriceChange }[] = []
      const failed: { row: PricingRow; reason?: string }[] = []
      targets.forEach((row) => {
        try {
          const payload = batchMode === 'newapi_ratio'
            ? ratioPricePayload(tenantID, row.modelName, {
              currency: batchCurrency, pricingExtras: draftFor(row).pricingExtras,
              baseInputPerMillionYuan: Number(values.base_input_per_million_yuan),
              modelRatio: Number(values.model_ratio),
              completionRatio: Number(values.completion_ratio),
              cachedInputRatio: values.cached_input_ratio == null ? null : Number(values.cached_input_ratio),
              cacheWriteRatio: values.cache_write_ratio == null ? null : Number(values.cache_write_ratio),
            })
            : directPricePayload(tenantID, row.modelName, {
              currency: batchCurrency, pricingExtras: draftFor(row).pricingExtras,
              inputPerMillionYuan: Number(values.input_per_million_yuan),
              outputPerMillionYuan: Number(values.output_per_million_yuan),
              cachedInputPerMillionYuan: values.cached_input_per_million_yuan == null
                ? null
                : Number(values.cached_input_per_million_yuan),
              cacheWritePerMillionYuan: values.cache_write_per_million_yuan == null
                ? null
                : Number(values.cache_write_per_million_yuan),
            })
          built.push({ row, payload, change: buildPriceChange(row.modelName, row.modelLabel, row.current, payload) })
        } catch (error) {
          failed.push({ row, reason: failureReason(error) || '定价参数无效' })
        }
      })

      const writes = built.filter(({ change }) => change.changed)
      if (writes.length > 0 && !(await askConfirm(built.map(({ change }) => change)))) return
      if (writes.length === 0 && failed.length === 0) {
        setSaveNotice('所选模型的价格都没有变化，未新增版本')
        setBatchOpen(false)
        return
      }

      const settled = await Promise.allSettled(writes.map(({ payload, change }) => (
        submitPrice(batchMode, withZeroConfirmation(payload, change))
      )))
      const rejected = writes.flatMap((write, index) => (
        settled[index].status === 'rejected'
          ? [{ ...write, error: (settled[index] as PromiseRejectedResult).reason as unknown }]
          : []
      ))
      // 被 409 清零拦下的行集中处理：一次性重读当前价、合并成一个确认框，确认后只重发这些行。
      const conflicts = rejected.filter(({ error }) => isZeroConfirmationRequired(error))
      const otherFailures = rejected
        .filter(({ error }) => !isZeroConfirmationRequired(error))
        .map(({ row, error }) => ({ row, reason: failureReason(error) }))
      let recovered = 0
      const conflictFailures: { row: PricingRow; reason?: string }[] = []
      if (conflicts.length > 0) {
        const results = await resolveZeroConflicts(conflicts.map(({ row, payload, error }) => ({ row, mode: batchMode, payload, error })))
        results.forEach((result) => {
          if (result.status === 'saved') recovered += 1
          else conflictFailures.push({ row: result.row, reason: result.reason })
        })
      }
      const allFailed = [...failed, ...otherFailures, ...conflictFailures]
      const succeeded = writes.length - rejected.length + recovered
      setSelectedKeys(new Set(allFailed.map(({ row }) => row.key)))
      setBatchResult({
        successCount: succeeded,
        unchangedCount: built.length - writes.length,
        failed: allFailed.map(({ row, reason }) => ({ label: row.modelLabel, reason })),
      })
      setBatchOpen(false)
      if (succeeded) await onRefresh()
    } finally {
      setBatchSaving(false)
    }
  }

  const visibleKeys = filteredRows.map((row) => row.key)
  const allVisibleSelected = visibleKeys.length > 0 && visibleKeys.every((key) => selectedKeys.has(key))
  const someVisibleSelected = visibleKeys.some((key) => selectedKeys.has(key))

  const columns: ColumnsType<PricingRow> = [
    {
      title: <Checkbox
        aria-label="选择当前结果"
        checked={allVisibleSelected}
        indeterminate={!allVisibleSelected && someVisibleSelected}
        onChange={(event) => setSelectedKeys((previous) => {
          const next = new Set(previous)
          visibleKeys.forEach((key) => event.target.checked ? next.add(key) : next.delete(key))
          return next
        })}
      />,
      width: 48,
      fixed: 'left',
      render: (_, row) => <Checkbox
        aria-label={`选择 ${row.modelLabel}`}
        checked={selectedKeys.has(row.key)}
        onChange={(event) => setSelectedKeys((previous) => {
          const next = new Set(previous)
          event.target.checked ? next.add(row.key) : next.delete(row.key)
          return next
        })}
      />,
    },
    {
      title: '模型',
      key: 'model',
      width: 210,
      fixed: 'left',
      render: (_, row) => <Space direction="vertical" size={2}>
        <ModelIdentity modelName={row.modelName} label={row.modelLabel} strong />
        <Text type="secondary" style={{ fontSize: 12 }}>{row.providerName}</Text>
      </Space>,
    },
    {
      title: '计费方式 / 币种', key: 'kind', width: 180,
      render: (_, row) => {
        const draft = draftFor(row)
        const extras = draft.pricingExtras
        const image = extras.image_pricing?.mode === 'per_image'
        const legacy = !extras.image_pricing && (extras.image_per_image_micros !== undefined || extras.newapi_fixed_quantity !== undefined)
        const multimodal = extras.image_input_per_million_micros != null || extras.image_output_per_million_micros != null || extras.cached_image_input_per_million_micros != null
        return <Space direction="vertical" size={2}>
          <Tag color={legacy ? 'default' : image ? 'purple' : multimodal ? 'cyan' : 'blue'}>{legacy ? '沿用旧配置' : image ? '按张生图' : multimodal ? '多模态 Token' : 'Token'}</Tag>
          <Text type="secondary">{draft.currency === 'USD' ? '美元 USD' : '人民币 CNY'} · {draft.mode === 'newapi_ratio' ? '倍率' : '直接单价'}</Text>
        </Space>
      },
    },
    {
      title: '当前价格', key: 'price', width: 280,
      render: (_, row) => {
        const draft = draftFor(row)
        if (!row.current) return <Text type="secondary">点击配置填写价格</Text>
        const extras = draft.pricingExtras
        if (extras.image_pricing?.mode === 'per_image') {
          const variants = extras.image_pricing.variants ?? []
          return <Space direction="vertical" size={2}>
            <Text>{variants.length} 个尺寸与质量价格</Text>
            {variants.slice(0, 2).map((variant) => {
              const quantity = variant.price_per_image_micros > 0 && variant.price_per_image_micros < 10000 ? 1000 : 1
              return <Text type="secondary" key={`${variant.size}/${variant.quality}`}>{variant.size === '*' ? '任意尺寸' : variant.size} / {variant.quality === '*' ? '任意质量' : imageQualityLabel(variant.quality)}：{formatMicros(variant.price_per_image_micros, draft.currency, quantity)}/{quantity === 1 ? '张' : '1000 张'}</Text>
            })}
          </Space>
        }
        if (!extras.image_pricing && (extras.image_per_image_micros || extras.newapi_fixed_quantity)) {
          return <Space direction="vertical" size={2}>
            <Text>{historyPrice(row.current)} / 百万 Token</Text>
            <Text type="secondary">{extras.newapi_fixed_quantity ? `固定 ${formatMicros(extras.request_per_call_micros, draft.currency, 1000)}/千个原计价单位` : `每张附加 ${formatMicros(extras.image_per_image_micros, draft.currency, 1000)}/1000 张`}</Text>
          </Space>
        }
        return <Space direction="vertical" size={2}>
          <Text>{historyPrice(row.current)} / 百万 Token</Text>
          {(extras.image_input_per_million_micros != null || extras.image_output_per_million_micros != null) && <Text type="secondary">图像输入 {extras.image_input_per_million_micros == null ? '随文本价' : formatMicros(extras.image_input_per_million_micros, draft.currency)} · 图像输出 {extras.image_output_per_million_micros == null ? '随输出价' : formatMicros(extras.image_output_per_million_micros, draft.currency)}</Text>}
        </Space>
      },
    },
    {
      title: '附加收费', key: 'extensions', width: 170,
      render: (_, row) => {
        const extras = draftFor(row).pricingExtras
        return <Space direction="vertical" size={2}>
          <Text>工具：{Object.keys(extras.tool_prices_per_thousand_micros ?? {}).length} 类</Text>
          <Text type="secondary">{extras.request_per_call_micros && !extras.newapi_fixed_quantity ? `调用 ${formatMicros(extras.request_per_call_micros, draftFor(row).currency, 1000)}/千次` : '未设额外调用费'}</Text>
        </Space>
      },
    },
    {
      title: '状态',
      key: 'status',
      width: 100,
      render: (_, row) => row.history.length === 0
        ? <Tag>未配置</Tag>
        : row.current
          ? <Tag color="green">已配置</Tag>
          : <Tag color="gold">当前未生效</Tag>,
    },
    {
      title: '操作',
      key: 'actions',
      width: 190,
      fixed: 'right',
      render: (_, row) => <Space size={6}>
        <Button size="small" icon={<SettingOutlined />} aria-label={`${row.modelName} 图片与工具计费`} onClick={() => setAdvancedRow(row)}>配置</Button>
        <Button
          type="primary"
          size="small"
          icon={<SaveOutlined />}
          title="保存新定价版本"
          aria-label={`保存 ${row.modelName} 定价`}
          loading={savingKeys.has(row.key)}
          onClick={() => saveRow(row)}
        />
        <Button
          size="small"
          icon={<HistoryOutlined />}
          title="查看定价历史"
          aria-label={`查看 ${row.modelName} 历史`}
          onClick={() => setHistoryRow(row)}
        />
      </Space>,
    },
  ]

  return <div>
    <Space wrap style={{ width: '100%', justifyContent: 'space-between', marginBottom: 12 }}>
      <Space wrap>
        <Input
          allowClear
          prefix={<SearchOutlined />}
          placeholder="搜索模型或供应商"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          style={{ width: 260 }}
        />
        <Checkbox checked={onlyUnconfigured} onChange={(event) => setOnlyUnconfigured(event.target.checked)}>
          只看未配置
        </Checkbox>
      </Space>
      <Space wrap><Button
        type="primary"
        icon={<TagsOutlined />}
        aria-label="批量套价"
        disabled={selectedKeys.size === 0}
        onClick={openBatch}
      >
        批量套价
      </Button></Space>
    </Space>

    {historyTruncated && <Alert
      showIcon
      type="warning"
      message="价格历史记录较多，仅加载了前 500 条，部分模型的历史版本可能未列出；当前生效价格已单独完整加载。"
      style={{ marginBottom: 12 }}
    />}
    {effectiveTruncated && <Alert
      showIcon
      type="warning"
      message="当前生效价格超过 500 条，列表可能不完整，请联系管理员处理。"
      style={{ marginBottom: 12 }}
    />}

    {saveNotice && <Alert
      closable
      showIcon
      type="success"
      message={saveNotice}
      onClose={() => setSaveNotice('')}
      style={{ marginBottom: 12 }}
    />}

    {batchResult && <Alert
      closable
      showIcon
      type={batchResult.failed.length ? 'warning' : 'success'}
      message={`成功 ${batchResult.successCount} 个，失败 ${batchResult.failed.length} 个`}
      description={<Space direction="vertical" size={4}>
        {batchResult.unchangedCount > 0 && <Text type="secondary">另有 {batchResult.unchangedCount} 个模型价格没有变化，未新增版本</Text>}
        {batchResult.failed.length > 0 && <Space wrap>失败模型：{batchResult.failed.map(({ label, reason }) => <span key={label}>
          <Text code>{label}</Text>{reason && <Text type="secondary">（{reason}）</Text>}
        </span>)}</Space>}
      </Space>}
      onClose={() => setBatchResult(null)}
      style={{ marginBottom: 12 }}
    />}

    <Table
      rowKey="key"
      size="small"
      columns={columns}
      dataSource={filteredRows}
      loading={loading}
      pagination={{ pageSize: 20, showSizeChanger: true }}
      scroll={{ x: 1100 }}
      locale={{ emptyText: onlyUnconfigured ? '全部模型均已配置价格' : models.length ? '没有符合条件的模型，可清空搜索或筛选后再看' : <span>还没有可定价的模型。先在“模型管理”里接入上游渠道和模型，再回来定价。</span> }}
    />

    {advancedRow && <ModelPricingEditor key={advancedRow.key} tenantID={tenantID} row={advancedRow} draft={draftFor(advancedRow)}
      saving={savingKeys.has(advancedRow.key)} onCancel={() => setAdvancedRow(null)}
      onSave={async (override) => {
        const result = await saveRow(advancedRow, override)
        if (result) updateDraft(advancedRow, override)
        return result
      }} />}

    {pendingConfirm && <PriceChangeConfirm key={pendingConfirm.id} changes={pendingConfirm.changes}
      onConfirm={() => settleConfirm(true)} onCancel={() => settleConfirm(false)} />}

    <Modal
      title={`${historyRow?.modelName ?? ''} 定价历史`}
      open={historyRow !== null}
      width={720}
      onCancel={() => setHistoryRow(null)}
      footer={<Button onClick={() => setHistoryRow(null)}>关闭</Button>}
    >
      <Table
        rowKey="id"
        size="small"
        dataSource={historyRow?.history ?? []}
        pagination={false}
        locale={{ emptyText: '该模型暂无历史定价' }}
        columns={[
          { title: '版本', dataIndex: 'version', width: 80, render: (value: number) => `v${value}` },
          { title: '方式', dataIndex: 'pricing_mode', width: 100, render: (value: PricingMode, price) => price.pricing_extras?.image_pricing?.mode === 'per_image' ? '按张生图' : value === 'newapi_ratio' ? '倍率' : '直接单价' },
          { title: '价格', key: 'price', render: (_, price) => historyPrice(price) },
          { title: '状态', dataIndex: 'status', width: 90, render: (value: string) => <Tag color={value === 'active' ? 'green' : 'default'}>{value === 'active' ? '已启用' : '已停用'}</Tag> },
          { title: '生效时间', dataIndex: 'effective_at', width: 170, render: (value: string) => value ? new Date(value).toLocaleString() : '-' },
        ] as ColumnsType<BillingPrice>}
      />
    </Modal>

    <Modal
      title="批量套价"
      open={batchOpen}
      okText={`应用到 ${selectedKeys.size} 个模型`}
      cancelText="取消"
      confirmLoading={batchSaving}
      onCancel={() => setBatchOpen(false)}
      onOk={() => batchForm.submit()}
      styles={{ body: { maxHeight: 'calc(100vh - 220px)', overflowY: 'auto' } }}
    >
      <Form form={batchForm} layout="vertical" onFinish={applyBatch}>
        <Form.Item label="货币单位（不做汇率换算）"><Select value={batchCurrency} onChange={setBatchCurrency} options={[{ label: '人民币 CNY', value: 'CNY' }, { label: '美元 USD', value: 'USD' }]} /></Form.Item>
        <Form.Item label="计费方式">
          <Segmented
            aria-label="批量计费方式"
            value={batchMode}
            options={[{ label: '直接单价', value: 'direct' }, { label: '倍率', value: 'newapi_ratio' }]}
            onChange={(value) => setBatchMode(value as PricingMode)}
          />
        </Form.Item>
        {batchMode === 'newapi_ratio' ? <>
          <Form.Item name="base_input_per_million_yuan" label={`基础输入单价（${unit(batchCurrency)}/百万 Token）`} rules={[{ required: true, message: '请输入基础输入单价' }]}>
            <TwoDecimalInput min={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="model_ratio" label="模型倍率" rules={[{ required: true, message: '请输入模型倍率' }]}>
            <TwoDecimalInput min={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="completion_ratio" label="输出倍率" rules={[{ required: true, message: '请输入输出倍率' }]}>
            <TwoDecimalInput min={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="cached_input_ratio" label="缓存读取倍率（可选）"><TwoDecimalInput min={0} style={{ width: '100%' }} /></Form.Item>
          <Form.Item name="cache_write_ratio" label="缓存写入倍率（可选）"><TwoDecimalInput min={0} style={{ width: '100%' }} /></Form.Item>
        </> : <>
          <Form.Item name="input_per_million_yuan" label={`输入单价（${unit(batchCurrency)}/百万 Token）`} rules={[{ required: true, message: '请输入输入单价' }]}>
            <TwoDecimalInput min={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="output_per_million_yuan" label={`输出单价（${unit(batchCurrency)}/百万 Token）`} rules={[{ required: true, message: '请输入输出单价' }]}>
            <TwoDecimalInput min={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="cached_input_per_million_yuan" label="缓存读取单价（可选）"><TwoDecimalInput min={0} style={{ width: '100%' }} /></Form.Item>
          <Form.Item name="cache_write_per_million_yuan" label="缓存写入单价（可选）"><TwoDecimalInput min={0} style={{ width: '100%' }} /></Form.Item>
        </>}
      </Form>
    </Modal>
  </div>
}

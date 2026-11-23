import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Checkbox, Modal, Select, Space, Typography } from 'antd'
import { billingEmployeeApi } from '../../services/api'
import { useCurrencyStore } from '../../stores/currency'
import { extractApiError } from '../../utils/apiError'

type CurrencyCount = { currency: string; count: number; zero_balance_count?: number }
type UnpricedModel = { model_name: string; customer_group: string; currencies: string[] }
type Preview = {
  confirm_token: string
  wallets: CurrencyCount[]
  active_prices: CurrencyCount[]
  upstream_rates: CurrencyCount[]
  fixed_costs: CurrencyCount[]
  reserved_wallets?: number
  reservations: number
  monthly_grants: number
  conflict_users?: string[]
  // 切换后会变成「未定价」的模型+客户组；非空时后端要求执行请求带 confirm_unpriced
  unpriced_models?: UnpricedModel[]
  // 已删除模型的遗留价格，只展示条数，不阻止执行
  legacy_orphan_prices?: { pairs: number; rows: number }
}

export default function CurrencySwitch({ tenantID, currency, onSuccess }: { tenantID: string; currency: string; onSuccess: () => void }) {
  const currentTenant = useRef(tenantID)
  currentTenant.current = tenantID
  const [open, setOpen] = useState(false)
  const [target, setTarget] = useState(currency === 'USD' ? 'CNY' : 'USD')
  const [preview, setPreview] = useState<Preview | null>(null)
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [ackUnpriced, setAckUnpriced] = useState(false)
  useEffect(() => { setOpen(false); setPreview(null); setConfirming(false); setBusy(false); setAckUnpriced(false) }, [tenantID])
  const unpriced = preview?.unpriced_models ?? []
  const needUnpricedAck = unpriced.length > 0
  const orphanPairs = preview?.legacy_orphan_prices?.pairs ?? 0
  const submit = async (execute = false) => {
    setBusy(true); setError('')
    try {
      const response = await billingEmployeeApi.switchCurrency(tenantID, { currency: target, preview: !execute, ...(execute ? { confirm_token: preview?.confirm_token, ...(needUnpricedAck && ackUnpriced ? { confirm_unpriced: true } : {}) } : {}) })
      if (currentTenant.current !== tenantID) return
      if (!execute) { setPreview(response.data.data); setAckUnpriced(false) }
      else {
        useCurrencyStore.getState().setTenantCurrency(target)
        setOpen(false); setConfirming(false); onSuccess()
      }
    } catch (e) {
      if (currentTenant.current !== tenantID) return
      setError(extractApiError(e) || '币种切换失败，请重新预览后重试')
      setConfirming(false); setPreview(null); setAckUnpriced(false)
    } finally { setBusy(false) }
  }
  const blocked = !!preview && (preview.reservations > 0 || (preview.reserved_wallets ?? 0) > 0 || !!preview.conflict_users?.length)
  return <>
    <Button onClick={() => { setTarget(currency === 'USD' ? 'CNY' : 'USD'); setPreview(null); setError(''); setConfirming(false); setAckUnpriced(false); setOpen(true) }}>切换系统币种…</Button>
    <Modal open={open} title={confirming ? '确认切换系统币种' : '切换系统币种'} onCancel={() => { if (!busy) setOpen(false) }} footer={<Space>
      <Button disabled={busy} onClick={() => setOpen(false)}>取消</Button>
      {!preview ? <Button type="primary" loading={busy} onClick={() => void submit()}>预览影响</Button> : !confirming ? <Button type="primary" disabled={blocked || (needUnpricedAck && !ackUnpriced)} onClick={() => setConfirming(true)}>继续切换</Button> : <Button danger type="primary" loading={busy} onClick={() => void submit(true)}>确认切换</Button>}
    </Space>}>
      <Space direction="vertical" style={{ width: '100%' }}>
        <Alert type="warning" message="金额数字保持不变，仅修改币种标记，不做汇率换算。历史用量和扣费记录保持原币种。" />
        <Select aria-label="目标币种" value={target} disabled={!!preview || busy} onChange={setTarget} options={[{ value: 'CNY', label: '人民币 CNY' }, { value: 'USD', label: '美元 USD' }].filter(item => item.value !== currency)} />
        {preview && <>
          {preview.wallets.map(item => <Typography.Text key={item.currency}>{item.currency}：{item.count} 个钱包，零余额 {item.zero_balance_count ?? 0} 个</Typography.Text>)}
          {([['active_prices', '有效模型价格'], ['upstream_rates', '上游费率'], ['fixed_costs', '固定成本']] as const).map(([key, label]) => <Typography.Text key={key}>{label}：{preview[key].map(item => `${item.currency} ${item.count} 条`).join('、') || '0 条'}</Typography.Text>)}
          <Typography.Text>在途预占：{preview.reservations}；本月赠金：{preview.monthly_grants} 条；有预占的钱包：{preview.reserved_wallets ?? 0} 个</Typography.Text>
          {orphanPairs > 0 && <Typography.Text>{`已删除模型的遗留价格：${orphanPairs} 个模型/客户组（${preview.legacy_orphan_prices?.rows ?? 0} 行价格），切换时照常作废，不影响计费`}</Typography.Text>}
          {needUnpricedAck && <>
            <Alert type="warning" showIcon message={`以下 ${unpriced.length} 个模型切换后将变为未定价`} description={<div style={{ maxHeight: 160, overflowY: 'auto' }}>
              {unpriced.map(item => <div key={`${item.model_name}\u0000${item.customer_group}`}>{`${item.model_name}（客户组 ${item.customer_group}）· 现有价格币种 ${(item.currencies || []).join('、')}`}</div>)}
            </div>} />
            <Checkbox checked={ackUnpriced} disabled={confirming || busy} onChange={event => setAckUnpriced(event.target.checked)}>我已知晓这些模型切换后无法计费，仍要切换</Checkbox>
          </>}
          {blocked && <Alert type="error" message={preview.reservations > 0 || (preview.reserved_wallets ?? 0) > 0 ? '存在在途预占，请结算后重新预览。' : `钱包冲突用户：${preview.conflict_users?.join('、')}`} />}
          {confirming && <Alert type="warning" message={`确认将系统币种从 ${currency} 切换为 ${target}？请确认价格将按官网目标币种重新录入。`} />}
        </>}
        {error && <Alert type="error" showIcon message={error} />}
      </Space>
    </Modal>
  </>
}

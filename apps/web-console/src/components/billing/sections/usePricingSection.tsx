import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Empty, Input, Pagination, Popconfirm, Select, Space, Tag, Typography, message } from 'antd'
import {  FilterOutlined, InfoCircleOutlined, PlusOutlined, SearchOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { billingAdminApi } from '../../../services/api'
import { extractApiError } from '../../../utils/apiError'
import ModelPricingTable from '../ModelPricingTable'
import UpstreamRatesPanel from '../UpstreamRatesPanel'
import ChannelFixedCostsPanel from '../ChannelFixedCostsPanel'
import TariffPlanEditor from '../TariffPlanEditor'
import { BILLING_SECTION_LABELS as labels } from '../sectionLabels'
import ModelIdentity from '../ModelIdentity'
import { invalidateBillingQueries, type BillingContext } from '../useBillingContext'
import { PRICE_LIST_LIMIT, mergePrices } from '../modelPricing'
import { MICROS_PER_YUAN, groupTariffRules, minuteToTime, tariffBandLabels, timezoneLabel, unwrap } from '../billingFormat'

const { Text } = Typography

// 价格与成本分区：模型定价（内部结算价）、时段计费、上游渠道成本。
// 代码从原 BillingOperations.tsx 原样迁出，查询键、文案与交互不变。
export function usePricingSection(ctx: BillingContext) {
  const queryClient = useQueryClient()
  const { tenantID, billingModels, billingModelsQuery } = ctx
  const refresh = () => invalidateBillingQueries(queryClient, tenantID)
  const [tariffOpen, setTariffOpen] = useState(false)
  const [editingTariff, setEditingTariff] = useState<any>(null)
  const [tariffPreviewModel, setTariffPreviewModel] = useState('')
  const [tariffPlanID, setTariffPlanID] = useState('')
  const [tariffModelSearch, setTariffModelSearch] = useState('')
  const [tariffProviderFilter, setTariffProviderFilter] = useState('')
  const [tariffChannelFilter, setTariffChannelFilter] = useState('')
  const [tariffModelStatusFilter, setTariffModelStatusFilter] = useState('')
  const [tariffBandFilter, setTariffBandFilter] = useState('')
  const [tariffPage, setTariffPage] = useState(1)
  const [tariffPageSize, setTariffPageSize] = useState(24)
  // 历史列表后端最多返回 500 行（按模型名升序、版本降序截断），版本多时靠后的模型会整体缺失；
  // 所以另读一份「当前生效价」，两份按 id 去重合并后交给下游，当前价与「已配置」判断不再受历史截断影响。
  // 两个查询键共用 ['billing-prices', tenantID] 前缀，invalidateQueries 一次刷新两个。
  const pricesQuery = useQuery({
    queryKey: ['billing-prices', tenantID],
    queryFn: () => billingAdminApi.prices(tenantID, { limit: PRICE_LIST_LIMIT }),
    enabled: !!tenantID,
  })
  const effectivePricesQuery = useQuery({
    queryKey: ['billing-prices', tenantID, 'effective'],
    queryFn: () => billingAdminApi.prices(tenantID, { scope: 'effective', limit: PRICE_LIST_LIMIT }),
    enabled: !!tenantID,
  })
  const tariffsQuery = useQuery({
    queryKey: ['billing-tariffs', tenantID],
    queryFn: () => billingAdminApi.tariffs(tenantID),
    enabled: !!tenantID,
  })
  const tariffPreviewQuery = useQuery({
    queryKey: ['billing-tariff-preview', tenantID, tariffPreviewModel],
    queryFn: () => billingAdminApi.previewTariff(tenantID, tariffPreviewModel),
    enabled: !!tenantID && !!tariffPreviewModel,
    retry: false,
  })
  const tariffMutation = useMutation({
    mutationFn: async (input: { payload: Record<string, unknown>; publish: boolean }) => {
      const result = editingTariff
        ? await billingAdminApi.updateTariff(tenantID, editingTariff.id, input.payload)
        : await billingAdminApi.createTariff(tenantID, input.payload)
      const plan = result.data?.data
      if (input.publish && plan?.id) await billingAdminApi.publishTariff(tenantID, plan.id)
      return { plan, published: input.publish }
    },
    onSuccess: ({ plan, published }) => {
      message.success(published ? '时段方案已保存并发布，新请求按新版本计费' : '时段方案草稿已保存')
      if (plan?.id) setTariffPlanID(plan.id)
      setTariffOpen(false)
      setEditingTariff(null)
      refresh()
    },
    onError: (error: any) => { message.error(extractApiError(error) || '保存或发布失败，请检查时段；已保存草稿可在方案列表中继续编辑'); refresh() },
  })
  const publishTariffMutation = useMutation({
    mutationFn: (id: string) => billingAdminApi.publishTariff(tenantID, id),
    onSuccess: () => { message.success('计费时段方案已发布，新请求将按新版本计费'); refresh() },
    onError: (error: any) => message.error(extractApiError(error) || '发布计费时段方案失败'),
  })
  const retireTariffMutation = useMutation({
    mutationFn: (id: string) => billingAdminApi.retireTariff(tenantID,id),
    onSuccess: () => { message.success('时段方案已停用，新请求按原价计费'); refresh() },
    onError: (error: any) => message.error(extractApiError(error) || '停用时段方案失败'),
  })
  const deleteTariffMutation = useMutation({
    mutationFn: (id: string) => billingAdminApi.deleteTariff(tenantID, id),
    onSuccess: async (_, deletedID) => {
      message.success('计费时段方案已删除，历史账单仍可追溯原版本')
      if (tariffPlanID === deletedID) setTariffPlanID('')
      await queryClient.invalidateQueries({ queryKey: ['billing-tariffs', tenantID] })
    },
    onError: (error: any) => message.error(extractApiError(error) || '删除计费时段方案失败，请稍后重试'),
  })
  const historyPrices = unwrap(pricesQuery.data)
  const effectivePrices = unwrap(effectivePricesQuery.data)
  const prices = useMemo(() => mergePrices(historyPrices, effectivePrices), [historyPrices, effectivePrices])
  const historyTruncated = historyPrices.length >= PRICE_LIST_LIMIT
  const effectiveTruncated = effectivePrices.length >= PRICE_LIST_LIMIT
  const modelMetaByName = useMemo(() => {
    const result = new Map<string, any>()
    for (const item of billingModels) {
      const modelName = String(item.model_name || '').trim()
      if (!modelName) continue
      const current = result.get(modelName) || { modelName, modelLabel: item.model_label || modelName, providerNames: [], providerTypes: [], statuses: [] }
      if (item.model_label && current.modelLabel === modelName) current.modelLabel = item.model_label
      if (item.provider_name && !current.providerNames.includes(item.provider_name)) current.providerNames.push(item.provider_name)
      if (item.provider_type && !current.providerTypes.includes(item.provider_type)) current.providerTypes.push(item.provider_type)
      if (item.status && !current.statuses.includes(item.status)) current.statuses.push(item.status)
      result.set(modelName, current)
    }
    return result
  }, [billingModels])
  const providerTypeLabels: Record<string, string> = { openai: 'OpenAI', anthropic: 'Anthropic', azure: 'Azure OpenAI', bedrock: 'AWS Bedrock', gemini: 'Google Gemini', qwen: '通义千问', deepseek: 'DeepSeek' }
  const channelLabel = (value?: string) => providerTypeLabels[value || ''] || '其他渠道'
  const modelOptions = Array.from(modelMetaByName.values()).map((item: any) => ({ value: item.modelName, label: item.modelLabel + ' · ' + (item.providerTypes.map(channelLabel).join(' / ') || '未知厂商') + ' · ' + (item.providerNames.join(' / ') || '未知渠道') }))
  useEffect(() => {
    if (!modelOptions.some((item: any) => item.value === tariffPreviewModel)) setTariffPreviewModel(modelOptions[0]?.value || '')
  }, [modelOptions, tariffPreviewModel])
  const tariffs = unwrap(tariffsQuery.data)
  const selectedTariff = tariffs.find((item: any) => item.id === tariffPlanID) || tariffs.find((item: any) => item.status === 'active') || tariffs[0]
  const tariffPlanOptions = tariffs.map((item: any) => ({ value: item.id, label: (item.name || '未命名方案') + ' · v' + item.version + (item.status === 'active' ? ' · 已生效' : item.status === 'draft' ? ' · 草稿' : ' · 历史版本') }))
  const tariffProviderOptions = Array.from(new Set(Array.from(modelMetaByName.values()).flatMap((item: any) => item.providerTypes))).sort().map((value) => ({ value, label: channelLabel(value) }))
  const tariffChannelOptions = Array.from(new Set(Array.from(modelMetaByName.values()).flatMap((item: any) => item.providerNames))).sort().map((value) => ({ value, label: value }))
  const selectedTariffGroups = useMemo(() => {
    const groups = groupTariffRules(selectedTariff?.rules)
    return groups.map(([modelName, rules]) => {
      const meta = modelMetaByName.get(modelName) || { modelName, modelLabel: modelName, providerNames: [], providerTypes: [], statuses: ['active'] }
      const visibleRules = tariffBandFilter ? rules.filter((rule: any) => (rule.band || 'custom') === tariffBandFilter) : rules
      return { modelName, modelLabel: meta.modelLabel || modelName, providerNames: meta.providerNames, providerTypes: meta.providerTypes, statuses: meta.statuses, rules: visibleRules }
    }).filter((group: any) => {
      if (!group.rules.length) return false
      if (tariffProviderFilter && !group.providerTypes.includes(tariffProviderFilter)) return false
      if (tariffChannelFilter && !group.providerNames.includes(tariffChannelFilter)) return false
      if (tariffModelStatusFilter && !group.statuses.includes(tariffModelStatusFilter)) return false
      const keyword = tariffModelSearch.trim().toLocaleLowerCase()
      if (!keyword) return true
      return [group.modelName, group.modelLabel, ...group.providerNames, ...group.providerTypes].some((value) => String(value).toLocaleLowerCase().includes(keyword))
    })
  }, [modelMetaByName, selectedTariff, tariffBandFilter, tariffChannelFilter, tariffModelSearch, tariffModelStatusFilter, tariffProviderFilter])
  const totalTariffGroups = groupTariffRules(selectedTariff?.rules).length
  const currentTariffPage = Math.min(tariffPage, Math.max(1, Math.ceil(selectedTariffGroups.length / tariffPageSize)))
  const visibleTariffGroups = selectedTariffGroups.slice((currentTariffPage - 1) * tariffPageSize, currentTariffPage * tariffPageSize)
  useEffect(() => {
    if (!tariffs.some((item: any) => item.id === tariffPlanID)) {
      const preferred = tariffs.find((item: any) => item.status === 'active') || tariffs[0]
      if (preferred?.id) setTariffPlanID(preferred.id)
    }
  }, [tariffPlanID, tariffs])
  useEffect(() => { setTariffPage(1) }, [tariffBandFilter, tariffChannelFilter, tariffModelSearch, tariffModelStatusFilter, tariffPageSize, tariffPlanID])
  const tariffPreview = tariffPreviewQuery.data?.data?.data
  const items = [
      { key: 'upstream-costs', label: labels.upstream, children: <UpstreamRatesPanel tenantID={tenantID} models={billingModels} prices={prices} /> },
      { key: 'fixed-costs', label: labels.fixed, children: <ChannelFixedCostsPanel tenantID={tenantID} /> },
      { key: 'prices', label: labels.prices, children: <Card><ModelPricingTable tenantID={tenantID} models={billingModels} prices={prices} loading={billingModelsQuery.isLoading || pricesQuery.isLoading || effectivePricesQuery.isLoading} historyTruncated={historyTruncated} effectiveTruncated={effectiveTruncated} onRefresh={() => queryClient.invalidateQueries({ queryKey: ['billing-prices', tenantID] })} /></Card> },
      { key: 'tariffs', label: labels.tariffs, children: <Card
        className="billing-tariff-shell"
        title={<div className="billing-tariff-shell-title"><Text strong>模型时段计费</Text></div>}
        extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => {
        setEditingTariff(null)
        setTariffOpen(true)
      }}>新增时段方案</Button>}>
        {tariffsQuery.isLoading ? <div className="billing-tariff-loading"><Text type="secondary">正在加载计费方案…</Text></div> : selectedTariff ? <>
          <div className="billing-tariff-preview-bar">
            <div className="billing-tariff-preview-select">
              <Text type="secondary">当前时段预览</Text>
              <Select showSearch optionFilterProp="label" value={tariffPreviewModel || undefined} onChange={setTariffPreviewModel} options={modelOptions} placeholder="选择模型查看当前倍率" />
            </div>
            <div className="billing-tariff-preview-result">
              <InfoCircleOutlined />
              <div><Text strong>{tariffPreview ? (modelMetaByName.get(tariffPreviewModel)?.modelLabel || tariffPreviewModel) + ' · ' + (tariffBandLabels[tariffPreview.band] || tariffPreview.rule_name) + ' · ' + (tariffPreview.multiplier_ppm / MICROS_PER_YUAN).toFixed(2) + '×' : '请选择模型查看当前生效方案'}</Text></div>
            </div>
          </div>
          <div className="billing-tariff-plan-switcher">
            <div className="billing-tariff-plan-switcher-main">
              <Text type="secondary">计费方案</Text>
              <Select value={selectedTariff.id} options={tariffPlanOptions} onChange={setTariffPlanID} />
            </div>
            <div className="billing-tariff-plan-switcher-summary">
              <Text strong>{selectedTariffGroups.length}</Text><Text type="secondary"> / {totalTariffGroups} 个模型</Text>
              <Text type="secondary">当前筛选结果 · 分页加载</Text>
            </div>
          </div>
          <div className="billing-tariff-filter-bar">
            <div className="billing-tariff-filter-heading"><FilterOutlined /><div><Text strong>模型筛选</Text><Text type="secondary">按模型、厂商和渠道快速定位</Text></div></div>
            <Input allowClear prefix={<SearchOutlined />} value={tariffModelSearch} onChange={(event) => setTariffModelSearch(event.target.value)} placeholder="搜索模型名、显示名或厂商" />
            <Select allowClear placeholder="全部厂商" value={tariffProviderFilter || undefined} options={tariffProviderOptions} onChange={(value) => setTariffProviderFilter(value || '')} />
            <Select allowClear placeholder="全部渠道" value={tariffChannelFilter || undefined} options={tariffChannelOptions} onChange={(value) => setTariffChannelFilter(value || '')} />
            <Select placeholder="全部状态" value={tariffModelStatusFilter || undefined} options={[{ value: '', label: '全部状态' }, { value: 'active', label: '已启用' }, { value: 'disabled', label: '已停用' }]} onChange={setTariffModelStatusFilter} />
            <Select allowClear placeholder="全部时段" value={tariffBandFilter || undefined} options={[{ value: 'valley', label: '优惠时段' }, { value: 'flat', label: '标准时段' }, { value: 'peak', label: '高价时段' }, { value: 'custom', label: '自定义时段' }]} onChange={(value) => setTariffBandFilter(value || '')} />
            <Button type="link" onClick={() => { setTariffModelSearch(''); setTariffProviderFilter(''); setTariffChannelFilter(''); setTariffModelStatusFilter(''); setTariffBandFilter('') }}>清空筛选</Button>
          </div>
          <article className="billing-tariff-plan-card">
            <div className="billing-tariff-plan-header">
              <div>
                <div className="billing-tariff-plan-title"><Text strong>{selectedTariff.name || '未命名方案'}</Text><Tag>v{selectedTariff.version}</Tag></div>
                <div className="billing-tariff-plan-meta"><Tag color={selectedTariff.status === 'active' ? 'green' : selectedTariff.status === 'draft' ? 'gold' : 'default'}>{selectedTariff.status === 'active' ? '已生效' : selectedTariff.status === 'draft' ? '草稿' : selectedTariff.status === 'retired' ? "已停用" : '未知状态'}</Tag><Text type="secondary">{timezoneLabel(selectedTariff.timezone)} · {(selectedTariff.rules || []).length} 条规则 · 仅影响新请求</Text></div>
              </div>
              <Space>
                <Button onClick={() => { setEditingTariff(selectedTariff); setTariffOpen(true) }}>编辑方案</Button>
                {selectedTariff.status === 'draft' ? <>
                <Button type="primary" ghost loading={publishTariffMutation.isPending} onClick={() => publishTariffMutation.mutate(selectedTariff.id)}>发布方案</Button>
                </> : null}
                {selectedTariff.status === 'active' ? <Popconfirm title="确认停用方案？" description="停用后新请求按原价计费，历史账单保留原倍率。" okText="确认停用" cancelText="取消" onConfirm={() => retireTariffMutation.mutate(selectedTariff.id)}><Button danger loading={retireTariffMutation.isPending}>停用</Button></Popconfirm> : <Popconfirm
                  title={selectedTariff.status === 'draft' ? '确认删除草稿？' : '确认删除历史方案？'}
                  description={selectedTariff.status === 'draft' ? '删除后无法恢复。' : '列表将隐藏该版本，历史账单与规则保留供审计追溯。'}
                  okText="确认删除"
                  cancelText="取消"
                  okButtonProps={{ danger: true, loading: deleteTariffMutation.isPending }}
                  onConfirm={() => deleteTariffMutation.mutate(selectedTariff.id)}
                >
                  <Button danger loading={deleteTariffMutation.isPending}>删除</Button>
                </Popconfirm>}
              </Space>
            </div>
            {visibleTariffGroups.length ? <div className="billing-tariff-model-groups">
              {visibleTariffGroups.map((group: any) => <div className="billing-tariff-model-group" key={group.modelName}>
                <div className="billing-tariff-model-heading"><span className="billing-tariff-model-dot" /><div className="billing-tariff-model-heading-name"><ModelIdentity modelName={group.modelName} label={group.modelLabel} strong /></div><Text type="secondary">{group.rules.length} 个时段</Text></div>
                <div className="billing-tariff-model-source"><Tag color="blue">厂商：{group.providerTypes.map(channelLabel).join(' / ') || '未知'}</Tag><Tag>渠道：{group.providerNames.join(' / ') || '未知'}</Tag></div>
                <div className="billing-tariff-rule-pills">{group.rules.map((rule: any) => <span className={['billing-tariff-rule-pill', 'billing-tariff-rule-' + (rule.band || 'custom')].join(' ')} key={rule.id || rule.code}><span className="billing-tariff-rule-band">{tariffBandLabels[rule.band] || rule.name || '自定义时段'}</span><span>{rule.special_date ? String(rule.special_date).slice(0, 10) : (rule.weekdays || []).map((day: number) => ['一', '二', '三', '四', '五', '六', '日'][day - 1]).join('、') + ' / 每周'} · {minuteToTime(rule.start_minute)}–{minuteToTime(rule.end_minute)}</span><strong>{(Number(rule.multiplier_ppm || 0) / MICROS_PER_YUAN).toFixed(2)}×</strong></span>)}</div>
              </div>)}
            </div> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有符合条件的模型" />}
            <div className="billing-tariff-pagination"><Pagination current={currentTariffPage} pageSize={tariffPageSize} total={selectedTariffGroups.length} showSizeChanger pageSizeOptions={[24, 48, 96]} showTotal={(total, range) => String(range[0]) + '-' + String(range[1]) + ' / ' + total + ' 个模型'} onChange={(page, pageSize) => { setTariffPage(page); setTariffPageSize(pageSize) }} /></div>
          </article>
        </> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无时段计费方案"><Button type="primary" icon={<PlusOutlined />} onClick={() => { setEditingTariff(null); setTariffOpen(true) }}>从模板创建时段方案</Button></Empty>}
     </Card> },
  ]
  const modals = <>
    <TariffPlanEditor open={tariffOpen} plan={editingTariff || undefined} modelOptions={modelOptions}
      loading={tariffMutation.isPending} onCancel={() => { setTariffOpen(false); setEditingTariff(null) }}
      onSave={(payload, publish) => tariffMutation.mutate({ payload, publish })} />
  </>
  return { items, modals }
}

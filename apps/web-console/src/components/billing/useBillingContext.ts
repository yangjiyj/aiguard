import { useCurrencyStore } from '../../stores/currency'
import { useEffect, useMemo, useState } from 'react'
import { useQuery, type QueryClient } from '@tanstack/react-query'
import { billingAdminApi, billingEmployeeApi, tenantApi } from '../../services/api'
import { unwrap } from './billingFormat'

// 计费各页共享的上下文：可管理租户、计费运行模式和计费模型目录。
// 从原 BillingOperations.tsx 迁出，查询键与刷新策略保持不变。
export function useBillingContext() {
  const [tenantID, setTenantID] = useState('')
  const tenantsQuery = useQuery({ queryKey: ['billing-tenants'], queryFn: () => tenantApi.list() })
  const tenants = useMemo(() => {
    const data = tenantsQuery.data?.data
    return Array.isArray(data) ? data : Array.isArray(data?.data) ? data.data : []
  }, [tenantsQuery.data])

  useEffect(() => {
    if (!tenantID && tenants.length) {
      const preferred = tenants.find((item: any) => item.id !== 'system') || tenants[0]
      setTenantID(preferred.id)
    }
  }, [tenantID, tenants])

  const settingsQuery = useQuery({ queryKey: ['employee-settings', tenantID], queryFn: () => billingEmployeeApi.settings(tenantID), enabled: !!tenantID })
  useEffect(() => {
    const currency = settingsQuery.data?.data?.data?.currency
    if (currency) useCurrencyStore.getState().setTenantCurrency(currency)
  }, [settingsQuery.data])
  const runtimeQuery = useQuery({
    queryKey: ['billing-runtime'],
    queryFn: () => billingAdminApi.runtime(),
    refetchInterval: 15_000,
    refetchOnWindowFocus: true,
  })
  const billingModelsQuery = useQuery({
    queryKey: ['billing-models', tenantID],
    queryFn: () => billingAdminApi.models(tenantID),
    enabled: !!tenantID,
  })
  const billingRuntime = runtimeQuery.data?.data?.data
  const billingMode: string = billingRuntime?.mode || 'unknown'
  const billingModels = unwrap(billingModelsQuery.data)
  return { tenantID, setTenantID, tenants, tenantsQuery, runtimeQuery, billingRuntime, billingMode, billingModelsQuery, billingModels }
}

export type BillingContext = ReturnType<typeof useBillingContext>

// 与原页面 refresh() 完全一致：一次失效全部计费查询。
export const invalidateBillingQueries = async (queryClient: QueryClient, tenantID: string) => {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: ['billing-runtime'] }),
    queryClient.invalidateQueries({ queryKey: ['billing-models', tenantID] }),
    queryClient.invalidateQueries({ queryKey: ['billing-customers', tenantID] }),
    queryClient.invalidateQueries({ queryKey: ['billing-customer-groups', tenantID] }),
    queryClient.invalidateQueries({ queryKey: ['billing-ledger', tenantID] }),
    queryClient.invalidateQueries({ queryKey: ['billing-prices', tenantID] }),
    queryClient.invalidateQueries({ queryKey: ['billing-redemptions', tenantID] }),
    queryClient.invalidateQueries({ queryKey: ['billing-tariffs', tenantID] }),
    queryClient.invalidateQueries({ queryKey: ['billing-tariff-preview', tenantID] }),
  ])
}

export const billingModeColor: Record<string, string> = { prepaid: 'green', metering: 'gold', off: 'default' }
export const billingModeLabel: Record<string, string> = { prepaid: '预付扣费', metering: '按量计费', off: '计费关闭', unknown: '模式待确认' }

// 预付费账户（高级）折叠区只在 prepaid 模式或系统设置 billing_prepaid_tools_visible=true 时出现；
// 老版本控制面不返回该字段时按运行模式判定。
export const prepaidToolsVisible = (runtime: any) =>
  typeof runtime?.prepaid_tools_visible === 'boolean' ? runtime.prepaid_tools_visible : runtime?.mode === 'prepaid'

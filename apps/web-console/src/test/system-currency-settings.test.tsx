import { afterEach, expect, test, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SystemSettings from '../pages/SystemSettings'
import { apiClient, billingEmployeeApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { useCurrencyStore } from '../stores/currency'
import { canAccessPath, canSeeMenuItem } from '../utils/access'

afterEach(() => { cleanup(); vi.restoreAllMocks(); useAuthStore.setState({ user: null }) })
// 系统设置仍只对系统管理员开放（三员分立）。切换系统币种只有平台管理员可以操作（影响全部钱包与价格）。
test.each(['platform_admin', 'admin'])('%s 可从菜单与路由到达系统币种设置', role => {
 expect(canAccessPath(role, '/system/settings')).toBe(true)
 expect(canSeeMenuItem(role, '/system/settings')).toBe(true)
})
test.each(['tenant_owner', 'tenant_admin'])('%s 不进入系统设置，也无权切换币种', role => {
 expect(canAccessPath(role, '/system/settings')).toBe(false)
 expect(canSeeMenuItem(role, '/system/settings')).toBe(false)
 expect(canAccessPath(role, '/cost/budgets')).toBe(true)
})
test('平台管理员只读取本租户币种，预览确认后刷新币种和设置', async () => {
 useAuthStore.setState({ user: { id: 'a', username: '管理员', role: 'platform_admin', tenant_id: 'tenant-a' } })
 vi.spyOn(apiClient, 'get').mockResolvedValue({ data: {} } as any)
 const settings = vi.spyOn(billingEmployeeApi, 'settings').mockResolvedValueOnce({ data: { data: { currency: 'USD' } } } as any).mockResolvedValue({ data: { data: { currency: 'CNY' } } } as any)
 const change = vi.spyOn(billingEmployeeApi, 'switchCurrency').mockResolvedValueOnce({ data: { data: { confirm_token: 'token', wallets: [], active_prices: [], upstream_rates: [], fixed_costs: [], reservations: 0, reserved_wallets: 0, monthly_grants: 0 } } } as any).mockResolvedValueOnce({ data: { data: { executed: true } } } as any)
 const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } })
 render(<QueryClientProvider client={cache}><SystemSettings /></QueryClientProvider>)
 expect(await screen.findByText('当前系统币种：USD')).toBeInTheDocument()
 expect(screen.queryByText(/最终汇率/)).not.toBeInTheDocument()
 expect(settings).toHaveBeenCalledWith('tenant-a')
 fireEvent.click(screen.getByText('切换系统币种…'))
 fireEvent.click(screen.getByText('预览影响'))
 await screen.findByText('继续切换')
 fireEvent.click(screen.getByText('继续切换'))
 fireEvent.click(screen.getByText('确认切换'))
 await waitFor(() => expect(change).toHaveBeenCalledWith('tenant-a', { currency: 'CNY', preview: false, confirm_token: 'token' }))
 await screen.findByText('当前系统币种：CNY')
 expect(useCurrencyStore.getState().tenantCurrency).toBe('CNY')
})

test.each(['admin'])('%s 只能看到当前系统币种，看不到切换入口', async role => {
 useAuthStore.setState({ user: { id: 'a', username: '管理员', role, tenant_id: 'tenant-a' } })
 vi.spyOn(billingEmployeeApi, 'settings').mockResolvedValue({ data: { data: { currency: 'USD' } } } as any)
 const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } })
 render(<QueryClientProvider client={cache}><SystemSettings /></QueryClientProvider>)
 expect(await screen.findByText('当前系统币种：USD')).toBeInTheDocument()
 expect(screen.queryByText('切换系统币种…')).not.toBeInTheDocument()
})

import { afterEach, describe, expect, it, vi } from 'vitest'
import { apiClient, billingAdminApi } from '../services/api'

afterEach(() => vi.restoreAllMocks())

describe('billing cursor request presence', () => {
  it('sends the empty first cursor as an actual query parameter', async () => {
    const spy = vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: [], meta: { has_more: false, next_cursor: '' } } })
    await billingAdminApi.customers('tenant-a', '', 100)
    expect(spy).toHaveBeenLastCalledWith('/billing/customers', { params: { tenant_id: 'tenant-a', cursor: '', limit: 100 } })
    const config = spy.mock.calls[0][1]
    expect(apiClient.getUri({ url: '/billing/customers', ...config })).toContain('cursor=')
    await billingAdminApi.ledger('tenant-a', '', undefined, 100)
    expect(spy).toHaveBeenLastCalledWith('/billing/ledger', { params: { tenant_id: 'tenant-a', cursor: '', limit: 100 } })
  })

  it('does not silently opt in callers which omit the cursor', async () => {
    const spy = vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: [] } })
    await billingAdminApi.customers('tenant-a')
    expect(spy).toHaveBeenLastCalledWith('/billing/customers', { params: { tenant_id: 'tenant-a' } })
  })
})

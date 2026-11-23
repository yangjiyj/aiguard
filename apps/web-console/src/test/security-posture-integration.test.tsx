import { afterEach, expect, it, vi } from 'vitest'
import { render, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import api from '../services/api'
import SecurityPolicyCenter from '../pages/SecurityPolicyCenter'
import { useAuthStore } from '../stores/auth'

afterEach(() => vi.restoreAllMocks())

it('renders the tenant policy workflow without runtime diagnostic requests or writes', async () => {
  useAuthStore.setState({ token: 'token', isAuthenticated: true, user: {
    id: 'reader', username: 'reader', role: 'platform_admin', tenant_id: 'tenant-a',
  } })
  const get = vi.spyOn(api, 'get').mockImplementation(async (path) => {
    if (path === '/system/settings') return { data: { security_execution_mode: {
      configured_mode: 'record', effective_mode: 'record', locked: false, source: 'system_setting',
      runtime_verified: false, runtime_status: 'pending',
    } } } as never
    return { data: { data: [], total: 0, runtime_verified: false } } as never
  })
  const put = vi.spyOn(api, 'put')
  const post = vi.spyOn(api, 'post')
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  window.history.replaceState({}, '', '/security/policies')
  render(<BrowserRouter><QueryClientProvider client={client}><SecurityPolicyCenter /></QueryClientProvider></BrowserRouter>)
  await waitFor(() => expect(document.querySelectorAll('.enterprise-scene-card')).toHaveLength(5))
  expect(get.mock.calls.map(([path]) => path)).not.toContain('/security/posture')
  expect(put).not.toHaveBeenCalled()
  expect(post).not.toHaveBeenCalled()
})

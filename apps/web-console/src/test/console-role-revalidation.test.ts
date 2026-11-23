import { afterEach, expect, it } from 'vitest'
import { apiClient, authApi } from '../services/api'
import { useAuthStore } from '../stores/auth'

const originalAdapter = apiClient.defaults.adapter
afterEach(() => { apiClient.defaults.adapter = originalAdapter; useAuthStore.getState().logout() })

it('clears a persisted console session when the control plane rejects its current role', async () => {
  useAuthStore.getState().login('previous-admin-session', { id: 'admin', username: 'admin', role: 'platform_admin' })
  apiClient.defaults.adapter = async () => { throw { response: { status: 403, data: { error: { code: 'console_role_required' } } } } }
  await expect(authApi.me()).rejects.toMatchObject({ response: { status: 403 } })
  expect(useAuthStore.getState().token).toBeNull()
  expect(useAuthStore.getState().isAuthenticated).toBe(false)
})

it('preserves an authorized session after an unrelated action permission denial', async () => {
  useAuthStore.getState().login('current-admin-session', { id: 'admin', username: 'admin', role: 'tenant_admin' })
  apiClient.defaults.adapter = async () => { throw { response: { status: 403, data: { error: { code: 'permission_denied' } } } } }
  await expect(authApi.me()).rejects.toMatchObject({ response: { status: 403 } })
  expect(useAuthStore.getState().token).toBe('current-admin-session')
  expect(useAuthStore.getState().isAuthenticated).toBe(true)
})

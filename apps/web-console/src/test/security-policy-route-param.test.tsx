import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { useSearchParams } from 'react-router-dom'
import App from '../App'
import { licenseApi } from '../services/api'

const { mockAuth } = vi.hoisted(() => ({
  mockAuth: { isAuthenticated: true, user: { role: 'platform_admin', password_change_required: false }, logout: vi.fn() },
}))
vi.mock('../stores/auth', () => ({ useAuthStore: () => mockAuth }))
function PolicyCenterProbe() {
  const [params] = useSearchParams()
  return <div>策略中心路由 policy={params.get('policy')}</div>
}
vi.mock('../pages/SecurityPolicyCenter', () => ({ default: () => <PolicyCenterProbe /> }))

describe('策略中心路由', () => {
  beforeEach(() => {
    vi.spyOn(licenseApi, 'status').mockResolvedValue({ data: { valid: false, features: [] } } as never)
  })

  it('keeps ?policy= on the way to the policy center', async () => {
    window.history.replaceState({}, '', '/security/policies?policy=p-123')
    render(<App />)
    expect(await screen.findByText('策略中心路由 policy=p-123')).toBeInTheDocument()
    expect(window.location.search).toBe('?policy=p-123')
  })
})

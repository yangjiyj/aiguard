import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { beforeEach, describe, expect, it } from 'vitest'
import { useState } from 'react'

import AuditQueryIdentityBoundary from '../components/AuditQueryIdentityBoundary'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { useAuthStore } from '../stores/auth'

function ActiveAuditQuery() {
  const identity = useAuditQueryIdentity()
  const [selected, setSelected] = useState(false)
  const query = useQuery({
    queryKey: ['content-audit', identity, 'active'],
    queryFn: async () => identity + ':fresh',
  })
  return (
    <div>
      <div data-testid="active-audit">{query.data || 'loading'}</div>
      <button onClick={() => setSelected(true)}>{selected ? 'local-selected' : 'local-empty'}</button>
    </div>
  )
}

describe('AuditQueryIdentityBoundary', () => {
  beforeEach(() => {
    useAuthStore.setState({
      token: 'token-a',
      user: { id: 'user-a', username: 'A', role: 'platform_admin', tenant_id: 'tenant-a' },
      isAuthenticated: true,
    })
  })

  it('removes only sensitive audit queries when the authenticated identity changes', async () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    queryClient.setQueryData(['content-audit', 'alerts'], { secret: 'tenant-a' })
    queryClient.setQueryData(['access-retention-content', 'req-a'], { secret: 'tenant-a' })
    queryClient.setQueryData(['audit-operations', undefined], { secret: 'tenant-a' })
    queryClient.setQueryData(['alerts-inbox-snap'], { secret: 'tenant-a' })
    queryClient.setQueryData(['model-routing', 'status'], { reusable: true })

    render(
      <QueryClientProvider client={queryClient}>
        <AuditQueryIdentityBoundary>
          <div>child</div>
        </AuditQueryIdentityBoundary>
      </QueryClientProvider>,
    )

    act(() => {
      useAuthStore.getState().setUser({
        id: 'user-b',
        username: 'B',
        role: 'tenant_admin',
        tenant_id: 'tenant-b',
      })
    })

    await waitFor(() => expect(queryClient.getQueryData(['content-audit', 'alerts'])).toBeUndefined())
    expect(queryClient.getQueryData(['access-retention-content', 'req-a'])).toBeUndefined()
    expect(queryClient.getQueryData(['audit-operations', undefined])).toBeUndefined()
    expect(queryClient.getQueryData(['alerts-inbox-snap'])).toBeUndefined()
    expect(queryClient.getQueryData(['model-routing', 'status'])).toEqual({ reusable: true })
  })

  it('remounts active audit observers onto the new identity without painting cached data', async () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    queryClient.setQueryData(['content-audit', 'tenant-a|user-a|platform_admin', 'active'], 'tenant-a:secret')

    render(
      <QueryClientProvider client={queryClient}>
        <AuditQueryIdentityBoundary>
          <ActiveAuditQuery />
        </AuditQueryIdentityBoundary>
      </QueryClientProvider>,
    )
    expect(await screen.findByText('tenant-a:secret')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'local-empty' }))
    expect(screen.getByRole('button', { name: 'local-selected' })).toBeInTheDocument()

    act(() => {
      useAuthStore.getState().setUser({
        id: 'user-b',
        username: 'B',
        role: 'tenant_admin',
        tenant_id: 'tenant-b',
      })
    })

    expect(screen.queryByText('tenant-a:secret')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'local-empty' })).toBeInTheDocument()
    expect(await screen.findByText('tenant-b|user-b|tenant_admin:fresh')).toBeInTheDocument()
    expect(queryClient.getQueryData([
      'content-audit',
      'tenant-b|user-b|tenant_admin',
      'active',
    ])).toBe('tenant-b|user-b|tenant_admin:fresh')
  })
})

import { beforeEach, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import api from '../services/api'
import SecurityPostureCard from '../components/SecurityPostureCard'
import { useAuthStore } from '../stores/auth'

vi.mock('../services/api', () => ({ default: { get: vi.fn(), put: vi.fn(), post: vi.fn() } }))

const channelIDs = ['chat', 'mcp', 'skill', 'forward_proxy', 'reverse_proxy']
const posture = {
  tenant_id: 'tenant-a', generated_at: '2026-10-05T00:00:00Z', runtime_verified: true,
  channels: channelIDs.map((id) => ({
    id, configured_mode: 'protect', effective_mode: id === 'forward_proxy' ? 'mixed' : 'protect',
    runtime_verified: true, fail_modes: [{ id: 'inspection', mode: 'closed' }],
    controls: [{ id: 'result_checker', enabled: true, wired: id !== 'mcp' }],
  })),
  ml_layers: [{ id: 'tier1', configured_enabled: true, runtime_enabled: false, runtime_verified: true }],
  warnings: ['mcp_tool_result_checker_unwired'],
}

function renderCard(client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  return render(<QueryClientProvider client={client}><SecurityPostureCard /></QueryClientProvider>)
}

beforeEach(() => {
  vi.resetAllMocks()
  useAuthStore.setState({ token: 'token', isAuthenticated: true, user: {
    id: 'reader', username: 'reader', role: 'platform_admin', tenant_id: 'tenant-a',
  } })
})

it('shows all channels, mixed mode, fail modes, wiring and observed ML state', async () => {
  vi.mocked(api.get).mockResolvedValue({ data: posture } as never)
  renderCard()
  for (const id of channelIDs) {
    expect(await screen.findByTestId(`posture-channel-${id}`)).toHaveAttribute('data-verified', 'true')
  }
  expect(screen.getByTestId('posture-effective-forward_proxy')).toHaveAttribute('data-mode', 'mixed')
  expect(screen.getByTestId('posture-fail-chat-inspection')).toHaveAttribute('data-mode', 'closed')
  expect(screen.getByTestId('posture-control-mcp-result_checker')).toHaveAttribute('data-wired', 'false')
  expect(screen.getByTestId('posture-ml-tier1')).toHaveAttribute('data-enabled', 'false')
  expect(screen.getByTestId('posture-warnings')).toHaveTextContent('mcp_tool_result_checker_unwired')
  expect(api.put).not.toHaveBeenCalled()
  expect(api.post).not.toHaveBeenCalled()
})

it('does not claim active protection or wiring from an unverified receipt', async () => {
  vi.mocked(api.get).mockResolvedValue({ data: { ...posture, runtime_verified: false,
    channels: posture.channels.map((channel) => ({ ...channel, runtime_verified: false })),
    ml_layers: posture.ml_layers.map((layer) => ({ ...layer, runtime_verified: false })),
  } } as never)
  renderCard()
  expect(await screen.findByTestId('posture-effective-chat')).toHaveAttribute('data-mode', 'unknown')
  expect(screen.getByTestId('posture-fail-chat-inspection')).toHaveAttribute('data-mode', 'unknown')
  expect(screen.getByTestId('posture-control-mcp-result_checker')).toHaveAttribute('data-wired', 'unknown')
  expect(screen.getByTestId('posture-ml-tier1')).toHaveAttribute('data-enabled', 'unknown')
})

it('shows conflicting runtime modes without claiming verified controls', async () => {
  vi.mocked(api.get).mockResolvedValue({ data: { ...posture, runtime_verified: false,
    channels: posture.channels.map((channel) => ({ ...channel, effective_mode: 'mixed', runtime_verified: false })),
  } } as never)
  renderCard()
  expect(await screen.findByTestId('posture-effective-chat')).toHaveAttribute('data-mode', 'mixed')
  expect(screen.getByTestId('posture-channel-chat')).toHaveAttribute('data-verified', 'false')
  expect(screen.getByTestId('posture-control-mcp-result_checker')).toHaveAttribute('data-wired', 'unknown')
})

it('refreshes and stops showing verified protection after a failed read', async () => {
  vi.mocked(api.get).mockResolvedValueOnce({ data: posture } as never).mockRejectedValue(new Error('offline'))
  renderCard()
  expect(await screen.findByTestId('posture-effective-chat')).toHaveAttribute('data-mode', 'protect')
  fireEvent.click(screen.getByTestId('posture-refresh'))
  expect(await screen.findByTestId('posture-load-error')).toBeInTheDocument()
  expect(screen.queryByTestId('posture-effective-chat')).not.toBeInTheDocument()
})

it('isolates cached posture across tenant identity changes', async () => {
  vi.mocked(api.get).mockResolvedValueOnce({ data: posture } as never)
    .mockImplementationOnce(() => new Promise(() => {}))
  renderCard()
  expect(await screen.findByTestId('posture-effective-chat')).toHaveAttribute('data-mode', 'protect')
  useAuthStore.setState({ user: { id: 'other', username: 'other', role: 'platform_admin', tenant_id: 'tenant-b' } })
  await waitFor(() => expect(api.get).toHaveBeenCalledTimes(2))
  expect(screen.queryByTestId('posture-effective-chat')).not.toBeInTheDocument()
})

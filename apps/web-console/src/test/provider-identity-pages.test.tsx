import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { readFileSync } from 'node:fs'
import Providers from '../pages/Providers'
import ModelManagement from '../pages/ModelManagement'
import ModelRouting from '../pages/ModelRouting'
import { modelApi, modelRoutingApi, providerApi } from '../services/api'
import deepseekLogo from '../assets/providers/deepseek.svg'
import qwenLogo from '../assets/providers/qwen.svg'

vi.mock('../stores/auth', () => ({
  useAuthStore: (selector?: (state: { user: { role: string } }) => unknown) => {
    const state = { user: { role: 'tenant_auditor' } }
    return selector ? selector(state) : state
  },
}))

const ok = (data: unknown) => ({ data, status: 200, statusText: 'OK', headers: {}, config: {} } as any)
const providerFixtures = [
  { id: 'p_ds', name: 'Channel DeepSeek', provider_type: 'deepseek', base_url: 'https://api.deepseek.com', has_credential: false, status: 'disabled' },
  { id: 'p_qw', name: 'Channel Qwen', provider_type: 'qwen', base_url: 'https://dashscope.aliyuncs.com/compatible-mode/v1', has_credential: true, status: 'active', callable: true, availability_state: 'callable' },
  { id: 'p_other', name: 'DeepSeek', provider_type: 'custom', base_url: 'https://example.invalid', has_credential: true, status: 'active', callable: true, availability_state: 'callable' },
]
let client: QueryClient

function renderPage(Page: () => JSX.Element) {
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<MemoryRouter><QueryClientProvider client={client}><Page /></QueryClientProvider></MemoryRouter>)
}

function identityInRow(name: string) {
  const identityName = screen.getAllByText(name).find((element) => element.classList.contains('provider-identity__name'))!
  return identityName.closest('.provider-identity')!
}

beforeEach(() => {
  vi.spyOn(providerApi, 'list').mockResolvedValue(ok({ items: providerFixtures }))
  vi.spyOn(providerApi, 'metrics').mockResolvedValue(ok({ data: [] }))
  vi.spyOn(providerApi, 'deleted').mockResolvedValue(ok({ items: [] }))
})

afterEach(() => {
  cleanup()
  client?.clear()
  vi.restoreAllMocks()
})

describe('ProviderIdentity + pages', () => {
  it('Providers: provider_type -> SVG; custom.name != SVG; has_credential', async () => {
    renderPage(Providers)
    await screen.findByText('Channel DeepSeek')
    expect(identityInRow('Channel DeepSeek').querySelector('img')).toHaveAttribute('src', deepseekLogo)
    expect(identityInRow('Channel Qwen').querySelector('img')).toHaveAttribute('src', qwenLogo)
    expect(identityInRow('DeepSeek').querySelector('img')).toBeNull()

    const providerSource = readFileSync('src/pages/Providers.tsx', 'utf8')
    const syncText = providerSource.match(/setCatalogSyncProvider\(r\)[\s\S]*?\n\s*>\n\s*([^<]+?)\s*<\/Button>/)![1].trim()
    expect(syncText).toBeTruthy()
    const configuredText = providerSource.match(/>\{v \? '([^']+)' : '([^']+)'\}<\/Tag>/)!
    const deepseekRow = screen.getByText('Channel DeepSeek').closest('tr')!
    const qwenRow = screen.getByText('Channel Qwen').closest('tr')!
    expect(within(deepseekRow).getByRole('button', { name: new RegExp(syncText) })).toBeDisabled()
    expect(within(qwenRow).getByRole('button', { name: new RegExp(syncText) })).toBeEnabled()
    expect(within(deepseekRow).getAllByText(configuredText[2]).length).toBeGreaterThan(0)
    expect(within(qwenRow).getByText(configuredText[1])).toBeInTheDocument()
  })

  it('ModelManagement: provider_id -> provider_type, model_name != SVG', async () => {
    vi.spyOn(modelApi, 'list').mockResolvedValue(ok({ items: [
      { id: 'm_ds', provider_id: 'p_ds', model_name: 'any-model-a', status: 'active', callable: true, availability_state: 'callable' },
      { id: 'm_qw', provider_id: 'p_qw', model_name: 'any-model-b', status: 'active', callable: true, availability_state: 'callable' },
      { id: 'm_other', provider_id: 'p_other', model_name: 'qwen-max', status: 'active', callable: true, availability_state: 'callable' },
      { id: 'm_removed', provider_id: 'p_missing', model_name: 'deepseek-r1', status: 'active', callable: true, availability_state: 'callable' },
    ] }))
    renderPage(ModelManagement)
    await screen.findByText('Channel DeepSeek')
    expect(identityInRow('Channel DeepSeek').querySelector('img')).toHaveAttribute('src', deepseekLogo)
    expect(identityInRow('Channel Qwen').querySelector('img')).toHaveAttribute('src', qwenLogo)
    expect(identityInRow('DeepSeek').querySelector('img')).toBeNull()
    const removedRow = screen.getByText('deepseek-r1').closest('tr')!
    expect(removedRow.querySelector('.provider-identity img')).toBeNull()
    expect(removedRow.querySelector('.provider-identity [data-icon="api"]')).not.toBeNull()
    expect(providerApi.list).toHaveBeenCalledTimes(1)
  })

  it('ModelRouting: route_ref -> API; health_state/model_name != SVG; canWrite', async () => {
    const user = userEvent.setup()
    vi.spyOn(modelRoutingApi, 'overview').mockResolvedValue({ default_rule: null, model_exceptions: [], multi_route_model_count: 1, outbound_route_available: true, legacy_report: [] })
    vi.spyOn(modelRoutingApi, 'status').mockResolvedValue({ models: [{
      model_name: 'qwen-max', state: 'pending', route_count: 2, config_version: 0,
      routes: [
        { route_ref: 'rt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', provider_name: 'DeepSeek', avg_ttft_ms: 20, samples_30m: 2, failures_30m: 0, health_state: 'healthy' },
        { route_ref: 'rt_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', provider_name: 'Qwen', avg_ttft_ms: null, samples_30m: 0, failures_30m: 0, health_state: 'unknown' },
      ],
    }], next_cursor: '' })
    const saveDefault = vi.spyOn(modelRoutingApi, 'saveDefault')
    const saveOverride = vi.spyOn(modelRoutingApi, 'saveOverride')
    const { container } = renderPage(ModelRouting)
    const row = (await screen.findByText('qwen-max')).closest('tr')!
    const actionButtons = within(row).getAllByRole('button').filter((button) => !button.classList.contains('ant-table-row-expand-icon'))
    expect(actionButtons).toHaveLength(1)
    for (const button of actionButtons) expect(button).toBeDisabled()
    await user.click(row.querySelector('.ant-table-row-expand-icon')!)
    await screen.findByText('DeepSeek')
    for (const name of ['DeepSeek', 'Qwen']) {
      expect(identityInRow(name).querySelector('img')).toBeNull()
      expect(identityInRow(name).querySelector('[data-icon="api"]')).not.toBeNull()
    }
    expect(container.textContent).not.toContain('rt_aaaaaaaa')
    expect(providerApi.list).not.toHaveBeenCalled()
    expect(saveDefault).not.toHaveBeenCalled()
    expect(saveOverride).not.toHaveBeenCalled()
  })
})

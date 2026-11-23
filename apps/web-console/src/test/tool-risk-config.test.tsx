import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ConfigProvider } from 'antd'
import ToolRiskConfig from '../pages/ToolRiskConfig'
import { toolRiskConfigApi } from '../services/api'
import { useAuthStore } from '../stores/auth'

vi.mock('../hooks/useSecurityExecutionMode', () => ({ useSecurityExecutionMode: () => ({ mode: { effective_mode: 'record' }, isError: false }) }))
const legacy = { id: 'existing', tool_name: 'Bash', tool_type: 'system', risk_level: 'critical', action: 'audit', description: '既有分类' }
const renderPage = () => render(<ConfigProvider theme={{ token: { motion: false } }}><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><ToolRiskConfig /></QueryClientProvider></ConfigProvider>)

describe('Optional exact tool deny list', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    useAuthStore.setState({ user: { id: 'admin', username: 'admin', role: 'platform_admin', tenant_id: 'tenant-a' }, token: 'fixture', isAuthenticated: true })
    vi.spyOn(toolRiskConfigApi, 'list').mockResolvedValue({ data: { data: [legacy] } } as never)
    vi.spyOn(toolRiskConfigApi, 'create').mockResolvedValue({ data: {} } as never)
    vi.spyOn(toolRiskConfigApi, 'update').mockResolvedValue({ data: {} } as never)
    vi.spyOn(toolRiskConfigApi, 'delete').mockResolvedValue({ data: {} } as never)
  })
  it('requires no mapping work for normal tools and does not mutate legacy audit records', async () => {
    renderPage()
    expect(await screen.findByText('暂无禁用工具')).toBeInTheDocument()
    expect(screen.getByText('默认：行为规则')).toBeInTheDocument()
    expect(screen.queryByText('网关工具观测')).not.toBeInTheDocument()
    expect(screen.queryByText(/未配置/)).not.toBeInTheDocument()
    expect(toolRiskConfigApi.list).toHaveBeenCalledWith()
    expect(toolRiskConfigApi.update).not.toHaveBeenCalled()
    expect(toolRiskConfigApi.create).not.toHaveBeenCalled()
  })
  it('disables only the chosen exact tool after confirmation and preserves its metadata', async () => {
    renderPage(); await screen.findByText('暂无禁用工具')
    await userEvent.click(screen.getByRole('button', { name: '禁用工具' }))
    await userEvent.type(screen.getByLabelText('精确工具名称'), 'Bash')
    await userEvent.click(screen.getByRole('button', { name: '加入禁用名单' }))
    expect(toolRiskConfigApi.update).not.toHaveBeenCalled()
    await userEvent.click(await screen.findByRole('button', { name: '确认禁用' }))
    await waitFor(() => expect(toolRiskConfigApi.update).toHaveBeenCalledWith('existing', { tool_type: 'system', risk_level: 'critical', action: 'block', description: '既有分类' }))
    expect(toolRiskConfigApi.create).not.toHaveBeenCalled()
    expect(Object.keys(vi.mocked(toolRiskConfigApi.update).mock.calls[0][1]).sort()).toEqual(['action', 'description', 'risk_level', 'tool_type'])
  })
  it('restores behavior policy processing without deleting the classification record', async () => {
    vi.mocked(toolRiskConfigApi.list).mockResolvedValue({ data: { data: [{ ...legacy, action: 'block' }] } } as never)
    renderPage()
    expect(await screen.findByText('仅留记录')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '移出禁用名单 Bash' }))
    await userEvent.click(await screen.findByRole('button', { name: '移出名单' }))
    await waitFor(() => expect(toolRiskConfigApi.update).toHaveBeenCalledWith('existing', { tool_type: 'system', risk_level: 'critical', action: 'audit', description: '既有分类' }))
    expect(toolRiskConfigApi.delete).not.toHaveBeenCalled()
  })
  it('keeps unauthorized readers from changing the list', async () => {
    useAuthStore.setState({ user: { id: 'owner', username: 'owner', role: 'tenant_owner', tenant_id: 'tenant-a' } })
    renderPage(); await screen.findByText('暂无禁用工具')
    expect(screen.getByRole('button', { name: '禁用工具' })).toBeDisabled()
  })
})

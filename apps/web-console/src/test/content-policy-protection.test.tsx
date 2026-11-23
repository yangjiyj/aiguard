import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import api, { securityReplyApi } from '../services/api'
import SecurityReplySettings from '../pages/security-policy/SecurityReplySettings'
import SensitiveDataPolicy from '../pages/security-policy/SensitiveDataPolicy'
import { chooseOption } from './protectionTestUtils'
import { useAuthStore } from '../stores/auth'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn() } }
})

const wrapper = ({ children }: { children: ReactNode }) => (
  <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>{children}</QueryClientProvider>
)

const templates = { default: '请求含有不允许的内容', prompt_injection: '', content_safety: '', data_leak: '' }

describe('内容策略：涉密标记的模型生成内容与固定回复', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role: 'platform_admin', tenant_id: 'tenant_default' }, isAuthenticated: true })
    vi.spyOn(api, 'get').mockResolvedValue({ data: {} } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
    vi.spyOn(securityReplyApi, 'get').mockResolvedValue({ data: { schema_version: 1, enabled: false, templates } } as never)
    vi.spyOn(securityReplyApi, 'update').mockResolvedValue({ data: {} } as never)
  })

  it('涉密文件标记详情可把模型生成内容改为按策略', async () => {
    const user = userEvent.setup()
    render(<SensitiveDataPolicy policies={[]} auditOnly={false} runtimeVerified runtimeStatus="verified" canManage onSaved={vi.fn()} />, { wrapper })
    const row = screen.getByText('企业敏感信息').closest('[role=row]') as HTMLElement
    await user.click(within(row).getByRole('button', { name: /配\s*置/ }))
    const select = await screen.findByRole('combobox', { name: '模型生成内容' })
    await waitFor(() => expect(select).toBeEnabled())
    await chooseOption(select, '按策略')
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/security/system-settings', { model_output_classified_disposition: 'follow_policy' }))
  })

  it('无权角色看到但不能改模型生成内容', async () => {
    const user = userEvent.setup()
    render(<SensitiveDataPolicy policies={[]} auditOnly={false} runtimeVerified runtimeStatus="verified" canManage={false} onSaved={vi.fn()} />, { wrapper })
    const row = screen.getByText('企业敏感信息').closest('[role=row]') as HTMLElement
    await user.click(within(row).getByRole('button', { name: /配\s*置/ }))
    const select = await screen.findByRole('combobox', { name: '模型生成内容' })
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/system/settings'))
    expect(select).toBeDisabled()
  })

  it('租户级安全员不能改模型生成内容（平台级设置）', async () => {
    useAuthStore.setState({ token: 't', user: { id: 'u2', username: 'so', role: 'security_officer', tenant_id: 'tenant-a' }, isAuthenticated: true })
    const user = userEvent.setup()
    render(<SensitiveDataPolicy policies={[]} auditOnly={false} runtimeVerified runtimeStatus="verified" canManage onSaved={vi.fn()} />, { wrapper })
    const row = screen.getByText('企业敏感信息').closest('[role=row]') as HTMLElement
    await user.click(within(row).getByRole('button', { name: /配\s*置/ }))
    const select = await screen.findByRole('combobox', { name: '模型生成内容' })
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/system/settings'))
    expect(select).toBeDisabled()
  })

  it('模型生成内容读取失败时提示', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('boom'))
    const user = userEvent.setup()
    render(<SensitiveDataPolicy policies={[]} auditOnly={false} runtimeVerified runtimeStatus="verified" canManage onSaved={vi.fn()} />, { wrapper })
    const row = screen.getByText('企业敏感信息').closest('[role=row]') as HTMLElement
    await user.click(within(row).getByRole('button', { name: /配\s*置/ }))
    expect(await screen.findByText('读取失败')).toBeInTheDocument()
  })

  it('固定回复可开关并改模板', async () => {
    const user = userEvent.setup()
    render(<SecurityReplySettings canManage />, { wrapper })
    const toggle = await screen.findByRole('switch', { name: '启用固定回复' })
    await waitFor(() => expect(toggle).toBeEnabled())
    await user.click(toggle)
    const text = screen.getByLabelText('内容安全回复')
    await user.type(text, '该内容不符合单位规定')
    await user.click(screen.getByRole('button', { name: '保存固定回复' }))
    await waitFor(() => expect(securityReplyApi.update).toHaveBeenCalledWith({
      enabled: true,
      templates: { ...templates, content_safety: '该内容不符合单位规定' },
    }))
  })

  it('固定回复对无权角色只读', async () => {
    render(<SecurityReplySettings canManage={false} />, { wrapper })
    const toggle = await screen.findByRole('switch', { name: '启用固定回复' })
    await waitFor(() => expect(securityReplyApi.get).toHaveBeenCalled())
    expect(toggle).toBeDisabled()
    expect(screen.getByRole('button', { name: '保存固定回复' })).toBeDisabled()
  })
})

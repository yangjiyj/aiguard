import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useAuthStore } from '../stores/auth'
import SemanticConsole from '../pages/SemanticConsole'

const mockApi = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
  post: vi.fn(),
}))

const mockProviderApi = vi.hoisted(() => ({
  list: vi.fn(),
}))

vi.mock('../services/api', () => ({
  default: mockApi,
  providerApi: mockProviderApi,
}))

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return {
    ...actual,
    message: {
      success: vi.fn(),
      error: vi.fn(),
      warning: vi.fn(),
    },
  }
})

describe('SemanticConsole page', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    useAuthStore.setState({ token: 't', user: { id: 'a', username: 'admin', role: 'platform_admin', tenant_id: 'tenant_default' }, isAuthenticated: true } as any)
    vi.clearAllMocks()
    mockProviderApi.list.mockResolvedValue({ data: { data: [] } })
    mockApi.get.mockImplementation((path: string) => {
      if (path === '/security/semantic/runtime-status') {
        return Promise.resolve({
          data: {
            runtime: {
              desired_revision: '0123456789abcdef',
              status: 'applied',
              runtime_verified: true,
              components: [
                { component: 'security-engine', status: 'applied', fresh: true, config_loaded: true, judge_required: true, judge_operational: true },
                { component: 'gateway-core', status: 'applied', fresh: true, config_loaded: true, judge_required: false, judge_operational: false },
              ],
            },
          },
        })
      }
      return Promise.resolve({
        data: {
          config_version: 'v-initial',
          semantic_enabled: 'true',
          semantic_input_enabled: 'true',
          semantic_agent_enabled: 'false',
          semantic_output_enabled: 'false',
          judge_allow_private_egress: 'false',
          semantic_sample_rate: '0.2',
          semantic_total_timeout: '6',
          judge_backend: 'bundled',
        },
      })
    })
  })

  const renderPage = () =>
    render(
      <QueryClientProvider client={queryClient}>
        <SemanticConsole />
      </QueryClientProvider>
    )

  it('renders the three console cards in Chinese', async () => {
    renderPage()

    expect(await screen.findByText('检测开关')).toBeInTheDocument()
    expect(screen.getByText('检测大脑')).toBeInTheDocument()
    expect(screen.getByText('测试与保存')).toBeInTheDocument()
    // 语义拦截由防护策略决定：页面说明默认记录告警、拦截须在策略里显式选择
    expect(screen.getByText(/语义命中默认记录并告警/)).toBeInTheDocument()
    expect(screen.getAllByText(/智能分析命中时/).length).toBeGreaterThan(0)
    // 大脑三选一用中文枚举，不露英文
    expect(screen.getByText('自带 CPU 模型')).toBeInTheDocument()
    expect(screen.getByText('已接入模型上游')).toBeInTheDocument()
    expect(screen.getByText('自定义端点')).toBeInTheDocument()
    expect(screen.getByText('模型输出使用数据与内容安全检测')).toBeInTheDocument()
    expect(screen.queryByRole('switch', { name: '输出检测' })).not.toBeInTheDocument()
  })

  it('does not invent enabled defaults when semantic settings are absent', async () => {
    mockApi.get.mockImplementation((path: string) => {
      if (path === '/security/semantic/runtime-status') {
        return Promise.resolve({ data: { runtime: { status: 'pending', runtime_verified: false, components: [] } } })
      }
      return Promise.resolve({ data: {} })
    })

    renderPage()

    expect(await screen.findByText('尚未配置语义检测')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '语义检测总开关' })).not.toBeChecked()
    expect(screen.getByRole('switch', { name: '输入检测' })).not.toBeChecked()
    expect(screen.getByRole('switch', { name: 'Agent 检测' })).not.toBeChecked()
  })

  it('shows desired configuration separately from component applied state', async () => {
    mockApi.get.mockImplementation((path: string) => {
      if (path === '/security/semantic/runtime-status') {
        return Promise.resolve({
          data: {
            runtime: {
              status: 'partially_applied',
              runtime_verified: false,
              components: [
                { component: 'security-engine', status: 'applied', fresh: true, config_loaded: true, judge_required: true, judge_operational: true },
                { component: 'gateway-core', status: 'pending', fresh: false, config_loaded: false, judge_required: false, judge_operational: false },
              ],
            },
          },
        })
      }
      return Promise.resolve({ data: { semantic_enabled: 'true', judge_backend: 'bundled' } })
    })

    renderPage()

    expect(await screen.findByText('部分组件已加载')).toBeInTheDocument()
    expect(screen.queryByText('语义配置已验证生效')).not.toBeInTheDocument()
    expect(screen.getByText(/安全检测引擎：已加载/)).toBeInTheDocument()
    expect(screen.getByText(/模型网关：等待回执/)).toBeInTheDocument()
  })

  it('never shows green when config loaded but the enabled judge is unavailable', async () => {
    mockApi.get.mockImplementation((path: string) => {
      if (path === '/security/semantic/runtime-status') {
        return Promise.resolve({
          data: {
            runtime: {
              status: 'applied',
              runtime_verified: true,
              components: [
                {
                  component: 'security-engine', status: 'applied', fresh: true,
                  config_loaded: true, judge_required: true, judge_operational: false,
                  judge_consecutive_failures: 2,
                },
                { component: 'gateway-core', status: 'applied', fresh: true, config_loaded: true },
              ],
            },
          },
        })
      }
      return Promise.resolve({ data: { semantic_enabled: 'true', judge_backend: 'bundled' } })
    })

    renderPage()

    expect(await screen.findByText('配置已加载，但语义裁判不可用')).toBeInTheDocument()
    expect(screen.queryByText('语义配置已验证生效')).not.toBeInTheDocument()
    expect(screen.getByText(/安全检测引擎：配置已加载 · 裁判不可用/)).toBeInTheDocument()
    expect(screen.getByText(/基础规则仍运行，依赖大模型的语义判断暂不可用/)).toBeInTheDocument()
  })

  it('shows runtime unavailable instead of treating a reachable judge as applied', async () => {
    mockApi.get.mockImplementation((path: string) => {
      if (path === '/security/semantic/runtime-status') {
        return Promise.reject({ response: { status: 503 } })
      }
      return Promise.resolve({ data: { semantic_enabled: 'true', judge_backend: 'bundled' } })
    })

    renderPage()

    expect(await screen.findByText('运行态不可验证')).toBeInTheDocument()
    expect(screen.queryByText('语义配置已验证生效')).not.toBeInTheDocument()
  })

  it('never shows applied when a required forward proxy has no fresh receipt', async () => {
    mockApi.get.mockImplementation((path: string) => path === '/security/semantic/runtime-status'
      ? Promise.resolve({ data: { runtime: { status: 'applied', runtime_verified: true, proxy_required: true, components: [
        { component: 'security-engine', status: 'applied', fresh: true, config_loaded: true, judge_required: false },
        { component: 'gateway-core', status: 'applied', fresh: true, config_loaded: true },
      ] } } })
      : Promise.resolve({ data: { semantic_enabled: 'true', judge_backend: 'bundled' } }))
    renderPage()
    expect(await screen.findByText('组件仅回报配置版本，运行健康未验证')).toBeInTheDocument()
    expect(screen.queryByText('语义配置已验证生效')).not.toBeInTheDocument()
  })

  it('saves only the semantic_* / judge_* keys and omits the unchanged judge_api_key', async () => {
    mockApi.put.mockResolvedValue({ data: { message: 'settings updated' } })

    renderPage()

    await screen.findByText('检测开关')
    await userEvent.click(await screen.findByRole('button', { name: /保存/ }))

    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalledWith(
        '/security/semantic/settings',
        expect.objectContaining({
          semantic_enabled: true,
          semantic_input_enabled: true,
          semantic_agent_enabled: false,
          semantic_output_enabled: false,
          inspect_user_input: true,
          inspect_model_output: true,
          inspect_tool_results: true,
          inspect_builtin_context: false,
          inspect_history: false,
          judge_backend: 'bundled',
        })
      )
    })
    // bundled 模式不应提交 custom 端点的密钥；占位/未改动不覆盖已存密钥
    const payload = mockApi.put.mock.calls[0][1] as Record<string, unknown>
    expect(payload).not.toHaveProperty('judge_api_key')
    // 未保存过阈值时按默认 0.85 回显并随保存提交
    expect(payload.semantic_block_min_confidence).toBe(0.85)
  })

  it('shows the semantic block threshold with guidance and saves the configured value', async () => {
    mockApi.put.mockResolvedValue({ data: { message: 'settings updated' } })
    mockApi.get.mockImplementation((path: string) => {
      if (path === '/security/semantic/runtime-status') {
        return Promise.resolve({ data: { runtime: { status: 'applied', runtime_verified: true, components: [] } } })
      }
      return Promise.resolve({ data: { config_version: 'v-threshold', semantic_enabled: 'true', judge_backend: 'bundled', semantic_total_timeout: '9', semantic_block_min_confidence: '0.9' } })
    })

    renderPage()

    const input = await screen.findByRole('spinbutton', { name: '拦截置信度阈值' })
    await waitFor(() => expect(input).toHaveValue('0.90'))
    expect(screen.getByText(/裁判置信度不低于该值时才拦截/)).toBeInTheDocument()
    // 上下文裁判置信度是固定映射值：说明阈值对它的实际含义
    expect(screen.getByText('上下文裁判置信度固定为 0.9：阈值 ≤0.9 时拦截，>0.9 时只记录。')).toBeInTheDocument()
    await userEvent.clear(input)
    await userEvent.type(input, '0.95')
    await userEvent.click(screen.getByRole('button', { name: /保存/ }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalledWith('/security/semantic/settings',
      expect.objectContaining({ semantic_block_min_confidence: 0.95, expected_version: 'v-threshold' })))
  })

  it('persists independent all-layer scope without claiming it has applied', async () => {
    mockApi.put.mockResolvedValue({ data: { message: 'settings updated' } })
    renderPage()
    const builtin = await screen.findByRole('switch', { name: '内置提示词与工具定义' })
    await waitFor(() => expect(screen.getByRole('switch', { name: '本轮用户输入' })).toBeChecked())
    expect(builtin).not.toBeChecked()
    expect(screen.getByRole('switch', { name: '随请求携带的历史消息' })).not.toBeChecked()
    expect(screen.getByRole('switch', { name: '工具与检索返回' })).toBeChecked()
    await userEvent.click(builtin)
    await userEvent.click(screen.getByRole('button', { name: /保存/ }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalledWith('/security/semantic/settings', expect.objectContaining({
      inspect_builtin_context: true, inspect_history: false, inspect_tool_results: true,
    })))
  })

  it('requires HTTPS and explicit opt-in before using a private custom judge', async () => {
    mockApi.put.mockResolvedValue({ data: { message: 'settings updated' } })
    renderPage()

    await userEvent.click(await screen.findByRole('radio', { name: /自定义端点/ }))
    expect(await screen.findByText('私网裁判需要显式授权')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('switch', { name: '允许访问私网裁判' }))
    await userEvent.type(screen.getByLabelText('端点地址'), 'https://10.0.0.8/v1/chat/completions')
    await userEvent.type(screen.getByLabelText('模型名'), 'judge-model')
    await userEvent.click(screen.getByRole('button', { name: /保存/ }))

    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalledWith(
        '/security/semantic/settings',
        expect.objectContaining({
          judge_backend: 'custom',
          judge_allow_private_egress: true,
          judge_url: 'https://10.0.0.8/v1/chat/completions',
        }),
      )
    })
  })

  it('accepts a plain http custom judge only after private egress is authorized', async () => {
    mockApi.put.mockResolvedValue({ data: { message: 'settings updated' } })
    renderPage()

    await userEvent.click(await screen.findByRole('radio', { name: /自定义端点/ }))
    await userEvent.type(screen.getByLabelText('端点地址'), 'http://172.16.20.10:8000/v1/chat/completions')
    await userEvent.type(screen.getByLabelText('模型名'), 'judge-model')
    await userEvent.click(screen.getByRole('button', { name: /保存/ }))
    expect(await screen.findByText(/私网 HTTP 端点需先开启私网授权/)).toBeInTheDocument()
    expect(mockApi.put).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole('switch', { name: '允许访问私网裁判' }))
    await userEvent.click(screen.getByRole('button', { name: /保存/ }))

    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalledWith(
        '/security/semantic/settings',
        expect.objectContaining({
          judge_backend: 'custom',
          judge_allow_private_egress: true,
          judge_url: 'http://172.16.20.10:8000/v1/chat/completions',
        }),
      )
    })
  })

  it('tests the judge connection with the current brain config and shows a Chinese verdict', async () => {
    mockApi.post.mockResolvedValue({
      data: { ok: true, verdict: 'malicious', latency_ms: 1800 },
    })

    renderPage()

    await userEvent.click(await screen.findByRole('button', { name: /测试连接/ }))

    await waitFor(() => {
      expect(mockApi.post).toHaveBeenCalledWith(
        '/security/semantic/test-judge',
        expect.objectContaining({ judge_backend: 'bundled' }),
        { timeout: 65_000 },
      )
    })
  })

  // High-3：读取走专用接口并拿到 config_version；保存必须带回；409 要提示重新读取。
  it('reads the semantic config from the dedicated endpoint and sends expected_version back on save', async () => {
    mockApi.put.mockResolvedValue({ data: { message: 'ok' } })
    renderPage()
    await screen.findByText('检测开关')
    expect(mockApi.get).toHaveBeenCalledWith('/security/semantic/settings')
    await userEvent.click(await screen.findByRole('button', { name: /保存/ }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalledWith('/security/semantic/settings',
      expect.objectContaining({ expected_version: 'v-initial' })))
  })

  it('tells the user to reload when someone else saved first (409 version_conflict)', async () => {
    mockApi.put.mockRejectedValue({ response: { status: 409, data: { error: { code: 'version_conflict', message: '配置已被其他人修改，请刷新页面重新读取后再保存' } } } })
    renderPage()
    await screen.findByText('检测开关')
    await userEvent.click(await screen.findByRole('button', { name: /保存/ }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalled())
    const { message } = await import('antd')
    await waitFor(() => expect((message.error as any)).toHaveBeenCalledWith(expect.stringContaining('请刷新页面重新读取')))
  })

  // 安全员：研判服务地址与密钥由系统管理员配置，页面不提供 custom / 地址 / 密钥 / 私网授权。
  it('hides the custom endpoint, address, key and private-egress switch from a security officer', async () => {
    useAuthStore.setState({ token: 't', user: { id: 'o', username: 'officer', role: 'security_officer', tenant_id: 'tenant_default' }, isAuthenticated: true } as any)
    renderPage()
    await screen.findByText('检测开关')
    expect(screen.queryByRole('radio', { name: /自定义端点/ })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('端点地址')).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/密钥/)).not.toBeInTheDocument()
    expect(screen.queryByRole('switch', { name: '允许访问私网裁判' })).not.toBeInTheDocument()
    expect(screen.getByText(/研判服务地址与密钥由系统管理员配置/)).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /自带 CPU 模型/ })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /已接入模型上游/ })).toBeInTheDocument()
  })

  it('never sends judge_url / judge_api_key / custom when a security officer saves', async () => {
    useAuthStore.setState({ token: 't', user: { id: 'o', username: 'officer', role: 'security_officer', tenant_id: 'tenant_default' }, isAuthenticated: true } as any)
    mockApi.put.mockResolvedValue({ data: { message: 'ok' } })
    renderPage()
    await screen.findByText('检测开关')
    await userEvent.click(await screen.findByRole('button', { name: /保存/ }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalled())
    const payload = mockApi.put.mock.calls[0][1] as Record<string, unknown>
    expect(payload).not.toHaveProperty('judge_url')
    expect(payload).not.toHaveProperty('judge_api_key')
    expect(payload).not.toHaveProperty('judge_allow_private_egress')
    expect(payload.judge_backend).not.toBe('custom')
  })

  it('keeps the full custom endpoint form for the system administrator', async () => {
    renderPage()
    await screen.findByText('检测开关')
    expect(screen.getByRole('radio', { name: /自定义端点/ })).toBeInTheDocument()
  })
})

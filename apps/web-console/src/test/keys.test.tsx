import keysSource from '../pages/Keys.tsx?raw'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { Modal, message } from 'antd'
import React from 'react'
import Keys from '../pages/Keys'
import api, { keyApi, budgetApi } from '../services/api'

const walletLinkLabel = keysSource.match(/aria-label=\{'([^']+) ' \+ r\.key_prefix\}/)?.[1]
if (!walletLinkLabel) throw new Error('Production wallet action label not found')
const walletActionName = new RegExp(walletLinkLabel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ' demo-key1')

const usageTitle = String.fromCodePoint(0x7528, 0x91cf, 0x4e0e, 0x989d, 0x5ea6)
const usageActionPrefix = usageTitle + ' '
const pendingCostLabel = String.fromCodePoint(0x5f85, 0x6838, 0x5b9e)
const unpricedQualityLabel = String.fromCodePoint(0x542b, 0x672a, 0x5b9a, 0x4ef7, 0x8bf7, 0x6c42)
const statisticsTimezoneLabel = String.fromCodePoint(0x7edf, 0x8ba1, 0x65f6, 0x533a)

// Task 2.1 (P0-1): 内部 key 列表「再查→只得掩码」，UI 绝不回显明文。
// 列表仅展示掩码前缀（对账标识），完整密钥走受保护 reveal 端点按需取，取不到则引导重置。
vi.mock('../services/api', () => ({
  default: { get: vi.fn().mockResolvedValue({ data: {} }) },
  keyApi: {
    list: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    revoke: vi.fn(),
    delete: vi.fn(),
    reveal: vi.fn(),
    setTrafficClass: vi.fn(),
  },
  budgetApi: {
    keyReadModel: vi.fn(),
  },
  projectApi: {
    list: vi.fn().mockResolvedValue({ data: { items: [] } }),
  },
  userApi: {
    list: vi.fn().mockResolvedValue({ data: { items: [] } }),
  },
}))

vi.mock('../stores/auth', () => ({
  useAuthStore: () => ({ user: { id: 'admin_1', username: 'admin', role: 'platform_admin' } }),
}))

const KEY_ROW = {
  id: 'key_abc12345',
  project_id: 'proj_1',
  user_id: 'user_1',
  name: 'demo 应用密钥',
  key_prefix: 'demo-key1',
  scopes: ['chat'],
  status: 'active',
  created_at: '2026-06-08T00:00:00Z',
}

function makeWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

function mockClipboard() {
  const writeText = vi.fn().mockResolvedValue(undefined)
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText },
  })
  return writeText
}

// antd 的 Modal.info 是命令式挂到 body 的 portal，RTL 的自动 cleanup 不会卸载它，
// 会跨用例残留污染 DOM；jsdom 不触发退场动画结束，销毁后清理挂载点以保证隔离。
afterEach(() => {
  cleanup()
  Modal.destroyAll()
  document.body.innerHTML = ''
})

describe('Keys page — 内部 key 明文不回显 (Task 2.1)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(keyApi.list).mockResolvedValue({
      data: {
        items: [
          {
            ...KEY_ROW,
            full_key: 'demo-key1-PLAINTEXT-LEAK-SHOULD-NOT-RENDER',
          },
        ],
      },
    } as never)
  })

  it('列表渲染掩码前缀（对账标识），但不回显明文', async () => {
    render(<Keys />, { wrapper: makeWrapper() })

    // 数据已加载：列表展示掩码前缀（仅作对账标识展示，不再提供「复制前缀」按钮，
    // 完整密钥统一走操作列的受保护 reveal 复制按钮，见「复制完整密钥 (reveal)」用例）
    expect(await screen.findByText('demo-key1')).toBeTruthy()
    expect(screen.getByRole('link', { name: walletActionName })).toHaveAttribute(
      'href',
      '/cost/budgets?scope_type=key&scope_id=key_abc12345',
    )

    // 明文绝不出现在 DOM 任何位置
    const leak = screen.queryAllByText((content) => content.includes('PLAINTEXT-LEAK'))
    expect(leak.length).toBe(0)
  })
})

describe('Keys page - usage and quota presentation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(keyApi.list).mockResolvedValue({ data: { items: [KEY_ROW] } } as never)
  })

  it('keeps internal billing diagnostics out of the product drawer', async () => {
    const quality = {
      observed_available: true, actual_available: false, coverage_verified: false,
      fields_present: { cost_micros: true, cost_estimated_requests: true, cost_unpriced_requests: true },
      total_micros: 1_250_000, estimated_requests: 1, unpriced_requests: 0,
      reason_code: 'settled_request_coverage_unverified',
    }
    vi.mocked(budgetApi.keyReadModel).mockResolvedValue({ data: { data: {
      key: { id: KEY_ROW.id, attribution: 'user' },
      confirmed_usage: { available: true, month_tokens: 12, month_tokens_available: true,
        month_requests: 3, month_requests_available: true, day_tokens: 4, day_tokens_available: true,
        day_requests: 1, day_requests_available: true, month_cost_micros: 1_250_000, day_cost_micros: 1_250_000,
        month_cost_quality: quality, day_cost_quality: quality,
        bucket_timezone: 'Asia/Shanghai', bucket_timezone_source: 'internal_bucket_source',
        cost_currency: 'CNY', cost_currency_available: false, cost_currency_note: 'internal_currency_note',
        cost_quality_note: 'internal_quality_note', rpm: 2, concurrency: 1 },
      window: { available: false, reason_code: 'invalid_bucket_labels' }, effective_quota: {},
      in_flight: { owner_level_available: false, key_level_reason: 'internal_wallet_reason' },
    } } } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.click(screen.getByRole('button', { name: `${usageActionPrefix}${KEY_ROW.key_prefix}` }))
    await screen.findByText(/12 tokens/)
    expect(screen.getByText(`${usageTitle} · ${KEY_ROW.name}`)).toBeInTheDocument()
    for (const internal of ['estimated_requests=', 'unpriced_requests=', 'total_micros=',
      'actual_available', 'coverage_verified', 'fields_present', 'raw_observed_evidence',
      'settled_request_coverage_unverified', 'internal_bucket_source', 'internal_currency_note',
      'internal_quality_note', 'internal_wallet_reason', 'invalid_bucket_labels', 'micros']) {
      expect(document.body.textContent).not.toContain(internal)
    }
    expect(document.body.textContent).not.toContain('1,250,000')
    expect(document.body.textContent).not.toContain('CNY')
  })

  it('known currency converts micros to the normal monetary unit', async () => {
    const quality = { observed_available: true, fields_present: { cost_micros: true,
      cost_estimated_requests: true, cost_unpriced_requests: true }, estimated_requests: 1, unpriced_requests: 0 }
    vi.mocked(budgetApi.keyReadModel).mockResolvedValue({ data: { data: {
      key: { id: KEY_ROW.id, attribution: 'project' },
      confirmed_usage: { available: true, month_tokens: 12, month_tokens_available: true,
        month_requests: 3, month_requests_available: true, day_tokens: 4, day_tokens_available: true,
        day_requests: 1, day_requests_available: true, month_cost_micros: 1_250_000, day_cost_micros: 250_000,
        month_cost_quality: quality, day_cost_quality: quality, cost_currency_available: true,
        cost_currency: 'USD', rpm: 2, concurrency: 1 },
      window: { available: false }, effective_quota: {}, in_flight: { owner_level_available: false },
    } } } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.click(screen.getByRole('button', { name: `${usageActionPrefix}${KEY_ROW.key_prefix}` }))
    await screen.findByText(/12 tokens/)
    const content = document.body.textContent?.replace(/\s/g, ' ')
    expect(content).toContain('USD 1.25')
    expect(content).toContain('USD 0.25')
    expect(content).not.toContain('1,250,000')
  })

  it.each([
    { observed_available: true, fields_present: { cost_micros: false } },
    { observed_available: false, fields_present: { cost_micros: true } },
  ])('requires both observation and field presence before showing money %j', async (quality) => {
    vi.mocked(budgetApi.keyReadModel).mockResolvedValue({ data: { data: {
      key: { id: KEY_ROW.id, attribution: 'user' },
      confirmed_usage: { available: true, month_tokens: 12, month_tokens_available: true,
        month_requests: 3, month_requests_available: true, day_tokens: 4, day_tokens_available: true,
        day_requests: 1, day_requests_available: true, month_cost_micros: 1_250_000, day_cost_micros: 1_250_000,
        month_cost_quality: quality, day_cost_quality: quality, cost_currency_available: true,
        cost_currency: 'USD', rpm: 2, concurrency: 1 },
      window: { available: false }, effective_quota: {}, in_flight: { owner_level_available: false },
    } } } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.click(screen.getByRole('button', { name: `${usageActionPrefix}${KEY_ROW.key_prefix}` }))
    await screen.findByText(/12 tokens/)
    expect(document.body.textContent).not.toContain('USD')
    expect(screen.getAllByText(pendingCostLabel)).toHaveLength(2)
  })
})

describe('Keys page — 复制完整密钥 (reveal)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(keyApi.list).mockResolvedValue({ data: { items: [KEY_ROW] } } as never)
  })

  it('reveal 返回 full_key 时复制完整密钥（非前缀）', async () => {
    const writeText = mockClipboard()
    vi.mocked(keyApi.reveal).mockResolvedValue({ data: { full_key: 'sk-FULL-REAL-KEY-9f8e7d' } } as never)

    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')

    fireEvent.click(screen.getByRole('button', { name: /复制完整密钥/ }))

    await waitFor(() => expect(keyApi.reveal).toHaveBeenCalledWith('key_abc12345'))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('sk-FULL-REAL-KEY-9f8e7d'))
    // 复制的是完整密钥而非前缀
    expect(writeText).not.toHaveBeenCalledWith('demo-key1')
  })

  it('存量老 key（reason=created_before_encryption）弹提示引导重置，不复制', async () => {
    const writeText = mockClipboard()
    vi.mocked(keyApi.reveal).mockResolvedValue({
      data: { full_key: null, reason: 'created_before_encryption' },
    } as never)

    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')

    fireEvent.click(screen.getByRole('button', { name: /复制完整密钥/ }))

    await waitFor(() => expect(keyApi.reveal).toHaveBeenCalledWith('key_abc12345'))
    // 弹出引导重置的提示（Modal.info）
    expect(await screen.findByText(/完整值不可恢复/)).toBeTruthy()
    // 不复制任何内容
    expect(writeText).not.toHaveBeenCalled()
  })
})

describe('Keys page — 备注字段', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(keyApi.list).mockResolvedValue({ data: { items: [KEY_ROW] } } as never)
  })

  it('列表展示「备注」列及备注值', async () => {
    render(<Keys />, { wrapper: makeWrapper() })
    // 备注值直接展示（KEY_ROW.name）
    expect(await screen.findByText('demo 应用密钥')).toBeTruthy()
  })

  it('创建密钥弹窗含备注输入框', async () => {
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.click(screen.getByRole('button', { name: /创建密钥/ }))
    // 备注输入（用占位符定位，避免与列头「备注」文本冲突）
    expect(await screen.findByPlaceholderText(/门户对接/)).toBeTruthy()
  })

  it('创建密钥必须展示模型 API 与 MCP 网关两类产品权限', async () => {
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.click(screen.getByRole('button', { name: /创建密钥/ }))

    expect(await screen.findByText('调用权限')).toBeTruthy()
    expect(screen.getByText(/模型 API/)).toBeTruthy()
    expect(screen.getByText(/MCP 网关/)).toBeTruthy()
  })

  it('行内编辑备注调用 keyApi.update（仅传 name）', async () => {
    vi.mocked(keyApi.update).mockResolvedValue({ data: {} } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo 应用密钥')

    // 点击 antd Typography 的行内编辑铅笔
    const editTrigger = document.querySelector('.ant-typography-edit') as HTMLElement
    expect(editTrigger).toBeTruthy()
    fireEvent.click(editTrigger)

    // 行内编辑框用 ant-typography-edit-content 限定；列表新增的搜索框也是 textbox，
    // 全局 findByRole('textbox') 会命中多个元素
    const textarea = await waitFor(() => {
      const input = document.querySelector('.ant-typography-edit-content input, .ant-typography-edit-content textarea') as HTMLInputElement
      expect(input).toBeTruthy()
      return input
    })
    fireEvent.change(textarea, { target: { value: '门户生产密钥' } })
    fireEvent.blur(textarea) // 失焦提交

    await waitFor(() =>
      expect(keyApi.update).toHaveBeenCalledWith('key_abc12345', { name: '门户生产密钥' }),
    )
  })
})

describe('Keys page — 流量类别（告警车道依据）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(keyApi.list).mockResolvedValue({ data: { items: [KEY_ROW, { ...KEY_ROW, id: 'key_eval0001', name: '测评目标', key_prefix: 'eval-key1', traffic_class: 'evaluation' }] } } as never)
  })

  it('每把密钥显示自己的流量类别，默认是普通业务', async () => {
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    expect(within(screen.getByTestId('traffic-class-key_abc12345')).getByText('普通业务')).toBeTruthy()
    expect(within(screen.getByTestId('traffic-class-key_eval0001')).getByText('测评流量')).toBeTruthy()
  })

  it('选择新类别后调用服务端接口，并刷新列表', async () => {
    vi.mocked(keyApi.setTrafficClass).mockResolvedValue({ data: {} } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.mouseDown(within(screen.getByTestId('traffic-class-key_abc12345')).getByRole('combobox'))
    fireEvent.click(await screen.findByTitle('编程助手'))
    await waitFor(() => expect(keyApi.setTrafficClass).toHaveBeenCalledWith('key_abc12345', 'coding'))
    await waitFor(() => expect(vi.mocked(keyApi.list).mock.calls.length).toBeGreaterThan(1))
  })

  it('接口失败时给出明确提示，不假装已保存', async () => {
    const errorSpy = vi.spyOn(message, 'error').mockImplementation((() => undefined) as never)
    const successSpy = vi.spyOn(message, 'success').mockImplementation((() => undefined) as never)
    vi.mocked(keyApi.setTrafficClass).mockRejectedValue(new Error('boom'))
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.mouseDown(within(screen.getByTestId('traffic-class-key_abc12345')).getByRole('combobox'))
    // 下拉选项挂在 body 的 portal 里；列表里另一把密钥也显示"测评流量"，所以只在下拉层里找。
    const dropdown = await waitFor(() => { const el = document.querySelector('.ant-select-dropdown'); if (!el) throw new Error('dropdown not open'); return el as HTMLElement })
    fireEvent.click(within(dropdown).getByTitle('测评流量'))
    await waitFor(() => expect(keyApi.setTrafficClass).toHaveBeenCalled())
    await waitFor(() => expect(errorSpy).toHaveBeenCalledWith(expect.stringMatching(/流量类别保存失败/)))
    expect(successSpy).not.toHaveBeenCalled()
  })

  it('说明文字讲清楚这个标记只改告警分组，不影响检测与放行', async () => {
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    expect(screen.getAllByText(/只改变安全告警页的分组/).length).toBeGreaterThan(0)
  })
})

describe('Keys page — 复制完整密钥兜底（HTTP 明文页）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(keyApi.list).mockResolvedValue({ data: { items: [KEY_ROW] } } as never)
  })

  it('无 Clipboard API 且 execCommand 失败时，弹窗展示完整密钥供手动复制', async () => {
    // 模拟明文 HTTP 页：navigator.clipboard 不可用，execCommand 复制返回 false
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined })
    ;(document as unknown as { execCommand: () => boolean }).execCommand = vi.fn().mockReturnValue(false)

    vi.mocked(keyApi.reveal).mockResolvedValue({ data: { full_key: 'sk-HTTP-REVEAL-abc' } } as never)

    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')

    fireEvent.click(screen.getByRole('button', { name: /复制完整密钥/ }))

    await waitFor(() => expect(keyApi.reveal).toHaveBeenCalledWith('key_abc12345'))
    // 兜底弹窗：完整密钥出现在可复制的输入框里（标题为「完整密钥」）
    expect(await screen.findByDisplayValue('sk-HTTP-REVEAL-abc')).toBeTruthy()
    expect(screen.getByText('完整密钥')).toBeTruthy()
  })
})

describe('Keys page — 重置密钥', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(keyApi.list).mockResolvedValue({ data: { items: [KEY_ROW] } } as never)
  })

  it('确认后先撤销旧 key 再用同应用/用户/名称/scopes 建新 key，并一次性展示新完整密钥', async () => {
    vi.mocked(keyApi.revoke).mockResolvedValue({ data: {} } as never)
    vi.mocked(keyApi.create).mockResolvedValue({
      data: { id: 'key_new999', full_key: 'sk-NEW-RESET-KEY-abc123' },
    } as never)

    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')

    // 打开重置确认气泡（触发按钮带 redo 图标，无障碍名为「redo重置」，气泡未开时唯一）
    fireEvent.click(screen.getByRole('button', { name: /重置/ }))
    // 确认执行
    fireEvent.click(await screen.findByRole('button', { name: '确认重置' }))

    // 先撤销旧 key
    await waitFor(() => expect(keyApi.revoke).toHaveBeenCalledWith('key_abc12345'))
    // 再用同上下文建新 key
    await waitFor(() =>
      expect(keyApi.create).toHaveBeenCalledWith({
        project_id: 'proj_1',
        user_id: 'user_1',
        name: 'demo 应用密钥',
        scopes: ['chat'],
      }),
    )
    // 复用一次性弹窗展示新完整密钥
    expect(await screen.findByText('密钥已创建')).toBeTruthy()
  })
})

describe('Keys page — 部署后的对外调用地址', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(keyApi.list).mockResolvedValue({ data: { items: [] } } as never)
  })
  afterEach(() => {
    vi.mocked(api.get).mockResolvedValue({ data: {} } as never)
  })

  it.each([
    'http://customer.example:8084/v1',
    'https://models.example/customer/v1',
    'http://[2001:db8::1]:18080/v1',
  ])('固定地址模式优先展示并复制实际配置的地址 %s', async (base) => {
    vi.mocked(api.get).mockResolvedValue({ data: { gateway_public_base_url: base + '/', gateway_public_url_mode: 'configured' } } as never)
    const writeText = mockClipboard()
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText(base)
    expect(screen.queryByText(/http:\/\/.*:8080\/v1/)).toBeNull()
    expect(screen.queryByText(/https:\/\/.*:8453\/v1/)).toBeNull()
    const buttons = screen.getAllByRole('button', { name: /^(?:copy)?复制$/ })
    expect(buttons).toHaveLength(1)
    fireEvent.click(buttons[0])
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(base))
  })

  it('地址加载期间不展示猜测的端口', () => {
    vi.mocked(api.get).mockReturnValue(new Promise(() => {}))
    render(<Keys />, { wrapper: makeWrapper() })
    expect(screen.getByText('正在读取调用地址…')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /^(?:copy)?复制$/ })).toBeNull()
  })

  it('未配置固定地址时使用浏览器当前入口的实际端口', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: {} } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    expect(await screen.findByText(window.location.origin + '/v1')).toBeTruthy()
    expect(screen.getByRole('button', { name: /^(?:copy)?复制$/ })).toBeTruthy()
  })

  it('读取失败时提示错误，不回退到 8080', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('unavailable'))
    render(<Keys />, { wrapper: makeWrapper() })
    expect(await screen.findByText(/调用地址读取失败/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /^(?:copy)?复制$/ })).toBeNull()
  })
})

describe('Keys page - usage and quota data', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(keyApi.list).mockResolvedValue({ data: { items: [KEY_ROW] } } as never)
  })

  it('preserves owner wallet attribution without inventing key-level reservations or usage', async () => {
    vi.mocked(budgetApi.keyReadModel).mockResolvedValue({
      data: {
        data: {
          key: { id: 'key_abc12345', key_prefix: 'demo-key1', name: 'demo 应用密钥', status: 'active', attribution: 'user', user_id: 'user_1' },
          confirmed_usage: { available: false, reason_code: 'budget_snapshot_unavailable' },
          effective_quota: { daily_token_limit: 1000, monthly_token_limit: 0, quota_timezone: 'Asia/Shanghai' },
          window: { available: false, reason_code: 'invalid_bucket_labels' },
          in_flight: {
            key_level_available: false,
            key_level_reason: 'billing_reservations are wallet(user)-scoped; no key attribution exists',
            owner_level_available: true,
            owner_wallets: [
              { level: 'user', user_id: 'user_1', wallet_id: 'w1', currency: 'CNY', balance_micros: 5000000, reserved_micros: 1000000, available_micros: 4000000 },
            ],
          },
          generated_at: '2026-10-02T05:00:00Z',
        },
      },
    } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.click(screen.getByRole('button', { name: `${usageActionPrefix}${KEY_ROW.key_prefix}` }))
    // Wallet evidence must remain user-scoped when key attribution is unavailable.
    expect(await screen.findByText('用户级')).toBeInTheDocument()
    // An unavailable snapshot must not leak its internal reason code.
    expect(document.body.textContent).not.toContain('budget_snapshot_unavailable')
    // owner 级钱包证据按用户级标签如实展示
    expect(screen.getByText('用户级')).toBeInTheDocument()
    expect(screen.getByText('w1')).toBeInTheDocument()
    expect(document.body.textContent?.replace(/\s/g, ' ')).toContain('CNY 4.00')
  })

  it('把费用质量与桶时区摊开讲，不让含估算的总额被当成真实账单', async () => {
    vi.mocked(budgetApi.keyReadModel).mockResolvedValue({
      data: {
        data: {
          key: { id: 'key_abc12345', key_prefix: 'demo-key1', name: 'demo 应用密钥', status: 'active', attribution: 'user', user_id: 'user_1' },
          confirmed_usage: {
            available: true, month_tokens_available: true, month_requests_available: true, day_tokens_available: true, day_requests_available: true, scope: 'key',
            month_bucket: '2026-10', day_bucket: '2026-10-02',
            month_tokens: 100, month_requests: 5, month_cost_micros: 1_000_000,
            day_tokens: 20, day_requests: 2, day_cost_micros: 300_000,
            rpm: 3, concurrency: 1,
            // 本月：一笔按估算计费
            month_cost_quality: { observed_available: true, actual_available: false, coverage_verified: false, fields_present: { cost_micros: true, cost_estimated_requests: true, cost_unpriced_requests: true }, total_micros: 1_000_000, estimated_requests: 1, unpriced_requests: 0, quality: 'estimated' },
            // 今日：一笔既无价格也无估算 —— 总额低于真实花费
            day_cost_quality: { observed_available: true, actual_available: false, coverage_verified: false, fields_present: { cost_micros: true, cost_estimated_requests: true, cost_unpriced_requests: true }, total_micros: 300_000, estimated_requests: 0, unpriced_requests: 1, quality: 'unpriced' },
            cost_quality_note: "cost_micros is always the sum and is never adjusted by these labels",
            cost_currency_note: 'settlement currency is the owner wallet currency',
            bucket_timezone: 'Asia/Shanghai',
            bucket_timezone_source: 'key scope policy quota_timezone',
          },
          effective_quota: { daily_token_limit: 1000, monthly_token_limit: 0, quota_timezone: 'Asia/Shanghai' },
          window: { available: true, day_started_at: '2026-10-02T00:00:00Z', day_reset_at: '2026-10-03T00:00:00Z', month_started_at: '2026-10-01T00:00:00Z', month_reset_at: '2026-11-01T00:00:00Z' },
          in_flight: { key_level_available: false, key_level_reason: 'no key attribution', owner_level_available: false, owner_wallets: [] },
          generated_at: '2026-10-02T05:00:00Z',
        },
      },
    } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.click(screen.getByRole('button', { name: `${usageActionPrefix}${KEY_ROW.key_prefix}` }))
    // 两个窗口的质量各自独立报出，不合并
    expect(await screen.findByText('本月费用质量')).toBeInTheDocument()
    expect(screen.getByText('今日费用质量')).toBeInTheDocument()
    expect(screen.getByText('含估算价')).toBeInTheDocument()
    expect(screen.getByText(unpricedQualityLabel)).toBeInTheDocument()
    expect(screen.getByText('估算 1 笔')).toBeInTheDocument()
    // 质量标签必须说明后果，否则管理员仍会把总额当账单
    expect(screen.getAllByText(/总额不等于实际账单/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/总额不等于实际账单/).length).toBeGreaterThan(0)
    // 桶时区与来源：决定跨时区管理员看到的是不是同一天
    expect(screen.getByText(statisticsTimezoneLabel)).toBeInTheDocument()
    expect(screen.getByText('Asia/Shanghai')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('key scope policy quota_timezone')
  })

  it('未上报费用质量时如实标注，不默认当成全部实际价', async () => {
    vi.mocked(budgetApi.keyReadModel).mockResolvedValue({
      data: {
        data: {
          key: { id: 'key_abc12345', key_prefix: 'demo-key1', name: 'demo 应用密钥', status: 'active', attribution: 'user', user_id: 'user_1' },
          // 老版本后端：没有 cost_quality 字段
          confirmed_usage: { available: true, month_tokens_available: true, month_requests_available: true, day_tokens_available: true, day_requests_available: true, month_tokens: 10, month_requests: 1, month_cost_micros: 500_000, day_tokens: 1, day_requests: 1, day_cost_micros: 100_000, rpm: 1, concurrency: 1 },
          effective_quota: { daily_token_limit: 1000, monthly_token_limit: 0, quota_timezone: 'Asia/Shanghai' },
          window: { available: false, reason_code: 'invalid_bucket_labels' },
          in_flight: { key_level_available: false, key_level_reason: 'no key attribution', owner_level_available: false, owner_wallets: [] },
          generated_at: '2026-10-02T05:00:00Z',
        },
      },
    } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.click(screen.getByRole('button', { name: `${usageActionPrefix}${KEY_ROW.key_prefix}` }))
    expect(await screen.findByText('本月费用质量')).toBeInTheDocument()
    // 缺失即未上报，绝不显示成绿色「全部实际价」
    expect(screen.getAllByText(pendingCostLabel)).toHaveLength(2)
    expect(screen.queryByText('全部实际价')).not.toBeInTheDocument()
  })

  it.each([
    { quality: 'actual' },
    { quality: 'actual', estimated_requests: 0, unpriced_requests: 0, fields_present: { cost_estimated_requests: true, cost_unpriced_requests: true } },
    { quality: 'actual', estimated_requests: null, unpriced_requests: null },
  ])('does not infer actual-price coverage from missing or zero counters %j', async (quality) => {
    vi.mocked(budgetApi.keyReadModel).mockResolvedValue({ data: { data: {
      key: { id: 'key_abc12345', attribution: 'user' },
      confirmed_usage: { available: true, month_tokens_available: true, month_requests_available: true, day_tokens_available: true, day_requests_available: true, month_tokens: 10, month_requests: 1, month_cost_micros: null,
        day_tokens: 2, day_requests: 1, day_cost_micros: 0, rpm: 0, concurrency: 0,
        month_cost_quality: quality, day_cost_quality: quality },
      window: { available: false }, effective_quota: {}, in_flight: { owner_level_available: false },
    } } } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.click(screen.getByRole('button', { name: `${usageActionPrefix}${KEY_ROW.key_prefix}` }))
    expect(await screen.findAllByText(pendingCostLabel)).toHaveLength(2)
    expect(screen.getByText(/10 tokens/)).toBeInTheDocument()
    expect(screen.getByText(/2 tokens/)).toBeInTheDocument()
    expect(screen.queryByText('全部实际价')).not.toBeInTheDocument()
    expect(screen.queryByText('无计费样本')).not.toBeInTheDocument()
  })

  it('keeps volume evidence when cost is unavailable and honors cost field presence independently per bucket', async () => {
    vi.mocked(budgetApi.keyReadModel).mockResolvedValue({ data: { data: {
      key: { id: 'key_abc12345', attribution: 'user' },
      confirmed_usage: { available: true,
        month_tokens: 101, month_tokens_available: true, month_requests: 7, month_requests_available: true,
        day_tokens: 9999, day_tokens_available: false, day_requests: 3, day_requests_available: true,
        month_cost_micros: 777777, day_cost_micros: 333333,
        month_cost_quality: { observed_available: false, actual_available: false, coverage_verified: false,
          total_micros: 777777, estimated_requests: 8, unpriced_requests: 9,
          fields_present: { cost_micros: false, cost_estimated_requests: false, cost_unpriced_requests: false } },
        day_cost_quality: { observed_available: true, actual_available: false, coverage_verified: false,
          total_micros: 333333, estimated_requests: 1, unpriced_requests: 2,
          fields_present: { cost_micros: true, cost_estimated_requests: true, cost_unpriced_requests: true } },
        cost_currency: 'USD', cost_currency_available: true, cost_currency_note: 'internal_currency_note',
        rpm: 0, concurrency: 0 },
      window: { available: false }, effective_quota: {}, in_flight: { owner_level_available: false },
    } } } as never)
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText('demo-key1')
    fireEvent.click(screen.getByRole('button', { name: `${usageActionPrefix}${KEY_ROW.key_prefix}` }))
    expect(await screen.findByText(/101 tokens/)).toBeInTheDocument()
    expect(screen.getByText(/7 /)).toBeInTheDocument()
    expect(screen.queryByText(/777,777/)).not.toBeInTheDocument()
    expect(screen.queryByText(/9,999/)).not.toBeInTheDocument()
    expect(document.body.textContent?.replace(/\s/g, ' ')).toContain('USD 0.33')
    expect(screen.getAllByText(pendingCostLabel)).toHaveLength(1)
    expect(screen.getByText(unpricedQualityLabel)).toBeInTheDocument()
    expect(screen.getByText('估算 1 笔')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('estimated_requests=')
    expect(document.body.textContent).not.toContain('internal_currency_note')
  })
})


describe('Keys page - delete usable keys', () => {
  it.each(['active', 'revoked'])('deletes a %s key after one confirmation and refreshes the list', async (status) => {
    vi.clearAllMocks()
    vi.mocked(keyApi.list).mockResolvedValue({ data: { items: [{ ...KEY_ROW, status }] } } as never)
    vi.mocked(keyApi.delete).mockImplementation(async () => {
      vi.mocked(keyApi.list).mockResolvedValue({ data: { items: [] } } as never)
      return { data: {} } as never
    })
    render(<Keys />, { wrapper: makeWrapper() })
    await screen.findByText(KEY_ROW.key_prefix)
    fireEvent.click(screen.getByRole('button', { name: /删除/ }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('密钥立即失效')
    expect(keyApi.delete).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: /删\s*除/ }))
    await waitFor(() => expect(keyApi.delete).toHaveBeenCalledOnce())
    expect(keyApi.delete).toHaveBeenCalledWith(KEY_ROW.id)
    await waitFor(() => expect(screen.queryByText(KEY_ROW.key_prefix)).not.toBeInTheDocument())
  })
})

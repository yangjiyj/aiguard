import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import OperationAudit from '../pages/OperationAudit'
import { statsApi, ws8AuditApi } from '../services/api'
import { useAuthStore } from '../stores/auth'

vi.mock('../services/api', () => ({
  operationAuditApi: {
    list: vi.fn(),
  },
  // W8 8.7：列表改走带筛选 / 服务端分页的接口，导出走服务端全量。
  ws8AuditApi: {
    listOperations: vi.fn(),
    exportOperations: vi.fn(),
  },
  statsApi: {
    getOverview: vi.fn(),
  },
}))

vi.mock('../utils/reportExport', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../utils/reportExport')>()
  return { ...actual, downloadBlob: vi.fn() }
})

const operationAuditApi = { list: ws8AuditApi.listOperations }

describe('OperationAudit page', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
    vi.mocked(statsApi.getOverview).mockResolvedValue({
      data: { timezone: 'Asia/Shanghai', execution_mode: { mode: 'record' } },
    } as any)
    useAuthStore.setState({
      token: 'admin-token',
      user: { id: 'admin-a', username: 'A', role: 'platform_admin', tenant_id: 'tenant-a' },
      isAuthenticated: true,
    })
  })

  const renderPage = (initialEntries = ['/system/audit-operations']) =>
    render(
      <MemoryRouter initialEntries={initialEntries}>
        <QueryClientProvider client={queryClient}>
          <OperationAudit />
        </QueryClientProvider>
      </MemoryRouter>
    )

  it('loads operation logs through the authenticated admin API client', async () => {
    vi.mocked(operationAuditApi.list).mockResolvedValue({
      data: {
        data: [
          {
            id: 'op_001',
            user_id: 'user_admin',
            action_type: 'update_system_settings',
            action_detail: { security_audit_only: 'true' },
            target_type: 'system',
            target_id: 'settings',
            ip_address: '127.0.0.1',
            created_at: '2026-05-11T09:01:35Z',
          },
        ],
        total: 1,
      },
    } as any)

    renderPage()

    expect(await screen.findByText('user_admin')).toBeInTheDocument()
    expect(screen.getByText('修改系统设置')).toBeInTheDocument()
    expect(screen.getByText('settings')).toBeInTheDocument()
    expect(screen.getByText('安全审计模式：true')).toBeInTheDocument()
    expect(screen.queryByText('{"security_audit_only":"true"}')).not.toBeInTheDocument()
    expect(operationAuditApi.list).toHaveBeenCalledWith({ limit: 20, offset: 0 })
    const auditQuery = queryClient.getQueryCache().getAll().find((q) => q.queryKey[0] === 'audit-operations')
    expect(auditQuery?.queryKey).toEqual([
      'audit-operations',
      'tenant-a|admin-a|platform_admin',
      {},
      1,
    ])
  })

  it('renders backend operation codes as Chinese audit language', async () => {
    vi.mocked(operationAuditApi.list).mockResolvedValue({
      data: {
        data: [
          {
            id: 'op_fx_001',
            user_id: '',
            action_type: 'fx.update',
            action_detail: { effective_at: '2026-06-10T11:13:44Z', rate: 7.35 },
            target_type: 'fx_rate',
            target_id: 'USD_CNY',
            ip_address: '192.168.1.4',
            created_at: '2026-06-10T11:13:44Z',
          },
        ],
        total: 1,
      },
    } as any)

    renderPage()

    expect(await screen.findByText('系统任务')).toBeInTheDocument()
    expect(screen.getByText('更新汇率')).toBeInTheDocument()
    expect(screen.getByText('汇率设置')).toBeInTheDocument()
    expect(screen.getByText('汇率：7.35')).toBeInTheDocument()
    expect(screen.queryByText('fx.update')).not.toBeInTheDocument()
    expect(screen.queryByText('fx_rate')).not.toBeInTheDocument()
    expect(screen.queryByText('{"effective_at":"2026-06-10T11:13:44Z","rate":7.35}')).not.toBeInTheDocument()
  })

  it('把消息中心批量已读的审计动作显示为中文，不露 alert_inbox.bulk_read', async () => {
    vi.mocked(operationAuditApi.list).mockResolvedValue({
      data: {
        data: [
          {
            id: 'op_bulk_read',
            user_id: 'user_admin',
            action_type: 'alert_inbox.bulk_read',
            action_detail: {},
            target_type: 'alert_inbox',
            target_id: 'alert',
            ip_address: '127.0.0.1',
            created_at: '2026-10-22T01:00:00Z',
          },
        ],
        total: 1,
      },
    } as any)

    renderPage()

    expect(await screen.findByText('批量标记消息已读')).toBeInTheDocument()
    expect(screen.queryByText('alert_inbox.bulk_read')).not.toBeInTheDocument()
    expect(screen.queryByText('系统操作')).not.toBeInTheDocument()
  })

  it('renders price version and zero-price audit actions as Chinese audit language', async () => {
    vi.mocked(operationAuditApi.list).mockResolvedValue({
      data: {
        data: [
          {
            id: 'op_price_001', user_id: 'admin-a', username: 'A', action_type: 'billing.price.create',
            action_detail: { model_name: 'gpt-x', old_version: 2, version: 3, zero_price_confirmed: true },
            target_type: 'billing_price', target_id: 'gpt-x', ip_address: '192.168.1.4', created_at: '2026-10-22T11:13:44Z',
          },
          {
            id: 'op_price_002', user_id: 'admin-a', username: 'A', action_type: 'billing.price.zero_rejected',
            action_detail: { model_name: 'gpt-y' }, target_type: 'billing_price', target_id: 'gpt-y', ip_address: '192.168.1.4', created_at: '2026-10-22T11:14:44Z',
          },
          {
            id: 'op_price_003', user_id: 'admin-a', username: 'A', action_type: 'billing.ratio_price.create',
            action_detail: { change_summary: '输入 ¥4.00 → ¥2.00' }, target_type: 'billing_price', target_id: 'gpt-z', ip_address: '192.168.1.4', created_at: '2026-10-22T11:15:44Z',
          },
          {
            id: 'op_price_004', user_id: 'admin-a', username: 'A', action_type: 'billing.price.unchanged',
            action_detail: { model_name: 'gpt-u' }, target_type: 'billing_price', target_id: 'gpt-u', ip_address: '192.168.1.4', created_at: '2026-10-22T11:16:44Z',
          },
        ],
        total: 4,
      },
    } as any)

    renderPage()

    expect(await screen.findByText('新增模型价格版本')).toBeInTheDocument()
    expect(screen.getByText('拦截价格清零')).toBeInTheDocument()
    expect(screen.getByText('新增倍率价格版本')).toBeInTheDocument()
    expect(screen.getByText('价格未变化（未新增版本）')).toBeInTheDocument()
    expect(screen.getByText('已确认改为 0：是')).toBeInTheDocument()
    expect(screen.getByText('原版本：2')).toBeInTheDocument()
    expect(screen.getByText('新版本：3')).toBeInTheDocument()
    expect(screen.getByText('价格变化：输入 ¥4.00 → ¥2.00')).toBeInTheDocument()
    expect(screen.queryByText('系统操作')).not.toBeInTheDocument()
    expect(screen.queryByText('billing.price.create')).not.toBeInTheDocument()
  })

  it('passes user_id from the URL so delete blocker links land on the right audit records', async () => {
    vi.mocked(operationAuditApi.list).mockResolvedValue({
      data: {
        data: [
          {
            id: 'op_002',
            user_id: 'user_blocked',
            action_type: 'create_key',
            action_detail: { key_id: 'key_001' },
            target_type: 'internal_key',
            target_id: 'key_001',
            ip_address: '127.0.0.1',
            created_at: '2026-05-11T09:11:35Z',
          },
        ],
        total: 1,
      },
    } as any)

    renderPage(['/system/audit-operations?user_id=user_blocked&audit_id=op_002'])

    expect(await screen.findByText('user_blocked')).toBeInTheDocument()
    expect(operationAuditApi.list).toHaveBeenCalledWith({
      limit: 20,
      offset: 0,
      user_id: 'user_blocked',
    })
  })

  const oneRow = (overrides: Record<string, unknown> = {}) => ({
    data: {
      data: [
        {
          id: 'op_w8',
          user_id: 'user_w8',
          action_type: 'create_key',
          action_detail: {},
          target_type: 'internal_key',
          target_id: 'key_w8',
          ip_address: '10.0.0.8',
          created_at: '2026-05-11T09:01:35Z',
          ...overrides,
        },
      ],
      total: 57,
    },
  })

  it('W8 8.9: renders operation time in the tenant timezone from stats overview', async () => {
    vi.mocked(statsApi.getOverview).mockResolvedValue({ data: { timezone: 'Asia/Tokyo' } } as any)
    vi.mocked(ws8AuditApi.listOperations).mockResolvedValue(oneRow() as any)

    renderPage()

    // 09:01:35Z 在东京时区为 18:01:35，与导出文件使用同一时区。
    expect(await screen.findByText('2026-05-11 18:01:35')).toBeInTheDocument()
  })

  it('W8 8.7: shows the backend username and server-side total, and paginates on the server', async () => {
    vi.mocked(ws8AuditApi.listOperations).mockResolvedValue(oneRow({ username: 'alice' }) as any)

    renderPage()

    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.queryByText('user_w8')).not.toBeInTheDocument()
    expect(screen.getByText(/57/, { selector: '.ant-pagination-total-text' })).toBeInTheDocument()
    fireEvent.click(screen.getByTitle('2'))
    await waitFor(() => expect(ws8AuditApi.listOperations).toHaveBeenLastCalledWith({ limit: 20, offset: 20 }))
  })

  it('W8 8.7: filters by action type on the server', async () => {
    vi.mocked(ws8AuditApi.listOperations).mockResolvedValue(oneRow() as any)

    renderPage()
    await screen.findByText('user_w8')

    const actionSelect = screen.getByRole('combobox', { name: '按操作类型筛选' })
    fireEvent.mouseDown(actionSelect)
    const firstOption = await waitFor(() => {
      const el = document.querySelector('.ant-select-item-option')
      expect(el).not.toBeNull()
      return el as HTMLElement
    })
    fireEvent.click(firstOption)

    await waitFor(() => expect(ws8AuditApi.listOperations).toHaveBeenLastCalledWith({
      action_type: 'update_system_settings',
      limit: 20,
      offset: 0,
    }))
  })

  it('W8 8.7: export trail records render as named actions, not the generic fallback', async () => {
    vi.mocked(ws8AuditApi.listOperations).mockResolvedValue({
      data: {
        data: ['export_operation_audit', 'export_block_records', 'export_alert_inbox'].map((action, i) => ({
          id: `op_exp_${i}`, user_id: 'user_w8', action_type: action, action_detail: {}, target_type: 'audit', target_id: '', created_at: '2026-05-11T09:01:35Z',
        })),
        total: 3,
      },
    } as any)

    renderPage()

    await screen.findAllByText('user_w8')
    expect(screen.queryByText('系统操作')).not.toBeInTheDocument()
    expect(screen.queryByText('export_operation_audit')).not.toBeInTheDocument()
  })

  it('W8 8.7: exports CSV and XLSX on the server with the same filters as the list', async () => {
    vi.mocked(ws8AuditApi.listOperations).mockResolvedValue(oneRow() as any)
    vi.mocked(ws8AuditApi.exportOperations).mockResolvedValue({ data: new Blob(['x']) } as any)

    renderPage(['/system/audit-operations?user_id=user_w8'])
    await screen.findByText('user_w8')

    fireEvent.click(screen.getByRole('button', { name: /CSV/ }))
    await waitFor(() => expect(ws8AuditApi.exportOperations).toHaveBeenCalledWith('csv', { user_id: 'user_w8' }))
    fireEvent.click(screen.getByRole('button', { name: /Excel/ }))
    await waitFor(() => expect(ws8AuditApi.exportOperations).toHaveBeenCalledWith('xlsx', { user_id: 'user_w8' }))
  })

  it('renders provider recovery and routing lifecycle actions as readable audit events', async () => {
    vi.mocked(operationAuditApi.list).mockResolvedValue({
      data: {
        data: [
          { id: 'op_restore', user_id: 'admin', action_type: 'restore_provider', action_detail: { restored: true }, target_type: 'provider', target_id: 'provider_1', created_at: '2026-08-26T10:00:00Z' },
          { id: 'op_reject', user_id: 'admin', action_type: 'delete_provider_rejected', action_detail: { reason: 'provider_in_use' }, target_type: 'provider', target_id: 'provider_1', created_at: '2026-08-26T10:01:00Z' },
          { id: 'op_route', user_id: 'admin', action_type: 'model_routing_default_saved', action_detail: { scope: 'default' }, target_type: 'model_routing', target_id: 'default', created_at: '2026-08-26T10:02:00Z' },
        ],
        total: 3,
      },
    } as any)

    renderPage()

    expect(await screen.findByText('恢复模型上游')).toBeInTheDocument()
    expect(screen.getByText('拒绝删除在用模型上游')).toBeInTheDocument()
    expect(screen.getByText('保存默认模型路由')).toBeInTheDocument()
    expect(screen.queryByText('restore_provider')).not.toBeInTheDocument()
    expect(screen.queryByText('delete_provider_rejected')).not.toBeInTheDocument()
  })

  it('安全策略的新建、修改、批量修改、删除都按中文动作显示，不落到“系统操作”', async () => {
    vi.mocked(operationAuditApi.list).mockResolvedValue({
      data: {
        data: [
          { id: 'op_sp_create', user_id: 'admin', action_type: 'security_policy.create', action_detail: {}, target_type: 'security_policy', target_id: 'rule_a', created_at: '2026-11-09T10:00:00Z' },
          { id: 'op_sp_update', user_id: 'admin', action_type: 'security_policy.update', action_detail: {}, target_type: 'security_policy', target_id: 'rule_a', created_at: '2026-11-09T10:01:00Z' },
          { id: 'op_sp_batch', user_id: 'admin', action_type: 'security_policy.batch_update', action_detail: { count: 3 }, target_type: 'security_policy', target_id: 'batch', created_at: '2026-11-09T10:02:00Z' },
          { id: 'op_sp_delete', user_id: 'admin', action_type: 'security_policy.delete', action_detail: { policy_id: 'rule_a', name: '厂房关键词' }, target_type: 'security_policy', target_id: 'rule_a', created_at: '2026-11-09T10:03:00Z' },
        ],
        total: 4,
      },
    } as any)

    renderPage()

    expect(await screen.findByText('删除安全策略')).toBeInTheDocument()
    expect(screen.getByText('创建安全策略')).toBeInTheDocument()
    expect(screen.getByText('修改安全策略')).toBeInTheDocument()
    expect(screen.getByText('批量修改安全策略')).toBeInTheDocument()
    expect(screen.getByText('名称：厂房关键词')).toBeInTheDocument()
    expect(screen.getByText('策略编号：rule_a')).toBeInTheDocument()
    expect(screen.queryByText('系统操作')).not.toBeInTheDocument()
    expect(screen.queryByText('业务对象')).not.toBeInTheDocument()
    expect(screen.queryByText('security_policy.delete')).not.toBeInTheDocument()
  })
})

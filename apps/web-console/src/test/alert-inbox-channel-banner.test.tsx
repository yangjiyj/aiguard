import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import AlertInbox from '../pages/AlertInbox'
import * as api from '../services/api'

const BANNER = '尚未配置告警通知渠道，告警只会留在本页'

describe('消息中心：告警通知渠道为 0 时的常驻提示', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.restoreAllMocks()
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [] } } as any)
    // 页面默认是「按天折叠」视图，会先请求折叠接口；这里只给空结果，避免渲染瞬间发出真实 HTTP 请求。
    vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue({ data: { groups: [], total_groups: 0, total_items: 0, unread_count: 0 } } as any)
  })

  // 本文件验证的是通知渠道横幅（与展示方式无关）；渲染后切到「逐条明细」，保持原有用例语义（仍断言旧接口被调用）。
  const renderPage = () => {
    const view = render(
      <MemoryRouter initialEntries={['/cost/alerts']}>
        <QueryClientProvider client={queryClient}>
          <Routes>
            <Route path="/cost/alerts" element={<AlertInbox />} />
            <Route path="/system/notify-channels" element={<div>通知渠道配置页</div>} />
          </Routes>
        </QueryClientProvider>
      </MemoryRouter>,
    )
    fireEvent.click(within(screen.getByRole('radiogroup', { name: '消息展示方式' })).getByText('逐条明细'))
    return view
  }

  it('0 个渠道时显示提示，点「去配置」跳到渠道配置页', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({ data: { channels: [] } } as any)
    renderPage()
    expect(await screen.findByText(BANNER)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '去配置' }))
    expect(await screen.findByText('通知渠道配置页')).toBeInTheDocument()
  })

  it('已有渠道时不显示提示', async () => {
    const list = vi.spyOn(api.notifyApi, 'list').mockResolvedValue({
      data: { channels: [{ id: 'nc_1', type: 'feishu', name: '安全值班群', enabled: true, config_json: {} }] },
    } as any)
    renderPage()
    await waitFor(() => expect(list).toHaveBeenCalled())
    await waitFor(() => expect(api.alertApi.inbox).toHaveBeenCalled())
    expect(screen.queryByText(BANNER)).not.toBeInTheDocument()
  })

  it('渠道接口失败（如无权限）时不显示提示，避免误导', async () => {
    const list = vi.spyOn(api.notifyApi, 'list').mockRejectedValue({ response: { status: 403 } })
    renderPage()
    await waitFor(() => expect(list).toHaveBeenCalled())
    expect(screen.queryByText(BANNER)).not.toBeInTheDocument()
  })
})

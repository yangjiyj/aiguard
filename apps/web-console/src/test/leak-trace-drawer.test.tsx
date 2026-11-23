import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import LeakTraceDrawer from '../components/LeakTraceDrawer'

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../services/api', () => ({ default: mockApi }))

const renderDrawer = () =>
  render(
    <MemoryRouter>
      <LeakTraceDrawer open onClose={() => {}} />
    </MemoryRouter>,
  )

describe('LeakTraceDrawer', () => {
  beforeEach(() => vi.clearAllMocks())

  it('水印命中时显示请求并链接到对应留证', async () => {
    mockApi.post.mockResolvedValue({
      data: {
        method: 'watermark',
        watermark: 'verified',
        matches: [{ request_id: 'req_abc', occurred_at: '2026-10-30T08:00:00Z', username: 'zhangsan', target: 'gpt-4', agent_type: 'enterprise-portal' }],
      },
    })
    renderDrawer()
    await userEvent.type(screen.getByLabelText('疑似泄露的文本'), '泄露的回答')
    await userEvent.click(screen.getByRole('button', { name: '开始溯源' }))

    expect(await screen.findByText('已通过隐式水印定位到原始请求')).toBeInTheDocument()
    expect(mockApi.post).toHaveBeenCalledWith('/audit/leak-trace', { text: '泄露的回答' })
    expect(screen.getByText('zhangsan')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '查看留证' })).toHaveAttribute('href', '/audit/access-retention?request_id=req_abc')
  })

  it('没有水印时展示检索片段和未命中提示', async () => {
    mockApi.post.mockResolvedValue({
      data: { method: 'fragments', watermark: 'absent', fragments: ['第一段足够长的片段'], matches: [], note: '在所选时间范围内没有找到包含这些片段的助手回复' },
    })
    renderDrawer()
    await userEvent.type(screen.getByLabelText('疑似泄露的文本'), '一段文字')
    await userEvent.click(screen.getByRole('button', { name: '开始溯源' }))

    expect(await screen.findByText(/没有可用的隐式水印/)).toBeInTheDocument()
    expect(screen.getByText('第一段足够长的片段')).toBeInTheDocument()
    expect(screen.getByText('在所选时间范围内没有找到包含这些片段的助手回复')).toBeInTheDocument()
  })

  it('校验未通过的水印给出警告，接口报错时显示服务端原因', async () => {
    mockApi.post.mockResolvedValueOnce({ data: { method: 'fragments', watermark: 'forged', fragments: ['x'.repeat(20)], matches: [] } })
    renderDrawer()
    await userEvent.type(screen.getByLabelText('疑似泄露的文本'), 'abc')
    await userEvent.click(screen.getByRole('button', { name: '开始溯源' }))
    expect(await screen.findByText('文本里有格式完整的水印，但校验未通过')).toBeInTheDocument()

    // antd 加载图标退出动画期间仍计入按钮名称，按正则找按钮并等加载结束再点。
    await waitFor(() => expect(screen.getByRole('button', { name: /开始溯源/ })).not.toHaveClass('ant-btn-loading'))
    mockApi.post.mockRejectedValueOnce({ response: { data: { error: { message: '文本过长' } } } })
    await userEvent.click(screen.getByRole('button', { name: /开始溯源/ }))
    await waitFor(() => expect(screen.getByText('文本过长')).toBeInTheDocument())
  })

  it('没有输入时不能提交', () => {
    renderDrawer()
    expect(screen.getByRole('button', { name: '开始溯源' })).toBeDisabled()
  })
})

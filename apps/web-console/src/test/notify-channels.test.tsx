import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import NotifyChannels from '../pages/NotifyChannels'
import * as api from '../services/api'

// NotifyChannels 页规格测试（TDD 红）
// 后端已完整：deploy/migrations/024_notify_channels.sql + notify_handler.go
// Dispatcher 发送 email/webhook/dingtalk/wecom/feishu 五种渠道；页面可对单个渠道发送测试消息

describe('NotifyChannels CRUD', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
  })

  const renderPage = () =>
    render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <NotifyChannels />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  const openChannelTypeSelect = () => {
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '渠道类型' }))
  }

  const fillInput = (label: string, value: string) => {
    fireEvent.change(screen.getByLabelText(label), { target: { value } })
  }

  // ===== Test 1: 列表渲染 =====
  it('renders notify channels list with type/name/enabled status', async () => {
    // 后端返回 {channels: [...]}
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({
      data: {
        channels: [
          { id: 'nc_email01', type: 'email', name: '运维告警邮箱', enabled: true, config_json: { host: 'smtp.example.com', port: 465 } },
          { id: 'nc_webhook01', type: 'webhook', name: 'Slack 推送', enabled: false, config_json: { url: 'https://hooks.slack.com/xxx' } },
          { id: 'nc_dingtalk01', type: 'dingtalk', name: '钉钉机器人', enabled: true, config_json: { access_token: 'abc123' } },
        ],
      },
    } as any)

    renderPage()

    // 等待数据加载完成（header 立即渲染，但数据依赖查询）
    expect(await screen.findByText('运维告警邮箱')).toBeInTheDocument()
    expect(screen.getByText('Slack 推送')).toBeInTheDocument()
    expect(screen.getByText('钉钉机器人')).toBeInTheDocument()
    // 类型显示（友好名）
    expect(screen.getByText('邮件')).toBeInTheDocument()
    expect(screen.getByText('Webhook')).toBeInTheDocument()
    expect(screen.getByText('钉钉')).toBeInTheDocument()
    // 启用状态（Switch checkedChildren/unCheckedChildren 显示为文本）
    expect(screen.getAllByText('启用').length).toBe(2)
    expect(screen.getByText('禁用')).toBeInTheDocument()
  })

  // ===== Test 2: 创建邮件渠道 =====
  it('creates email channel with host/port/from/to config', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({ data: { channels: [] } } as any)
    vi.spyOn(api.notifyApi, 'create').mockResolvedValue({
      data: { id: 'nc_email02', type: 'email', name: '安全告警邮箱', enabled: true },
    } as any)

    renderPage()

    await screen.findByText('通知渠道配置')

    // 点击新建按钮（antd icon 会污染 aria-label，用 regex 匹配）
    fireEvent.click(screen.getByRole('button', { name: /新建渠道/ }))

    // 弹窗出现
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('新建通知渠道')).toBeInTheDocument()

    // 选择类型：邮件
    openChannelTypeSelect()
    fireEvent.click(screen.getByText('邮件'))

    // 填写名称
    fillInput('渠道名称', '安全告警邮箱')

    // 填写邮件配置（host/port/from/to）
    fillInput('SMTP 主机', 'smtp.secure.com')
    fillInput('端口', '587')
    fillInput('发件人', 'alert@secure.com')
    fillInput('收件人（逗号分隔）', 'ops@secure.com,sec@secure.com')

    // 提交（antd Modal OK button 文本可见，用 getByText 避免 aria-label 污染）
    fireEvent.click(screen.getByText('确认'))

    await waitFor(() => {
      expect(api.notifyApi.create).toHaveBeenCalledWith({
        type: 'email',
        name: '安全告警邮箱',
        config_json: {
          host: 'smtp.secure.com',
          port: '587',
          from: 'alert@secure.com',
          to: ['ops@secure.com', 'sec@secure.com'],
        },
      })
    })
  })

  // ===== Test 3: 创建 Webhook 渠道 =====
  it('creates webhook channel with url/method/headers config', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({ data: { channels: [] } } as any)
    vi.spyOn(api.notifyApi, 'create').mockResolvedValue({
      data: { id: 'nc_webhook02', type: 'webhook', name: '企业微信机器人', enabled: true },
    } as any)

    renderPage()

    await screen.findByText('通知渠道配置')
    fireEvent.click(screen.getByRole('button', { name: /新建渠道/ }))
    expect(await screen.findByRole('dialog')).toBeInTheDocument()

    // 选择类型：Webhook
    openChannelTypeSelect()
    fireEvent.click(screen.getByText('Webhook'))

    // 填写名称
    fillInput('渠道名称', '企业微信机器人')

    // 填写 webhook 配置
    fillInput('URL', 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx')
    // 方法默认 POST，不点下拉避免"POST"重复匹配

    // 提交
    fireEvent.click(screen.getByRole('button', { name: /确认/ }))

    await waitFor(() => {
      expect(api.notifyApi.create).toHaveBeenCalledWith({
        type: 'webhook',
        name: '企业微信机器人',
        config_json: {
          url: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx',
          method: 'POST',
        },
      })
    })
  })

  // ===== Test 4: 创建钉钉渠道 =====
  it('creates dingtalk channel with access_token/secret config', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({ data: { channels: [] } } as any)
    vi.spyOn(api.notifyApi, 'create').mockResolvedValue({
      data: { id: 'nc_dingtalk02', type: 'dingtalk', name: '运维钉钉群', enabled: true },
    } as any)

    renderPage()

    await screen.findByText('通知渠道配置')
    fireEvent.click(screen.getByRole('button', { name: /新建渠道/ }))
    expect(await screen.findByRole('dialog')).toBeInTheDocument()

    // 选择类型：钉钉
    openChannelTypeSelect()
    fireEvent.click(screen.getByText('钉钉'))

    // 填写名称
    fillInput('渠道名称', '运维钉钉群')

    // 填写钉钉配置
    fillInput('Access Token', 'dingtalk_token_xxx')
    fillInput('签名密钥', 'secret_key_yyy')

    // 提交
    fireEvent.click(screen.getByRole('button', { name: /确认/ }))

    await waitFor(() => {
      expect(api.notifyApi.create).toHaveBeenCalledWith({
        type: 'dingtalk',
        name: '运维钉钉群',
        config_json: {
          access_token: 'dingtalk_token_xxx',
          secret: 'secret_key_yyy',
        },
      })
    })
  })

  // ===== Test 5: 编辑渠道 =====
  it('edits channel name and config_json', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({
      data: {
        channels: [
          { id: 'nc_email01', type: 'email', name: '运维告警邮箱', enabled: true, config_json: { host: 'smtp.example.com', port: 465 } },
        ],
      },
    } as any)
    vi.spyOn(api.notifyApi, 'update').mockResolvedValue({ data: { ok: true } } as any)

    renderPage()

    expect(await screen.findByText('运维告警邮箱')).toBeInTheDocument()

    // 点击编辑按钮
    fireEvent.click(screen.getByRole('button', { name: /编辑/ }))

    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('编辑通知渠道')).toBeInTheDocument()

    // 修改名称
    fillInput('渠道名称', '运维告警邮箱-已更新')

    // 修改端口
    fillInput('端口', '587')

    // 提交
    fireEvent.click(screen.getByRole('button', { name: /确认/ }))

    await waitFor(() => {
      expect(api.notifyApi.update).toHaveBeenCalledWith('nc_email01', {
        name: '运维告警邮箱-已更新',
        config_json: {
          host: 'smtp.example.com',
          port: '587',
        },
        enabled: true,
      })
    })
  })

  // ===== Test 6: 启用/禁用切换 =====
  it('toggles channel enabled status', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({
      data: {
        channels: [
          { id: 'nc_webhook01', type: 'webhook', name: 'Slack 推送', enabled: false, config_json: { url: 'https://hooks.slack.com/xxx' } },
        ],
      },
    } as any)
    vi.spyOn(api.notifyApi, 'update').mockResolvedValue({ data: { ok: true } } as any)

    renderPage()

    expect(await screen.findByText('Slack 推送')).toBeInTheDocument()
    expect(screen.getByText('禁用')).toBeInTheDocument()

    // 点击启用开关
    await userEvent.click(screen.getByRole('switch', { name: '启用状态' }))

    await waitFor(() => {
      expect(api.notifyApi.update).toHaveBeenCalledWith('nc_webhook01', {
        name: 'Slack 推送',
        config_json: { url: 'https://hooks.slack.com/xxx' },
        enabled: true,
      })
    })
  })

  // ===== Test 7: 删除渠道 =====
  it('deletes channel with confirmation', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({
      data: {
        channels: [
          { id: 'nc_dingtalk01', type: 'dingtalk', name: '钉钉机器人', enabled: true, config_json: { access_token: 'abc123' } },
        ],
      },
    } as any)
    vi.spyOn(api.notifyApi, 'delete').mockResolvedValue({ data: { ok: true } } as any)

    renderPage()

    expect(await screen.findByText('钉钉机器人')).toBeInTheDocument()

    // 点击删除按钮
    await userEvent.click(screen.getByRole('button', { name: /删除/ }))

    // 确认弹窗（Popconfirm 的 okText="确认删除"，避免 title 冲突）
    expect(await screen.findByText('删除确认')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /确认删除/ }))

    await waitFor(() => {
      expect(api.notifyApi.delete).toHaveBeenCalledWith('nc_dingtalk01')
    })
  })

  // ===== Test 8: 不暴露 wecom/feishu（假按钮约束）=====
  it('offers wecom and feishu now that the dispatcher sends them', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({ data: { channels: [] } } as any)

    renderPage()

    await screen.findByText('通知渠道配置')
    fireEvent.click(screen.getByRole('button', { name: /新建渠道/ }))
    expect(await screen.findByRole('dialog')).toBeInTheDocument()

    openChannelTypeSelect()
    for (const label of ['邮件', 'Webhook', '钉钉', '企业微信', '飞书']) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
  })

  it('creates wecom channel from robot webhook url', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({ data: { channels: [] } } as any)
    vi.spyOn(api.notifyApi, 'create').mockResolvedValue({ data: { id: 'nc_wecom01' } } as any)

    renderPage()
    await screen.findByText('通知渠道配置')
    fireEvent.click(screen.getByRole('button', { name: /新建渠道/ }))
    expect(await screen.findByRole('dialog')).toBeInTheDocument()

    openChannelTypeSelect()
    fireEvent.click(screen.getByText('企业微信'))
    fillInput('渠道名称', '安全值班群')
    fillInput('机器人 Webhook 地址', 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=demo')
    fireEvent.click(screen.getByRole('button', { name: /确认/ }))

    await waitFor(() => {
      expect(api.notifyApi.create).toHaveBeenCalledWith({
        type: 'wecom',
        name: '安全值班群',
        config_json: { webhook_url: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=demo' },
      })
    })
  })

  it('creates feishu channel with optional signing secret', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({ data: { channels: [] } } as any)
    vi.spyOn(api.notifyApi, 'create').mockResolvedValue({ data: { id: 'nc_feishu01' } } as any)

    renderPage()
    await screen.findByText('通知渠道配置')
    fireEvent.click(screen.getByRole('button', { name: /新建渠道/ }))
    expect(await screen.findByRole('dialog')).toBeInTheDocument()

    openChannelTypeSelect()
    fireEvent.click(screen.getByText('飞书'))
    fillInput('渠道名称', '飞书告警群')
    fillInput('机器人 Webhook 地址', 'https://open.feishu.cn/open-apis/bot/v2/hook/demo')
    fillInput('签名密钥（可选）', 'demo-secret')
    fireEvent.click(screen.getByRole('button', { name: /确认/ }))

    await waitFor(() => {
      expect(api.notifyApi.create).toHaveBeenCalledWith({
        type: 'feishu',
        name: '飞书告警群',
        config_json: { webhook_url: 'https://open.feishu.cn/open-apis/bot/v2/hook/demo', secret: 'demo-secret' },
      })
    })
  })

  it('sends a test message and shows success in Chinese', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({
      data: { channels: [{ id: 'nc_feishu01', type: 'feishu', name: '飞书告警群', enabled: true, config_json: { webhook_url: 'https://open.feishu.cn/x' } }] },
    } as any)
    const test = vi.spyOn(api.notifyApi, 'test').mockResolvedValue({ data: { ok: true, message: '测试消息已发送' } } as any)

    renderPage()
    expect(await screen.findByText('飞书告警群')).toBeInTheDocument()
    expect(screen.getByText('飞书')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /发送测试消息/ }))

    await waitFor(() => expect(test).toHaveBeenCalledWith('nc_feishu01'))
    expect(await screen.findByText('测试消息已发送，请到对应渠道查收')).toBeInTheDocument()
  })

  it('shows the backend Chinese reason when the test message fails', async () => {
    vi.spyOn(api.notifyApi, 'list').mockResolvedValue({
      data: { channels: [{ id: 'nc_wecom01', type: 'wecom', name: '安全值班群', enabled: false, config_json: { key: 'k' } }] },
    } as any)
    vi.spyOn(api.notifyApi, 'test').mockRejectedValue({
      response: { status: 502, data: { error: { code: 'notify_test_failed', message: '测试消息发送失败：企业微信拒绝了消息（错误码 93000），请检查机器人地址或 Key 是否有效' } } },
    })

    renderPage()
    expect(await screen.findByText('安全值班群')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /发送测试消息/ }))

    expect(await screen.findByText(/企业微信拒绝了消息（错误码 93000）/)).toBeInTheDocument()
    expect(screen.queryByText(/notify_test_failed/)).not.toBeInTheDocument()
  })
})
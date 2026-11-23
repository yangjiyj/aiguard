import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import api, { contentSecurityApi } from '../services/api'
import FilePolicySettings from '../pages/security-policy/FilePolicySettings'
import { useAuthStore } from '../stores/auth'
import { SECURITY_EXECUTION_MODE_QUERY_KEY } from '../services/securityExecutionMode'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn() } }
})

const wrapper = ({ children }: { children: ReactNode }) => (
  <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>{children}</QueryClientProvider>
)

describe('文件与附件安全：高风险文件可改动作、可加例外', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role: 'platform_admin', tenant_id: 'tenant_default' }, isAuthenticated: true })
    vi.spyOn(api, 'get').mockResolvedValue({ data: { file_content_dlp_enabled: false } } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
    vi.spyOn(contentSecurityApi, 'getFilePolicy').mockResolvedValue({
      data: {
        allowed_types: ['txt'],
        blocked_types: ['zip', 'unknown', 'executable', 'script'],
        max_file_mb: 20,
        max_attachments: 10,
        max_zip_ratio: 100,
        zip_bomb_action: 'block',
        max_zip_entries: 500,
      },
    } as never)
    vi.spyOn(contentSecurityApi, 'listExceptions').mockResolvedValue({ data: { items: [] } } as never)
    vi.spyOn(contentSecurityApi, 'updateFilePolicy').mockResolvedValue({ data: {} } as never)
    vi.spyOn(contentSecurityApi, 'createException').mockResolvedValue({ data: {} } as never)
  })

  it('解锁三类、伪装可执行、压缩炸弹、文件引用和上传检测失败都能改并保存', async () => {
    const user = userEvent.setup()
    render(<FilePolicySettings canManage />, { wrapper })
    const risk = await screen.findByLabelText('高风险文件')
    await waitFor(() => expect(within(risk).getByLabelText('伪装可执行文件处理方式')).toBeEnabled())
    expect(within(risk).getByLabelText('压缩炸弹处理方式')).toHaveValue('block')
    expect(within(risk).getByLabelText('条目数上限')).toHaveValue(500)
    // 旧策略里强塞进禁止清单的三类不再当作禁止。
    expect(within(risk).getByLabelText('脚本处理方式')).toHaveValue('alert_allow')

    await user.selectOptions(within(risk).getByLabelText('可执行文件 / 动态库处理方式'), 'block')
    await user.selectOptions(within(risk).getByLabelText('伪装可执行文件处理方式'), 'block')
    await user.selectOptions(within(risk).getByLabelText('未知类型处理方式'), 'allow')
    await user.selectOptions(within(risk).getByLabelText('未核验的文件引用处理方式'), 'block')
    await user.selectOptions(within(risk).getByLabelText('文件引用核验失败处理方式'), 'alert_allow')
    await user.clear(within(risk).getByLabelText('嵌套层数上限'))
    // 后端上限 100。
    await user.type(within(risk).getByLabelText('嵌套层数上限'), '50')
    await user.selectOptions(within(risk).getByLabelText('上传检测失败处理方式'), 'block')
    await user.click(screen.getByRole('button', { name: '保存网页 AI 附件准入' }))

    await waitFor(() => expect(contentSecurityApi.updateFilePolicy).toHaveBeenCalledWith(expect.objectContaining({
      blocked_types: ['zip'],
      executable_action: 'block',
      disguised_executable_action: 'block',
      script_action: 'alert_allow',
      unknown_action: 'allow',
      zip_bomb_action: 'block',
      max_zip_entries: 500,
      max_zip_nested: 50,
      unverified_file_reference_action: 'block',
      file_reference_lookup_failure_action: 'alert_allow',
    })))
    // 上传检测失败是安全员也能改的平台级安全键，走安全设置接口；正文检测开关没改不发。
    expect(api.put).toHaveBeenCalledWith('/security/system-settings', { upload_inspection_failure_action: 'block' })
    expect(api.put).not.toHaveBeenCalledWith('/system/settings', expect.anything())
  })

  it('每行加例外打开内容例外弹窗，规则预填引擎规则 ID；长期传 never（存空、显示永久）', async () => {
    const user = userEvent.setup()
    render(<FilePolicySettings canManage />, { wrapper })
    const risk = await screen.findByLabelText('高风险文件')
    await user.click(within(risk).getByRole('button', { name: '伪装可执行文件加例外' }))
    expect(await screen.findByLabelText('关联规则')).toHaveValue('file-disguised-exec')
    await user.click(screen.getByRole('checkbox', { name: '长期' }))
    await user.type(screen.getByLabelText('原因'), '研发打包机需要上传安装包')
    await user.click(screen.getByRole('button', { name: '创建例外' }))
    await waitFor(() => expect(contentSecurityApi.createException).toHaveBeenCalledWith({
      scope_type: 'tenant',
      scope_ref: '',
      rule_id: 'file-disguised-exec',
      decision: 'audit',
      reason: '研发打包机需要上传安装包',
      expires_at: 'never',
    }))
    // 故障类没有例外。
    expect(within(risk).queryByRole('button', { name: '文件引用核验失败加例外' })).not.toBeInTheDocument()
  })

  it('禁止发送的文件类型可加例外，规则预填带类型的编号', async () => {
    const user = userEvent.setup()
    render(<FilePolicySettings canManage />, { wrapper })
    const zip = await screen.findByLabelText('ZIP发送方式')
    await waitFor(() => expect(zip).toHaveValue('blocked'))
    // 允许发送的类型没有例外可加。
    expect(screen.queryByRole('button', { name: 'TXT加例外' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'ZIP加例外' }))
    expect(await screen.findByLabelText('关联规则')).toHaveValue('file-policy-blocked-type:zip')
  })

  it('刚改成禁止发送的类型同样能加例外', async () => {
    const user = userEvent.setup()
    render(<FilePolicySettings canManage />, { wrapper })
    const docx = await screen.findByLabelText('DOCX发送方式')
    await waitFor(() => expect(docx).toBeEnabled())
    expect(screen.queryByRole('button', { name: 'DOCX加例外' })).not.toBeInTheDocument()
    await user.selectOptions(docx, 'blocked')
    await user.click(screen.getByRole('button', { name: 'DOCX加例外' }))
    expect(await screen.findByLabelText('关联规则')).toHaveValue('file-policy-blocked-type:docx')
  })

  it('脚本有独立规则 file-script', async () => {
    const user = userEvent.setup()
    render(<FilePolicySettings canManage />, { wrapper })
    const risk = await screen.findByLabelText('高风险文件')
    await user.click(within(risk).getByRole('button', { name: '脚本加例外' }))
    expect(await screen.findByLabelText('关联规则')).toHaveValue('file-script')
  })

  it('未核验的文件引用预填 file-id-unverified，核验失败（故障类）没有例外', async () => {
    const user = userEvent.setup()
    render(<FilePolicySettings canManage />, { wrapper })
    const risk = await screen.findByLabelText('高风险文件')
    expect(within(risk).queryByRole('button', { name: '文件引用核验失败加例外' })).not.toBeInTheDocument()
    await user.click(within(risk).getByRole('button', { name: '未核验的文件引用加例外' }))
    expect(await screen.findByLabelText('关联规则')).toHaveValue('file-id-unverified')
  })

  it('嵌套层数上限超过 100 时报错不保存', async () => {
    const user = userEvent.setup()
    const { message } = await import('antd')
    render(<FilePolicySettings canManage />, { wrapper })
    const risk = await screen.findByLabelText('高风险文件')
    await waitFor(() => expect(within(risk).getByLabelText('嵌套层数上限')).toBeEnabled())
    await user.type(within(risk).getByLabelText('嵌套层数上限'), '101')
    await user.click(screen.getByRole('button', { name: '保存网页 AI 附件准入' }))
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('嵌套层数上限必须是 1-100 的整数'))
    expect(contentSecurityApi.updateFilePolicy).not.toHaveBeenCalled()
  })

  it('文件类型名单含引擎认的文本与源码类型', async () => {
    render(<FilePolicySettings canManage />, { wrapper })
    await screen.findByLabelText('高风险文件')
    for (const label of ['MD', 'MARKDOWN', 'YAML', 'YML', 'TOML', 'INI', 'XML', 'HTML', 'CSS', 'LOG', 'SQL', 'PY', 'JS', 'TS', 'TSX', 'JSX', 'GO', 'JAVA', 'C', 'H', 'CPP', 'CS', 'RB', 'PHP', 'RS', 'KT', 'SWIFT', 'SCALA', 'VUE']) {
      expect(screen.getByLabelText(`${label}发送方式`)).toBeInTheDocument()
    }
  })

  it('租户级安全员：上传检测失败（平台级设置）只读', async () => {
    useAuthStore.setState({ token: 't', user: { id: 'u2', username: 'so', role: 'security_officer', tenant_id: 'tenant-a' }, isAuthenticated: true })
    render(<FilePolicySettings canManage />, { wrapper })
    const risk = await screen.findByLabelText('高风险文件')
    await waitFor(() => expect(within(risk).getByLabelText('可执行文件 / 动态库处理方式')).toBeEnabled())
    expect(within(risk).getByLabelText('上传检测失败处理方式')).toBeDisabled()
  })

  it('部分失败：提示哪一步已保存，保留用户输入', async () => {
    const user = userEvent.setup()
    const { message } = await import('antd')
    vi.mocked(api.put).mockRejectedValue({ response: { data: { error: { code: 'invalid_request', message: '后端拒绝了这次保存' } } } })
    render(<FilePolicySettings canManage />, { wrapper })
    const risk = await screen.findByLabelText('高风险文件')
    await waitFor(() => expect(within(risk).getByLabelText('上传检测失败处理方式')).toBeEnabled())
    await user.selectOptions(within(risk).getByLabelText('上传检测失败处理方式'), 'block')
    await user.click(screen.getByRole('button', { name: '保存网页 AI 附件准入' }))
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('已保存：文件类型与高风险文件；未保存：后端拒绝了这次保存'))
    expect(contentSecurityApi.updateFilePolicy).toHaveBeenCalled()
    await waitFor(() => expect(contentSecurityApi.getFilePolicy).toHaveBeenCalledTimes(2))
    expect(within(risk).getByLabelText('上传检测失败处理方式')).toHaveValue('block')
  })

  it('系统设置缓存刷新（如执行模式轮询）不重置还没保存的草稿', async () => {
    const user = userEvent.setup()
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    render(<QueryClientProvider client={client}><FilePolicySettings canManage /></QueryClientProvider>)
    const docx = await screen.findByLabelText('DOCX发送方式')
    await waitFor(() => expect(docx).toBeEnabled())
    await user.selectOptions(docx, 'blocked')
    vi.mocked(api.get).mockResolvedValue({ data: { file_content_dlp_enabled: true } } as never)
    await client.invalidateQueries({ queryKey: ['system-settings'] })
    await waitFor(() => expect(client.getQueryData(['system-settings'])).toEqual({ file_content_dlp_enabled: true }))
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(screen.getByLabelText('DOCX发送方式')).toHaveValue('blocked')
    // 执行模式轮询用自己的查询键，不再和系统设置共用一个缓存。
    expect(SECURITY_EXECUTION_MODE_QUERY_KEY).not.toEqual(['system-settings'])
  })

  it('正文检测开关只有系统管理员能改', async () => {
    useAuthStore.setState({ token: 't', user: { id: 'u3', username: 'so', role: 'security_officer', tenant_id: 'tenant_default' }, isAuthenticated: true })
    render(<FilePolicySettings canManage />, { wrapper })
    const risk = await screen.findByLabelText('高风险文件')
    await waitFor(() => expect(within(risk).getByLabelText('上传检测失败处理方式')).toBeEnabled())
    expect(screen.getByLabelText('文件正文敏感数据检测')).toBeDisabled()
  })

  it('无权角色只读', async () => {
    render(<FilePolicySettings canManage={false} />, { wrapper })
    const risk = await screen.findByLabelText('高风险文件')
    await waitFor(() => expect(contentSecurityApi.getFilePolicy).toHaveBeenCalled())
    expect(within(risk).getByLabelText('可执行文件 / 动态库处理方式')).toBeDisabled()
    expect(within(risk).getByRole('button', { name: '压缩炸弹加例外' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'ZIP加例外' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '保存网页 AI 附件准入' })).toBeDisabled()
  })
})

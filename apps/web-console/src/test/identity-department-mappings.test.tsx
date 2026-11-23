import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { ConfigProvider, Modal } from 'antd'
import SsoConfig from '../pages/SsoConfig'
import { apiClient, identityApi, identitySourcesApi, orgApi } from '../services/api'

const SOURCES = [
  { id: 'ids_hq_active', source_alias: 'enterprise', display_name: '总部身份源', status: 'active', protocol: 'oidc', version: 1, issuer_url: 'https://hq.example.com', client_id: 'hq', client_secret_set: true, scopes: 'openid', dept_code_claim: 'department_code', dept_name_claim: 'department_name', groups_claim: 'groups' },
  { id: 'ids_hq_draft', source_alias: 'enterprise', display_name: '总部新配置', status: 'draft', protocol: 'oidc', version: 2, issuer_url: 'https://hq-new.example.com', client_id: 'hq-new', client_secret_set: true, scopes: 'openid', dept_code_claim: 'dept_no', dept_name_claim: 'dept_label', groups_claim: 'roles' },
  { id: 'ids_branch', source_alias: 'jjd-branch', display_name: '分公司身份源', status: 'active', protocol: 'oidc', version: 1, issuer_url: 'https://branch.example.com', client_id: 'branch', client_secret_set: true, scopes: 'openid' },
]
const MAPPING = { id: 'idm_hq', source_type: 'oidc', source_id: 'ids_hq_active', external_group: 'RD001', match_type: 'department', department_id: 'dept_rd', department_name: '研发部', priority: 10, enabled: true }

afterEach(() => Modal.destroyAll())

describe('部门映射与身份属性配置', () => {
  let client: QueryClient

  beforeEach(() => {
    vi.restoreAllMocks()
    client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.spyOn(identityApi, 'getSources').mockResolvedValue({ data: { data: SOURCES } } as any)
    vi.spyOn(identityApi, 'getStatus').mockResolvedValue({ data: { has_active: true, emergency_admin_available: true, callback_url: 'https://sso.example.com/callback', publish_status: 'active' } } as any)
    vi.spyOn(identitySourcesApi, 'getStatus').mockResolvedValue({ data: { has_active: true, emergency_admin_available: true, publish_status: 'active' } } as any)
    vi.spyOn(identityApi, 'saveDraft').mockResolvedValue({ data: {} } as any)
    vi.spyOn(identityApi, 'getDeptMappings').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(apiClient, 'get').mockImplementation(async (url: string, config?: any) => {
      if (url === '/teams') return { data: { data: [{ id: 'dept_rd', name: '研发部' }, { id: 'dept_ops', name: '运维部' }] } } as any
      if (url === '/identity/department-mappings') {
        const sourceID = config?.params?.source_id
        const rows = sourceID === 'ids_hq_active' ? [MAPPING] : sourceID === 'ids_branch'
          ? [{ ...MAPPING, id: 'idm_branch', source_id: sourceID, external_group: 'BR001', department_id: 'dept_ops', department_name: '运维部' }] : []
        return { data: { data: rows } } as any
      }
      return { data: { data: [] } } as any
    })
    vi.spyOn(apiClient, 'post').mockResolvedValue({ data: {} } as any)
    vi.spyOn(apiClient, 'patch').mockResolvedValue({ data: {} } as any)
    vi.spyOn(apiClient, 'delete').mockResolvedValue({ data: {} } as any)
  })

  function renderPage() {
    return render(<MemoryRouter><QueryClientProvider client={client}><ConfigProvider theme={{ token: { motion: false } }}><SsoConfig /></ConfigProvider></QueryClientProvider></MemoryRouter>)
  }

  async function choose(label: string, option: string) {
    fireEvent.mouseDown(screen.getByRole('combobox', { name: label }))
    const choices = await screen.findAllByText(option, { exact: true })
    fireEvent.click(choices[choices.length - 1])
  }

  // rc-util 在 NODE_ENV=test 下让所有 Modal 共用 test-id；按可见对话框和实际标题核验。
  async function findDialog(title: string) {
    const dialog = await screen.findByRole('dialog')
    await waitFor(() => expect(within(dialog).getByText(title)).toBeVisible())
    return dialog
  }

  it('部门编码、部门名称、用户组字段可编辑并随草稿保存', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByLabelText('部门编码字段')).toHaveValue('dept_no'))
    expect(screen.getByLabelText('部门名称字段')).toHaveValue('dept_label')
    expect(screen.getByLabelText('用户组字段')).toHaveValue('roles')
    fireEvent.change(screen.getByLabelText('部门编码字段'), { target: { value: 'staff_department_code' } })
    fireEvent.change(screen.getByLabelText('部门名称字段'), { target: { value: 'staff_department_name' } })
    fireEvent.change(screen.getByLabelText('用户组字段'), { target: { value: 'staff_groups' } })
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    await waitFor(() => expect(identityApi.saveDraft).toHaveBeenCalledWith(expect.objectContaining({
      dept_code_claim: 'staff_department_code', dept_name_claim: 'staff_department_name', groups_claim: 'staff_groups',
    })))
  })

  it('查询只取当前身份源生效配置，切换身份源不显示旧规则', async () => {
    renderPage()
    expect(await screen.findByText('RD001')).toBeInTheDocument()
    expect(apiClient.get).toHaveBeenCalledWith('/identity/department-mappings', { params: { source_type: 'oidc', source_id: 'ids_hq_active' } })
    expect(identityApi.getDeptMappings).not.toHaveBeenCalled()
    await choose('选择身份源', '分公司身份源')
    expect(await screen.findByText('BR001')).toBeInTheDocument()
    expect(screen.queryByText('RD001')).not.toBeInTheDocument()
    expect(apiClient.get).toHaveBeenCalledWith('/identity/department-mappings', { params: { source_type: 'oidc', source_id: 'ids_branch' } })
  })

  it('待启用配置独立查询和写入，部门下拉显示名称', async () => {
    renderPage()
    await screen.findByText('RD001')
    await choose('映射作用范围', '待启用配置')
    await waitFor(() => expect(apiClient.get).toHaveBeenCalledWith('/identity/department-mappings', { params: { source_type: 'oidc', source_id: 'ids_hq_draft' } }))
    expect(screen.queryByText('RD001')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '新增映射' }))
    await findDialog('新增部门映射')
    await choose('匹配来源', '部门编码')
    fireEvent.change(screen.getByLabelText('匹配值'), { target: { value: '  RD002  ' } })
    await choose('目标部门', '研发部')
    const rawDepartmentID = screen.queryByText('dept_rd')
    if (rawDepartmentID) expect(rawDepartmentID).not.toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: '保存映射' }))
    await waitFor(() => expect(apiClient.post).toHaveBeenCalledWith('/identity/department-mappings', {
      source_type: 'oidc', source_id: 'ids_hq_draft', external_group: 'RD002', match_type: 'department',
      department_id: 'dept_rd', priority: 100, enabled: true,
    }))
  })

  it('映射可编辑匹配值、目标部门和优先级', async () => {
    renderPage()
    await screen.findByText('RD001')
    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }))
    await findDialog('编辑部门映射')
    expect(screen.getByLabelText('匹配值')).toHaveValue('RD001')
    fireEvent.change(screen.getByLabelText('匹配值'), { target: { value: 'RD003' } })
    fireEvent.change(screen.getByLabelText('优先级'), { target: { value: '20' } })
    await choose('目标部门', '运维部')
    fireEvent.click(screen.getByRole('button', { name: '保存映射' }))
    await waitFor(() => expect(apiClient.patch).toHaveBeenCalledWith('/identity/department-mappings/idm_hq', expect.objectContaining({
      source_id: 'ids_hq_active', external_group: 'RD003', department_id: 'dept_ops', priority: 20,
    })))
  })

  it.each(['失败', '加载中', '目标缺失'] as const)('部门列表%s时编辑仍显示中文名称并阻止无效提交', async (state) => {
    if (state === '失败') {
      vi.spyOn(orgApi, 'listTeams').mockRejectedValue(new Error('department lookup unavailable'))
    } else if (state === '加载中') {
      vi.spyOn(orgApi, 'listTeams').mockImplementation(() => new Promise(() => {}) as any)
    } else {
      vi.spyOn(orgApi, 'listTeams').mockResolvedValue({ data: { data: [{ id: 'dept_ops', name: '运维部' }] } } as any)
    }
    renderPage()
    await screen.findByText('RD001')
    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }))
    const dialog = await findDialog('编辑部门映射')
    expect(within(dialog).getByText(/研发部/)).toBeVisible()
    const rawDepartmentID = within(dialog).queryByText('dept_rd', { exact: true })
    if (rawDepartmentID) expect(rawDepartmentID).not.toBeVisible()
    const save = within(dialog).getByRole('button', { name: '保存映射' })
    if (state !== '目标缺失') {
      expect(save).toBeDisabled()
    } else {
      fireEvent.click(save)
      expect(await within(dialog).findByText('目标部门不可用，请重新选择')).toBeVisible()
      expect(apiClient.patch).not.toHaveBeenCalled()
      await choose('目标部门', '运维部')
      fireEvent.click(save)
      await waitFor(() => expect(apiClient.patch).toHaveBeenCalledWith('/identity/department-mappings/idm_hq', expect.objectContaining({ department_id: 'dept_ops' })))
    }
  })

  it('目标部门缺失且规则没有部门名称时仅显示中文提示并要求重新选择', async () => {
    vi.spyOn(orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    const baseGet = vi.mocked(apiClient.get).getMockImplementation()!
    vi.mocked(apiClient.get).mockImplementation(async (url: string, config?: any) => {
      if (url === '/identity/department-mappings') return { data: { data: [{ ...MAPPING, department_name: '' }] } } as any
      return baseGet(url, config)
    })
    renderPage()
    await screen.findByText('RD001')
    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }))
    const dialog = await findDialog('编辑部门映射')
    expect(within(dialog).getByText('原目标部门不可用，请重新选择')).toBeVisible()
    const rawDepartmentID = within(dialog).queryByText('dept_rd', { exact: true })
    if (rawDepartmentID) expect(rawDepartmentID).not.toBeVisible()
    fireEvent.click(within(dialog).getByRole('button', { name: '保存映射' }))
    expect(await within(dialog).findByText('目标部门不可用，请重新选择')).toBeVisible()
    expect(apiClient.patch).not.toHaveBeenCalled()
  })

  it('停用和删除使用原规则作用范围，删除需确认', async () => {
    renderPage()
    await screen.findByText('RD001')
    fireEvent.click(screen.getByRole('button', { name: '停用规则' }))
    await waitFor(() => expect(apiClient.patch).toHaveBeenCalledWith('/identity/department-mappings/idm_hq', expect.objectContaining({
      source_type: 'oidc', source_id: 'ids_hq_active', enabled: false,
    })))
    fireEvent.click(screen.getByRole('button', { name: /删\s*除/ }))
    const dialog = await findDialog('确认删除映射')
    expect(apiClient.delete).not.toHaveBeenCalled()
    expect(within(dialog).getByText(/RD001/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '确认删除' }))
    await waitFor(() => expect(apiClient.delete).toHaveBeenCalledWith('/identity/department-mappings/idm_hq'))
  })

  it('预览同时提交部门编码和用户组并用部门名称解释冲突', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ data: {
      matched: true, ambiguous: true, candidate_ids: ['dept_rd', 'dept_ops'],
      candidate_departments: [{ department_id: 'dept_rd', department_name: '研发部' }, { department_id: 'dept_ops', department_name: '运维部' }],
    } } as any)
    renderPage()
    await screen.findByText('RD001')
    fireEvent.click(screen.getByRole('button', { name: '预览映射' }))
    const dialog = await findDialog('预览部门映射')
    fireEvent.change(screen.getByLabelText('预览部门编码'), { target: { value: ' RD001\nRD002\nRD001 ' } })
    fireEvent.change(screen.getByLabelText('预览用户组'), { target: { value: ' engineers\n oncall ' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '查看结果' }))
    await waitFor(() => expect(apiClient.post).toHaveBeenCalledWith('/identity/department-mappings/preview', {
      source_type: 'oidc', source_id: 'ids_hq_active', external_departments: ['RD001', 'RD002'], external_groups: ['engineers', 'oncall'],
    }))
    expect(await within(dialog).findByText(/研发部.*运维部/)).toBeInTheDocument()
    expect(within(dialog).getByText(/调整优先级/)).toBeInTheDocument()
    expect(within(dialog).queryByText('dept_rd')).not.toBeInTheDocument()
  })

  function deferredResponse() {
    let resolve!: (response: any) => void
    let reject!: (error: unknown) => void
    const promise = new Promise<any>((resolvePromise, rejectPromise) => {
      resolve = resolvePromise
      reject = rejectPromise
    })
    return { promise, resolve, reject }
  }

  it.each(['成功', '失败'] as const)('预览输入变化后忽略旧请求的迟到%s响应', async (outcome) => {
    const response = deferredResponse()
    vi.mocked(apiClient.post).mockImplementationOnce(() => response.promise)
    renderPage()
    await screen.findByText('RD001')
    fireEvent.click(screen.getByRole('button', { name: '预览映射' }))
    const dialog = await findDialog('预览部门映射')
    fireEvent.change(screen.getByLabelText('预览部门编码'), { target: { value: 'RD001' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '查看结果' }))
    await waitFor(() => expect(apiClient.post).toHaveBeenCalledWith('/identity/department-mappings/preview', expect.objectContaining({ external_departments: ['RD001'] })))
    fireEvent.change(screen.getByLabelText('预览部门编码'), { target: { value: 'OPS002' } })
    await act(async () => {
      if (outcome === '成功') response.resolve({ data: { matched: true, ambiguous: false, department_id: 'dept_rd', department_name: '研发部' } })
      else response.reject({ response: { data: { error: { message: '旧预览失败' } } } })
    })
    await waitFor(() => expect(client.isMutating()).toBe(0))
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '查看结果' })).not.toHaveClass('ant-btn-loading'))
    expect(within(dialog).queryByText('将分配至「研发部」')).not.toBeInTheDocument()
    expect(within(dialog).queryByText('旧预览失败')).not.toBeInTheDocument()

    vi.mocked(apiClient.post).mockResolvedValueOnce({ data: { matched: true, ambiguous: false, department_id: 'dept_ops', department_name: '运维部' } } as any)
    fireEvent.click(within(dialog).getByRole('button', { name: '查看结果' }))
    await waitFor(() => expect(apiClient.post).toHaveBeenCalledWith('/identity/department-mappings/preview', expect.objectContaining({ external_departments: ['OPS002'] })))
    expect(await within(dialog).findByText('将分配至「运维部」')).toBeVisible()
  })

  it.each(['成功', '失败'] as const)('关闭重开预览后忽略旧请求的迟到%s响应', async (outcome) => {
    const response = deferredResponse()
    vi.mocked(apiClient.post).mockImplementationOnce(() => response.promise)
    renderPage()
    await screen.findByText('RD001')
    fireEvent.click(screen.getByRole('button', { name: '预览映射' }))
    const dialog = await findDialog('预览部门映射')
    fireEvent.change(screen.getByLabelText('预览部门编码'), { target: { value: 'RD001' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '查看结果' }))
    await waitFor(() => expect(apiClient.post).toHaveBeenCalledTimes(1))
    fireEvent.click(within(dialog).getByRole('button', { name: /关\s*闭/ }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: '预览映射' }))
    const reopened = await findDialog('预览部门映射')
    expect(screen.getByLabelText('预览部门编码')).toHaveValue('')
    await act(async () => {
      if (outcome === '成功') response.resolve({ data: { matched: true, ambiguous: false, department_id: 'dept_rd', department_name: '研发部' } })
      else response.reject({ response: { data: { error: { message: '旧预览失败' } } } })
    })
    await waitFor(() => expect(client.isMutating()).toBe(0))
    expect(within(reopened).queryByText('将分配至「研发部」')).not.toBeInTheDocument()
    expect(within(reopened).queryByText('旧预览失败')).not.toBeInTheDocument()
  })

  it('切换身份源会关闭旧配置的编辑与删除对话框', async () => {
    renderPage()
    await screen.findByText('RD001')
    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }))
    await findDialog('编辑部门映射')
    await choose('选择身份源', '分公司身份源')
    await screen.findByText('BR001')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(apiClient.patch).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: /删\s*除/ }))
    await findDialog('确认删除映射')
    await choose('选择身份源', '默认身份源（总部身份源）')
    await screen.findByText('RD001')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(apiClient.delete).not.toHaveBeenCalled()
  })

  it('未保存身份源不请求无来源过滤的映射列表', async () => {
    vi.mocked(identityApi.getSources).mockResolvedValue({ data: { data: [] } } as any)
    renderPage()
    expect(await screen.findByText('请先保存身份源草稿，再配置部门映射')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增映射' })).toBeDisabled()
    expect(apiClient.get).not.toHaveBeenCalledWith('/identity/department-mappings', expect.anything())
  })
})

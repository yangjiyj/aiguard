import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import RawEvidenceDrawer from '../components/RawEvidenceDrawer'
import { rawEvidenceApi } from '../services/rawEvidence'
import { canToggleRawEvidenceRole, canViewRawEvidenceRole } from '../utils/access'
import { useAuthStore } from '../stores/auth'

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return { ...actual, message: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }
})

const item = {
  id: 'cre_1', request_id: 'req_123', direction: 'input' as const, role: 'user', message_index: 0,
  disposition: 'blocked' as const, block_id: 'evt_blk_9', rule_ids: ['r-key'], rule_names: ['密钥'], categories: [],
  content_chars: 12, created_at: '2026-11-06T08:00:00Z', truncated: false, original_chars: 12,
}

describe('原文留证入口权限', () => {
  it('只有系统管理员和安全保密员可见（旧 admin 角色值与后端一致不放行）', () => {
    for (const role of ['platform_admin', 'security_officer']) expect(canViewRawEvidenceRole(role)).toBe(true)
    for (const role of ['admin', 'auditor', 'tenant_admin', 'tenant_owner', 'developer', 'viewer', 'dept_manager', 'chat_user', undefined]) {
      expect(canViewRawEvidenceRole(role)).toBe(false)
    }
  })

  it('全局开关只有系统管理员能改', () => {
    expect(canToggleRawEvidenceRole('platform_admin')).toBe(true)
    for (const role of ['security_officer', 'admin', 'auditor', 'tenant_admin', undefined]) expect(canToggleRawEvidenceRole(role)).toBe(false)
  })
})

describe('RawEvidenceDrawer', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    useAuthStore.setState({ user: { id: 'u', username: 'u', role: 'platform_admin', tenant_id: 't' }, isAuthenticated: true, token: 't' } as never)
    vi.spyOn(rawEvidenceApi, 'list').mockResolvedValue({ data: { items: [item], total: 1, enabled: true } } as never)
  })

  it('覆盖范围只留一行小字，不出长段警告', async () => {
    render(<RawEvidenceDrawer open onClose={() => {}} />)
    expect(await screen.findByText(/仅覆盖聊天类通道的文本/)).toBeTruthy()
    expect(screen.queryByText(/工具调用拦截/)).toBeNull()
    expect(document.querySelector('.ant-alert')).toBeNull()
  })

  it('安全保密员只看开关状态，不能切换；系统管理员可切换', async () => {
    useAuthStore.setState({ user: { id: 'u', username: 'u', role: 'security_officer', tenant_id: 't' } } as never)
    const { unmount } = render(<RawEvidenceDrawer open onClose={() => {}} />)
    expect(await screen.findByText('已开启（系统管理员可修改）')).toBeTruthy()
    expect(screen.queryByLabelText('脱敏原文留证开关')).toBeNull()
    unmount()
    useAuthStore.setState({ user: { id: 'u', username: 'u', role: 'platform_admin', tenant_id: 't' } } as never)
    render(<RawEvidenceDrawer open onClose={() => {}} />)
    expect(await screen.findByLabelText('脱敏原文留证开关')).toBeTruthy()
  })

  it('只有确实被截断时才显示一行截断提示', async () => {
    const reveal = vi.spyOn(rawEvidenceApi, 'reveal').mockResolvedValue({ data: { ...item, text: '很长的原文', truncated: true, original_chars: 600000, content_chars: 524288 } } as never)
    const { unmount } = render(<RawEvidenceDrawer open requestId="req_123" onClose={() => {}} />)
    fireEvent.click((await screen.findAllByText('查看原文'))[0])
    expect(await screen.findByText('原文共 600000 字，仅保存前 524288 字')).toBeTruthy()
    unmount()
    reveal.mockResolvedValue({ data: { ...item, text: '短原文' } } as never)
    render(<RawEvidenceDrawer open requestId="req_123" onClose={() => {}} />)
    fireEvent.click((await screen.findAllByText('查看原文'))[0])
    expect((await screen.findByLabelText('原文内容')).textContent).toBe('短原文')
    expect(screen.queryByText(/仅保存前/)).toBeNull()
  })

  it('默认只显示命中信息，不显示原文；按请求 ID 预填并查询', async () => {
    render(<RawEvidenceDrawer open requestId="req_123" onClose={() => {}} />)
    await waitFor(() => expect(rawEvidenceApi.list).toHaveBeenCalledWith({ request_id: 'req_123' }))
    expect(await screen.findByText('evt_blk_9')).toBeTruthy()
    expect(screen.getByText('密钥')).toBeTruthy()
    expect(screen.queryByLabelText('原文内容')).toBeNull()
  })

  it('点查看原文直接查看：不弹事由框、不二次确认，事由可不填', async () => {
    const reveal = vi.spyOn(rawEvidenceApi, 'reveal').mockResolvedValue({ data: { ...item, text: 'sk-LIVE-SECRET-12' } } as never)
    render(<RawEvidenceDrawer open requestId="req_123" onClose={() => {}} />)
    fireEvent.click((await screen.findAllByText('查看原文'))[0])
    await waitFor(() => expect(reveal).toHaveBeenCalledWith('cre_1', ''))
    expect((await screen.findByLabelText('原文内容')).textContent).toBe('sk-LIVE-SECRET-12')
    expect(screen.queryByText('确认查看并留痕')).toBeNull()
  })

  it('选填的事由随查看一起提交', async () => {
    const reveal = vi.spyOn(rawEvidenceApi, 'reveal').mockResolvedValue({ data: { ...item, text: 'x' } } as never)
    render(<RawEvidenceDrawer open requestId="req_123" onClose={() => {}} />)
    fireEvent.change(await screen.findByLabelText('查看事由'), { target: { value: ' 核查工单 ' } })
    fireEvent.click((await screen.findAllByText('查看原文'))[0])
    await waitFor(() => expect(reveal).toHaveBeenCalledWith('cre_1', '核查工单'))
  })

  it('同会话重复出现的原文标为重复，照样能直接查看', async () => {
    vi.spyOn(rawEvidenceApi, 'list').mockResolvedValue({ data: { items: [{ ...item, id: 'cre_ref', ref_evidence_id: 'cre_1' }], total: 1, enabled: true } } as never)
    const reveal = vi.spyOn(rawEvidenceApi, 'reveal').mockResolvedValue({ data: { ...item, id: 'cre_ref', text: '首条原文' } } as never)
    render(<RawEvidenceDrawer open requestId="req_123" onClose={() => {}} />)
    expect(await screen.findByText('重复')).toBeTruthy()
    fireEvent.click(screen.getByText('查看原文'))
    await waitFor(() => expect(reveal).toHaveBeenCalledWith('cre_ref', ''))
    expect((await screen.findByLabelText('原文内容')).textContent).toBe('首条原文')
  })

  it('按阻断编号与规则定位', async () => {
    render(<RawEvidenceDrawer open onClose={() => {}} />)
    await waitFor(() => expect(rawEvidenceApi.list).toHaveBeenCalledWith({}))
    fireEvent.change(screen.getByLabelText('阻断编号'), { target: { value: 'evt_blk_9' } })
    fireEvent.change(screen.getByLabelText('命中规则'), { target: { value: '密钥' } })
    fireEvent.click(screen.getByText('查 询'))
    await waitFor(() => expect(rawEvidenceApi.list).toHaveBeenLastCalledWith({ block_id: 'evt_blk_9', rule: '密钥' }))
  })
})

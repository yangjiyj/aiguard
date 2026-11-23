import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AgentBehaviorPolicy from '../pages/security-policy/AgentBehaviorPolicy'
import { isBasicAction, securityPoliciesApi, type PolicyCenterAgentBehavior } from '../services/securityPoliciesApi'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn() } }
})

const destructive = (overrides: Partial<PolicyCenterAgentBehavior> = {}): PolicyCenterAgentBehavior => ({
  key: 'destructive_operation',
  label: '删除与破坏',
  description: '',
  configured_action: 'alert_allow',
  current_action: 'alert_allow',
  health: 'ok',
  allowed_actions: ['record', 'alert_allow', 'confirm', 'block'],
  has_advanced_overrides: false,
  configured: true,
  version: 'v1',
  ...overrides,
} as PolicyCenterAgentBehavior)

describe('删除与破坏卡片：后端给了 confirm 时可选可存', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('isBasicAction 只在允许动作里有 confirm 时认 confirm', () => {
    expect(isBasicAction('confirm', ['record', 'confirm'])).toBe(true)
    expect(isBasicAction('confirm', ['record', 'block'])).toBe(false)
    expect(isBasicAction('confirm')).toBe(false)
    expect(isBasicAction('block')).toBe(true)
  })

  it('选人工确认并保存', async () => {
    let current = destructive()
    const loadItems = vi.fn(async () => [current])
    const save = vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockImplementation(async (_key, input) => {
      current = destructive({ configured_action: input.action, current_action: input.action, version: 'v2' })
      return { data: {} } as never
    })
    render(<MemoryRouter><AgentBehaviorPolicy items={[current]} auditOnly={false} canManage loadItems={loadItems} onReload={vi.fn()} /></MemoryRouter>)
    const group = screen.getByRole('radiogroup', { name: '删除与破坏处理方式' })
    const confirm = within(group).getByRole('radio', { name: '人工确认' })
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)
    fireEvent.click(screen.getByRole('button', { name: '保存全部调整' }))
    fireEvent.click(screen.getByRole('button', { name: '确认保存' }))
    await waitFor(() => expect(save).toHaveBeenCalledWith('destructive_operation', { action: 'confirm', version: 'v1' }))
  })

  it('已配置为人工确认时正常显示、可改', () => {
    const item = destructive({ configured_action: 'confirm', current_action: 'confirm' })
    render(<MemoryRouter><AgentBehaviorPolicy items={[item]} auditOnly={false} canManage loadItems={async () => [item]} onReload={vi.fn()} /></MemoryRouter>)
    const group = screen.getByRole('radiogroup', { name: '删除与破坏处理方式' })
    expect(within(group).getByRole('radio', { name: '人工确认' })).toBeChecked()
    expect(group).not.toHaveClass('ant-segmented-disabled')
    expect(screen.queryByText('当前不可保存')).not.toBeInTheDocument()
  })
})

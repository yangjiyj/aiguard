import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Modal } from 'antd'
import UserDeleteBlockerContent, { type DeleteBlockerError } from '../components/UserDeleteBlockerContent'
import { showUserDeleteBlockerModal } from '../components/UserDeleteBlockerModal'
import { useThemeStore } from '../stores/theme'

const blockerError: DeleteBlockerError = {
  message: '无法删除用户：该用户仍有资源占用。',
  details: {
    blockers: [
      {
        kind: 'project_owner',
        label: '应用负责人',
        count: 1,
        entry: '应用管理',
        action: '先移交负责人给其他用户，或删除该应用',
        items: [
          { id: 'project_delete_user_ref', name: 'referenced project', route: '/apps?project_id=project_delete_user_ref' },
        ],
      },
    ],
  },
}

afterEach(() => {
  Modal.destroyAll()
  vi.restoreAllMocks()
})

describe('UserDeleteBlockerModal', () => {
  it('去处理只在 click 阶段导航，避免 mousedown 销毁吞掉跳转', async () => {
    const onNavigate = vi.fn()
    render(<UserDeleteBlockerContent error={blockerError} onNavigate={onNavigate} />)

    const link = await screen.findByRole('link', { name: '去处理' })
    fireEvent.mouseDown(link)
    expect(onNavigate).not.toHaveBeenCalled()

    await userEvent.click(link)
    expect(onNavigate).toHaveBeenCalledTimes(1)
    expect(onNavigate).toHaveBeenCalledWith('/apps?project_id=project_delete_user_ref')
  })

  it('深色主题下静态弹窗使用深色样式', async () => {
    useThemeStore.setState({ mode: 'dark', isDark: true })

    showUserDeleteBlockerModal(blockerError, vi.fn())

    expect(await screen.findAllByText('用户无法删除')).not.toHaveLength(0)
    expect(document.querySelector('.user-delete-blocker-modal-dark')).toBeTruthy()
    expect(screen.getByTestId('user-delete-blocker-project_owner')).toHaveClass('user-delete-blocker-card')
  })
})

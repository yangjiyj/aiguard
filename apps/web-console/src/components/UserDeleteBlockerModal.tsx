import { Modal } from 'antd'
import UserDeleteBlockerContent, { type DeleteBlockerError } from './UserDeleteBlockerContent'
import { useThemeStore } from '../stores/theme'

export function showUserDeleteBlockerModal(error: DeleteBlockerError, navigate?: (route: string) => void) {
  const modalRef: { current?: ReturnType<typeof Modal.warning> } = {}
  const closeAndNavigate = (route: string) => {
    modalRef.current?.destroy()
    Modal.destroyAll()
    if (navigate) {
      navigate(route)
      return
    }
    if (typeof window !== 'undefined') {
      window.location.assign(route)
    }
  }
  const isDark = useThemeStore.getState().isDark

  modalRef.current = Modal.warning({
    title: '用户无法删除',
    width: 640,
    className: `user-delete-blocker-modal ${isDark ? 'user-delete-blocker-modal-dark' : 'user-delete-blocker-modal-light'}`,
    content: <UserDeleteBlockerContent error={error} onNavigate={closeAndNavigate} />,
    okText: '知道了',
    transitionName: '',
    maskTransitionName: '',
  })
}

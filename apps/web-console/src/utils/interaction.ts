import type { KeyboardEvent } from 'react'

export const getActivationProps = (activate: () => void) => ({
  role: 'button' as const,
  tabIndex: 0,
  onClick: activate,
  onKeyDown: (event: KeyboardEvent<HTMLElement>) => {
    if (event.key !== 'Enter' && event.key !== ' ') return
    event.preventDefault()
    activate()
  },
})

import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type ThemeMode = 'dark' | 'light' | 'system'

interface ThemeState {
  mode: ThemeMode
  /** Resolved actual appearance after checking system preference */
  isDark: boolean
  setMode: (mode: ThemeMode) => void
}

function getSystemDark(): boolean {
  if (typeof window === 'undefined') return false
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

function resolveDark(mode: ThemeMode): boolean {
  if (mode === 'system') return getSystemDark()
  return mode === 'dark'
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set) => ({
      mode: 'dark',
      isDark: true,
      setMode: (mode: ThemeMode) => {
        set({ mode, isDark: resolveDark(mode) })
      },
    }),
    {
      name: 'theme-mode',
      onRehydrateStorage: () => (state) => {
        if (state) {
          state.isDark = resolveDark(state.mode)
        }
      },
    },
  ),
)

// Listen for system theme changes
if (typeof window !== 'undefined') {
  const mq = window.matchMedia('(prefers-color-scheme: dark)')
  mq.addEventListener('change', () => {
    const store = useThemeStore.getState()
    if (store.mode === 'system') {
      store.setMode('system')
    }
  })
}

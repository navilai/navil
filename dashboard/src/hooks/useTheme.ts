import { useCallback, useEffect, useState } from 'react'

export type Theme = 'system' | 'light' | 'dark'

const STORAGE_KEY = 'navil-theme'

/**
 * Tiny theme hook (no library dep). Three states:
 *  - "system" → follows prefers-color-scheme, updates live as the OS flips
 *  - "light"  → forces light, ignores OS
 *  - "dark"   → forces dark, ignores OS
 *
 * Persists choice under "navil-theme". Applies/removes `.dark` class on <html>.
 */
export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(() => {
    if (typeof window === 'undefined') return 'system'
    return (localStorage.getItem(STORAGE_KEY) as Theme | null) ?? 'system'
  })

  // Apply the resolved theme to <html>.
  useEffect(() => {
    if (typeof window === 'undefined') return

    const apply = () => {
      const root = document.documentElement
      const resolved =
        theme === 'system'
          ? window.matchMedia('(prefers-color-scheme: dark)').matches
            ? 'dark'
            : 'light'
          : theme
      root.classList.toggle('dark', resolved === 'dark')
      root.style.colorScheme = resolved
    }

    apply()

    if (theme === 'system') {
      const mq = window.matchMedia('(prefers-color-scheme: dark)')
      mq.addEventListener('change', apply)
      return () => mq.removeEventListener('change', apply)
    }
  }, [theme])

  const setTheme = useCallback((next: Theme) => {
    if (typeof window === 'undefined') return
    if (next === 'system') localStorage.removeItem(STORAGE_KEY)
    else localStorage.setItem(STORAGE_KEY, next)
    setThemeState(next)
  }, [])

  return { theme, setTheme }
}

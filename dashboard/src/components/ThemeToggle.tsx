import { useTheme } from '../hooks/useTheme'

const NEXT = {
  system: 'light',
  light: 'dark',
  dark: 'system',
} as const

const LABEL = {
  system: 'Theme: system. Switch to light.',
  light: 'Theme: light. Switch to dark.',
  dark: 'Theme: dark. Switch to system.',
} as const

const PATHS = {
  // Inline SVG paths so we don't need a new icon dep in the dashboard repo.
  system: (
    <>
      <rect x="3" y="4" width="18" height="12" rx="1.5" />
      <path d="M8 21h8M12 17v4" />
    </>
  ),
  light: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
    </>
  ),
  dark: <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />,
} as const

/**
 * 3-state theme cycle for the OSS dashboard.
 * Mirrors the marketing-site toggle for visual continuity.
 * No icon-library dep — inline SVG.
 */
export default function ThemeToggle() {
  const { theme, setTheme } = useTheme()

  return (
    <button
      type="button"
      onClick={() => setTheme(NEXT[theme])}
      aria-label={LABEL[theme]}
      title={LABEL[theme]}
      className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-rule text-ink-muted transition-colors hover:border-ink hover:text-ink"
    >
      <svg
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {PATHS[theme]}
      </svg>
    </button>
  )
}

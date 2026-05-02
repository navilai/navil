/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Token-driven Navil palette — see ./src/index.css for the values.
        // Existing pages use these names (e.g. `bg-navil-bg`); they now
        // automatically respond to the active theme via CSS variables.
        navil: {
          bg: 'var(--bg)',
          'bg-secondary': 'var(--surface)',
          card: 'var(--surface)',
          'card-hover': 'var(--surface-elevated)',
          border: 'var(--rule)',
          accent: 'var(--signal-cyan)',
          'accent-dim': 'var(--signal-cyan)',
        },
        // Semantic tokens — preferred for new code.
        bg: 'var(--bg)',
        surface: 'var(--surface)',
        'surface-elevated': 'var(--surface-elevated)',
        ink: 'var(--ink)',
        'ink-secondary': 'var(--ink-secondary)',
        'ink-muted': 'var(--ink-muted)',
        rule: 'var(--rule)',
        'rule-strong': 'var(--rule-strong)',
        'signal-cyan': 'var(--signal-cyan)',
        'signal-amber': 'var(--signal-amber)',
        'signal-red': 'var(--signal-red)',
        'signal-green': 'var(--signal-green)',
      },
      fontFamily: {
        sans: ['Geist', 'system-ui', 'sans-serif'],
        mono: ['"Geist Mono"', 'ui-monospace', 'monospace'],
      },
      borderRadius: {
        card: '12px',
      },
      animation: {
        fadeIn: 'fadeIn 0.4s ease-out forwards',
        slideUp: 'slideUp 0.4s ease-out forwards',
        slideDown: 'slideDown 0.2s ease-out forwards',
        shimmer: 'shimmer 1.5s infinite',
        pulseGlow: 'pulseGlow 2s ease-in-out infinite',
        scoreReveal: 'scoreReveal 1.2s ease-out 0.3s forwards',
        'reveal-up': 'revealUp 0.6s ease-out forwards',
        'cursor-blink': 'cursorBlink 1s step-end infinite',
        'pulse-dot': 'pulseDot 2s ease-in-out infinite',
        'scan-line': 'scanLine 4s linear infinite',
      },
      keyframes: {
        fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideDown: {
          '0%': { opacity: '0', transform: 'translateY(-4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        pulseGlow: { '0%, 100%': { opacity: '0.4' }, '50%': { opacity: '1' } },
        scoreReveal: {
          '0%': { strokeDashoffset: '283' },
          '100%': { strokeDashoffset: 'var(--score-offset)' },
        },
        revealUp: {
          '0%': { opacity: '0', transform: 'translateY(24px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        cursorBlink: { '0%, 100%': { opacity: '1' }, '50%': { opacity: '0' } },
        pulseDot: {
          '0%, 100%': { opacity: '0.4', transform: 'scale(1)' },
          '50%': { opacity: '1', transform: 'scale(1.5)' },
        },
        scanLine: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
      },
      backdropBlur: { xs: '2px' },
    },
  },
  plugins: [],
}

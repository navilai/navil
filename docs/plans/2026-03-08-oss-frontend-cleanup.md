# OSS Frontend Cleanup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Strip all SaaS/marketing code from `dashboard/src/`, move routes to `/`, and replace billing gates with an LLM-key availability check so AI features work out-of-the-box.

**Architecture:** Delete 36 SaaS files, rewrite 5 core files (App.tsx, main.tsx, DashboardLayout, UpgradePrompt, UserProfile), create one new hook (`useLLMAvailable`), make 4 one-line import swaps in SSE pages.

**Tech Stack:** React 18, React Router 6, TypeScript, Vite, FastAPI (no changes needed)

---

## Quick Reference: What to Delete vs Keep

**DELETE** (36 files — full paths below in Task 1)
**KEEP** (these 10 OSS dashboard pages are untouched):
`Agents`, `Alerts`, `Credentials`, `Feedback`, `Gateway`, `Pentest`, `Policy`, `Scanner`, `SelfHealing`, `Settings`

**KEEP** (shared UI components — untouched):
`Icon`, `PageHeader`, `SeverityBadge`, `StatusBadge`, `AnimatedNumber`, `CodeBlock`, `ConnectionError`, `LLMErrorCard`, `MiniBar`, `RelativeTime`, `ScoreGauge`, `ScrollToTop`, `SectionHeader`, `Skeleton`, `SparklineChart`

**KEEP** (hooks — untouched):
`useNavilStream`, `useReveal`, `useSessionState`

**KEEP** (everything in `navil/` Python backend — untouched)

---

### Task 1: Delete all SaaS / marketing files

**Files:**
- Delete (36 files — all paths relative to `dashboard/src/`)

**Step 1: Run the delete command**

```bash
cd /Users/clawbot/claude/naivl/dashboard/src

# Pages — marketing
rm pages/Landing.tsx pages/Pricing.tsx pages/About.tsx pages/Blog.tsx pages/Changelog.tsx

# Pages — auth / cloud onboarding
rm pages/SignIn.tsx pages/SignUp.tsx pages/Onboarding.tsx

# Pages — SaaS-only features
rm pages/ApiKeys.tsx pages/Analytics.tsx

# Pages — admin portal (multi-tenant)
rm pages/admin/AdminOverview.tsx pages/admin/AdminTenants.tsx \
   pages/admin/AdminAlerts.tsx pages/admin/AdminApiKeys.tsx \
   pages/admin/AdminSystem.tsx

# Pages — solutions (marketing)
rm pages/solutions/MCPSecurity.tsx pages/solutions/AICompliance.tsx \
   pages/solutions/PentestAutomation.tsx

# Pages — docs (belong on navil.ai)
rm pages/docs/APIReference.tsx pages/docs/Configuration.tsx \
   pages/docs/DocsHub.tsx pages/docs/LLMIntegration.tsx \
   pages/docs/PentestDocs.tsx pages/docs/PolicyEngine.tsx \
   pages/docs/Proxy.tsx

# Components — marketing only
rm components/MegaNav.tsx components/Footer.tsx components/NewsletterSignup.tsx \
   components/FeatureComparisonTable.tsx components/MockTrafficMonitor.tsx \
   components/MockRemediationEngine.tsx

# Layouts — marketing / admin / docs
rm layouts/PublicLayout.tsx layouts/AdminLayout.tsx layouts/DocsLayout.tsx

# Auth — Clerk + local session (no auth needed in OSS self-hosted)
rm auth/ClerkProviderWrapper.tsx auth/AuthTokenBridge.tsx \
   auth/ProtectedRoute.tsx auth/LocalAuthContext.tsx

# Hooks — billing
rm hooks/useBilling.ts
```

**Step 2: Verify deletions**

```bash
ls pages/ pages/admin/ pages/solutions/ pages/docs/ \
   components/ layouts/ auth/ hooks/ 2>&1 | grep -v "No such"
```

Expected: none of the deleted filenames appear. `auth/` directory may now be empty or gone.

**Step 3: Commit**

```bash
cd /Users/clawbot/claude/naivl
git add -A
git commit -m "chore: delete SaaS marketing, auth, admin, docs frontend files"
```

---

### Task 2: Create `useLLMAvailable` hook

**Files:**
- Create: `dashboard/src/hooks/useLLMAvailable.ts`

**Step 1: Write the hook**

```typescript
import { useEffect, useState } from 'react'
import { api } from '../api'

interface UseLLMAvailableResult {
  canUseLLM: boolean
  loading: boolean
}

/**
 * Returns canUseLLM=true when the user has configured an LLM API key
 * in Settings. Uses GET /api/local/settings/llm → LLMConfig.api_key_set.
 * No billing, no plan tiers — OSS only.
 */
export default function useLLMAvailable(): UseLLMAvailableResult {
  const [canUseLLM, setCanUseLLM] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getLLMSettings()
      .then(s => setCanUseLLM(s.api_key_set))
      .catch(() => setCanUseLLM(false))
      .finally(() => setLoading(false))
  }, [])

  return { canUseLLM, loading }
}
```

**Step 2: Verify it type-checks (no test needed for a trivial hook)**

```bash
cd /Users/clawbot/claude/naivl/dashboard
npx tsc --noEmit 2>&1 | head -30
```

Expected: no errors referencing `useLLMAvailable.ts`

**Step 3: Commit**

```bash
cd /Users/clawbot/claude/naivl
git add dashboard/src/hooks/useLLMAvailable.ts
git commit -m "feat: add useLLMAvailable hook (replaces billing-gated useBilling)"
```

---

### Task 3: Simplify `UpgradePrompt.tsx`

**Files:**
- Modify: `dashboard/src/components/UpgradePrompt.tsx`

Current file references `/dashboard/settings` and has "Upgrade to Lite" / Stripe concepts.
Replace entirely with a plain "configure API key" prompt.

**Step 1: Overwrite the file**

```typescript
import { Link } from 'react-router-dom'
import Icon from './Icon'

interface UpgradePromptProps {
  /** Short description of the gated feature. */
  feature: string
  /** compact=true renders a single inline row; default is a full card. */
  compact?: boolean
}

/**
 * Shown in place of AI-powered features when no LLM API key is configured.
 * Directs the user to Settings to add their key.
 */
export default function UpgradePrompt({ feature, compact }: UpgradePromptProps) {
  if (compact) {
    return (
      <div className="flex items-center gap-3 p-3 rounded-lg bg-violet-500/5 border border-violet-500/20">
        <Icon name="sparkles" size={14} className="text-violet-400 shrink-0" />
        <p className="text-xs text-gray-400 flex-1">
          {feature} requires an LLM API key.{' '}
          <Link to="/settings" className="text-cyan-400 hover:underline">
            Configure in Settings
          </Link>
        </p>
      </div>
    )
  }

  return (
    <div className="glass-card p-8 text-center animate-fadeIn">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-violet-500/10 mb-4">
        <Icon name="sparkles" size={32} className="text-violet-400" />
      </div>
      <h3 className="text-lg font-medium text-gray-200 mb-2">{feature}</h3>
      <p className="text-sm text-gray-500 mb-6 max-w-md mx-auto">
        Configure an LLM API key in Settings to enable AI-powered analysis.
      </p>
      <Link
        to="/settings"
        className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-400"
      >
        <Icon name="key" size={14} />
        Configure API Key
      </Link>
    </div>
  )
}
```

**Step 2: Verify type-check**

```bash
cd /Users/clawbot/claude/naivl/dashboard
npx tsc --noEmit 2>&1 | head -20
```

Expected: no errors from UpgradePrompt.tsx

**Step 3: Commit**

```bash
cd /Users/clawbot/claude/naivl
git add dashboard/src/components/UpgradePrompt.tsx
git commit -m "refactor: replace billing UpgradePrompt with OSS API key prompt"
```

---

### Task 4: Simplify `UserProfile.tsx`

**Files:**
- Modify: `dashboard/src/components/UserProfile.tsx`

Current file imports `useUser`/`useClerk` from `@clerk/clerk-react` and `LocalAuthContext`
(both deleted). Replace with a single static OSS footer showing version + settings link.

**Step 1: Overwrite the file**

```typescript
import { NavLink } from 'react-router-dom'
import Icon from './Icon'

/**
 * Sidebar footer for the OSS self-hosted dashboard.
 * Shows version number and a shortcut to Settings.
 */
export default function UserProfile() {
  return (
    <div className="relative border-t border-gray-800/60">
      <div className="p-3 flex items-center gap-3">
        <div className="w-7 h-7 rounded-full bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center shrink-0 text-xs font-semibold text-cyan-400">
          N
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-xs text-gray-300 truncate">Navil OSS</p>
          <p className="text-[10px] text-gray-600 truncate">Self-hosted</p>
        </div>
      </div>
      <div className="px-3 pb-3 flex items-center justify-end">
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-gray-600">v0.1.0</span>
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `p-1 rounded transition-colors ${
                isActive
                  ? 'text-cyan-400 bg-cyan-500/10'
                  : 'text-gray-600 hover:text-gray-400 hover:bg-gray-800/60'
              }`
            }
          >
            <Icon name="settings" size={12} />
          </NavLink>
        </div>
      </div>
    </div>
  )
}
```

**Step 2: Verify type-check**

```bash
cd /Users/clawbot/claude/naivl/dashboard
npx tsc --noEmit 2>&1 | head -20
```

Expected: no errors from UserProfile.tsx

**Step 3: Commit**

```bash
cd /Users/clawbot/claude/naivl
git add dashboard/src/components/UserProfile.tsx
git commit -m "refactor: strip Clerk/local auth from UserProfile, OSS-only footer"
```

---

### Task 5: Rewrite `DashboardLayout.tsx`

**Files:**
- Modify: `dashboard/src/layouts/DashboardLayout.tsx`

Changes needed:
1. Remove `isCloud` constant (references deleted `VITE_CLERK_PUBLISHABLE_KEY`)
2. Update all `navItems` paths: `/dashboard/x` → `/x`
3. Remove `Dashboard` and `Analytics` and `API Keys` nav items (pages deleted)
4. Change logo `<Link to="/dashboard">` → `<Link to="/">`
5. Change `end={to === '/dashboard'}` → `end={to === '/'}`
6. Remove cloud/OSS badge from logo — always show "OSS"

**Step 1: Overwrite the file**

```typescript
import { useState } from 'react'
import { NavLink, Outlet, Link } from 'react-router-dom'
import Icon, { type IconName } from '../components/Icon'
import UserProfile from '../components/UserProfile'

const navItems: { to: string; label: string; icon: IconName }[] = [
  { to: '/',              label: 'Agents',       icon: 'bot' },
  { to: '/gateway',       label: 'Gateway',      icon: 'gateway' },
  { to: '/pentest',       label: 'Pentest',      icon: 'pentest' },
  { to: '/scanner',       label: 'Scanner',      icon: 'scan' },
  { to: '/alerts',        label: 'Alerts',       icon: 'alert' },
  { to: '/credentials',   label: 'Credentials',  icon: 'key' },
  { to: '/policy',        label: 'Policy',       icon: 'shield' },
  { to: '/feedback',      label: 'Feedback',     icon: 'activity' },
  { to: '/self-healing',  label: 'Self-Healing', icon: 'sparkles' },
  { to: '/settings',      label: 'Settings',     icon: 'settings' },
]

export default function DashboardLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="flex h-screen">
      {/* Mobile backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-30 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-56 bg-gray-900/80 backdrop-blur-xl border-r border-gray-800/60 flex flex-col
          transform transition-transform duration-300 md:relative md:translate-x-0
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        {/* Subtle gradient overlay */}
        <div className="absolute inset-0 bg-gradient-to-b from-cyan-500/[0.03] to-transparent pointer-events-none rounded-r-xl" />

        <div className="relative p-5 border-b border-gray-800/60">
          <Link to="/" className="text-xl font-bold flex items-center gap-2.5 hover:opacity-80 transition-opacity">
            <div className="relative">
              <div className="absolute inset-0 bg-cyan-500/20 rounded-lg blur-sm animate-pulseGlow" />
              <Icon name="shield" size={24} className="text-cyan-400 relative" />
            </div>
            <span>
              Navil{' '}
              <span className="text-xs font-normal px-1.5 py-0.5 rounded text-cyan-400 bg-cyan-400/10">
                OSS
              </span>
            </span>
          </Link>
          <p className="text-xs text-gray-500 mt-1.5">Agent Security Dashboard</p>
        </div>

        <nav className="relative flex-1 p-3 space-y-1">
          {navItems.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm nav-glow ${
                  isActive
                    ? 'nav-active-bar bg-cyan-500/10 text-cyan-300 font-medium'
                    : 'text-gray-400 hover:bg-gray-800/60 hover:text-gray-200'
                }`
              }
            >
              <Icon name={icon} size={18} />
              {label}
            </NavLink>
          ))}
        </nav>

        <UserProfile />
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        {/* Mobile hamburger */}
        <button
          onClick={() => setSidebarOpen(true)}
          aria-label="Open navigation menu"
          className="md:hidden fixed top-4 left-4 z-20 p-2 bg-gray-900/80 backdrop-blur border border-gray-800/60 rounded-lg text-gray-400 hover:text-gray-200"
        >
          <Icon name="menu" size={20} />
        </button>

        <div className="max-w-7xl mx-auto px-6 pt-16 pb-6 md:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
```

**Step 2: Verify type-check**

```bash
cd /Users/clawbot/claude/naivl/dashboard
npx tsc --noEmit 2>&1 | head -30
```

Expected: no errors from DashboardLayout.tsx

**Step 3: Commit**

```bash
cd /Users/clawbot/claude/naivl
git add dashboard/src/layouts/DashboardLayout.tsx
git commit -m "refactor: remove cloud flag from DashboardLayout, routes to root /"
```

---

### Task 6: Rewrite `App.tsx`

**Files:**
- Modify: `dashboard/src/App.tsx`

Replace the full SaaS routing tree with a minimal OSS router. All 10 dashboard pages
at root `/`. No `ProtectedRoute`, no `PublicLayout`, no `AdminLayout`.

**Step 1: Overwrite the file**

```typescript
/**
 * Navil OSS — local self-hosted dashboard.
 * All routes live at the root path (/).
 */
import { Routes, Route, Navigate } from 'react-router-dom'
import DashboardLayout from './layouts/DashboardLayout'

import Agents from './pages/Agents'
import Gateway from './pages/Gateway'
import Pentest from './pages/Pentest'
import Scanner from './pages/Scanner'
import Alerts from './pages/Alerts'
import Credentials from './pages/Credentials'
import Policy from './pages/Policy'
import Feedback from './pages/Feedback'
import SelfHealing from './pages/SelfHealing'
import Settings from './pages/Settings'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<DashboardLayout />}>
        <Route index element={<Agents />} />
        <Route path="gateway" element={<Gateway />} />
        <Route path="pentest" element={<Pentest />} />
        <Route path="scanner" element={<Scanner />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="credentials" element={<Credentials />} />
        <Route path="policy" element={<Policy />} />
        <Route path="feedback" element={<Feedback />} />
        <Route path="self-healing" element={<SelfHealing />} />
        <Route path="settings" element={<Settings />} />
      </Route>

      {/* Catch-all: redirect old /dashboard/* deep links to root */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
```

**Step 2: Verify type-check**

```bash
cd /Users/clawbot/claude/naivl/dashboard
npx tsc --noEmit 2>&1 | head -30
```

Expected: no errors

**Step 3: Commit**

```bash
cd /Users/clawbot/claude/naivl
git add dashboard/src/App.tsx
git commit -m "refactor: OSS-only App.tsx — dashboard at root /, remove all SaaS routes"
```

---

### Task 7: Simplify `main.tsx`

**Files:**
- Modify: `dashboard/src/main.tsx`

Remove `ClerkProviderWrapper` and `LocalAuthProvider` — both deleted. Just `BrowserRouter` → `App`.

**Step 1: Overwrite the file**

```typescript
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)
```

**Step 2: Verify type-check**

```bash
cd /Users/clawbot/claude/naivl/dashboard
npx tsc --noEmit 2>&1 | head -30
```

Expected: zero errors

**Step 3: Commit**

```bash
cd /Users/clawbot/claude/naivl
git add dashboard/src/main.tsx
git commit -m "refactor: strip Clerk/LocalAuth wrappers from main.tsx"
```

---

### Task 8: Swap `useBilling` → `useLLMAvailable` in all 4 SSE pages

**Files:**
- Modify: `dashboard/src/pages/Scanner.tsx`
- Modify: `dashboard/src/pages/Alerts.tsx`
- Modify: `dashboard/src/pages/SelfHealing.tsx`
- Modify: `dashboard/src/pages/Policy.tsx`

Each page currently has:
```typescript
import useBilling from '../hooks/useBilling'
// ...
const { canUseLLM, setPlan } = useBilling()
// ...
<UpgradePrompt feature="..." onUpgrade={() => setPlan('lite')} compact />
```

Apply the following diff to each page:

**Scanner.tsx, SelfHealing.tsx (pattern):**
1. Line `import useBilling from '../hooks/useBilling'` → `import useLLMAvailable from '../hooks/useLLMAvailable'`
2. Line `const { canUseLLM, setPlan } = useBilling()` → `const { canUseLLM } = useLLMAvailable()`
3. Any `<UpgradePrompt ... onUpgrade={() => setPlan('lite')} ... />` → remove the `onUpgrade` prop

**Alerts.tsx (uses `setPlan` in two places):**
Same substitution — remove `setPlan` from destructuring and from `onUpgrade` prop.

**Policy.tsx (uses `setPlan` in one place):**
Same substitution.

**Step 1: Apply the change to Scanner.tsx**

```bash
cd /Users/clawbot/claude/naivl/dashboard/src/pages
```

Edit `Scanner.tsx`:
- `import useBilling from '../hooks/useBilling'` → `import useLLMAvailable from '../hooks/useLLMAvailable'`
- `const { canUseLLM, setPlan } = useBilling()` → `const { canUseLLM } = useLLMAvailable()`
- `<UpgradePrompt feature="AI Deep Analysis" onUpgrade={() => setPlan('lite')} compact />` → `<UpgradePrompt feature="AI Deep Analysis" compact />`

**Step 2: Apply the change to Alerts.tsx**

Edit `Alerts.tsx`:
- `import useBilling from '../hooks/useBilling'` → `import useLLMAvailable from '../hooks/useLLMAvailable'`
- `const { canUseLLM, setPlan } = useBilling()` → `const { canUseLLM } = useLLMAvailable()`
- `<UpgradePrompt feature="AI-powered alert analysis" onUpgrade={() => setPlan('lite')} compact />` → `<UpgradePrompt feature="AI-powered alert analysis" compact />`

**Step 3: Apply the change to SelfHealing.tsx**

Edit `SelfHealing.tsx`:
- Same pattern: swap import + remove `setPlan` from destructure + remove `onUpgrade` prop

**Step 4: Apply the change to Policy.tsx**

Edit `Policy.tsx`:
- Same pattern: swap import + remove `setPlan` from destructure + remove `onUpgrade` prop

**Step 5: Verify all four pages type-check cleanly**

```bash
cd /Users/clawbot/claude/naivl/dashboard
npx tsc --noEmit 2>&1
```

Expected: zero errors

**Step 6: Commit**

```bash
cd /Users/clawbot/claude/naivl
git add dashboard/src/pages/Scanner.tsx dashboard/src/pages/Alerts.tsx \
        dashboard/src/pages/SelfHealing.tsx dashboard/src/pages/Policy.tsx
git commit -m "refactor: replace useBilling with useLLMAvailable in all 4 SSE pages"
```

---

### Task 9: Full build + backend test verification

**Step 1: Run the React production build**

```bash
cd /Users/clawbot/claude/naivl/dashboard
npm run build 2>&1
```

Expected output:
- Zero TypeScript errors
- `✓ built in X.XXs`
- Output in `dashboard/dist/`
- No references to deleted files in error output

**Step 2: Confirm no stale imports remain**

```bash
cd /Users/clawbot/claude/naivl/dashboard/src
grep -r "useBilling\|ClerkProvider\|ProtectedRoute\|LocalAuthContext\|AuthTokenBridge\|PublicLayout\|AdminLayout\|DocsLayout\|Landing\|Pricing\|SignIn\|SignUp\|Analytics\|ApiKeys\|AdminOverview\|AdminTenants" . 2>&1
```

Expected: **no output** (all stale imports are gone)

**Step 3: Run backend tests**

```bash
cd /Users/clawbot/claude/naivl
pytest 2>&1 | tail -5
```

Expected:
```
271 passed in X.XXs
```
(no failures — backend unchanged)

**Step 4: Smoke-test the server**

Start the server and verify the dashboard loads at `/`:

```bash
# Server should already be running at port 8484; if not:
# python3 -m navil cloud serve --port 8484
```

Navigate to `http://localhost:8484` — should render Agents page with OSS sidebar.
Navigate to `http://localhost:8484/settings` — Settings page with Community Threat Feed toggle.
Navigate to `http://localhost:8484/policy` — Policy engine page.

**Step 5: Final commit**

```bash
cd /Users/clawbot/claude/naivl
git add docs/plans/
git commit -m "docs: add OSS frontend cleanup design + implementation plan"
```

---

## Summary

| Task | Files Changed | Description |
|------|---------------|-------------|
| 1 | 36 deletions | Delete all SaaS/marketing/auth/admin/docs files |
| 2 | +1 create | `useLLMAvailable.ts` — OSS LLM key availability hook |
| 3 | 1 modify | `UpgradePrompt.tsx` — remove Stripe/plan language |
| 4 | 1 modify | `UserProfile.tsx` — strip Clerk/local auth |
| 5 | 1 modify | `DashboardLayout.tsx` — routes to `/`, OSS badge only |
| 6 | 1 modify | `App.tsx` — OSS router, root `/` |
| 7 | 1 modify | `main.tsx` — strip auth providers |
| 8 | 4 modify | SSE pages: swap `useBilling` → `useLLMAvailable` |
| 9 | verify | `npm run build` + `pytest` + smoke test |

**Critical invariant**: The `useNavilStream` hook, all SSE endpoints, and all 10 local dashboard pages are never touched. Only the marketing/SaaS front door is removed.

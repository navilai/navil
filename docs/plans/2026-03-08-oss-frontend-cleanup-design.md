# OSS Frontend Cleanup — Design Doc
**Date:** 2026-03-08
**Status:** Approved

## Problem

The `dashboard/src/` directory contains the full Navil Cloud SaaS frontend:
marketing landing page, pricing, blog, auth (Clerk), admin portal, solutions pages,
docs pages, and a multi-tenant `/dashboard` route tree. The OSS repo must serve
only the local proxy monitoring dashboard.

## Goals

1. Delete all SaaS/marketing frontend code.
2. Move dashboard routes from `/dashboard/*` to `/*` (root).
3. Replace `useBilling` + billing-gated `UpgradePrompt` with a simple LLM-key
   availability check so AI features work out-of-the-box in OSS.
4. `npm run build` passes; 271 backend tests still pass.

## Approach

**Approach A — Minimal surgery**: rewrite `App.tsx` with OSS-only routes at `/`,
update `DashboardLayout.tsx` nav paths, delete SaaS files, replace `useBilling`
with `useLLMAvailable`. FastAPI `app.py` unchanged (already serves `/{path:path}`).

## Files to DELETE (35)

### Pages
- `pages/Landing.tsx`, `pages/Pricing.tsx`, `pages/About.tsx`, `pages/Blog.tsx`,
  `pages/Changelog.tsx`
- `pages/SignIn.tsx`, `pages/SignUp.tsx`, `pages/Onboarding.tsx`
- `pages/ApiKeys.tsx`, `pages/Analytics.tsx`
- `pages/admin/AdminOverview.tsx`, `AdminTenants.tsx`, `AdminAlerts.tsx`,
  `AdminApiKeys.tsx`, `AdminSystem.tsx`
- `pages/solutions/MCPSecurity.tsx`, `AICompliance.tsx`, `PentestAutomation.tsx`
- `pages/docs/APIReference.tsx`, `Configuration.tsx`, `DocsHub.tsx`,
  `LLMIntegration.tsx`, `PentestDocs.tsx`, `PolicyEngine.tsx`, `Proxy.tsx`

### Components
- `components/MegaNav.tsx`, `Footer.tsx`, `NewsletterSignup.tsx`,
  `FeatureComparisonTable.tsx`, `MockTrafficMonitor.tsx`, `MockRemediationEngine.tsx`

### Layouts
- `layouts/PublicLayout.tsx`, `layouts/AdminLayout.tsx`, `layouts/DocsLayout.tsx`

### Auth
- `auth/ClerkProviderWrapper.tsx`, `auth/AuthTokenBridge.tsx`,
  `auth/ProtectedRoute.tsx`

### Hooks
- `hooks/useBilling.ts`

## Files to MODIFY (5)

### `App.tsx` (rewrite)
OSS-only routes, no `ProtectedRoute`, all paths at `/` not `/dashboard`:
```
/              → DashboardLayout (Agents as index)
/gateway       → Gateway
/scanner       → Scanner
/pentest       → Pentest
/agents        → Agents
/alerts        → Alerts
/credentials   → Credentials
/policy        → Policy
/feedback      → Feedback
/self-healing  → SelfHealing
/settings      → Settings
*              → <Navigate to="/" replace />
```

### `main.tsx`
Remove `ClerkProviderWrapper` and `LocalAuthProvider` wrappers. Just
`<BrowserRouter><App /></BrowserRouter>`.

### `DashboardLayout.tsx`
- Update `navItems` paths: `/dashboard/x` → `/x`
- Remove cloud/OSS conditional badge — always show "OSS"
- Remove `UserProfile` import (cloud user session concept)
- Logo link: `/dashboard` → `/`

### `hooks/useLLMAvailable.ts` (replaces `useBilling.ts`)
```ts
// Returns { canUseLLM: boolean, loading: boolean }
// canUseLLM = true if LLM api_key is configured in settings
```
Calls `GET /api/local/settings/llm/get`, checks `response.api_key !== ''`.

### `components/UpgradePrompt.tsx`
- Remove "Upgrade to Lite" / "LITE FEATURE" badge
- Replace with "Configure API Key" prompt pointing to `/settings`
- Props simplified: remove `onUpgrade`

### All SSE pages (4 files)
1-line import change: `useBilling` → `useLLMAvailable`, remove `setPlan`.
Pages: `Scanner.tsx`, `Alerts.tsx`, `SelfHealing.tsx`, `Policy.tsx`.

## Files Unchanged

- `navil/api/local/app.py` — already serves SPA correctly
- All SSE hooks, streaming logic, local API routes
- All kept dashboard pages and shared UI components

## Verification

1. `cd dashboard && npm run build` — zero errors
2. `pytest` — ~271 tests pass
3. Browser: `/` renders Agents dashboard, `/settings` works, LLM toggle present

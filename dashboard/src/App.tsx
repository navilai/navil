/**
 * Navil OSS — local self-hosted dashboard.
 *
 * Two modes:
 *  - Local (no Clerk key): no auth wall, all pages accessible immediately.
 *  - Cloud (VITE_CLERK_PUBLISHABLE_KEY set): Clerk sign-in required.
 */
import { Routes, Route, Navigate } from 'react-router-dom'
import {
  SignIn,
  SignUp,
  SignedIn,
  SignedOut,
  RedirectToSignIn,
} from '@clerk/clerk-react'
import DashboardLayout from './layouts/DashboardLayout'

import Agents from './pages/Agents'
import Gateway from './pages/Gateway'
import Pentest from './pages/Pentest'
import Scanner from './pages/Scanner'
import Alerts from './pages/Alerts'
import Credentials from './pages/Credentials'
import Policy from './pages/Policy'
import Scoping from './pages/Scoping'
import Feedback from './pages/Feedback'
import SelfHealing from './pages/SelfHealing'
import AgentCard from './pages/AgentCard'
import Settings from './pages/Settings'
import Analytics from './pages/Analytics'
import Billing from './pages/Billing'
import Webhooks from './pages/Webhooks'
import ThreatRules from './pages/ThreatRules'
import CloudGuard from './components/CloudGuard'

/**
 * When running locally via `navil cloud serve`, no Clerk publishable key
 * is set. The Clerk components are imported but only rendered when a
 * ClerkProvider is present (see main.tsx).
 */
const hasClerk = !!import.meta.env.VITE_CLERK_PUBLISHABLE_KEY

/**
 * Auth-aware layout wrapper.
 * Local mode: renders DashboardLayout directly — no sign-in wall.
 * Cloud mode: wraps in Clerk's SignedIn / SignedOut guards.
 */
function ProtectedLayout() {
  if (!hasClerk) return <DashboardLayout />

  return (
    <>
      <SignedIn>
        <DashboardLayout />
      </SignedIn>
      <SignedOut>
        <RedirectToSignIn />
      </SignedOut>
    </>
  )
}

export default function App() {
  return (
    <Routes>
      {/* Auth routes — only relevant when Clerk is configured */}
      {hasClerk && (
        <>
          <Route
            path="/sign-in/*"
            element={
              <div className="min-h-screen bg-[#0a0e17] flex items-center justify-center">
                <SignIn routing="path" path="/sign-in" signUpUrl="/sign-up" />
              </div>
            }
          />
          <Route
            path="/sign-up/*"
            element={
              <div className="min-h-screen bg-[#0a0e17] flex items-center justify-center">
                <SignUp routing="path" path="/sign-up" signInUrl="/sign-in" />
              </div>
            }
          />
        </>
      )}

      {/* Dashboard routes */}
      <Route path="/" element={<ProtectedLayout />}>
        <Route index element={<Agents />} />
        <Route path="gateway" element={<Gateway />} />
        <Route path="pentest" element={<Pentest />} />
        <Route path="scanner" element={<Scanner />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="credentials" element={<Credentials />} />
        <Route path="policy" element={<Policy />} />
        <Route path="scoping" element={<Scoping />} />
        <Route path="feedback" element={<Feedback />} />
        <Route path="self-healing" element={<SelfHealing />} />
        <Route path="agent-card" element={<AgentCard />} />
        <Route path="settings" element={<Settings />} />
        {/* Cloud management pages — guarded for local mode */}
        <Route path="analytics" element={<CloudGuard title="Analytics" subtitle="Threat detection analytics"><Analytics /></CloudGuard>} />
        <Route path="billing" element={<CloudGuard title="Billing" subtitle="Manage your subscription"><Billing /></CloudGuard>} />
        <Route path="webhooks" element={<CloudGuard title="Webhooks" subtitle="Manage webhook integrations"><Webhooks /></CloudGuard>} />
        <Route path="threat-rules" element={<CloudGuard title="Threat Rules" subtitle="Custom detection rules"><ThreatRules /></CloudGuard>} />
      </Route>

      {/* Catch-all: redirect old /dashboard/* deep links to root */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

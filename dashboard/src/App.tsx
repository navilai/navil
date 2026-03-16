/**
 * Navil OSS — local self-hosted dashboard.
 * All routes live at the root path (/).
 */
import { Routes, Route, Navigate } from 'react-router-dom'
import { SignIn, SignUp, SignedIn, SignedOut, RedirectToSignIn } from '@clerk/clerk-react'
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
import Analytics from './pages/Analytics'
import Billing from './pages/Billing'
import Webhooks from './pages/Webhooks'
import ThreatRules from './pages/ThreatRules'

export default function App() {
  return (
    <Routes>
      {/* Auth routes */}
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

      {/* Protected routes */}
      <Route
        path="/"
        element={
          <>
            <SignedIn>
              <DashboardLayout />
            </SignedIn>
            <SignedOut>
              <RedirectToSignIn />
            </SignedOut>
          </>
        }
      >
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
        {/* Cloud management pages */}
        <Route path="analytics" element={<Analytics />} />
        <Route path="billing" element={<Billing />} />
        <Route path="webhooks" element={<Webhooks />} />
        <Route path="threat-rules" element={<ThreatRules />} />
      </Route>

      {/* Catch-all: redirect old /dashboard/* deep links to root */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

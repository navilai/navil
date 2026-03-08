/**
 * Navil Cloud — full navil.ai hosted experience.
 *
 * Extends the OSS dashboard with public marketing pages,
 * docs, solutions, pricing, and the landing page.
 *
 * This file replaces dashboard/src/App.tsx at build time.
 */
import { Routes, Route, Navigate } from 'react-router-dom'
import ScrollToTop from './components/ScrollToTop'
import { isAuthEnabled } from './auth/ClerkProviderWrapper'
import AuthTokenBridge from './auth/AuthTokenBridge'
import ProtectedRoute from './auth/ProtectedRoute'
import DashboardLayout from './layouts/DashboardLayout'
import PublicLayout from './layouts/PublicLayout'
import DocsLayout from './layouts/DocsLayout'

// Auth
import SignIn from './pages/SignIn'
import SignUp from './pages/SignUp'

// Public / marketing pages
import Landing from './pages/Landing'
import Pricing from './pages/Pricing'
import About from './pages/About'
import Blog from './pages/Blog'
import Changelog from './pages/Changelog'

// Solutions
import MCPSecurity from './pages/solutions/MCPSecurity'
import AICompliance from './pages/solutions/AICompliance'
import PentestAutomation from './pages/solutions/PentestAutomation'

// Docs
import DocsHub from './pages/docs/DocsHub'
import GettingStarted from './pages/docs/GettingStarted'
import Configuration from './pages/docs/Configuration'
import PolicyEngine from './pages/docs/PolicyEngine'
import ProxyDocs from './pages/docs/Proxy'
import LLMIntegration from './pages/docs/LLMIntegration'
import PentestDocs from './pages/docs/PentestDocs'
import APIReference from './pages/docs/APIReference'

// Dashboard pages
import Dashboard from './pages/Dashboard'
import Scanner from './pages/Scanner'
import Agents from './pages/Agents'
import Alerts from './pages/Alerts'
import Credentials from './pages/Credentials'
import Policy from './pages/Policy'
import Feedback from './pages/Feedback'
import SelfHealing from './pages/SelfHealing'
import Gateway from './pages/Gateway'
import Pentest from './pages/Pentest'
import Analytics from './pages/Analytics'
import Settings from './pages/Settings'
import ApiKeys from './pages/ApiKeys'
import Onboarding from './pages/Onboarding'

// Admin pages
import AdminLayout from './layouts/AdminLayout'
import AdminOverview from './pages/admin/AdminOverview'
import AdminTenants from './pages/admin/AdminTenants'
import AdminAlerts from './pages/admin/AdminAlerts'
import AdminApiKeys from './pages/admin/AdminApiKeys'
import AdminSystem from './pages/admin/AdminSystem'

export default function App() {
  return (
    <>
      <ScrollToTop />
      {isAuthEnabled() && <AuthTokenBridge />}

      <Routes>
        {/* Public marketing pages */}
        <Route element={<PublicLayout />}>
          <Route path="/" element={<Landing />} />
          <Route path="/pricing" element={<Pricing />} />
          <Route path="/about" element={<About />} />
          <Route path="/blog" element={<Blog />} />
          <Route path="/changelog" element={<Changelog />} />

          {/* Solutions */}
          <Route path="/solutions/mcp-security" element={<MCPSecurity />} />
          <Route path="/solutions/ai-compliance" element={<AICompliance />} />
          <Route path="/solutions/pentest-automation" element={<PentestAutomation />} />

          {/* Docs */}
          <Route path="/docs" element={<DocsLayout />}>
            <Route index element={<DocsHub />} />
            <Route path="getting-started" element={<GettingStarted />} />
            <Route path="configuration" element={<Configuration />} />
            <Route path="policy-engine" element={<PolicyEngine />} />
            <Route path="proxy" element={<ProxyDocs />} />
            <Route path="llm-integration" element={<LLMIntegration />} />
            <Route path="pentest" element={<PentestDocs />} />
            <Route path="api-reference" element={<APIReference />} />
          </Route>
        </Route>

        {/* Auth routes */}
        <Route path="/sign-in/*" element={<SignIn />} />
        <Route path="/sign-up/*" element={<SignUp />} />

        {/* Onboarding (protected, no sidebar) */}
        <Route
          path="/onboarding"
          element={
            <ProtectedRoute>
              <Onboarding />
            </ProtectedRoute>
          }
        />

        {/* Protected dashboard routes */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <DashboardLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="gateway" element={<Gateway />} />
          <Route path="pentest" element={<Pentest />} />
          <Route path="scanner" element={<Scanner />} />
          <Route path="agents" element={<Agents />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="credentials" element={<Credentials />} />
          <Route path="policy" element={<Policy />} />
          <Route path="feedback" element={<Feedback />} />
          <Route path="self-healing" element={<SelfHealing />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="api-keys" element={<ApiKeys />} />
          <Route path="settings" element={<Settings />} />
        </Route>

        {/* Admin portal */}
        <Route
          path="/admin"
          element={
            <ProtectedRoute>
              <AdminLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<AdminOverview />} />
          <Route path="tenants" element={<AdminTenants />} />
          <Route path="alerts" element={<AdminAlerts />} />
          <Route path="api-keys" element={<AdminApiKeys />} />
          <Route path="system" element={<AdminSystem />} />
        </Route>

        {/* Catch-all → landing */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  )
}

import { useState } from 'react'
import { NavLink, Outlet, Link } from 'react-router-dom'
import { UserButton } from '@clerk/clerk-react'
import Icon, { type IconName } from '../components/Icon'

const hasClerk = !!import.meta.env.VITE_CLERK_PUBLISHABLE_KEY
const hasCloudApi = !!import.meta.env.VITE_API_BASE_URL

const navItems: { to: string; label: string; icon: IconName }[] = [
  { to: '/',             label: 'Agents',       icon: 'bot' },
  { to: '/gateway',      label: 'Gateway',      icon: 'gateway' },
  { to: '/pentest',      label: 'Pentest',      icon: 'pentest' },
  { to: '/scanner',      label: 'Scanner',      icon: 'scan' },
  { to: '/alerts',       label: 'Alerts',       icon: 'alert' },
  { to: '/credentials',  label: 'Credentials',  icon: 'key' },
  { to: '/policy',       label: 'Policy',       icon: 'shield' },
  { to: '/scoping',      label: 'Scoping',      icon: 'layers' },
  { to: '/feedback',     label: 'Feedback',     icon: 'activity' },
  { to: '/self-healing', label: 'Self-Healing', icon: 'sparkles' },
  { to: '/agent-card',   label: 'A2A',           icon: 'link' },
  { to: '/settings',     label: 'Settings',     icon: 'settings' },
]

const cloudNavItems: { to: string; label: string; icon: IconName }[] = [
  { to: '/analytics',    label: 'Analytics',    icon: 'chart' },
  { to: '/billing',      label: 'Billing',      icon: 'credit-card' },
  { to: '/webhooks',     label: 'Webhooks',     icon: 'link' },
  { to: '/threat-rules', label: 'Threat Rules', icon: 'zap' },
]

export default function DashboardLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="flex h-screen bg-[#0a0e17]">
      {/* Mobile backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-56 bg-[#111827] border-r border-[#2a3650] flex flex-col
          transform transition-transform duration-300 md:relative md:translate-x-0
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        {/* Subtle gradient overlay */}
        <div className="absolute inset-0 bg-gradient-to-b from-[#00e5c8]/[0.03] to-transparent pointer-events-none" />

        <div className="relative p-5 border-b border-[#2a3650]">
          <Link to="/" className="text-xl font-extrabold flex items-center gap-2.5 py-1.5 hover:opacity-80 transition-opacity">
            <div className="relative">
              <div className="absolute inset-0 bg-[#00e5c8]/20 rounded-lg blur-sm animate-pulseGlow" />
              <Icon name="shield" size={24} className="text-[#00e5c8] relative" />
            </div>
            <span className="text-[#f0f4fc]">
              Navil{' '}
              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded text-[#00e5c8] bg-[#00e5c8]/10 tracking-wider uppercase">
                OSS
              </span>
            </span>
          </Link>
          <p className="text-xs text-[#5a6a8a] mt-1.5">Agent Security Dashboard</p>
        </div>

        <nav className="relative flex-1 p-3 space-y-0.5 overflow-y-auto">
          {navItems.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-3 rounded-lg text-sm transition-all duration-200 min-h-[44px] nav-glow ${
                  isActive
                    ? 'nav-active-bar bg-[#00e5c8]/10 text-[#00e5c8] font-semibold'
                    : 'text-[#8b9bc0] hover:bg-[#1a2235] hover:text-[#f0f4fc]'
                }`
              }
            >
              <Icon name={icon} size={18} />
              {label}
            </NavLink>
          ))}

          {/* Cloud section divider — only shown when connected to cloud API */}
          {hasCloudApi && (
            <>
              <div className="pt-3 pb-1 px-3">
                <p className="text-[10px] font-semibold text-[#5a6a8a] uppercase tracking-widest">Cloud</p>
              </div>

              {cloudNavItems.map(({ to, label, icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  onClick={() => setSidebarOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-3 rounded-lg text-sm transition-all duration-200 min-h-[44px] nav-glow ${
                      isActive
                        ? 'nav-active-bar bg-[#00e5c8]/10 text-[#00e5c8] font-semibold'
                        : 'text-[#8b9bc0] hover:bg-[#1a2235] hover:text-[#f0f4fc]'
                    }`
                  }
                >
                  <Icon name={icon} size={18} />
                  {label}
                </NavLink>
              ))}
            </>
          )}

          {/* External links */}
          <div className="pt-3 pb-1 px-3">
            <p className="text-[10px] font-semibold text-[#5a6a8a] uppercase tracking-widest">Links</p>
          </div>

          <a
            href="https://navil.ai/overview"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 text-[#8b9bc0] hover:bg-[#1a2235] hover:text-[#f0f4fc]"
          >
            <Icon name="globe" size={18} />
            Cloud Dashboard
            <Icon name="external-link" size={12} className="ml-auto opacity-50" />
          </a>

          <a
            href="https://navil.ai/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 text-[#8b9bc0] hover:bg-[#1a2235] hover:text-[#f0f4fc]"
          >
            <Icon name="book" size={18} />
            Documentation
            <Icon name="external-link" size={12} className="ml-auto opacity-50" />
          </a>
        </nav>

        {/* User profile / logout */}
        <div className="relative border-t border-[#2a3650]">
          <div className="p-3 flex items-center gap-3">
            {hasClerk ? (
              <UserButton
                appearance={{
                  elements: {
                    avatarBox: 'w-7 h-7',
                    userButtonPopoverCard: 'bg-[#111827] border-[#2a3650]',
                  },
                }}
              />
            ) : (
              <div className="w-7 h-7 rounded-full bg-[#00e5c8]/20 flex items-center justify-center">
                <Icon name="shield" size={14} className="text-[#00e5c8]" />
              </div>
            )}
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-[#f0f4fc] truncate">
                {hasClerk ? 'Navil Cloud' : 'Local Mode'}
              </p>
              <p className="text-[10px] text-[#5a6a8a] truncate">
                {hasClerk ? 'Authenticated' : 'No sign-in required'}
              </p>
            </div>
          </div>
          <div className="px-3 pb-3 flex items-center justify-end">
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-[#5a6a8a] font-mono">v0.1.0</span>
              <NavLink
                to="/settings"
                className={({ isActive }) =>
                  `p-1 rounded transition-all duration-200 ${
                    isActive
                      ? 'text-[#00e5c8] bg-[#00e5c8]/10'
                      : 'text-[#5a6a8a] hover:text-[#8b9bc0] hover:bg-[#1a2235]'
                  }`
                }
              >
                <Icon name="settings" size={12} />
              </NavLink>
            </div>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto bg-[#0a0e17]">
        {/* Mobile hamburger */}
        <button
          onClick={() => setSidebarOpen(true)}
          aria-label="Open navigation menu"
          className="md:hidden fixed top-4 left-4 z-20 p-2 bg-[#111827] border border-[#2a3650] rounded-lg text-[#8b9bc0] hover:text-[#f0f4fc] transition-colors"
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

import { useState } from 'react'
import { NavLink, Outlet, Link } from 'react-router-dom'
import Icon, { type IconName } from '../components/Icon'
import UserProfile from '../components/UserProfile'

const navItems: { to: string; label: string; icon: IconName }[] = [
  { to: '/',             label: 'Agents',       icon: 'bot' },
  { to: '/gateway',      label: 'Gateway',      icon: 'gateway' },
  { to: '/pentest',      label: 'Pentest',      icon: 'pentest' },
  { to: '/scanner',      label: 'Scanner',      icon: 'scan' },
  { to: '/alerts',       label: 'Alerts',       icon: 'alert' },
  { to: '/credentials',  label: 'Credentials',  icon: 'key' },
  { to: '/policy',       label: 'Policy',       icon: 'shield' },
  { to: '/feedback',     label: 'Feedback',     icon: 'activity' },
  { to: '/self-healing', label: 'Self-Healing', icon: 'sparkles' },
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
          <Link to="/" className="text-xl font-extrabold flex items-center gap-2.5 hover:opacity-80 transition-opacity">
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
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 nav-glow ${
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

          {/* Cloud section divider */}
          <div className="pt-3 pb-1 px-3">
            <p className="text-[10px] font-semibold text-[#5a6a8a] uppercase tracking-widest">Cloud</p>
          </div>

          {cloudNavItems.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 nav-glow ${
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
        </nav>

        <UserProfile />
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

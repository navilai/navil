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

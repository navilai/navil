import { useState } from 'react'
import { NavLink, Outlet, Link } from 'react-router-dom'
import Icon, { type IconName } from '../components/Icon'

const adminNavItems: { to: string; label: string; icon: IconName }[] = [
  { to: '/admin', label: 'Overview', icon: 'chart' },
  { to: '/admin/tenants', label: 'Tenants', icon: 'bot' },
  { to: '/admin/alerts', label: 'Alerts', icon: 'alert' },
  { to: '/admin/api-keys', label: 'API Keys', icon: 'key' },
  { to: '/admin/system', label: 'System', icon: 'settings' },
]

export default function AdminLayout() {
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
        {/* Red gradient for admin */}
        <div className="absolute inset-0 bg-gradient-to-b from-red-500/[0.05] to-transparent pointer-events-none rounded-r-xl" />

        <div className="relative p-5 border-b border-gray-800/60">
          <Link to="/admin" className="text-xl font-bold flex items-center gap-2.5 hover:opacity-80 transition-opacity">
            <div className="relative">
              <div className="absolute inset-0 bg-red-500/20 rounded-lg blur-sm animate-pulseGlow" />
              <Icon name="shield" size={24} className="text-red-400 relative" />
            </div>
            <span>
              Navil{' '}
              <span className="text-xs font-normal text-red-400 bg-red-400/10 px-1.5 py-0.5 rounded">
                Admin
              </span>
            </span>
          </Link>
          <p className="text-xs text-gray-500 mt-1.5">Operator Control Panel</p>
        </div>

        <nav className="relative flex-1 p-3 space-y-1">
          {adminNavItems.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/admin'}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm nav-glow ${
                  isActive
                    ? 'nav-active-bar bg-red-500/10 text-red-300 font-medium'
                    : 'text-gray-400 hover:bg-gray-800/60 hover:text-gray-200'
                }`
              }
            >
              <Icon name={icon} size={18} />
              {label}
            </NavLink>
          ))}

          {/* Separator + link back to dashboard */}
          <div className="border-t border-gray-800/60 my-3" />
          <Link
            to="/dashboard"
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-gray-500 hover:bg-gray-800/60 hover:text-gray-300"
          >
            <Icon name="chart" size={18} />
            Back to Dashboard
          </Link>
        </nav>
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

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

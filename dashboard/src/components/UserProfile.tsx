import { NavLink } from 'react-router-dom'
import Icon from './Icon'

/**
 * Sidebar footer for the OSS self-hosted dashboard.
 * Shows version number and a shortcut to Settings.
 */
export default function UserProfile() {
  return (
    <div className="relative border-t border-[#2a3650]">
      <div className="p-3 flex items-center gap-3">
        <div className="w-7 h-7 rounded-full bg-[#00e5c8]/15 border border-[#00e5c8]/30 flex items-center justify-center shrink-0 text-xs font-bold text-[#00e5c8]">
          N
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-[#f0f4fc] truncate">Navil OSS</p>
          <p className="text-[10px] text-[#5a6a8a] truncate">Self-hosted</p>
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
  )
}

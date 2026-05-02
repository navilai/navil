import { NavLink } from 'react-router-dom'
import Icon from './Icon'

/**
 * Sidebar footer for the OSS self-hosted dashboard.
 * Shows version number and a shortcut to Settings.
 */
export default function UserProfile() {
  return (
    <div className="relative border-t border-rule">
      <div className="p-3 flex items-center gap-3">
        <div className="w-7 h-7 rounded-full bg-signal-cyan/15 border border-signal-cyan/30 flex items-center justify-center shrink-0 text-xs font-bold text-signal-cyan">
          N
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-ink truncate">Navil OSS</p>
          <p className="text-[10px] text-ink-muted truncate">Self-hosted</p>
        </div>
      </div>
      <div className="px-3 pb-3 flex items-center justify-end">
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-ink-muted font-mono">v0.1.0</span>
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `p-1 rounded transition-all duration-200 ${
                isActive
                  ? 'text-signal-cyan bg-signal-cyan/10'
                  : 'text-ink-muted hover:text-ink-secondary hover:bg-surface'
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

import { useState } from 'react'
import { Link } from 'react-router-dom'
import Icon, { type IconName } from './Icon'

interface LLMErrorCardProps {
  message: string
  errorType?: 'auth' | 'rate_limit' | 'quota' | 'billing' | 'unknown'
  onRetry?: () => void
  compact?: boolean
}

const errorConfig: Record<string, { icon: IconName; title: string; hint: string; accent: 'amber' | 'red'; showSettings: boolean }> = {
  auth: { icon: 'key', title: 'API Key Required', hint: 'Configure your LLM API key to enable AI features.', accent: 'amber', showSettings: true },
  rate_limit: { icon: 'clock', title: 'Rate Limit Reached', hint: 'Too many requests. Please wait a moment before trying again.', accent: 'amber', showSettings: false },
  quota: { icon: 'alert', title: 'API Quota Exceeded', hint: 'Your API quota has been reached. Check your provider account or wait for reset.', accent: 'amber', showSettings: false },
  billing: { icon: 'sparkles', title: 'Pro Plan Required', hint: 'Upgrade to Pro or configure your own API key to use AI features.', accent: 'amber', showSettings: true },
  unknown: { icon: 'warning', title: 'AI Analysis Failed', hint: 'An unexpected error occurred.', accent: 'red', showSettings: false },
}

const accentStyles = {
  amber: { border: 'border-[#f59e0b]/30', iconBg: 'bg-[#f59e0b]/10', iconText: 'text-[#f59e0b]', title: 'text-[#f59e0b]' },
  red: { border: 'border-[#ff4d6a]/30', iconBg: 'bg-[#ff4d6a]/10', iconText: 'text-[#ff4d6a]', title: 'text-[#ff4d6a]' },
}

export default function LLMErrorCard({ message, errorType = 'unknown', onRetry, compact }: LLMErrorCardProps) {
  const [showDetail, setShowDetail] = useState(false)
  const cfg = errorConfig[errorType] || errorConfig.unknown
  const styles = accentStyles[cfg.accent]

  if (compact) {
    return (
      <div className={`flex items-start gap-2 mt-2 p-2.5 rounded-lg bg-[#1a2235] border ${styles.border} animate-fadeIn`}>
        <Icon name={cfg.icon} size={14} className={`${styles.iconText} shrink-0 mt-0.5`} />
        <div className="flex-1 min-w-0">
          <p className={`text-xs font-medium ${styles.title}`}>{cfg.title}</p>
          <p className="text-xs text-[#5a6a8a] mt-0.5">{cfg.hint}</p>
          <div className="flex gap-3 mt-1">
            {cfg.showSettings && (
              <Link to="/settings" className="text-xs text-[#00e5c8] hover:text-[#00b8a0]">
                Go to Settings
              </Link>
            )}
            {onRetry && (
              <button onClick={onRetry} className="text-xs text-[#00e5c8] hover:text-[#00b8a0]">
                Retry
              </button>
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className={`glass-card ${styles.border} p-5 animate-fadeIn`}>
      <div className="flex items-start gap-4">
        <div className={`shrink-0 w-10 h-10 rounded-full ${styles.iconBg} flex items-center justify-center`}>
          <Icon name={cfg.icon} size={20} className={styles.iconText} />
        </div>
        <div className="flex-1 min-w-0">
          <p className={`font-medium ${styles.title}`}>{cfg.title}</p>
          <p className="text-sm text-[#8b9bc0] mt-1">{cfg.hint}</p>

          {message && message !== cfg.hint && (
            <button
              onClick={() => setShowDetail(!showDetail)}
              className="text-xs text-[#5a6a8a] hover:text-[#8b9bc0] mt-2 flex items-center gap-1 transition-colors duration-200"
            >
              <Icon name={showDetail ? 'chevron-down' : 'chevron-right'} size={12} />
              Technical detail
            </button>
          )}
          {showDetail && (
            <pre className="mt-2 text-xs text-[#5a6a8a] bg-[#0d1117] border border-[#2a3650] rounded-[12px] p-3 overflow-x-auto font-mono max-h-32 overflow-y-auto">
              {message}
            </pre>
          )}

          <div className="flex gap-3 mt-3">
            {cfg.showSettings && (
              <Link
                to="/settings"
                className="px-3 py-1.5 text-xs bg-[#00e5c8]/15 text-[#00e5c8] border border-[#00e5c8]/30 rounded-lg hover:bg-[#00e5c8]/25 flex items-center gap-1.5"
              >
                <Icon name="settings" size={13} />
                Configure API Key
              </Link>
            )}
            {onRetry && (
              <button
                onClick={onRetry}
                className="px-3 py-1.5 text-xs bg-[#1a2235] text-[#8b9bc0] border border-[#2a3650] rounded-lg hover:bg-[#1f2a40] hover:text-[#f0f4fc] flex items-center gap-1.5 transition-colors"
              >
                <Icon name="activity" size={13} />
                Retry
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

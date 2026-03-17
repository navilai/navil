import { Link } from 'react-router-dom'
import Icon from './Icon'

interface UpgradePromptProps {
  /** Short description of the gated feature. */
  feature: string
  /** compact=true renders a single inline row; default is a full card. */
  compact?: boolean
}

/**
 * Shown in place of AI-powered features when no LLM API key is configured.
 * Directs the user to Settings to add their key.
 */
export default function UpgradePrompt({ feature, compact }: UpgradePromptProps) {
  if (compact) {
    return (
      <div className="flex items-center gap-3 p-3 rounded-lg bg-violet-500/5 border border-violet-500/20">
        <Icon name="sparkles" size={14} className="text-violet-400 shrink-0" />
        <p className="text-xs text-[#8b9bc0] flex-1">
          {feature} requires an LLM API key.{' '}
          <Link to="/settings" className="text-[#00e5c8] hover:underline">
            Configure in Settings
          </Link>
        </p>
      </div>
    )
  }

  return (
    <div className="glass-card p-8 text-center animate-fadeIn">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-violet-500/10 border border-violet-500/20 mb-4">
        <Icon name="sparkles" size={32} className="text-violet-400" />
      </div>
      <h3 className="text-lg font-bold text-[#f0f4fc] mb-2">{feature}</h3>
      <p className="text-sm text-[#5a6a8a] mb-6 max-w-md mx-auto leading-relaxed">
        Configure an LLM API key in Settings to enable AI-powered analysis.
      </p>
      <Link
        to="/settings"
        className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] transition-all duration-200 hover:-translate-y-0.5"
      >
        <Icon name="key" size={14} />
        Configure API Key
      </Link>
    </div>
  )
}

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
        <p className="text-xs text-ink-secondary flex-1">
          {feature} requires an LLM API key.{' '}
          <Link to="/settings" className="text-signal-cyan hover:underline">
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
      <h3 className="text-lg font-bold text-ink mb-2">{feature}</h3>
      <p className="text-sm text-ink-muted mb-6 max-w-md mx-auto leading-relaxed">
        Configure an LLM API key in Settings to enable AI-powered analysis.
      </p>
      <Link
        to="/settings"
        className="inline-flex items-center gap-2 px-5 py-2.5 bg-signal-cyan text-bg rounded-lg text-sm font-semibold hover:bg-signal-cyan transition-all duration-200 hover:-translate-y-0.5"
      >
        <Icon name="key" size={14} />
        Configure API Key
      </Link>
    </div>
  )
}

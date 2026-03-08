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
        <p className="text-xs text-gray-400 flex-1">
          {feature} requires an LLM API key.{' '}
          <Link to="/settings" className="text-cyan-400 hover:underline">
            Configure in Settings
          </Link>
        </p>
      </div>
    )
  }

  return (
    <div className="glass-card p-8 text-center animate-fadeIn">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-violet-500/10 mb-4">
        <Icon name="sparkles" size={32} className="text-violet-400" />
      </div>
      <h3 className="text-lg font-medium text-gray-200 mb-2">{feature}</h3>
      <p className="text-sm text-gray-500 mb-6 max-w-md mx-auto">
        Configure an LLM API key in Settings to enable AI-powered analysis.
      </p>
      <Link
        to="/settings"
        className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-400"
      >
        <Icon name="key" size={14} />
        Configure API Key
      </Link>
    </div>
  )
}

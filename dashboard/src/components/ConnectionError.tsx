import Icon from './Icon'

interface ConnectionErrorProps {
  onRetry?: () => void
}

export default function ConnectionError({ onRetry }: ConnectionErrorProps) {
  return (
    <div className="max-w-lg mx-auto mt-16 text-center animate-fadeIn">
      <div className="glass-card p-8">
        <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-signal-red/10 border border-signal-red/20 flex items-center justify-center">
          <Icon name="warning" size={24} className="text-signal-red" />
        </div>
        <h2 className="text-lg font-bold text-ink mb-2">Unable to connect to Navil</h2>
        <p className="text-sm text-ink-secondary mb-6 leading-relaxed">
          The backend API is not responding. Make sure the Navil server is running:
        </p>
        <div className="bg-surface border border-rule rounded-[12px] p-3 mb-6 font-mono text-sm text-signal-cyan">
          $ navil cloud serve
        </div>
        <div className="flex items-center justify-center gap-3">
          <button
            onClick={onRetry}
            className="px-5 py-2.5 bg-signal-cyan text-bg rounded-lg text-sm font-semibold hover:bg-signal-cyan transition-all duration-200 hover:-translate-y-0.5 flex items-center gap-2"
          >
            <Icon name="activity" size={14} />
            Retry
          </button>
          <a
            href="https://navil.ai/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="px-5 py-2.5 bg-surface text-ink border border-rule rounded-lg text-sm font-semibold hover:bg-surface-elevated hover:border-ink-muted transition-all duration-200 flex items-center gap-2"
          >
            <Icon name="book" size={14} />
            Setup Guide
          </a>
        </div>
      </div>
    </div>
  )
}

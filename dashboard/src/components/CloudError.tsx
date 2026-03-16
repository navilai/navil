import Icon from './Icon'

interface CloudErrorProps {
  message: string
  onRetry?: () => void
}

/**
 * Error banner for cloud API failures.
 * Matches the existing dark theme design language.
 */
export default function CloudError({ message, onRetry }: CloudErrorProps) {
  return (
    <div className="max-w-lg mx-auto mt-16 text-center animate-fadeIn">
      <div className="glass-card p-8">
        <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-[#ff4d6a]/10 border border-[#ff4d6a]/20 flex items-center justify-center">
          <Icon name="warning" size={24} className="text-[#ff4d6a]" />
        </div>
        <h2 className="text-lg font-bold text-[#f0f4fc] mb-2">Cloud API Error</h2>
        <p className="text-sm text-[#8b9bc0] mb-6 leading-relaxed">
          {message}
        </p>
        {onRetry && (
          <button
            onClick={onRetry}
            className="px-5 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] transition-all duration-200 hover:-translate-y-0.5 flex items-center gap-2 mx-auto"
          >
            <Icon name="activity" size={14} />
            Retry
          </button>
        )}
      </div>
    </div>
  )
}

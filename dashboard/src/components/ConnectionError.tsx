import Icon from './Icon'

interface ConnectionErrorProps {
  onRetry?: () => void
}

export default function ConnectionError({ onRetry }: ConnectionErrorProps) {
  return (
    <div className="max-w-lg mx-auto mt-16 text-center animate-fadeIn">
      <div className="glass-card p-8">
        <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-[#ff4d6a]/10 border border-[#ff4d6a]/20 flex items-center justify-center">
          <Icon name="warning" size={24} className="text-[#ff4d6a]" />
        </div>
        <h2 className="text-lg font-bold text-[#f0f4fc] mb-2">Unable to connect to Navil</h2>
        <p className="text-sm text-[#8b9bc0] mb-6 leading-relaxed">
          The backend API is not responding. Make sure the Navil server is running:
        </p>
        <div className="bg-[#0d1117] border border-[#2a3650] rounded-[12px] p-3 mb-6 font-mono text-sm text-[#00e5c8]">
          $ navil cloud serve
        </div>
        <div className="flex items-center justify-center gap-3">
          <button
            onClick={onRetry}
            className="px-5 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] transition-all duration-200 hover:-translate-y-0.5 flex items-center gap-2"
          >
            <Icon name="activity" size={14} />
            Retry
          </button>
          <a
            href="https://navil.ai/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="px-5 py-2.5 bg-[#1a2235] text-[#f0f4fc] border border-[#2a3650] rounded-lg text-sm font-semibold hover:bg-[#1f2a40] hover:border-[#5a6a8a] transition-all duration-200 flex items-center gap-2"
          >
            <Icon name="book" size={14} />
            Setup Guide
          </a>
        </div>
      </div>
    </div>
  )
}

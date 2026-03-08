import Icon from '../components/Icon'
import useReveal from '../hooks/useReveal'

function Reveal({
  children,
  className = '',
}: {
  children: React.ReactNode
  className?: string
}) {
  const ref = useReveal()
  return (
    <div ref={ref} className={`reveal ${className}`}>
      {children}
    </div>
  )
}

const addedItems = [
  'MCP Config Scanner',
  'Policy Engine with YAML support',
  'Anomaly Detection (12 detectors)',
  'LLM-powered analysis (Anthropic/OpenAI/Gemini/Ollama)',
  'Penetration testing (11 SAFE-MCP scenarios)',
  'Security Proxy with JSON-RPC inspection',
  'Credential Manager with rotation',
  'Cloud dashboard with real-time monitoring',
  'Stripe billing integration',
  'Clerk authentication',
]

export default function Changelog() {
  return (
    <div className="bg-gray-950">
      <div className="max-w-4xl mx-auto px-6 py-28">
        <Reveal>
          <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400 mb-3">History</p>
          <h1 className="font-display text-4xl font-bold text-white mb-10">Changelog</h1>
        </Reveal>

        {/* v0.1.0 */}
        <Reveal>
          <div className="glass-card p-6 md:p-8">
            {/* Version header */}
            <div className="flex items-center gap-3 mb-6">
              <h2 className="font-display text-xl font-bold text-white">v0.1.0</h2>
              <span className="px-2.5 py-0.5 text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 rounded-full">
                initial release
              </span>
              <span className="text-sm text-gray-500 ml-auto font-mono">2025-05-01</span>
            </div>

            {/* Added */}
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Icon name="check" size={16} className="text-emerald-400" />
                <h3 className="text-sm font-mono font-semibold text-emerald-400 uppercase tracking-wider">
                  Added
                </h3>
              </div>

              <ul className="space-y-2.5">
                {addedItems.map((item) => (
                  <li key={item} className="flex items-start gap-2.5 text-sm">
                    <Icon
                      name="check"
                      size={14}
                      className="text-emerald-500/60 shrink-0 mt-0.5"
                    />
                    <span className="text-gray-300">{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </Reveal>
      </div>
    </div>
  )
}

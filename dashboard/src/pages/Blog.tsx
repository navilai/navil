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

export default function Blog() {
  return (
    <div className="bg-gray-950">
      <div className="max-w-4xl mx-auto px-6 py-28">
        <Reveal>
          <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400 mb-3">Resources</p>
          <h1 className="font-display text-4xl font-bold text-white mb-10">Blog</h1>
        </Reveal>

        {/* Coming soon card */}
        <Reveal>
          <div className="glass-card p-8 text-center mb-10">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-cyan-500/10 border border-cyan-500/20 mb-4">
              <Icon name="sparkles" size={22} className="text-cyan-400" />
            </div>
            <p className="text-gray-400 leading-relaxed max-w-lg mx-auto">
              We're working on our first posts. Stay tuned for security insights,
              product updates, and MCP best practices.
            </p>
          </div>
        </Reveal>

        {/* Skeleton article cards */}
        <Reveal>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {[0, 1, 2].map((i) => (
              <div key={i} className="glass-card p-5">
                <div className="skeleton h-32 w-full rounded-lg mb-4" />
                <div className="skeleton h-4 w-3/4 mb-3" />
                <div className="skeleton h-3 w-full mb-2" />
                <div className="skeleton h-3 w-5/6 mb-4" />
                <div className="skeleton h-3 w-1/3" />
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </div>
  )
}

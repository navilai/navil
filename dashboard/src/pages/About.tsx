import Icon, { type IconName } from '../components/Icon'
import useReveal from '../hooks/useReveal'

function Reveal({
  children,
  className = '',
  stagger = false,
}: {
  children: React.ReactNode
  className?: string
  stagger?: boolean
}) {
  const ref = useReveal()
  return (
    <div ref={ref} className={`${stagger ? 'reveal-stagger' : 'reveal'} ${className}`}>
      {children}
    </div>
  )
}

const commitments: { icon: IconName; title: string; description: string }[] = [
  {
    icon: 'heart',
    title: 'Apache 2.0 Core',
    description:
      'The scanner, policy engine, and anomaly detector are fully open-source under the Apache 2.0 license. Inspect, fork, and contribute freely.',
  },
  {
    icon: 'building',
    title: 'Cloud Edition',
    description:
      'The managed dashboard, proxy gateway, and LLM integrations are available as a hosted service for teams that want zero-ops security.',
  },
  {
    icon: 'users',
    title: 'Community First',
    description:
      'Security is a shared challenge. We prioritize community feedback, public roadmaps, and transparent disclosure over closed development.',
  },
]

export default function About() {
  return (
    <div className="bg-gray-950">
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 dot-grid pointer-events-none" />
        <div className="hero-glow absolute inset-0 pointer-events-none" />
        <div className="max-w-4xl mx-auto px-6 pt-28 pb-16 text-center relative">
          <Reveal>
            <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400 mb-4">About</p>
            <h1 className="font-display text-4xl sm:text-5xl font-bold text-white mb-6 leading-tight">
              Built for the{' '}
              <span className="text-gradient">AI Agent Era</span>
            </h1>
            <p className="text-lg text-gray-400 max-w-2xl mx-auto">
              Navil provides the security infrastructure that AI agents need to operate safely.
              We help teams monitor, govern, and protect their MCP deployments at every layer.
            </p>
          </Reveal>
        </div>
      </section>

      {/* Mission */}
      <section className="max-w-4xl mx-auto px-6 py-16">
        <Reveal>
          <div className="glass-card p-8 md:p-10">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                <Icon name="shield" size={20} className="text-cyan-400" />
              </div>
              <h2 className="font-display text-xl font-bold text-white">Our Mission</h2>
            </div>
            <p className="text-gray-400 leading-relaxed">
              As AI agents gain access to critical infrastructure through the Model Context Protocol,
              the attack surface expands faster than traditional security can keep up. Navil exists to
              close that gap. We build open-source tooling that gives every team visibility into agent
              behavior, enforceable security policies, and automated threat detection — so innovation
              doesn't come at the cost of safety.
            </p>
          </div>
        </Reveal>
      </section>

      {/* Open Source Commitment */}
      <section className="max-w-5xl mx-auto px-6 py-16">
        <Reveal className="text-center mb-12">
          <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400 mb-3">Values</p>
          <h2 className="font-display text-3xl font-bold text-white mb-3">
            Open Source Commitment
          </h2>
          <p className="text-gray-400">
            Transparency is the foundation of trust in security.
          </p>
        </Reveal>

        <Reveal stagger>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {commitments.map((c) => (
              <div key={c.title} className="reveal-child glass-card p-6">
                <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center mb-4">
                  <Icon name={c.icon} size={20} className="text-cyan-400" />
                </div>
                <h3 className="font-display text-sm font-medium text-gray-200 mb-2">{c.title}</h3>
                <p className="text-sm text-gray-500 leading-relaxed">{c.description}</p>
              </div>
            ))}
          </div>
        </Reveal>
      </section>

      {/* Contact */}
      <section className="max-w-4xl mx-auto px-6 pb-20">
        <Reveal>
          <div className="glass-card p-8 text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-cyan-500/10 border border-cyan-500/20 mb-4">
              <Icon name="mail" size={22} className="text-cyan-400" />
            </div>
            <h2 className="font-display text-xl font-bold text-white mb-2">Get in Touch</h2>
            <p className="text-gray-500 text-sm mb-1">Pantheon Lab Limited</p>
            <a
              href="mailto:info@pantheonlab.ai"
              className="text-cyan-400 hover:underline text-sm"
            >
              info@pantheonlab.ai
            </a>
          </div>
        </Reveal>
      </section>
    </div>
  )
}

import { Link } from 'react-router-dom'
import { useEffect, useState } from 'react'
import Icon, { type IconName } from '../components/Icon'
import LogoCloud from '../components/LogoCloud'
import TestimonialCard from '../components/TestimonialCard'
import FeatureComparisonTable from '../components/FeatureComparisonTable'
import NewsletterSignup from '../components/NewsletterSignup'
import MockTrafficMonitor from '../components/MockTrafficMonitor'
import MockAnomalyDashboard from '../components/MockAnomalyDashboard'
import MockRemediationEngine from '../components/MockRemediationEngine'
import useReveal from '../hooks/useReveal'

/* ─── Scroll-reveal wrapper ─────────────────────────────────────── */
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

/* ─── Typing animation for terminal ─────────────────────────────── */
function TerminalTyping() {
  const lines = [
    { text: '$ pip install navil', color: 'text-gray-300', delay: 0 },
    { text: '$ navil proxy start --target mcp://localhost:3000', color: 'text-gray-300', delay: 600 },
    { text: '', color: '', delay: 1200 },
    { text: '[navil] Proxy listening on :8484', color: 'text-cyan-400', delay: 1400 },
    { text: '[navil] 12 anomaly detectors active', color: 'text-cyan-400', delay: 1800 },
    { text: '[navil] Behavioral baselines initializing...', color: 'text-cyan-400', delay: 2200 },
    { text: '', color: '', delay: 2800 },
    { text: '[warn] Rate spike: data-reader (42 calls/min vs baseline 8)', color: 'text-amber-400', delay: 3200 },
    { text: '[crit] Exfiltration attempt: data-reader → /etc/passwd', color: 'text-red-400', delay: 3800 },
    { text: '', color: '', delay: 4200 },
    { text: '[auto] Agent blocked. Policy updated. Incident logged.', color: 'text-emerald-400', delay: 4600 },
  ]

  const [visibleCount, setVisibleCount] = useState(0)

  useEffect(() => {
    const timers = lines.map((line, i) =>
      setTimeout(() => setVisibleCount(i + 1), line.delay),
    )
    return () => timers.forEach(clearTimeout)
  }, [])

  return (
    <div className="p-5 font-mono text-[13px] leading-relaxed text-left min-h-[280px]">
      {lines.slice(0, visibleCount).map((line, i) =>
        line.text === '' ? (
          <div key={i} className="h-3" />
        ) : (
          <p key={i} className={`${line.color} ${i === visibleCount - 1 ? 'animate-fadeIn' : ''}`}>
            {line.text.startsWith('$') ? (
              <>
                <span className="text-cyan-500">$</span>{' '}
                <span className="text-gray-300">{line.text.slice(2)}</span>
              </>
            ) : (
              line.text
            )}
          </p>
        ),
      )}
      {visibleCount < lines.length && (
        <span className="inline-block w-2 h-4 bg-cyan-400 animate-cursor-blink" />
      )}
    </div>
  )
}

/* ─── Data ───────────────────────────────────────────────────────── */

const stats = [
  { value: '12', label: 'DETECTORS', pulse: true },
  { value: '11', label: 'PENTESTS' },
  { value: '<5m', label: 'SETUP' },
  { value: '100%', label: 'OPEN SOURCE' },
]

const bentoFeatures: {
  icon: IconName
  title: string
  desc: string
  span: string
  accent: string
  tag?: string
}[] = [
  {
    icon: 'gateway',
    title: 'Security Proxy',
    desc: 'Transparent interception of every JSON-RPC call between clients and MCP servers. Zero config changes. Full payload visibility.',
    span: 'col-span-1 lg:col-span-2 lg:row-span-2',
    accent: 'cyan',
  },
  {
    icon: 'activity',
    title: 'Anomaly Detection',
    desc: '12 behavioral detectors with adaptive per-agent baselines. Rate spikes, exfiltration, lateral movement — caught in real time.',
    span: 'col-span-1',
    accent: 'amber',
  },
  {
    icon: 'shield',
    title: 'Policy Engine',
    desc: 'Per-agent allowlists, denylists, rate limits, and data sensitivity controls.',
    span: 'col-span-1',
    accent: 'teal',
  },
  {
    icon: 'sparkles',
    title: 'AI Remediation',
    desc: 'LLM-powered root cause analysis. Auto-generated policies. One-click or fully automated fixes. Bring your own key.',
    span: 'col-span-1 lg:col-span-2',
    accent: 'violet',
    tag: 'AI',
  },
  {
    icon: 'scan',
    title: 'Config Scanner',
    desc: 'Deep analysis for leaked credentials, dangerous permissions, and unsigned server URLs.',
    span: 'col-span-1',
    accent: 'rose',
  },
  {
    icon: 'pentest',
    title: 'Pentest Engine',
    desc: '11 SAFE-MCP attack simulations probe your defenses without touching real infrastructure.',
    span: 'col-span-1',
    accent: 'orange',
    tag: 'PRO',
  },
]

const accentMap: Record<string, { bg: string; text: string; border: string }> = {
  cyan: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/20 hover:border-cyan-500/40' },
  amber: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20 hover:border-amber-500/40' },
  teal: { bg: 'bg-teal-500/10', text: 'text-teal-400', border: 'border-teal-500/20 hover:border-teal-500/40' },
  violet: { bg: 'bg-violet-500/10', text: 'text-violet-400', border: 'border-violet-500/20 hover:border-violet-500/40' },
  rose: { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/20 hover:border-rose-500/40' },
  orange: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20 hover:border-orange-500/40' },
}

const deepDive = [
  {
    heading: 'Monitor Every MCP Call',
    description:
      'The Navil proxy captures every JSON-RPC message in real time. Full visibility into tool invocations, argument payloads, and response data — without modifying your stack.',
    bullets: [
      'Zero-config transparent proxy',
      'Full request/response capture',
      'Live traffic dashboard',
      'Gateway-layer auth enforcement',
    ],
    icon: 'gateway' as IconName,
    mockLabel: 'Live Traffic Monitor',
    idx: 0,
  },
  {
    heading: 'Detect Threats Automatically',
    description:
      'Twelve behavioral detectors build adaptive baselines per agent and tool. When something deviates — rate spike, data exfiltration, lateral movement — Navil flags it instantly.',
    bullets: [
      '12 specialized anomaly detectors',
      'Per-agent adaptive baselines',
      'Real-time severity scoring',
      'Exfiltration & lateral movement detection',
    ],
    icon: 'alert' as IconName,
    mockLabel: 'Anomaly Detection',
    idx: 1,
  },
  {
    heading: 'Remediate with AI',
    description:
      "When a threat appears, Navil's LLM engine analyzes the full context — anomaly, agent history, policies — then recommends or auto-applies the fix. Seconds, not hours.",
    bullets: [
      'LLM root cause analysis',
      'Auto-generated policy patches',
      'One-click or full-auto remediation',
      'BYOK for any OpenAI-compatible model',
    ],
    icon: 'sparkles' as IconName,
    mockLabel: 'AI Remediation Engine',
    idx: 2,
  },
]

const steps = [
  {
    num: '01',
    icon: 'terminal' as IconName,
    title: 'Install & Connect',
    desc: 'pip install, point at your MCP servers. One command.',
    code: 'navil proxy start --target localhost:3000',
  },
  {
    num: '02',
    icon: 'eye' as IconName,
    title: 'Baselines Build',
    desc: 'Behavioral models calibrate in minutes. Every call profiled.',
    code: '[navil] 12 detectors active, 5 agents profiled',
  },
  {
    num: '03',
    icon: 'shield' as IconName,
    title: 'Threats Blocked',
    desc: 'Anomalies detected, explained, and auto-remediated.',
    code: '[alert] Exfiltration blocked → policy applied',
  },
]

const testimonials = [
  {
    quote:
      'Navil caught a credential exfiltration pattern in our staging environment that our existing monitoring completely missed.',
    author: 'Sarah Chen',
    role: 'Head of Security',
    company: 'Sentinel AI',
  },
  {
    quote:
      'We went from zero visibility into our MCP tool calls to full observability in under 5 minutes. The proxy setup is dead simple.',
    author: 'Marcus Johnson',
    role: 'Platform Lead',
    company: 'TechFlow',
  },
  {
    quote:
      "The auto-remediation blocked a rogue agent and tightened our policy before we even saw the alert. That's the tooling we need.",
    author: 'Elena Rodriguez',
    role: 'CTO',
    company: 'CloudSec',
  },
]

const trustBadges = [
  { icon: 'heart' as IconName, label: 'Apache 2.0' },
  { icon: 'lock' as IconName, label: 'SOC 2 Ready' },
  { icon: 'building' as IconName, label: 'Self-Host' },
  { icon: 'globe' as IconName, label: 'GDPR' },
]

/* ─── Component ──────────────────────────────────────────────────── */

export default function Landing() {
  return (
    <div className="bg-gray-950 grain">
      {/* ── HERO — asymmetric split ──────────────────────────────── */}
      <section className="relative overflow-hidden min-h-screen flex items-center">
        {/* Grid background */}
        <div className="absolute inset-0 dot-grid pointer-events-none" />
        <div className="absolute inset-0 pointer-events-none">
          <div className="hero-glow h-full" />
          <div className="absolute top-32 -left-20 w-[500px] h-[500px] bg-cyan-600/[0.06] rounded-full blur-[150px]" />
          <div className="absolute bottom-20 right-0 w-[400px] h-[300px] bg-teal-600/[0.04] rounded-full blur-[120px]" />
        </div>

        <div className="max-w-7xl mx-auto px-6 py-24 lg:py-0 grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-20 items-center relative">
          {/* Left — copy */}
          <div>
            <div
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-[11px] font-mono uppercase tracking-widest text-cyan-400 mb-8 animate-fadeIn"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse-dot" />
              Now in public beta
            </div>

            <h1
              className="font-display text-4xl sm:text-5xl lg:text-[3.5rem] xl:text-7xl font-bold text-white leading-[1.05] tracking-tight mb-6 animate-slideUp opacity-0"
              style={{ animationDelay: '0.1s' }}
            >
              Stop Threats
              <br />
              Before They
              <br />
              <span className="text-gradient">Reach Your Agents</span>
            </h1>

            <p
              className="text-base sm:text-lg text-gray-400 max-w-md mb-8 leading-relaxed animate-slideUp opacity-0"
              style={{ animationDelay: '0.25s' }}
            >
              Real-time monitoring, behavioral anomaly detection, and AI-powered
              remediation for every MCP server in your stack.
            </p>

            <div
              className="flex items-center gap-3 flex-wrap animate-slideUp opacity-0"
              style={{ animationDelay: '0.4s' }}
            >
              <Link
                to="/sign-up"
                className="group px-6 py-3 bg-cyan-500 text-gray-950 rounded-lg text-sm font-bold hover:bg-cyan-400 transition-all hover:shadow-lg hover:shadow-cyan-500/25 hover:-translate-y-0.5 flex items-center gap-2"
              >
                Get Started Free
                <Icon name="arrow-right" size={16} className="group-hover:translate-x-0.5 transition-transform" />
              </Link>
              <Link
                to="/docs/getting-started"
                className="px-6 py-3 bg-white/[0.03] text-gray-300 border border-gray-700/80 rounded-lg text-sm font-medium hover:bg-white/[0.06] hover:border-gray-600 transition-all flex items-center gap-2 font-mono"
              >
                <Icon name="code" size={16} />
                docs
              </Link>
            </div>

            <p
              className="text-[11px] text-gray-600 mt-4 font-mono animate-slideUp opacity-0"
              style={{ animationDelay: '0.5s' }}
            >
              Free forever &middot; 3 agents &middot; No credit card
            </p>
          </div>

          {/* Right — terminal */}
          <div
            className="animate-slideUp opacity-0"
            style={{ animationDelay: '0.3s' }}
          >
            <div className="relative">
              {/* Glow */}
              <div className="absolute -inset-4 bg-cyan-500/[0.06] rounded-3xl blur-2xl" />

              <div className="relative rounded-xl border border-gray-700/60 bg-gray-900/90 backdrop-blur-sm overflow-hidden shadow-2xl shadow-black/50">
                <div className="flex items-center gap-2 px-4 py-2.5 border-b border-gray-800/80 bg-gray-900/50">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
                  <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
                  <span className="w-2.5 h-2.5 rounded-full bg-green-500/70" />
                  <span className="ml-2 text-[11px] text-gray-500 font-mono">navil — terminal</span>
                </div>
                <TerminalTyping />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── STATS — status bar ───────────────────────────────────── */}
      <section className="border-y border-gray-800/60 bg-gray-900/20">
        <div className="max-w-7xl mx-auto px-6 py-5">
          <div className="flex items-center justify-between gap-6 overflow-x-auto">
            {stats.map((s) => (
              <div key={s.label} className="flex items-center gap-3 shrink-0">
                {s.pulse && (
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse-dot" />
                )}
                <span className="font-display text-xl font-bold text-white">{s.value}</span>
                <span className="text-[10px] font-mono uppercase tracking-widest text-gray-500">{s.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── SOCIAL PROOF ─────────────────────────────────────────── */}
      <Reveal className="max-w-6xl mx-auto px-6 py-16">
        <LogoCloud title="Trusted by security-conscious teams" />
      </Reveal>

      {/* ── BENTO FEATURES ───────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-6 py-20">
        <Reveal>
          <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400 mb-3">Core Platform</p>
          <h2 className="font-display text-3xl sm:text-4xl font-bold text-white mb-4">
            Six layers of defense
          </h2>
          <p className="text-gray-400 max-w-xl mb-14">
            From traffic interception to AI-powered remediation, Navil covers every layer of the agent stack.
          </p>
        </Reveal>

        <Reveal stagger className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 auto-rows-fr">
          {bentoFeatures.map((f) => {
            const a = accentMap[f.accent]
            return (
              <div
                key={f.title}
                className={`reveal-child glass-card p-6 border ${a.border} transition-all hover:-translate-y-0.5 hover:shadow-lg hover:shadow-black/20 ${f.span}`}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className={`w-10 h-10 rounded-lg ${a.bg} flex items-center justify-center`}>
                    <Icon name={f.icon} size={20} className={a.text} />
                  </div>
                  {f.tag && (
                    <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded-full ${a.bg} ${a.text} border ${a.border}`}>
                      {f.tag}
                    </span>
                  )}
                </div>
                <h3 className="font-display text-base font-semibold text-gray-100 mb-2">{f.title}</h3>
                <p className="text-sm text-gray-500 leading-relaxed">{f.desc}</p>
              </div>
            )
          })}
        </Reveal>
      </section>

      {/* ── DEEP-DIVE SECTIONS ───────────────────────────────────── */}
      <section className="border-t border-gray-800/40">
        <div className="max-w-7xl mx-auto px-6 py-24">
          <Reveal>
            <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400 mb-3">Deep Dive</p>
            <h2 className="font-display text-3xl sm:text-4xl font-bold text-white mb-16">
              Purpose-built for MCP security
            </h2>
          </Reveal>

          <div className="space-y-32">
            {deepDive.map((item) => {
              const reversed = item.idx % 2 !== 0
              return (
                <Reveal key={item.heading}>
                  <div className={`flex flex-col ${reversed ? 'lg:flex-row-reverse' : 'lg:flex-row'} gap-12 lg:gap-20 items-center`}>
                    {/* Copy */}
                    <div className="flex-1 space-y-5">
                      <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                        <Icon name={item.icon} size={20} className="text-cyan-400" />
                      </div>
                      <h3 className="font-display text-2xl sm:text-3xl font-bold text-white">{item.heading}</h3>
                      <p className="text-gray-400 leading-relaxed">{item.description}</p>
                      <ul className="space-y-2.5 pt-2">
                        {item.bullets.map((b) => (
                          <li key={b} className="flex items-center gap-2.5 text-sm text-gray-300">
                            <Icon name="check" size={14} className="text-cyan-400 shrink-0" />
                            {b}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Mock UI */}
                    <div className="flex-1 w-full">
                      <div className="glass-card p-1 rounded-xl shadow-xl shadow-black/20 border-cyan-500/10">
                        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-gray-700/50">
                          <span className="w-2 h-2 rounded-full bg-red-500/70" />
                          <span className="w-2 h-2 rounded-full bg-yellow-500/70" />
                          <span className="w-2 h-2 rounded-full bg-green-500/70" />
                          <span className="ml-2 text-[11px] text-gray-500 font-mono">{item.mockLabel}</span>
                        </div>
                        <div className="bg-gray-900/50 rounded-b-lg overflow-hidden">
                          {item.idx === 0 && <MockTrafficMonitor />}
                          {item.idx === 1 && <MockAnomalyDashboard />}
                          {item.idx === 2 && <MockRemediationEngine />}
                        </div>
                      </div>
                    </div>
                  </div>
                </Reveal>
              )
            })}
          </div>
        </div>
      </section>

      {/* ── HOW IT WORKS — vertical timeline ─────────────────────── */}
      <section className="border-t border-gray-800/40">
        <div className="max-w-3xl mx-auto px-6 py-24">
          <Reveal className="text-center mb-16">
            <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400 mb-3">How It Works</p>
            <h2 className="font-display text-3xl sm:text-4xl font-bold text-white">
              Secured in three commands
            </h2>
          </Reveal>

          <div className="relative">
            {/* Vertical line */}
            <div className="absolute left-5 top-0 bottom-0 w-px bg-gradient-to-b from-cyan-500/40 via-cyan-500/20 to-transparent" />

            <div className="space-y-12">
              {steps.map((s, i) => (
                <Reveal key={s.num}>
                  <div className="flex gap-6 items-start">
                    {/* Timeline node */}
                    <div className="relative shrink-0">
                      <div className="w-10 h-10 rounded-full bg-gray-900 border-2 border-cyan-500/40 flex items-center justify-center z-10 relative">
                        <span className="text-[11px] font-mono font-bold text-cyan-400">{s.num}</span>
                      </div>
                    </div>

                    {/* Content */}
                    <div className="flex-1 pb-2">
                      <div className="flex items-center gap-3 mb-2">
                        <Icon name={s.icon} size={18} className="text-cyan-400" />
                        <h3 className="font-display text-lg font-semibold text-gray-100">{s.title}</h3>
                      </div>
                      <p className="text-sm text-gray-500 mb-3">{s.desc}</p>
                      <div className="bg-gray-900/80 rounded-lg px-4 py-2.5 font-mono text-[13px] text-cyan-400 border border-gray-800/60 inline-block">
                        {s.code}
                      </div>
                    </div>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── TESTIMONIALS — editorial layout ───────────────────────── */}
      <section className="border-t border-gray-800/40">
        <div className="max-w-6xl mx-auto px-6 py-24">
          <Reveal>
            <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400 mb-3">What Teams Say</p>
            <h2 className="font-display text-3xl sm:text-4xl font-bold text-white mb-14">
              Trusted by security engineers
            </h2>
          </Reveal>

          <Reveal stagger>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Featured large testimonial */}
              <div className="reveal-child lg:col-span-2 glass-card p-8 border border-cyan-500/10 relative overflow-hidden">
                <div className="absolute top-4 right-6 text-[120px] font-display leading-none text-cyan-500/[0.06] select-none">
                  &ldquo;
                </div>
                <div className="relative">
                  <p className="text-lg sm:text-xl italic text-gray-200 leading-relaxed mb-6">
                    {testimonials[0].quote}
                  </p>
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-cyan-500/20 flex items-center justify-center text-xs font-bold text-cyan-400">
                      {testimonials[0].author.split(' ').map(w => w[0]).join('')}
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-gray-200">{testimonials[0].author}</p>
                      <p className="text-xs text-gray-500">{testimonials[0].role}, {testimonials[0].company}</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Smaller testimonials stacked */}
              <div className="flex flex-col gap-6">
                {testimonials.slice(1).map((t) => (
                  <div key={t.author} className="reveal-child flex-1">
                    <TestimonialCard {...t} />
                  </div>
                ))}
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── FEATURE COMPARISON ────────────────────────────────────── */}
      <section className="border-t border-gray-800/40 bg-gray-900/20">
        <div className="max-w-5xl mx-auto px-6 py-24">
          <Reveal className="text-center mb-14">
            <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400 mb-3">Plans</p>
            <h2 className="font-display text-3xl sm:text-4xl font-bold text-white mb-4">
              Compare features across plans
            </h2>
            <p className="text-gray-400">Start free. Scale as your agent fleet grows.</p>
          </Reveal>

          <Reveal>
            <FeatureComparisonTable />
            <div className="text-center mt-8">
              <Link
                to="/pricing"
                className="text-sm text-cyan-400 hover:text-cyan-300 font-mono"
              >
                View detailed pricing &rarr;
              </Link>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── TRUST BADGES ─────────────────────────────────────────── */}
      <Reveal className="max-w-4xl mx-auto px-6 py-12">
        <div className="flex items-center justify-center gap-8 flex-wrap">
          {trustBadges.map((badge) => (
            <div key={badge.label} className="flex items-center gap-2 text-gray-500">
              <Icon name={badge.icon} size={14} className="text-gray-600" />
              <span className="text-[11px] font-mono uppercase tracking-wider">{badge.label}</span>
            </div>
          ))}
        </div>
      </Reveal>

      {/* ── CTA — full-bleed dramatic ────────────────────────────── */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 dot-grid pointer-events-none opacity-50" />
        <div className="absolute inset-0 bg-gradient-to-b from-gray-950 via-cyan-950/20 to-gray-950 pointer-events-none" />

        <Reveal className="max-w-4xl mx-auto px-6 py-24 relative text-center">
          <h2 className="font-display text-3xl sm:text-5xl font-bold text-white mb-5">
            Ready to secure
            <br />
            <span className="text-gradient">your agents?</span>
          </h2>
          <p className="text-gray-400 mb-8 max-w-lg mx-auto">
            Join hundreds of teams protecting their MCP infrastructure.
            Start monitoring in minutes.
          </p>
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <Link
              to="/sign-up"
              className="group px-7 py-3.5 bg-cyan-500 text-gray-950 rounded-lg text-sm font-bold hover:bg-cyan-400 transition-all hover:shadow-lg hover:shadow-cyan-500/25 hover:-translate-y-0.5 flex items-center gap-2"
            >
              Get Started Free
              <Icon name="arrow-right" size={16} className="group-hover:translate-x-0.5 transition-transform" />
            </Link>
            <Link
              to="/pricing"
              className="px-7 py-3.5 bg-white/[0.03] text-gray-300 border border-gray-700/80 rounded-lg text-sm font-medium hover:bg-white/[0.06] transition-all font-mono"
            >
              View Pricing
            </Link>
          </div>
          <p className="text-[11px] text-gray-600 mt-4 font-mono">
            Free forever &middot; No credit card required
          </p>
        </Reveal>
      </section>

      {/* ── NEWSLETTER ────────────────────────────────────────────── */}
      <section className="max-w-4xl mx-auto px-6 pb-20">
        <NewsletterSignup />
      </section>
    </div>
  )
}

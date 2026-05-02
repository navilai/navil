const colors: Record<string, string> = {
  CRITICAL: 'bg-signal-red/15 text-signal-red border-signal-red/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-signal-amber/15 text-signal-amber border-signal-amber/30',
  LOW: 'bg-signal-cyan/15 text-signal-cyan border-signal-cyan/30',
  INFO: 'bg-ink-muted/15 text-ink-secondary border-ink-muted/30',
  OK: 'bg-signal-green/15 text-signal-green border-signal-green/30',
  UNKNOWN: 'bg-ink-muted/15 text-ink-secondary border-ink-muted/30',
}

const dotColors: Record<string, string> = {
  CRITICAL: 'bg-signal-red',
  HIGH: 'bg-orange-400',
  MEDIUM: 'bg-signal-amber',
  LOW: 'bg-signal-cyan',
  INFO: 'bg-ink-secondary',
  OK: 'bg-signal-green',
  UNKNOWN: 'bg-ink-secondary',
}

export default function SeverityBadge({ severity }: { severity: string }) {
  const cls = colors[severity] || colors.INFO
  const dot = dotColors[severity] || 'bg-ink-secondary'
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 text-[11px] font-semibold tracking-wide uppercase rounded-md border ${cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      {severity}
    </span>
  )
}

const colors: Record<string, string> = {
  ACTIVE: 'bg-signal-green/15 text-signal-green border-signal-green/30',
  ALLOW: 'bg-signal-green/15 text-signal-green border-signal-green/30',
  EXPIRED: 'bg-signal-amber/15 text-signal-amber border-signal-amber/30',
  ALERT: 'bg-signal-amber/15 text-signal-amber border-signal-amber/30',
  REVOKED: 'bg-signal-red/15 text-signal-red border-signal-red/30',
  DENY: 'bg-signal-red/15 text-signal-red border-signal-red/30',
  INACTIVE: 'bg-ink-muted/15 text-ink-secondary border-ink-muted/30',
}

const dotColors: Record<string, string> = {
  ACTIVE: 'bg-signal-green',
  ALLOW: 'bg-signal-green',
  EXPIRED: 'bg-signal-amber',
  ALERT: 'bg-signal-amber',
  REVOKED: 'bg-signal-red',
  DENY: 'bg-signal-red',
  INACTIVE: 'bg-ink-secondary',
}

export default function StatusBadge({ status }: { status: string }) {
  const cls = colors[status] || colors.INACTIVE
  const dot = dotColors[status] || 'bg-ink-secondary'
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 text-[11px] font-semibold tracking-wide uppercase rounded-md border ${cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      {status}
    </span>
  )
}

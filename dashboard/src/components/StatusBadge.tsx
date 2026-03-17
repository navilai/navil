const colors: Record<string, string> = {
  ACTIVE: 'bg-[#34d399]/15 text-[#34d399] border-[#34d399]/30',
  ALLOW: 'bg-[#34d399]/15 text-[#34d399] border-[#34d399]/30',
  EXPIRED: 'bg-[#fbbf24]/15 text-[#fbbf24] border-[#fbbf24]/30',
  ALERT: 'bg-[#fbbf24]/15 text-[#fbbf24] border-[#fbbf24]/30',
  REVOKED: 'bg-[#ff4d6a]/15 text-[#ff4d6a] border-[#ff4d6a]/30',
  DENY: 'bg-[#ff4d6a]/15 text-[#ff4d6a] border-[#ff4d6a]/30',
  INACTIVE: 'bg-[#5a6a8a]/15 text-[#8b9bc0] border-[#5a6a8a]/30',
}

const dotColors: Record<string, string> = {
  ACTIVE: 'bg-[#34d399]',
  ALLOW: 'bg-[#34d399]',
  EXPIRED: 'bg-[#fbbf24]',
  ALERT: 'bg-[#fbbf24]',
  REVOKED: 'bg-[#ff4d6a]',
  DENY: 'bg-[#ff4d6a]',
  INACTIVE: 'bg-[#8b9bc0]',
}

export default function StatusBadge({ status }: { status: string }) {
  const cls = colors[status] || colors.INACTIVE
  const dot = dotColors[status] || 'bg-[#8b9bc0]'
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 text-[11px] font-semibold tracking-wide uppercase rounded-md border ${cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      {status}
    </span>
  )
}

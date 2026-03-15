const colors: Record<string, string> = {
  CRITICAL: 'bg-[#ff4d6a]/15 text-[#ff4d6a] border-[#ff4d6a]/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-[#fbbf24]/15 text-[#fbbf24] border-[#fbbf24]/30',
  LOW: 'bg-[#60a5fa]/15 text-[#60a5fa] border-[#60a5fa]/30',
  INFO: 'bg-[#5a6a8a]/15 text-[#8b9bc0] border-[#5a6a8a]/30',
  OK: 'bg-[#34d399]/15 text-[#34d399] border-[#34d399]/30',
}

const dotColors: Record<string, string> = {
  CRITICAL: 'bg-[#ff4d6a]',
  HIGH: 'bg-orange-400',
  MEDIUM: 'bg-[#fbbf24]',
  LOW: 'bg-[#60a5fa]',
  INFO: 'bg-[#8b9bc0]',
  OK: 'bg-[#34d399]',
}

export default function SeverityBadge({ severity }: { severity: string }) {
  const cls = colors[severity] || colors.INFO
  const dot = dotColors[severity] || 'bg-[#8b9bc0]'
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 text-[11px] font-semibold tracking-wide uppercase rounded-md border ${cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      {severity}
    </span>
  )
}

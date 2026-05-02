import Icon, { type IconName } from './Icon'
import AnimatedNumber from './AnimatedNumber'

interface StatCardProps {
  label: string
  value: number | string
  icon: IconName
  accent?: string
  index?: number
}

export default function StatCard({ label, value, icon, accent = 'cyan', index = 0 }: StatCardProps) {
  const accentMap: Record<string, string> = {
    cyan: 'border-signal-cyan/20',
    red: 'border-signal-red/20',
    emerald: 'border-signal-green/20',
    amber: 'border-signal-amber/20',
  }
  const iconBgMap: Record<string, string> = {
    cyan: 'bg-signal-cyan/10',
    red: 'bg-signal-red/10',
    emerald: 'bg-signal-green/10',
    amber: 'bg-signal-amber/10',
  }
  const iconColorMap: Record<string, string> = {
    cyan: 'text-signal-cyan',
    red: 'text-signal-red',
    emerald: 'text-signal-green',
    amber: 'text-signal-amber',
  }

  const numericValue = typeof value === 'number' ? value : null

  return (
    <div
      className={`bg-surface border ${accentMap[accent] || accentMap.cyan} rounded-[12px] p-5 animate-slideUp opacity-0 hover:bg-surface-elevated hover:border-ink-muted/40 hover:-translate-y-0.5 transition-all duration-200`}
      style={{ animationDelay: `${index * 0.08}s` }}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-ink-secondary font-medium">{label}</p>
          {numericValue !== null ? (
            <AnimatedNumber value={numericValue} className="text-3xl font-bold mt-1.5 block text-ink" />
          ) : (
            <p className="text-3xl font-bold mt-1.5 text-ink">{value}</p>
          )}
        </div>
        <div className={`w-12 h-12 rounded-xl ${iconBgMap[accent] || 'bg-signal-cyan/10'} flex items-center justify-center`}>
          <Icon name={icon} size={24} className={iconColorMap[accent] || 'text-signal-cyan'} />
        </div>
      </div>
    </div>
  )
}

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
    cyan: 'border-[#00e5c8]/20',
    red: 'border-[#ff4d6a]/20',
    emerald: 'border-[#34d399]/20',
    amber: 'border-[#f59e0b]/20',
  }
  const iconBgMap: Record<string, string> = {
    cyan: 'bg-[#00e5c8]/10',
    red: 'bg-[#ff4d6a]/10',
    emerald: 'bg-[#34d399]/10',
    amber: 'bg-[#f59e0b]/10',
  }
  const iconColorMap: Record<string, string> = {
    cyan: 'text-[#00e5c8]',
    red: 'text-[#ff4d6a]',
    emerald: 'text-[#34d399]',
    amber: 'text-[#f59e0b]',
  }

  const numericValue = typeof value === 'number' ? value : null

  return (
    <div
      className={`bg-[#1a2235] border ${accentMap[accent] || accentMap.cyan} rounded-[12px] p-5 animate-slideUp opacity-0 hover:bg-[#1f2a40] hover:border-[#5a6a8a]/40 hover:-translate-y-0.5 transition-all duration-200`}
      style={{ animationDelay: `${index * 0.08}s` }}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-[#8b9bc0] font-medium">{label}</p>
          {numericValue !== null ? (
            <AnimatedNumber value={numericValue} className="text-3xl font-bold mt-1.5 block text-[#f0f4fc]" />
          ) : (
            <p className="text-3xl font-bold mt-1.5 text-[#f0f4fc]">{value}</p>
          )}
        </div>
        <div className={`w-12 h-12 rounded-xl ${iconBgMap[accent] || 'bg-[#00e5c8]/10'} flex items-center justify-center`}>
          <Icon name={icon} size={24} className={iconColorMap[accent] || 'text-[#00e5c8]'} />
        </div>
      </div>
    </div>
  )
}

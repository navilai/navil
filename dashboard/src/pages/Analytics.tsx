import { useEffect, useState, useCallback } from 'react'
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import {
  type TimeseriesResponse,
  type TopThreatsResponse,
} from '../cloudApi'
import useCloudApi from '../hooks/useCloudApi'
import PageHeader from '../components/PageHeader'
import StatCard from '../components/StatCard'
import SeverityBadge from '../components/SeverityBadge'
import CloudError from '../components/CloudError'
import Icon from '../components/Icon'

const RANGE_OPTIONS = [
  { label: '7d', value: 7 },
  { label: '14d', value: 14 },
  { label: '30d', value: 30 },
]

// Map threat types to severity for coloring
const THREAT_SEVERITY: Record<string, string> = {
  prompt_injection: 'CRITICAL',
  data_exfiltration: 'CRITICAL',
  privilege_escalation: 'HIGH',
  tool_misuse: 'HIGH',
  unusual_data_volume: 'MEDIUM',
  credential_abuse: 'HIGH',
  policy_violation: 'MEDIUM',
  lateral_movement: 'MEDIUM',
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ff4d6a',
  HIGH: '#f97316',
  MEDIUM: '#fbbf24',
  LOW: '#60a5fa',
  INFO: '#8b9bc0',
}

function getSeverityColor(eventType: string): string {
  const severity = THREAT_SEVERITY[eventType] || 'INFO'
  return SEVERITY_COLORS[severity] || SEVERITY_COLORS.INFO
}

export default function Analytics() {
  const cloud = useCloudApi()
  const [days, setDays] = useState(7)
  const [timeseries, setTimeseries] = useState<TimeseriesResponse | null>(null)
  const [threats, setThreats] = useState<TopThreatsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const fetchData = useCallback((d: number) => {
    setLoading(true)
    setError('')
    Promise.all([
      cloud.getTimeseries(d),
      cloud.getTopThreats(d),
    ]).then(([ts, th]) => {
      setTimeseries(ts)
      setThreats(th)
    }).catch((e: unknown) => {
      setError(e instanceof Error ? e.message : 'Failed to load analytics data.')
    }).finally(() => setLoading(false))
  }, [cloud])

  useEffect(() => { fetchData(days) }, [days, fetchData])

  const totalAlerts = timeseries?.data.reduce((sum, p) => sum + p.count, 0) || 0
  const avgDaily = timeseries?.data.length ? Math.round(totalAlerts / timeseries.data.length) : 0
  const peakDay = timeseries?.data.reduce((max, p) => p.count > max.count ? p : max, { date: '', count: 0 })
  const topThreat = threats?.data[0]

  // Heatmap data: transform timeseries into a 7x(days/7) grid
  const heatmapData = timeseries?.data.map(p => ({
    ...p,
    dayOfWeek: new Date(p.date + 'T00:00:00').getDay(),
    intensity: p.count,
  })) || []

  if (loading && !timeseries) {
    return (
      <div className="space-y-6">
        <PageHeader title="Analytics" subtitle="Threat detection analytics" />
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          {[0, 1, 2, 3].map(i => (
            <div key={i} className="skeleton h-24 rounded-xl" style={{ animationDelay: `${i * 0.1}s` }} />
          ))}
        </div>
        <div className="skeleton h-72 rounded-xl" />
        <div className="skeleton h-64 rounded-xl" />
      </div>
    )
  }

  if (error && !timeseries) {
    return (
      <div className="space-y-6">
        <PageHeader title="Analytics" subtitle="Threat detection analytics" />
        <CloudError message={error} onRetry={() => fetchData(days)} />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Analytics" subtitle="Threat detection analytics">
        <div className="flex gap-2">
          {RANGE_OPTIONS.map(opt => (
            <button
              key={opt.value}
              onClick={() => setDays(opt.value)}
              className={`px-3 py-1.5 text-xs rounded-lg border font-medium transition-all duration-200 ${
                days === opt.value
                  ? 'bg-[#00e5c8]/15 border-[#00e5c8]/40 text-[#00e5c8]'
                  : 'bg-[#1a2235] border-[#2a3650] text-[#8b9bc0] hover:border-[#5a6a8a] hover:text-[#f0f4fc]'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </PageHeader>

      {/* Stats row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Alerts" value={totalAlerts} icon="alert" accent="red" index={0} />
        <StatCard label="Daily Average" value={avgDaily} icon="chart" accent="cyan" index={1} />
        <StatCard label="Peak Day" value={peakDay?.count || 0} icon="arrow-up" accent="amber" index={2} />
        <StatCard label="Threat Types" value={threats?.data.length || 0} icon="shield" accent="emerald" index={3} />
      </div>

      {/* Alerts Over Time */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-2">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-5 flex items-center gap-2">
          <Icon name="chart" size={16} className="text-[#00e5c8]" />
          Alerts Over Time
        </h3>
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeseries?.data || []} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="alertGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00e5c8" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#00e5c8" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a3650" vertical={false} />
              <XAxis
                dataKey="date"
                stroke="#5a6a8a"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                tickFormatter={(v: string) => {
                  const d = new Date(v + 'T00:00:00')
                  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
                }}
              />
              <YAxis
                stroke="#5a6a8a"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                width={36}
              />
              <Tooltip
                contentStyle={{
                  background: '#1a2235',
                  border: '1px solid #2a3650',
                  borderRadius: '8px',
                  fontSize: '12px',
                  color: '#f0f4fc',
                }}
                labelFormatter={(v) => {
                  const d = new Date(String(v) + 'T00:00:00')
                  return d.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })
                }}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#00e5c8"
                strokeWidth={2}
                fill="url(#alertGradient)"
                name="Alerts"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Threats */}
        <div className="glass-card p-6 animate-slideUp opacity-0 stagger-3">
          <h3 className="text-sm font-semibold text-[#f0f4fc] mb-5 flex items-center gap-2">
            <Icon name="shield" size={16} className="text-[#ff4d6a]" />
            Top Threats
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={threats?.data.slice(0, 8) || []}
                layout="vertical"
                margin={{ top: 0, right: 10, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#2a3650" horizontal={false} />
                <XAxis
                  type="number"
                  stroke="#5a6a8a"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="event_type"
                  stroke="#5a6a8a"
                  fontSize={10}
                  tickLine={false}
                  axisLine={false}
                  width={120}
                  tickFormatter={(v: string) => v.replace(/_/g, ' ')}
                />
                <Tooltip
                  contentStyle={{
                    background: '#1a2235',
                    border: '1px solid #2a3650',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#f0f4fc',
                  }}
                  labelFormatter={(v) => String(v).replace(/_/g, ' ')}
                />
                <Bar dataKey="count" name="Count" radius={[0, 4, 4, 0]}>
                  {(threats?.data.slice(0, 8) || []).map((entry, index) => (
                    <Cell key={index} fill={getSeverityColor(entry.event_type)} fillOpacity={0.8} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Breakdown Table */}
        <div className="glass-card p-6 animate-slideUp opacity-0 stagger-4">
          <h3 className="text-sm font-semibold text-[#f0f4fc] mb-5 flex items-center gap-2">
            <Icon name="tag" size={16} className="text-[#fbbf24]" />
            Severity Breakdown
          </h3>
          {threats && threats.data.length > 0 ? (
            <div className="space-y-2">
              {threats.data.map((t, i) => {
                const severity = THREAT_SEVERITY[t.event_type] || 'INFO'
                const pct = topThreat ? Math.round((t.count / topThreat.count) * 100) : 0
                return (
                  <div key={t.event_type} className="flex items-center gap-3 animate-slideUp opacity-0" style={{ animationDelay: `${i * 0.04}s` }}>
                    <SeverityBadge severity={severity} />
                    <span className="text-sm text-[#f0f4fc] flex-1 truncate">
                      {t.event_type.replace(/_/g, ' ')}
                    </span>
                    <div className="w-24 h-1.5 bg-[#111827] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{ width: `${pct}%`, backgroundColor: getSeverityColor(t.event_type) }}
                      />
                    </div>
                    <span className="text-sm font-mono text-[#8b9bc0] w-10 text-right">{t.count}</span>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="text-center py-8">
              <Icon name="check" size={24} className="text-[#34d399] mx-auto mb-2" />
              <p className="text-sm text-[#8b9bc0]">No threats detected in this period.</p>
            </div>
          )}
        </div>
      </div>

      {/* Activity Heatmap */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-5">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-5 flex items-center gap-2">
          <Icon name="activity" size={16} className="text-violet-400" />
          Detection Heatmap
        </h3>
        <div className="flex flex-wrap gap-1.5">
          {heatmapData.map((cell, i) => {
            const maxCount = Math.max(...heatmapData.map(c => c.intensity), 1)
            const opacity = Math.max(0.1, cell.intensity / maxCount)
            return (
              <div
                key={i}
                title={`${cell.date}: ${cell.count} alerts`}
                className="w-8 h-8 rounded-md border border-[#2a3650] flex items-center justify-center text-[9px] font-mono transition-all duration-200 hover:scale-110 cursor-default"
                style={{ backgroundColor: `rgba(0, 229, 200, ${opacity})` }}
              >
                <span className={`${opacity > 0.5 ? 'text-[#0a0e17]' : 'text-[#8b9bc0]'}`}>
                  {cell.count}
                </span>
              </div>
            )
          })}
        </div>
        <div className="flex items-center gap-2 mt-3 text-[10px] text-[#5a6a8a]">
          <span>Less</span>
          {[0.1, 0.3, 0.5, 0.7, 0.9].map(o => (
            <div
              key={o}
              className="w-4 h-4 rounded-sm border border-[#2a3650]"
              style={{ backgroundColor: `rgba(0, 229, 200, ${o})` }}
            />
          ))}
          <span>More</span>
        </div>
      </div>

      {/* Detection Rate Trend */}
      {timeseries && timeseries.data.length >= 2 && (
        <div className="glass-card p-6 animate-slideUp opacity-0 stagger-6">
          <h3 className="text-sm font-semibold text-[#f0f4fc] mb-3 flex items-center gap-2">
            <Icon name="signal" size={16} className="text-[#34d399]" />
            Detection Trend
          </h3>
          {(() => {
            const half = Math.floor(timeseries.data.length / 2)
            const firstHalf = timeseries.data.slice(0, half).reduce((s, p) => s + p.count, 0)
            const secondHalf = timeseries.data.slice(half).reduce((s, p) => s + p.count, 0)
            const change = firstHalf > 0 ? Math.round(((secondHalf - firstHalf) / firstHalf) * 100) : 0
            const isUp = change > 0
            return (
              <div className="flex items-center gap-4">
                <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-semibold ${
                  isUp ? 'bg-[#ff4d6a]/10 text-[#ff4d6a]' : 'bg-[#34d399]/10 text-[#34d399]'
                }`}>
                  <Icon name={isUp ? 'arrow-up' : 'arrow-down'} size={14} />
                  {Math.abs(change)}%
                </div>
                <p className="text-sm text-[#8b9bc0]">
                  {isUp ? 'Increase' : 'Decrease'} in detections compared to the first half of the selected period.
                </p>
              </div>
            )
          })()}
        </div>
      )}
    </div>
  )
}

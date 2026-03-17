import { useEffect, useState } from 'react'
import { api, Agent, AgentDetail } from '../api'
import SeverityBadge from '../components/SeverityBadge'
import PageHeader from '../components/PageHeader'
import MiniBar from '../components/MiniBar'
import Icon from '../components/Icon'
import { SkeletonCard, SkeletonTable } from '../components/Skeleton'
import ConnectionError from '../components/ConnectionError'

const anomalyBarColor: Record<string, string> = {
  OK: 'bg-[#34d399]',
  LOW: 'bg-[#3b82f6]',
  MEDIUM: 'bg-[#f59e0b]',
  HIGH: 'bg-orange-500',
  CRITICAL: 'bg-[#ff4d6a]',
}

export default function Agents() {
  const [agents, setAgents] = useState<Agent[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [detail, setDetail] = useState<AgentDetail | null>(null)
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)

  const fetchData = () => {
    setError('')
    api.getAgents().then(a => { setAgents(a); setLoaded(true) }).catch(e => setError(e.message))
  }

  useEffect(() => { fetchData() }, [])

  useEffect(() => {
    if (selected) {
      setDetail(null)
      api.getAgent(selected).then(setDetail).catch(e => setError(e.message))
    }
  }, [selected])

  if (error) return (
    <div className="space-y-6">
      <PageHeader title="Agent Fleet" subtitle="Monitor and inspect agent behavior" />
      <ConnectionError onRetry={fetchData} />
    </div>
  )

  if (!loaded) return (
    <div className="space-y-6">
      <PageHeader title="Agent Fleet" subtitle="Monitor and inspect agent behavior" />
      <SkeletonTable rows={6} cols={5} />
    </div>
  )

  return (
    <div className="space-y-6">
      <PageHeader title="Agent Fleet" subtitle="Monitor and inspect agent behavior" />

      {/* Agent table */}
      <div className="glass-card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#2a3650] text-[#8b9bc0] text-left bg-[#111827]/60">
              <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Agent</th>
              <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Observations</th>
              <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Alerts</th>
              <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Tools</th>
              <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Avg Duration</th>
              <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Avg Data</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((a, i) => (
              <tr
                key={a.name}
                onClick={() => setSelected(a.name)}
                className={`border-b border-[#2a3650]/50 cursor-pointer transition-all duration-200 animate-fadeIn opacity-0 ${
                  selected === a.name
                    ? 'bg-[#00e5c8]/[0.07] border-l-2 border-l-[#00e5c8]'
                    : 'hover:bg-[#1f2a40]'
                }`}
                style={{ animationDelay: `${i * 0.04}s` }}
              >
                <td className="px-4 py-3 font-semibold text-[#f0f4fc]">{a.name}</td>
                <td className="px-4 py-3 text-[#8b9bc0]">{a.observations}</td>
                <td className="px-4 py-3">
                  {a.alert_count > 0 ? (
                    <span className="text-[#ff4d6a] font-semibold">{a.alert_count}</span>
                  ) : (
                    <span className="text-[#5a6a8a]">0</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1 flex-wrap">
                    {a.known_tools.slice(0, 4).map(t => (
                      <span key={t} className="px-2 py-0.5 bg-[#00e5c8]/10 text-[#00e5c8] border border-[#00e5c8]/20 rounded text-xs font-mono">
                        {t}
                      </span>
                    ))}
                    {a.known_tools.length > 4 && <span className="text-xs text-[#5a6a8a]">+{a.known_tools.length - 4}</span>}
                  </div>
                </td>
                <td className="px-4 py-3 text-[#8b9bc0] font-mono text-xs">{a.duration_mean}ms</td>
                <td className="px-4 py-3 text-[#8b9bc0] font-mono text-xs">{a.data_volume_mean}B</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Agent detail panel */}
      {selected && (
        <div className="space-y-4 animate-slideUp">
          <h3 className="text-lg font-bold flex items-center gap-2 text-[#f0f4fc]">
            <Icon name="bot" size={20} className="text-[#00e5c8]" />
            {selected}
            <button
              onClick={() => setSelected(null)}
              className="ml-auto flex items-center gap-1 text-xs text-[#5a6a8a] hover:text-[#f0f4fc] transition-colors duration-200"
            >
              <Icon name="x" size={14} /> close
            </button>
          </h3>

          {!detail ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <SkeletonCard />
              <SkeletonCard />
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Baseline info */}
              <div className="glass-card p-5">
                <h4 className="font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
                  <Icon name="chart" size={16} className="text-[#00e5c8]" />
                  Adaptive Baseline
                </h4>
                <div className="space-y-3">
                  {(() => {
                    const entries = Object.entries(detail.baseline).filter(([, v]) => typeof v === 'number')
                    const maxVal = Math.max(...entries.map(([, v]) => Math.abs(v as number)), 1)
                    return entries.map(([k, v]) => {
                      const numVal = v as number
                      return (
                        <div key={k}>
                          <div className="flex justify-between mb-1">
                            <p className="text-[#5a6a8a] text-xs">{k.replace(/_/g, ' ')}</p>
                            <p className="text-[#f0f4fc] font-mono text-xs">{numVal.toFixed(2)}</p>
                          </div>
                          <MiniBar value={Math.abs(numVal)} max={maxVal} color="bg-[#00e5c8]/60" height="h-1" />
                        </div>
                      )
                    })
                  })()}
                </div>
              </div>

              {/* Anomaly scores */}
              <div className="glass-card p-5">
                <h4 className="font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
                  <Icon name="activity" size={16} className="text-[#fbbf24]" />
                  Anomaly Scores
                </h4>
                {detail.anomaly_scores.length === 0 ? (
                  <p className="text-[#5a6a8a] text-sm">No anomaly scores computed yet.</p>
                ) : (
                  <div className="space-y-3">
                    {detail.anomaly_scores.map((s) => (
                      <div key={`${s.anomaly_type}-${s.level}`}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={s.level} />
                            <span className="text-sm text-[#f0f4fc] font-mono">{s.anomaly_type}</span>
                          </div>
                          <span className="text-sm font-semibold text-[#8b9bc0]">{(s.confidence * 100).toFixed(0)}%</span>
                        </div>
                        <MiniBar
                          value={s.confidence * 100}
                          max={100}
                          color={anomalyBarColor[s.level] || 'bg-[#5a6a8a]'}
                        />
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Agent alerts */}
              {detail.alerts.length > 0 && (
                <div className="lg:col-span-2 glass-card p-5">
                  <h4 className="font-semibold text-[#f0f4fc] mb-3 flex items-center gap-2">
                    <Icon name="alert" size={16} className="text-[#ff4d6a]" />
                    Active Alerts ({detail.alerts.length})
                  </h4>
                  <div className="space-y-2">
                    {detail.alerts.map((alert) => (
                      <div key={`${alert.severity}-${alert.timestamp}-${alert.description.slice(0, 40)}`} className="flex items-start gap-3 py-2.5 border-b border-[#2a3650]/50 last:border-0">
                        <SeverityBadge severity={alert.severity} />
                        <div className="flex-1">
                          <p className="text-sm text-[#f0f4fc]">{alert.description}</p>
                          <p className="text-xs text-[#00e5c8] mt-1">{alert.recommended_action}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

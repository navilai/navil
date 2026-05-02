import { useEffect, useState } from 'react'
import { api, Agent, AgentDetail } from '../api'
import SeverityBadge from '../components/SeverityBadge'
import PageHeader from '../components/PageHeader'
import MiniBar from '../components/MiniBar'
import Icon from '../components/Icon'
import { SkeletonCard, SkeletonTable } from '../components/Skeleton'
import ConnectionError from '../components/ConnectionError'

const anomalyBarColor: Record<string, string> = {
  OK: 'bg-signal-green',
  LOW: 'bg-signal-cyan',
  MEDIUM: 'bg-signal-amber',
  HIGH: 'bg-orange-500',
  CRITICAL: 'bg-signal-red',
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
            <tr className="border-b border-rule text-ink-secondary text-left bg-surface/60">
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
                className={`border-b border-rule/50 cursor-pointer transition-all duration-200 animate-fadeIn opacity-0 ${
                  selected === a.name
                    ? 'bg-signal-cyan/[0.07] border-l-2 border-l-[#00e5c8]'
                    : 'hover:bg-surface-elevated'
                }`}
                style={{ animationDelay: `${i * 0.04}s` }}
              >
                <td className="px-4 py-3 font-semibold text-ink">{a.name}</td>
                <td className="px-4 py-3 text-ink-secondary">{a.observations}</td>
                <td className="px-4 py-3">
                  {a.alert_count > 0 ? (
                    <span className="text-signal-red font-semibold">{a.alert_count}</span>
                  ) : (
                    <span className="text-ink-muted">0</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1 flex-wrap">
                    {a.known_tools.slice(0, 4).map(t => (
                      <span key={t} className="px-2 py-0.5 bg-signal-cyan/10 text-signal-cyan border border-signal-cyan/20 rounded text-xs font-mono">
                        {t}
                      </span>
                    ))}
                    {a.known_tools.length > 4 && <span className="text-xs text-ink-muted">+{a.known_tools.length - 4}</span>}
                  </div>
                </td>
                <td className="px-4 py-3 text-ink-secondary font-mono text-xs">{a.duration_mean}ms</td>
                <td className="px-4 py-3 text-ink-secondary font-mono text-xs">{a.data_volume_mean}B</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Agent detail panel */}
      {selected && (
        <div className="space-y-4 animate-slideUp">
          <h3 className="text-lg font-bold flex items-center gap-2 text-ink">
            <Icon name="bot" size={20} className="text-signal-cyan" />
            {selected}
            <button
              onClick={() => setSelected(null)}
              className="ml-auto flex items-center gap-1 text-xs text-ink-muted hover:text-ink transition-colors duration-200"
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
                <h4 className="font-semibold text-ink mb-4 flex items-center gap-2">
                  <Icon name="chart" size={16} className="text-signal-cyan" />
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
                            <p className="text-ink-muted text-xs">{k.replace(/_/g, ' ')}</p>
                            <p className="text-ink font-mono text-xs">{numVal.toFixed(2)}</p>
                          </div>
                          <MiniBar value={Math.abs(numVal)} max={maxVal} color="bg-signal-cyan/60" height="h-1" />
                        </div>
                      )
                    })
                  })()}
                </div>
              </div>

              {/* Anomaly scores */}
              <div className="glass-card p-5">
                <h4 className="font-semibold text-ink mb-4 flex items-center gap-2">
                  <Icon name="activity" size={16} className="text-signal-amber" />
                  Anomaly Scores
                </h4>
                {detail.anomaly_scores.length === 0 ? (
                  <p className="text-ink-muted text-sm">No anomaly scores computed yet.</p>
                ) : (
                  <div className="space-y-3">
                    {detail.anomaly_scores.map((s) => (
                      <div key={`${s.anomaly_type}-${s.level}`}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={s.level} />
                            <span className="text-sm text-ink font-mono">{s.anomaly_type}</span>
                          </div>
                          <span className="text-sm font-semibold text-ink-secondary">{(s.confidence * 100).toFixed(0)}%</span>
                        </div>
                        <MiniBar
                          value={s.confidence * 100}
                          max={100}
                          color={anomalyBarColor[s.level] || 'bg-ink-muted'}
                        />
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Agent alerts */}
              {detail.alerts.length > 0 && (
                <div className="lg:col-span-2 glass-card p-5">
                  <h4 className="font-semibold text-ink mb-3 flex items-center gap-2">
                    <Icon name="alert" size={16} className="text-signal-red" />
                    Active Alerts ({detail.alerts.length})
                  </h4>
                  <div className="space-y-2">
                    {detail.alerts.map((alert) => (
                      <div key={`${alert.severity}-${alert.timestamp}-${alert.description.slice(0, 40)}`} className="flex items-start gap-3 py-2.5 border-b border-rule/50 last:border-0">
                        <SeverityBadge severity={alert.severity} />
                        <div className="flex-1">
                          <p className="text-sm text-ink">{alert.description}</p>
                          <p className="text-xs text-signal-cyan mt-1">{alert.recommended_action}</p>
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

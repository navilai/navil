import { useEffect, useState } from 'react'
import { api, FeedbackStats, Alert } from '../api'
import PageHeader from '../components/PageHeader'
import MiniBar from '../components/MiniBar'
import Icon from '../components/Icon'
import AnimatedNumber from '../components/AnimatedNumber'
import SeverityBadge from '../components/SeverityBadge'

const verdictColors = {
  confirmed: 'bg-[#34d399]',
  dismissed: 'bg-[#5a6a8a]',
  escalated: 'bg-[#ff4d6a]',
}

const verdictChipStyles = {
  confirmed: {
    active: 'bg-[#34d399]/20 border-[#34d399]/40 text-[#34d399]',
    inactive: 'bg-[#1a2235] border-[#2a3650] text-[#8b9bc0] hover:border-[#34d399]/30 hover:text-[#34d399]',
  },
  dismissed: {
    active: 'bg-[#5a6a8a]/20 border-[#5a6a8a]/40 text-[#8b9bc0]',
    inactive: 'bg-[#1a2235] border-[#2a3650] text-[#8b9bc0] hover:border-[#5a6a8a]/30',
  },
  escalated: {
    active: 'bg-[#ff4d6a]/20 border-[#ff4d6a]/40 text-[#ff4d6a]',
    inactive: 'bg-[#1a2235] border-[#2a3650] text-[#8b9bc0] hover:border-[#ff4d6a]/30 hover:text-[#ff4d6a]',
  },
}

export default function Feedback() {
  const [stats, setStats] = useState<FeedbackStats | null>(null)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // Form state
  const [selectedAlert, setSelectedAlert] = useState('')
  const [verdict, setVerdict] = useState<'confirmed' | 'dismissed' | 'escalated'>('confirmed')
  const [notes, setNotes] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const loadData = () => {
    Promise.all([api.getFeedbackStats(), api.getAlerts()])
      .then(([s, a]) => { setStats(s); setAlerts(a) })
      .catch(e => setError(e.message))
  }

  useEffect(loadData, [])

  const handleSubmit = async () => {
    if (!selectedAlert) return
    const alert = alerts.find(a => `${a.timestamp}|${a.anomaly_type}|${a.agent}` === selectedAlert)
    if (!alert) return

    setSubmitting(true)
    setError('')
    setSuccess('')
    try {
      await api.submitFeedback({
        alert_timestamp: alert.timestamp,
        anomaly_type: alert.anomaly_type,
        agent_name: alert.agent,
        verdict,
        operator_notes: notes,
      })
      setSuccess('Feedback recorded successfully')
      setSelectedAlert('')
      setNotes('')
      loadData()
      setTimeout(() => setSuccess(''), 3000)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSubmitting(false)
    }
  }

  const totalByVerdict = stats ? Object.values(stats.by_anomaly_type).reduce(
    (acc, v) => ({
      confirmed: acc.confirmed + v.confirmed,
      dismissed: acc.dismissed + v.dismissed,
      escalated: acc.escalated + v.escalated,
    }),
    { confirmed: 0, dismissed: 0, escalated: 0 }
  ) : { confirmed: 0, dismissed: 0, escalated: 0 }

  return (
    <div className="space-y-6">
      <PageHeader title="Feedback" subtitle="Train the anomaly detector with human verdicts" />

      {/* Stats cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-card p-5 animate-slideUp opacity-0 hover:bg-[#1f2a40] hover:-translate-y-0.5 transition-all duration-200" style={{ animationDelay: '0s' }}>
          <p className="text-xs text-[#5a6a8a] font-medium mb-1">Total Feedback</p>
          <AnimatedNumber value={stats?.total_entries || 0} className="text-2xl font-bold block text-[#f0f4fc]" />
        </div>
        <div className="glass-card p-5 animate-slideUp opacity-0 hover:bg-[#1f2a40] hover:-translate-y-0.5 transition-all duration-200 border-[#34d399]/20" style={{ animationDelay: '0.06s' }}>
          <p className="text-xs text-[#34d399] font-medium mb-1">Confirmed</p>
          <AnimatedNumber value={totalByVerdict.confirmed} className="text-2xl font-bold text-[#34d399] block" />
        </div>
        <div className="glass-card p-5 animate-slideUp opacity-0 hover:bg-[#1f2a40] hover:-translate-y-0.5 transition-all duration-200" style={{ animationDelay: '0.12s' }}>
          <p className="text-xs text-[#8b9bc0] font-medium mb-1">Dismissed</p>
          <AnimatedNumber value={totalByVerdict.dismissed} className="text-2xl font-bold text-[#8b9bc0] block" />
        </div>
        <div className="glass-card p-5 animate-slideUp opacity-0 hover:bg-[#1f2a40] hover:-translate-y-0.5 transition-all duration-200 border-[#ff4d6a]/20" style={{ animationDelay: '0.18s' }}>
          <p className="text-xs text-[#ff4d6a] font-medium mb-1">Escalated</p>
          <AnimatedNumber value={totalByVerdict.escalated} className="text-2xl font-bold text-[#ff4d6a] block" />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Anomaly type breakdown */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
            <Icon name="chart" size={16} className="text-[#00e5c8]" />
            Feedback by Anomaly Type
          </h3>
          {stats && Object.keys(stats.by_anomaly_type).length > 0 ? (
            <div className="space-y-4">
              {Object.entries(stats.by_anomaly_type).map(([type, counts]) => {
                const total = counts.confirmed + counts.dismissed + counts.escalated
                return (
                  <div key={type}>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-sm text-[#f0f4fc] font-mono">{type}</span>
                      <span className="text-xs text-[#5a6a8a]">{total} entries</span>
                    </div>
                    <div className="flex gap-1 h-2 rounded-full overflow-hidden bg-[#111827]">
                      {counts.confirmed > 0 && (
                        <div className="bg-[#34d399] rounded-full" style={{ width: `${(counts.confirmed / total) * 100}%` }} />
                      )}
                      {counts.dismissed > 0 && (
                        <div className="bg-[#5a6a8a] rounded-full" style={{ width: `${(counts.dismissed / total) * 100}%` }} />
                      )}
                      {counts.escalated > 0 && (
                        <div className="bg-[#ff4d6a] rounded-full" style={{ width: `${(counts.escalated / total) * 100}%` }} />
                      )}
                    </div>
                    <div className="flex gap-4 mt-1 text-[10px] text-[#5a6a8a]">
                      <span className="text-[#34d399]">{counts.confirmed} confirmed</span>
                      <span>{counts.dismissed} dismissed</span>
                      <span className="text-[#ff4d6a]">{counts.escalated} escalated</span>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="text-[#5a6a8a] text-sm text-center py-4">No feedback data yet. Submit verdicts below.</p>
          )}
          {/* Legend */}
          <div className="flex gap-4 mt-4 pt-3 border-t border-[#2a3650]">
            <div className="flex items-center gap-1.5 text-xs text-[#5a6a8a]">
              <span className="w-2.5 h-2.5 rounded-full bg-[#34d399]" /> Confirmed
            </div>
            <div className="flex items-center gap-1.5 text-xs text-[#5a6a8a]">
              <span className="w-2.5 h-2.5 rounded-full bg-[#5a6a8a]" /> Dismissed
            </div>
            <div className="flex items-center gap-1.5 text-xs text-[#5a6a8a]">
              <span className="w-2.5 h-2.5 rounded-full bg-[#ff4d6a]" /> Escalated
            </div>
          </div>
        </div>

        {/* Submit feedback form */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
            <Icon name="activity" size={16} className="text-[#00e5c8]" />
            Submit Feedback
          </h3>
          <div className="space-y-4">
            <div>
              <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Select Alert</label>
              <select
                value={selectedAlert}
                onChange={e => setSelectedAlert(e.target.value)}
                className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
              >
                <option value="">Choose an alert...</option>
                {alerts.slice(0, 20).map((a) => (
                  <option key={`${a.timestamp}-${a.anomaly_type}-${a.agent}`} value={`${a.timestamp}|${a.anomaly_type}|${a.agent}`}>
                    [{a.severity}] {a.anomaly_type} — {a.agent}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs text-[#5a6a8a] font-medium mb-2">Verdict</label>
              <div className="flex gap-2">
                {(['confirmed', 'dismissed', 'escalated'] as const).map(v => (
                  <button
                    key={v}
                    onClick={() => setVerdict(v)}
                    className={`px-3 py-1.5 text-xs rounded-lg border capitalize ${
                      verdict === v
                        ? verdictChipStyles[v].active
                        : verdictChipStyles[v].inactive
                    }`}
                  >
                    {v}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Notes (optional)</label>
              <textarea
                value={notes}
                onChange={e => setNotes(e.target.value)}
                className="w-full h-24 bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none resize-none placeholder:text-[#5a6a8a] transition-colors"
                placeholder="Additional context about this alert..."
              />
            </div>

            <button
              onClick={handleSubmit}
              disabled={!selectedAlert || submitting}
              className="w-full px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-all duration-200"
            >
              <Icon name="activity" size={14} />
              {submitting ? 'Submitting...' : 'Submit Feedback'}
            </button>
          </div>
        </div>
      </div>

      {/* Success / Error messages */}
      {success && (
        <div className="glass-card border-[#34d399]/30 p-4 animate-slideUp flex items-center gap-2 text-sm text-[#34d399]">
          <Icon name="check" size={16} /> {success}
        </div>
      )}
      {error && <p className="text-[#ff4d6a] text-sm">{error}</p>}
    </div>
  )
}

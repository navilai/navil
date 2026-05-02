import { useEffect, useState } from 'react'
import { api, FeedbackStats, Alert } from '../api'
import PageHeader from '../components/PageHeader'
import MiniBar from '../components/MiniBar'
import Icon from '../components/Icon'
import AnimatedNumber from '../components/AnimatedNumber'
import SeverityBadge from '../components/SeverityBadge'

const verdictColors = {
  confirmed: 'bg-signal-green',
  dismissed: 'bg-ink-muted',
  escalated: 'bg-signal-red',
}

const verdictChipStyles = {
  confirmed: {
    active: 'bg-signal-green/20 border-signal-green/40 text-signal-green',
    inactive: 'bg-surface border-rule text-ink-secondary hover:border-signal-green/30 hover:text-signal-green',
  },
  dismissed: {
    active: 'bg-ink-muted/20 border-ink-muted/40 text-ink-secondary',
    inactive: 'bg-surface border-rule text-ink-secondary hover:border-ink-muted/30',
  },
  escalated: {
    active: 'bg-signal-red/20 border-signal-red/40 text-signal-red',
    inactive: 'bg-surface border-rule text-ink-secondary hover:border-signal-red/30 hover:text-signal-red',
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
        <div className="glass-card p-5 animate-slideUp opacity-0 hover:bg-surface-elevated hover:-translate-y-0.5 transition-all duration-200" style={{ animationDelay: '0s' }}>
          <p className="text-xs text-ink-muted font-medium mb-1">Total Feedback</p>
          <AnimatedNumber value={stats?.total_entries || 0} className="text-2xl font-bold block text-ink" />
        </div>
        <div className="glass-card p-5 animate-slideUp opacity-0 hover:bg-surface-elevated hover:-translate-y-0.5 transition-all duration-200 border-signal-green/20" style={{ animationDelay: '0.06s' }}>
          <p className="text-xs text-signal-green font-medium mb-1">Confirmed</p>
          <AnimatedNumber value={totalByVerdict.confirmed} className="text-2xl font-bold text-signal-green block" />
        </div>
        <div className="glass-card p-5 animate-slideUp opacity-0 hover:bg-surface-elevated hover:-translate-y-0.5 transition-all duration-200" style={{ animationDelay: '0.12s' }}>
          <p className="text-xs text-ink-secondary font-medium mb-1">Dismissed</p>
          <AnimatedNumber value={totalByVerdict.dismissed} className="text-2xl font-bold text-ink-secondary block" />
        </div>
        <div className="glass-card p-5 animate-slideUp opacity-0 hover:bg-surface-elevated hover:-translate-y-0.5 transition-all duration-200 border-signal-red/20" style={{ animationDelay: '0.18s' }}>
          <p className="text-xs text-signal-red font-medium mb-1">Escalated</p>
          <AnimatedNumber value={totalByVerdict.escalated} className="text-2xl font-bold text-signal-red block" />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Anomaly type breakdown */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-ink mb-4 flex items-center gap-2">
            <Icon name="chart" size={16} className="text-signal-cyan" />
            Feedback by Anomaly Type
          </h3>
          {stats && Object.keys(stats.by_anomaly_type).length > 0 ? (
            <div className="space-y-4">
              {Object.entries(stats.by_anomaly_type).map(([type, counts]) => {
                const total = counts.confirmed + counts.dismissed + counts.escalated
                return (
                  <div key={type}>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-sm text-ink font-mono">{type}</span>
                      <span className="text-xs text-ink-muted">{total} entries</span>
                    </div>
                    <div className="flex gap-1 h-2 rounded-full overflow-hidden bg-surface">
                      {counts.confirmed > 0 && (
                        <div className="bg-signal-green rounded-full" style={{ width: `${(counts.confirmed / total) * 100}%` }} />
                      )}
                      {counts.dismissed > 0 && (
                        <div className="bg-ink-muted rounded-full" style={{ width: `${(counts.dismissed / total) * 100}%` }} />
                      )}
                      {counts.escalated > 0 && (
                        <div className="bg-signal-red rounded-full" style={{ width: `${(counts.escalated / total) * 100}%` }} />
                      )}
                    </div>
                    <div className="flex gap-4 mt-1 text-[10px] text-ink-muted">
                      <span className="text-signal-green">{counts.confirmed} confirmed</span>
                      <span>{counts.dismissed} dismissed</span>
                      <span className="text-signal-red">{counts.escalated} escalated</span>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="text-ink-muted text-sm text-center py-4">No feedback data yet. Submit verdicts below.</p>
          )}
          {/* Legend */}
          <div className="flex gap-4 mt-4 pt-3 border-t border-rule">
            <div className="flex items-center gap-1.5 text-xs text-ink-muted">
              <span className="w-2.5 h-2.5 rounded-full bg-signal-green" /> Confirmed
            </div>
            <div className="flex items-center gap-1.5 text-xs text-ink-muted">
              <span className="w-2.5 h-2.5 rounded-full bg-ink-muted" /> Dismissed
            </div>
            <div className="flex items-center gap-1.5 text-xs text-ink-muted">
              <span className="w-2.5 h-2.5 rounded-full bg-signal-red" /> Escalated
            </div>
          </div>
        </div>

        {/* Submit feedback form */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-ink mb-4 flex items-center gap-2">
            <Icon name="activity" size={16} className="text-signal-cyan" />
            Submit Feedback
          </h3>
          <div className="space-y-4">
            <div>
              <label className="block text-xs text-ink-muted font-medium mb-1.5">Select Alert</label>
              <select
                value={selectedAlert}
                onChange={e => setSelectedAlert(e.target.value)}
                className="w-full bg-surface border border-rule rounded-lg px-3 py-2.5 text-sm text-ink focus:border-signal-cyan focus:outline-none transition-colors"
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
              <label className="block text-xs text-ink-muted font-medium mb-2">Verdict</label>
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
              <label className="block text-xs text-ink-muted font-medium mb-1.5">Notes (optional)</label>
              <textarea
                value={notes}
                onChange={e => setNotes(e.target.value)}
                className="w-full h-24 bg-surface border border-rule rounded-lg px-3 py-2.5 text-sm text-ink focus:border-signal-cyan focus:outline-none resize-none placeholder:text-ink-muted transition-colors"
                placeholder="Additional context about this alert..."
              />
            </div>

            <button
              onClick={handleSubmit}
              disabled={!selectedAlert || submitting}
              className="w-full px-4 py-2.5 bg-signal-cyan text-bg rounded-lg text-sm font-semibold hover:bg-signal-cyan hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-all duration-200"
            >
              <Icon name="activity" size={14} />
              {submitting ? 'Submitting...' : 'Submit Feedback'}
            </button>
          </div>
        </div>
      </div>

      {/* Success / Error messages */}
      {success && (
        <div className="glass-card border-signal-green/30 p-4 animate-slideUp flex items-center gap-2 text-sm text-signal-green">
          <Icon name="check" size={16} /> {success}
        </div>
      )}
      {error && <p className="text-signal-red text-sm">{error}</p>}
    </div>
  )
}

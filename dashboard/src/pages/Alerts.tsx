import { useEffect, useState, useRef } from 'react'
import { api, Alert, AnomalyExplanation } from '../api'
import { streamOnce } from '../hooks/useNavilStream'
import SeverityBadge from '../components/SeverityBadge'
import PageHeader from '../components/PageHeader'
import Icon from '../components/Icon'
import RelativeTime from '../components/RelativeTime'
import LLMErrorCard from '../components/LLMErrorCard'
import UpgradePrompt from '../components/UpgradePrompt'
import useLLMAvailable from '../hooks/useLLMAvailable'
import ConnectionError from '../components/ConnectionError'

const severities = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function Alerts() {
  const { canUseLLM } = useLLMAvailable()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [allAlerts, setAllAlerts] = useState<Alert[]>([])
  const [filter, setFilter] = useState('')
  const [expanded, setExpanded] = useState<number | null>(null)
  const [error, setError] = useState('')
  const [explaining, setExplaining] = useState<number | null>(null)
  const [streamingText, setStreamingText] = useState<Record<number, string>>({})
  const [explanations, setExplanations] = useState<Record<number, AnomalyExplanation>>({})
  const [llmError, setLlmError] = useState<Record<number, { message: string; type: string }>>({})
  const abortRef = useRef<(() => void) | null>(null)

  const fetchAlerts = () => {
    setError('')
    api.getAlerts().then(setAllAlerts).catch(e => setError(e.message))
    api.getAlerts(filter || undefined).then(setAlerts).catch(e => setError(e.message))
  }

  // Fetch all alerts once for counts
  useEffect(() => {
    api.getAlerts().then(setAllAlerts).catch(e => setError(e.message))
  }, [])

  useEffect(() => {
    api.getAlerts(filter || undefined)
      .then(setAlerts)
      .catch(e => setError(e.message))
  }, [filter])

  // Compute counts per severity
  const alertCounts: Record<string, number> = { '': allAlerts.length }
  for (const a of allAlerts) {
    alertCounts[a.severity] = (alertCounts[a.severity] || 0) + 1
  }

  if (error) return (
    <div className="space-y-6">
      <PageHeader title="Alerts" subtitle="Anomaly detection alerts" />
      <ConnectionError onRetry={fetchAlerts} />
    </div>
  )

  return (
    <div className="space-y-6">
      <PageHeader title="Alerts" subtitle={`${alerts.length} alert${alerts.length !== 1 ? 's' : ''} detected`}>
        <div className="flex gap-2">
          {severities.map(s => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`px-3 py-1.5 text-xs rounded-lg border flex items-center gap-1.5 font-medium transition-all duration-200 ${
                filter === s
                  ? 'bg-[#00e5c8]/15 border-[#00e5c8]/40 text-[#00e5c8]'
                  : 'bg-[#1a2235] border-[#2a3650] text-[#8b9bc0] hover:border-[#5a6a8a] hover:text-[#f0f4fc]'
              }`}
            >
              {s || 'All'}
              {alertCounts[s] !== undefined && (
                <span className="bg-[#111827] text-[#8b9bc0] text-[10px] px-1.5 py-0.5 rounded-full min-w-[20px] text-center font-semibold">
                  {alertCounts[s]}
                </span>
              )}
            </button>
          ))}
        </div>
      </PageHeader>

      {alerts.length === 0 ? (
        <div className="text-center py-16 animate-fadeIn">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[#34d399]/10 border border-[#34d399]/20 mb-4">
            <Icon name="check" size={32} className="text-[#34d399]" />
          </div>
          <p className="text-[#8b9bc0]">No alerts{filter ? ` with severity ${filter}` : ''}. Looking good!</p>
        </div>
      ) : (
        <div className="space-y-2">
          {alerts.map((alert, i) => (
            <div
              key={alert.timestamp + alert.anomaly_type + alert.agent}
              className="glass-card overflow-hidden animate-slideUp opacity-0"
              style={{ animationDelay: `${i * 0.03}s` }}
            >
              <div
                onClick={() => setExpanded(expanded === i ? null : i)}
                className="flex items-center gap-4 px-4 py-3 cursor-pointer hover:bg-[#1f2a40] transition-colors duration-200"
              >
                <SeverityBadge severity={alert.severity} />
                <span className="font-mono text-xs text-[#8b9bc0] w-40 shrink-0">{alert.anomaly_type}</span>
                <span className="text-sm text-[#f0f4fc] font-medium w-32 shrink-0">{alert.agent}</span>
                <span className="text-sm text-[#8b9bc0] flex-1 truncate">{alert.description}</span>
                <span className="text-sm text-[#5a6a8a] font-mono w-16 text-right">{(alert.confidence * 100).toFixed(0)}%</span>
                <Icon
                  name="chevron-down"
                  size={16}
                  className={`text-[#5a6a8a] transition-transform duration-200 ${expanded === i ? 'rotate-0' : '-rotate-90'}`}
                />
              </div>

              {/* Animated expand section */}
              <div
                className={`overflow-hidden transition-all duration-300 ease-out ${
                  expanded === i ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'
                }`}
              >
                <div className="px-4 pb-4 pt-2 border-t border-[#2a3650] space-y-3">
                  <div>
                    <p className="text-xs text-[#5a6a8a] font-medium uppercase tracking-wider mb-1.5">Evidence</p>
                    <ul className="space-y-1">
                      {alert.evidence.map((e, j) => (
                        <li key={j} className="text-sm text-[#8b9bc0] flex items-start gap-2">
                          <Icon name="chevron-right" size={12} className="text-[#5a6a8a] mt-0.5 shrink-0" />
                          {e}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <p className="text-xs text-[#5a6a8a] font-medium uppercase tracking-wider mb-1.5">Recommended Action</p>
                    <p className="text-sm text-[#00e5c8]">{alert.recommended_action}</p>
                  </div>
                  {/* AI Explanation */}
                  <div className="pt-2 border-t border-[#2a3650]/50">
                    {!explanations[i] ? (
                      canUseLLM ? (
                        <>
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              setExplaining(i)
                              setLlmError(prev => { const next = { ...prev }; delete next[i]; return next })
                              setStreamingText(prev => ({ ...prev, [i]: '' }))
                              abortRef.current?.()
                              const { promise, abort } = streamOnce<AnomalyExplanation>(
                                '/llm/explain-anomaly',
                                { anomaly_data: alert },
                                { onChunk: (_chunk, acc) => setStreamingText(prev => ({ ...prev, [i]: acc })) },
                              )
                              abortRef.current = abort
                              promise
                                .then(result => {
                                  setExplanations(prev => ({ ...prev, [i]: result }))
                                  setStreamingText(prev => { const next = { ...prev }; delete next[i]; return next })
                                })
                                .catch((err: Error) => {
                                  setLlmError(prev => ({ ...prev, [i]: { message: err.message, type: 'unknown' } }))
                                  setStreamingText(prev => { const next = { ...prev }; delete next[i]; return next })
                                })
                                .finally(() => setExplaining(null))
                            }}
                            disabled={explaining === i}
                            className="px-3 py-1.5 text-xs bg-violet-500/15 text-violet-400 border border-violet-500/30 rounded-lg hover:bg-violet-500/25 flex items-center gap-1.5 disabled:opacity-50"
                          >
                            <Icon name="sparkles" size={13} className={explaining === i ? 'animate-spin' : ''} />
                            {explaining === i ? 'Analyzing...' : 'Explain with AI'}
                          </button>
                          {explaining === i && streamingText[i] && (
                            <pre className="mt-2 text-xs text-[#8b9bc0] whitespace-pre-wrap font-mono bg-[#0d1117] rounded-lg p-2 max-h-32 overflow-y-auto">
                              {streamingText[i]}
                              <span className="animate-pulse text-violet-400">|</span>
                            </pre>
                          )}
                        </>
                      ) : (
                        <UpgradePrompt feature="AI-powered alert analysis" compact />
                      )
                    ) : (
                      <div className="space-y-2 animate-fadeIn">
                        <div className="flex items-center gap-2">
                          <Icon name="sparkles" size={14} className="text-violet-400" />
                          <span className="text-xs font-medium text-violet-400">AI Analysis</span>
                          <span className={`px-2 py-0.5 text-[10px] rounded-full font-medium ${
                            explanations[i].likely_threat
                              ? 'bg-[#ff4d6a]/15 text-[#ff4d6a] border border-[#ff4d6a]/30'
                              : 'bg-[#34d399]/15 text-[#34d399] border border-[#34d399]/30'
                          }`}>
                            {explanations[i].likely_threat ? 'Likely Threat' : 'Likely Benign'}
                          </span>
                        </div>
                        <p className="text-sm text-[#f0f4fc]">{explanations[i].explanation}</p>
                        {explanations[i].recommended_actions?.length > 0 && (
                          <div>
                            <p className="text-xs text-[#5a6a8a] mb-1">AI Recommended Actions</p>
                            <ul className="space-y-1">
                              {explanations[i].recommended_actions.map((a, j) => (
                                <li key={j} className="text-sm text-[#00e5c8] flex items-start gap-2">
                                  <Icon name="chevron-right" size={12} className="text-[#00e5c8] mt-0.5 shrink-0" />
                                  {a}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                    {llmError[i] && (
                      <LLMErrorCard
                        message={llmError[i].message}
                        errorType={llmError[i].type as any}
                        onRetry={() => {
                          setExplaining(i)
                          setLlmError(prev => { const next = { ...prev }; delete next[i]; return next })
                          setStreamingText(prev => ({ ...prev, [i]: '' }))
                          abortRef.current?.()
                          const { promise, abort } = streamOnce<AnomalyExplanation>(
                            '/llm/explain-anomaly',
                            { anomaly_data: alert },
                            { onChunk: (_chunk, acc) => setStreamingText(prev => ({ ...prev, [i]: acc })) },
                          )
                          abortRef.current = abort
                          promise
                            .then(result => {
                              setExplanations(prev => ({ ...prev, [i]: result }))
                              setStreamingText(prev => { const next = { ...prev }; delete next[i]; return next })
                            })
                            .catch((err: Error) => {
                              setLlmError(prev => ({ ...prev, [i]: { message: err.message, type: 'unknown' } }))
                              setStreamingText(prev => { const next = { ...prev }; delete next[i]; return next })
                            })
                            .finally(() => setExplaining(null))
                        }}
                        compact
                      />
                    )}
                  </div>
                  <div className="flex gap-4 text-xs text-[#5a6a8a]">
                    <span>Confidence: {(alert.confidence * 100).toFixed(1)}%</span>
                    <RelativeTime timestamp={alert.timestamp} className="text-[#5a6a8a]" />
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

import { useEffect, useState, useRef } from 'react'
import { api, RemediationSuggestion, RemediationAction, AutoRemediateResult, LLMConfig } from '../api'
import useSessionState from '../hooks/useSessionState'
import useNavilStream from '../hooks/useNavilStream'
import PageHeader from '../components/PageHeader'
import SeverityBadge from '../components/SeverityBadge'
import MiniBar from '../components/MiniBar'
import Icon from '../components/Icon'
import LLMErrorCard from '../components/LLMErrorCard'
import UpgradePrompt from '../components/UpgradePrompt'
import useLLMAvailable from '../hooks/useLLMAvailable'

const actionTypeColors: Record<string, string> = {
  policy_update: 'bg-[#00e5c8]/15 text-[#00e5c8] border-[#00e5c8]/30',
  threshold_adjustment: 'bg-[#f59e0b]/15 text-[#f59e0b] border-[#f59e0b]/30',
  credential_rotation: 'bg-[#f59e0b]/15 text-[#f59e0b] border-[#f59e0b]/30',
  agent_block: 'bg-[#ff4d6a]/15 text-[#ff4d6a] border-[#ff4d6a]/30',
  alert_escalation: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
}

const actionTypeDescriptions: Record<string, string> = {
  policy_update: 'Updates the security policy for this agent — changes what tools, data, or actions are allowed.',
  threshold_adjustment: 'Adjusts anomaly detection thresholds — makes the system more or less sensitive to deviations.',
  credential_rotation: 'Rotates credentials for this agent — revokes current access tokens and issues new ones.',
  agent_block: 'Blocks this agent entirely — denies all tool access until manually unblocked.',
  alert_escalation: 'Escalates to human review — flags these alerts for manual investigation by security team.',
}

const PHASES = ['analyzing', 'applying', 'verifying'] as const
type Phase = typeof PHASES[number]

export default function SelfHealing() {
  const { canUseLLM } = useLLMAvailable()
  const [llmConfig, setLlmConfig] = useState<LLMConfig | null>(null)
  const [error, setError] = useState<{ message: string; type: string } | null>(null)

  // Manual flow state
  const [analyzing, setAnalyzing] = useState(false)
  const [suggestion, setSuggestion] = useSessionState<RemediationSuggestion | null>('healing_suggestion', null)
  const [applying, setApplying] = useState<number | null>(null)
  const [applied, setApplied] = useState<Set<number>>(new Set())
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  // Auto-remediate flow state
  const [autoRemediating, setAutoRemediating] = useState(false)
  const [autoPhase, setAutoPhase] = useState<Phase | null>(null)
  const [autoResult, setAutoResult] = useSessionState<AutoRemediateResult | null>('healing_auto', null)
  const [autoApplying, setAutoApplying] = useState<number | null>(null)
  const [autoApplied, setAutoApplied] = useState<Set<number>>(new Set())

  const phaseTimersRef = useRef<ReturnType<typeof setTimeout>[]>([])
  const stream = useNavilStream<RemediationSuggestion>()

  const llmReady = llmConfig?.available && llmConfig?.api_key_set
  const busy = analyzing || stream.streaming || autoRemediating

  const toggleExpand = (i: number) => {
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(i) ? next.delete(i) : next.add(i)
      return next
    })
  }

  useEffect(() => {
    api.getLLMStatus().then(setLlmConfig).catch(() => setLlmConfig({ available: false, api_key_set: false, provider: '', model: '', base_url: '' }))
  }, [])

  // --- Manual flow handlers ---
  const handleAnalyze = () => {
    setAnalyzing(true)
    setError(null)
    setAutoResult(null)
    setApplied(new Set())
    setExpanded(new Set())
    stream.start({
      endpoint: '/llm/suggest-remediation',
      body: {},
      onDone: (res) => { setSuggestion(res); setAnalyzing(false) },
      onError: (msg) => { setError({ message: msg, type: 'unknown' }); setAnalyzing(false) },
    })
  }

  const handleApply = async (action: RemediationAction, index: number) => {
    setApplying(index)
    try {
      const res = await api.applyAction(action)
      if (res.success) {
        setApplied(prev => new Set([...prev, index]))
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      const errType = e instanceof Error && 'errorType' in e ? (e as Error & { errorType?: string }).errorType || 'unknown' : 'unknown'
      setError({ message: msg, type: errType })
    } finally {
      setApplying(null)
    }
  }

  // --- Auto-remediate handlers ---
  const handleAutoRemediate = async () => {
    setAutoRemediating(true)
    setAutoPhase('analyzing')
    setError(null)
    setSuggestion(null)
    setAutoApplied(new Set())
    setApplied(new Set())

    const timers: ReturnType<typeof setTimeout>[] = []
    timers.push(setTimeout(() => setAutoPhase('applying'), 3000))
    timers.push(setTimeout(() => setAutoPhase('verifying'), 6000))
    phaseTimersRef.current = timers

    try {
      const res = await api.autoRemediate()
      timers.forEach(clearTimeout)
      phaseTimersRef.current = []
      setAutoPhase(null)
      setAutoResult(res)
    } catch (e: unknown) {
      timers.forEach(clearTimeout)
      phaseTimersRef.current = []
      setAutoPhase(null)
      const msg = e instanceof Error ? e.message : String(e)
      const errType = e instanceof Error && 'errorType' in e ? (e as Error & { errorType?: string }).errorType || 'unknown' : 'unknown'
      setError({ message: msg, type: errType })
    } finally {
      setAutoRemediating(false)
    }
  }

  const handleAutoManualApply = async (action: RemediationAction, index: number) => {
    setAutoApplying(index)
    try {
      const res = await api.applyAction(action)
      if (res.success) {
        setAutoApplied(prev => new Set([...prev, index]))
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      const errType = e instanceof Error && 'errorType' in e ? (e as Error & { errorType?: string }).errorType || 'unknown' : 'unknown'
      setError({ message: msg, type: errType })
    } finally {
      setAutoApplying(null)
    }
  }

  // --- Shared action card renderer ---
  const renderActionBadges = (action: RemediationAction) => (
    <div className="flex items-center gap-2 flex-wrap">
      <span className={`px-2 py-0.5 text-[10px] font-medium rounded-md border ${
        actionTypeColors[action.type] || 'bg-[#5a6a8a]/15 text-[#8b9bc0] border-[#5a6a8a]/30'
      }`}>
        {action.type.replace(/_/g, ' ')}
      </span>
      <span className="text-xs font-mono text-[#8b9bc0]">{action.target}</span>
      {action.reversible && (
        <span className="px-1.5 py-0.5 text-[10px] bg-[#34d399]/10 text-[#34d399] rounded">reversible</span>
      )}
      {!action.reversible && (
        <span className="px-1.5 py-0.5 text-[10px] bg-[#ff4d6a]/10 text-[#ff4d6a] rounded">irreversible</span>
      )}
    </div>
  )

  return (
    <div className="space-y-6">
      <PageHeader title="Self-Healing" subtitle="AI-powered threat analysis and automated remediation">
        <div className="flex items-center gap-2">
          <button
            onClick={handleAnalyze}
            disabled={busy || !llmReady || !canUseLLM}
            className="px-4 py-2 bg-violet-600 text-white rounded-lg text-sm font-medium hover:bg-violet-500 hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
          >
            <Icon name="sparkles" size={14} className={analyzing ? 'animate-spin' : ''} />
            {analyzing ? 'Analyzing...' : 'Analyze Threats'}
          </button>
          <button
            onClick={handleAutoRemediate}
            disabled={busy || !llmReady || !canUseLLM}
            className="px-4 py-2 bg-[#34d399] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#10b981] hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
          >
            <Icon name="shield" size={14} className={autoRemediating ? 'animate-spin' : ''} />
            {autoRemediating ? 'Remediating...' : 'Auto-Remediate'}
          </button>
        </div>
      </PageHeader>

      {/* LLM status warnings */}
      {llmConfig && !llmConfig.available && (
        <LLMErrorCard message="LLM features require navil[llm]. Install with: pip install navil[llm]" errorType="auth" />
      )}
      {llmConfig?.available && !llmConfig?.api_key_set && (
        <LLMErrorCard message="No API key configured. Add your key in Settings to enable AI features." errorType="auth" />
      )}
      {error && (
        <LLMErrorCard message={error.message} errorType={error.type as any} onRetry={handleAnalyze} />
      )}
      {llmReady && !canUseLLM && !busy && !suggestion && !autoResult && (
        <UpgradePrompt feature="Self-Healing AI" />
      )}

      {/* Empty state */}
      {!suggestion && !autoResult && !busy && !error && llmReady && canUseLLM && (
        <div className="text-center py-16 animate-fadeIn">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-violet-500/10 border border-violet-500/20 mb-4">
            <Icon name="sparkles" size={32} className="text-violet-400" />
          </div>
          <p className="text-[#8b9bc0] leading-relaxed">Click "Analyze Threats" for manual review, or "Auto-Remediate" to automatically fix safe threats.</p>
        </div>
      )}

      {/* Manual analyze spinner */}
      {(analyzing || stream.streaming) && !suggestion && (
        <div className="text-center py-16 animate-fadeIn">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-violet-500/10 border border-violet-500/20 mb-4">
            <Icon name="sparkles" size={32} className="text-violet-400 animate-spin" />
          </div>
          <p className="text-[#8b9bc0]">Analyzing threats with AI...</p>
          {stream.text ? (
            <pre className="mt-3 mx-auto max-w-lg text-left text-xs text-[#8b9bc0] whitespace-pre-wrap font-mono bg-[#0d1117] rounded-lg p-3 max-h-40 overflow-y-auto">
              {stream.text}
              <span className="animate-pulse text-violet-400">|</span>
            </pre>
          ) : (
            <p className="text-xs text-[#5a6a8a] mt-1">This may take a few seconds</p>
          )}
        </div>
      )}

      {/* Auto-remediate phased progress */}
      {autoRemediating && !autoResult && (
        <div className="text-center py-16 animate-fadeIn">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[#34d399]/10 border border-[#34d399]/20 mb-6">
            <Icon name="shield" size={32} className="text-[#34d399] animate-spin" />
          </div>

          {/* Phase stepper */}
          <div className="flex items-center justify-center gap-2 mb-4">
            {PHASES.map((phase, i) => {
              const currentIdx = autoPhase ? PHASES.indexOf(autoPhase) : -1
              const isDone = currentIdx > i
              const isCurrent = autoPhase === phase
              return (
                <div key={phase} className="flex items-center gap-2">
                  {i > 0 && (
                    <div className={`w-8 h-px ${isDone ? 'bg-[#34d399]' : 'bg-[#2a3650]'}`} />
                  )}
                  <div className="flex items-center gap-1.5">
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-medium ${
                      isDone ? 'bg-[#34d399]/20 text-[#34d399]'
                        : isCurrent ? 'bg-[#34d399]/20 text-[#34d399] animate-pulse'
                        : 'bg-[#111827] text-[#5a6a8a]'
                    }`}>
                      {isDone ? <Icon name="check" size={11} /> : i + 1}
                    </div>
                    <span className={`text-xs capitalize ${
                      isCurrent ? 'text-[#34d399] font-medium' : isDone ? 'text-[#34d399]' : 'text-[#5a6a8a]'
                    }`}>
                      {phase === 'analyzing' ? 'Analyzing' : phase === 'applying' ? 'Applying' : 'Verifying'}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>

          <p className="text-xs text-[#5a6a8a]">Autonomous remediation in progress...</p>
        </div>
      )}

      {/* ===== MANUAL FLOW RESULTS ===== */}
      {suggestion && (
        <div className="space-y-6 animate-fadeIn">
          <div className="glass-card p-5 flex items-start gap-4">
            <div className="shrink-0"><SeverityBadge severity={suggestion.risk_assessment} /></div>
            <div>
              <p className="text-sm text-[#f0f4fc]">{suggestion.summary}</p>
              <p className="text-xs text-[#5a6a8a] mt-1">
                {suggestion.actions.length} remediation action{suggestion.actions.length !== 1 ? 's' : ''} suggested
              </p>
            </div>
          </div>

          {suggestion.actions.length === 0 ? (
            <div className="glass-card p-8 text-center">
              <Icon name="check" size={24} className="text-[#34d399] mx-auto mb-2" />
              <p className="text-[#8b9bc0] text-sm">No remediation actions needed. System looks healthy.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {suggestion.actions.map((action, i) => {
                const isExpanded = expanded.has(i)
                return (
                <div key={`${action.type}-${action.target}-${i}`} className={`glass-card p-4 animate-slideUp opacity-0 transition-all ${applied.has(i) ? 'border-[#34d399]/30' : ''}`}
                  style={{ animationDelay: `${i * 0.06}s` }}>
                  <div className="flex items-start gap-4">
                    <div className="flex-1">
                      <div className="mb-2">{renderActionBadges(action)}</div>
                      <p className="text-sm text-[#f0f4fc]">{action.reason}</p>
                      <div className="flex items-center gap-2 mt-2">
                        <span className="text-[10px] text-[#5a6a8a]">Confidence</span>
                        <MiniBar value={action.confidence * 100} max={100}
                          color={action.confidence >= 0.8 ? 'bg-[#34d399]' : action.confidence >= 0.5 ? 'bg-[#fbbf24]' : 'bg-orange-500'}
                          height="h-1" className="w-24" />
                        <span className="text-[10px] text-[#8b9bc0]">{(action.confidence * 100).toFixed(0)}%</span>
                        <button onClick={() => toggleExpand(i)} className="ml-auto text-[10px] text-[#5a6a8a] hover:text-[#f0f4fc] flex items-center gap-1 transition-colors">
                          <Icon name="info" size={11} />
                          {isExpanded ? 'Less' : 'Details'}
                        </button>
                      </div>
                      {isExpanded && (
                        <div className="mt-3 pt-3 border-t border-[#2a3650] space-y-2.5 animate-fadeIn">
                          <div>
                            <span className="text-[10px] uppercase tracking-wider text-[#5a6a8a] font-medium">What this does</span>
                            <p className="text-xs text-[#8b9bc0] mt-0.5">{actionTypeDescriptions[action.type] || 'Applies the recommended security change.'}</p>
                          </div>
                          <div>
                            <span className="text-[10px] uppercase tracking-wider text-[#5a6a8a] font-medium">Change</span>
                            <p className="text-xs font-mono text-[#f0f4fc] mt-0.5 bg-[#111827] rounded px-2 py-1.5">
                              {typeof action.value === 'string' ? action.value : JSON.stringify(action.value, null, 2)}
                            </p>
                          </div>
                          {action.reversible !== undefined && (
                            <div>
                              <span className="text-[10px] uppercase tracking-wider text-[#5a6a8a] font-medium">Reversibility</span>
                              <p className="text-xs text-[#8b9bc0] mt-0.5">
                                {action.reversible ? 'This action can be undone. The previous state will be restored if reverted.'
                                  : 'This action cannot be easily undone. Review carefully before applying.'}
                              </p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                    <div className="shrink-0">
                      {applied.has(i) ? (
                        <span className="px-3 py-1.5 text-xs bg-[#34d399]/15 text-[#34d399] border border-[#34d399]/30 rounded-lg flex items-center gap-1.5">
                          <Icon name="check" size={13} /> Applied
                        </span>
                      ) : (
                        <button onClick={() => handleApply(action, i)} disabled={applying === i}
                          className="px-3 py-1.5 text-xs bg-[#00e5c8]/15 text-[#00e5c8] border border-[#00e5c8]/30 rounded-lg hover:bg-[#00e5c8]/25 flex items-center gap-1.5 disabled:opacity-50">
                          <Icon name="shield" size={13} className={applying === i ? 'animate-spin' : ''} />
                          {applying === i ? 'Applying...' : 'Apply'}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
                )
              })}

              {applied.size > 0 && applied.size >= suggestion.actions.length && (
                <div className="glass-card p-5 text-center animate-fadeIn border-[#34d399]/20">
                  <Icon name="check" size={22} className="text-[#34d399] mx-auto mb-2" />
                  <p className="text-sm text-[#34d399] font-medium">All {applied.size} remediation actions applied</p>
                  <p className="text-xs text-[#5a6a8a] mt-1">Click "Analyze Threats" again to verify the system is now healthy.</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ===== AUTO-REMEDIATE RESULTS ===== */}
      {autoResult && (
        <div className="space-y-5 animate-fadeIn">
          {/* Initial analysis summary */}
          <div className="glass-card p-5 flex items-start gap-4">
            <div className="shrink-0"><SeverityBadge severity={autoResult.initial_analysis.risk_assessment} /></div>
            <div>
              <p className="text-sm text-[#f0f4fc]">{autoResult.initial_analysis.summary}</p>
              <p className="text-xs text-[#5a6a8a] mt-1">
                {autoResult.auto_applied.length} auto-applied
                {autoResult.manual_review.length > 0 && `, ${autoResult.manual_review.length} need review`}
                {autoResult.failed_to_apply.length > 0 && `, ${autoResult.failed_to_apply.length} failed`}
              </p>
            </div>
          </div>

          {/* Post-status banner */}
          <div className={`glass-card p-4 flex items-center gap-3 ${
            autoResult.post_status.healthy ? 'border-[#34d399]/20' : 'border-[#fbbf24]/20'
          }`}>
            <Icon name={autoResult.post_status.healthy ? 'check' : 'alert'} size={18}
              className={autoResult.post_status.healthy ? 'text-[#34d399]' : 'text-[#fbbf24]'} />
            <div>
              <p className={`text-sm font-medium ${autoResult.post_status.healthy ? 'text-[#34d399]' : 'text-[#fbbf24]'}`}>
                {autoResult.post_status.healthy
                  ? 'System Healthy — All Threats Resolved'
                  : `${autoResult.post_status.remaining_alert_count} alert${autoResult.post_status.remaining_alert_count !== 1 ? 's' : ''} remaining`}
              </p>
              <p className="text-xs text-[#5a6a8a]">
                {autoResult.post_status.healthy
                  ? 'All threats have been automatically resolved.'
                  : 'Some actions require manual review below.'}
              </p>
            </div>
          </div>

          {/* Auto-applied actions */}
          {autoResult.auto_applied.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-[#34d399] uppercase tracking-wider mb-3 flex items-center gap-2">
                <Icon name="check" size={13} />
                Auto-Applied ({autoResult.auto_applied.length})
              </h3>
              <div className="space-y-2">
                {autoResult.auto_applied.map((action, i) => (
                  <div key={`auto-${action.type}-${action.target}-${i}`} className="glass-card p-3 border-[#34d399]/20 animate-slideUp opacity-0"
                    style={{ animationDelay: `${i * 0.06}s` }}>
                    <div className="flex items-center gap-3">
                      <div className="flex-1">
                        {renderActionBadges(action)}
                        <p className="text-xs text-[#8b9bc0] mt-1.5">{action.reason}</p>
                      </div>
                      <Icon name="check" size={14} className="text-[#34d399] shrink-0" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Failed actions */}
          {autoResult.failed_to_apply.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-[#ff4d6a] uppercase tracking-wider mb-3 flex items-center gap-2">
                <Icon name="alert" size={13} />
                Failed ({autoResult.failed_to_apply.length})
              </h3>
              <div className="space-y-2">
                {autoResult.failed_to_apply.map((action, i) => (
                  <div key={`fail-${action.type}-${action.target}-${i}`} className="glass-card p-3 border-[#ff4d6a]/20">
                    {renderActionBadges(action)}
                    <p className="text-xs text-[#8b9bc0] mt-1.5">{action.reason}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Manual review actions */}
          {autoResult.manual_review.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-[#fbbf24] uppercase tracking-wider mb-3 flex items-center gap-2">
                <Icon name="eye" size={13} />
                Needs Manual Review ({autoResult.manual_review.length})
              </h3>
              <div className="space-y-3">
                {autoResult.manual_review.map((action, i) => (
                  <div key={`manual-${action.type}-${action.target}-${i}`} className="glass-card p-4 border-[#fbbf24]/20 animate-slideUp opacity-0"
                    style={{ animationDelay: `${(autoResult.auto_applied.length + i) * 0.06}s` }}>
                    <div className="flex items-start gap-4">
                      <div className="flex-1">
                        <div className="mb-2">{renderActionBadges(action)}</div>
                        <p className="text-sm text-[#f0f4fc]">{action.reason}</p>
                        <div className="flex items-center gap-2 mt-2">
                          <span className="text-[10px] text-[#5a6a8a]">Confidence</span>
                          <MiniBar value={action.confidence * 100} max={100}
                            color={action.confidence >= 0.8 ? 'bg-[#34d399]' : action.confidence >= 0.5 ? 'bg-[#fbbf24]' : 'bg-orange-500'}
                            height="h-1" className="w-24" />
                          <span className="text-[10px] text-[#8b9bc0]">{(action.confidence * 100).toFixed(0)}%</span>
                          {!action.reversible && (
                            <span className="text-[10px] text-[#fbbf24] ml-2">Irreversible — review carefully</span>
                          )}
                        </div>
                      </div>
                      <div className="shrink-0">
                        {autoApplied.has(i) ? (
                          <span className="px-3 py-1.5 text-xs bg-[#34d399]/15 text-[#34d399] border border-[#34d399]/30 rounded-lg flex items-center gap-1.5">
                            <Icon name="check" size={13} /> Applied
                          </span>
                        ) : (
                          <button onClick={() => handleAutoManualApply(action, i)} disabled={autoApplying === i}
                            className="px-3 py-1.5 text-xs bg-[#00e5c8]/15 text-[#00e5c8] border border-[#00e5c8]/30 rounded-lg hover:bg-[#00e5c8]/25 flex items-center gap-1.5 disabled:opacity-50">
                            <Icon name="shield" size={13} className={autoApplying === i ? 'animate-spin' : ''} />
                            {autoApplying === i ? 'Applying...' : 'Apply'}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* No actions at all */}
          {autoResult.auto_applied.length === 0 && autoResult.manual_review.length === 0 && autoResult.failed_to_apply.length === 0 && (
            <div className="glass-card p-8 text-center">
              <Icon name="check" size={24} className="text-[#34d399] mx-auto mb-2" />
              <p className="text-[#8b9bc0] text-sm">No remediation actions needed. System looks healthy.</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

import { useEffect, useState } from 'react'
import { api, PolicyCheckResult, PolicyDecision, PolicySuggestion, GeneratedPolicy } from '../api'
import useNavilStream from '../hooks/useNavilStream'
import PageHeader from '../components/PageHeader'
import StatusBadge from '../components/StatusBadge'
import SeverityBadge from '../components/SeverityBadge'
import RelativeTime from '../components/RelativeTime'
import Icon from '../components/Icon'
import { SkeletonTable } from '../components/Skeleton'
import LLMErrorCard from '../components/LLMErrorCard'
import UpgradePrompt from '../components/UpgradePrompt'
import useLLMAvailable from '../hooks/useLLMAvailable'
import useSessionState from '../hooks/useSessionState'

export default function Policy() {
  const { canUseLLM } = useLLMAvailable()
  const [decisions, setDecisions] = useState<PolicyDecision[]>([])
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState('')

  // Check form
  const [agentName, setAgentName] = useState('')
  const [toolName, setToolName] = useState('')
  const [action, setAction] = useState('')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useSessionState<PolicyCheckResult | null>('policy_check', null)

  // AI Policy Builder — Suggestions
  const [suggestions, setSuggestions] = useState<PolicySuggestion[]>([])
  const [suggestionsLoaded, setSuggestionsLoaded] = useState(false)
  const [actingOn, setActingOn] = useState<string | null>(null)
  const [autoGenYaml, setAutoGenYaml] = useSessionState('auto_gen_yaml', '')
  const [autoGenerating, setAutoGenerating] = useState(false)

  const loadSuggestions = () => {
    api.getPolicySuggestions()
      .then(res => { setSuggestions(res.suggestions); setSuggestionsLoaded(true) })
      .catch(() => setSuggestionsLoaded(true))
  }

  useEffect(loadSuggestions, [])

  const handleSuggestionAction = async (id: string, action: 'approve' | 'reject') => {
    setActingOn(id)
    try {
      await api.actOnSuggestion(id, action)
      setSuggestions(prev => prev.filter(s => s.id !== id))
    } catch {
      // silently fail
    } finally {
      setActingOn(null)
    }
  }

  const handleAutoGenerate = async () => {
    setAutoGenerating(true)
    try {
      const res = await api.autoGeneratePolicy()
      setAutoGenYaml(res.yaml)
    } catch {
      setAutoGenYaml('')
    } finally {
      setAutoGenerating(false)
    }
  }

  // AI Policy Generator
  const [genDescription, setGenDescription] = useSessionState('policy_desc', '')
  const [generating, setGenerating] = useState(false)
  const [generatedYaml, setGeneratedYaml] = useSessionState('policy_yaml', '')
  const [generatedPolicy, setGeneratedPolicy] = useSessionState<Record<string, unknown> | null>('policy_gen', null)
  const [refineInput, setRefineInput] = useState('')
  const [refining, setRefining] = useState(false)
  const [copied, setCopied] = useState(false)
  const [genError, setGenError] = useState<{ message: string; type: string } | null>(null)
  const genStream = useNavilStream<GeneratedPolicy>()
  const refineStream = useNavilStream<GeneratedPolicy>()

  const loadDecisions = () => {
    api.getPolicyDecisions()
      .then(d => { setDecisions(d); setLoaded(true) })
      .catch(e => setError(e.message))
  }

  useEffect(loadDecisions, [])

  const handleCheck = async () => {
    if (!agentName || !toolName || !action) return
    setChecking(true)
    setResult(null)
    setError('')
    try {
      const res = await api.checkPolicy(agentName, toolName, action)
      setResult(res)
      loadDecisions() // refresh decisions
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setChecking(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Policy Engine" subtitle="Check permissions and review decisions" />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Policy Checker */}
        <div className="space-y-4">
          <div className="glass-card p-5">
            <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
              <Icon name="shield" size={16} className="text-[#00e5c8]" />
              Check Permission
            </h3>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Agent Name</label>
                <input
                  value={agentName}
                  onChange={e => setAgentName(e.target.value)}
                  className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
                  placeholder="e.g., code-assistant"
                />
              </div>
              <div>
                <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Tool Name</label>
                <input
                  value={toolName}
                  onChange={e => setToolName(e.target.value)}
                  className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
                  placeholder="e.g., admin_panel"
                />
              </div>
              <div>
                <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Action</label>
                <input
                  value={action}
                  onChange={e => setAction(e.target.value)}
                  className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
                  placeholder="e.g., read, write, delete"
                />
              </div>
              <button
                onClick={handleCheck}
                disabled={!agentName || !toolName || !action || checking}
                className="w-full px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-all duration-200"
              >
                <Icon name="shield" size={14} />
                {checking ? 'Checking...' : 'Check Permission'}
              </button>
            </div>
          </div>

          {/* Result card */}
          {result && (
            <div className={`glass-card p-5 animate-slideUp ${
              result.allowed
                ? 'border-[#34d399]/30'
                : 'border-[#ff4d6a]/30'
            }`}>
              <div className="flex items-center gap-3 mb-2">
                {result.allowed ? (
                  <>
                    <div className="w-10 h-10 rounded-full bg-[#34d399]/15 flex items-center justify-center">
                      <Icon name="check" size={20} className="text-[#34d399]" />
                    </div>
                    <div>
                      <p className="font-medium text-[#34d399]">Allowed</p>
                      <p className="text-xs text-[#5a6a8a]">This action is permitted</p>
                    </div>
                  </>
                ) : (
                  <>
                    <div className="w-10 h-10 rounded-full bg-[#ff4d6a]/15 flex items-center justify-center">
                      <Icon name="x" size={20} className="text-[#ff4d6a]" />
                    </div>
                    <div>
                      <p className="font-medium text-[#ff4d6a]">Denied</p>
                      <p className="text-xs text-[#5a6a8a]">This action is blocked</p>
                    </div>
                  </>
                )}
              </div>
              <p className="text-sm text-[#8b9bc0] mt-2">{result.reason}</p>
            </div>
          )}
        </div>

        {/* Decision Log */}
        <div>
          <h3 className="text-sm font-semibold text-[#f0f4fc] mb-3 flex items-center gap-2">
            <Icon name="clock" size={16} className="text-[#5a6a8a]" />
            Decision Log
          </h3>
          {!loaded ? <SkeletonTable rows={8} cols={4} /> : (
            decisions.length === 0 ? (
              <div className="glass-card p-8 text-center">
                <p className="text-[#5a6a8a] text-sm">No policy decisions recorded yet.</p>
              </div>
            ) : (
              <div className="glass-card overflow-hidden max-h-[600px] overflow-y-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-[#111827]/90 backdrop-blur">
                    <tr className="border-b border-[#2a3650] text-[#8b9bc0] text-left">
                      <th className="px-3 py-2.5 font-medium text-xs uppercase tracking-wider">Decision</th>
                      <th className="px-3 py-2.5 font-medium text-xs uppercase tracking-wider">Agent</th>
                      <th className="px-3 py-2.5 font-medium text-xs uppercase tracking-wider">Tool / Action</th>
                      <th className="px-3 py-2.5 font-medium text-xs uppercase tracking-wider">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {decisions.map((d, i) => (
                      <tr
                        key={`${d.timestamp}-${d.agent}-${d.tool}-${d.action}`}
                        className="border-b border-[#2a3650]/50 hover:bg-[#1f2a40] animate-fadeIn opacity-0"
                        style={{ animationDelay: `${i * 0.03}s` }}
                      >
                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-2">
                            <StatusBadge status={d.decision} />
                          </div>
                        </td>
                        <td className="px-3 py-2.5 text-[#f0f4fc] text-xs">{d.agent}</td>
                        <td className="px-3 py-2.5">
                          <span className="text-[#f0f4fc] text-xs font-mono">{d.tool}</span>
                          <span className="text-[#5a6a8a] text-xs mx-1">&rarr;</span>
                          <span className="text-[#8b9bc0] text-xs">{d.action}</span>
                        </td>
                        <td className="px-3 py-2.5">
                          <RelativeTime timestamp={d.timestamp} className="text-[#5a6a8a] text-xs" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          )}
        </div>
      </div>

      {/* AI Policy Builder — Suggestions */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-[#f0f4fc] flex items-center gap-2">
            <Icon name="sparkles" size={16} className="text-[#00e5c8]" />
            Policy Suggestions
            {suggestions.length > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-[#00e5c8]/15 text-[#00e5c8]">
                {suggestions.length}
              </span>
            )}
          </h3>
          <button
            onClick={handleAutoGenerate}
            disabled={autoGenerating}
            className="px-3 py-1.5 text-xs bg-[#00e5c8]/15 text-[#00e5c8] border border-[#00e5c8]/30 rounded-lg hover:bg-[#00e5c8]/25 flex items-center gap-1.5 disabled:opacity-40 transition-colors"
          >
            <Icon name="zap" size={12} className={autoGenerating ? 'animate-spin' : ''} />
            {autoGenerating ? 'Generating...' : 'Auto-Generate from Baselines'}
          </button>
        </div>

        {!suggestionsLoaded ? <SkeletonTable rows={3} cols={4} /> : (
          suggestions.length === 0 ? (
            <div className="text-center py-6">
              <Icon name="check" size={24} className="text-[#34d399] mx-auto mb-2" />
              <p className="text-sm text-[#5a6a8a]">No pending suggestions. Your policy is up to date.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {suggestions.map(s => (
                <div
                  key={s.id}
                  className="flex items-start gap-3 p-3 rounded-lg bg-[#111827] border border-[#2a3650] hover:border-[#00e5c8]/30 transition-colors"
                >
                  <div className="shrink-0 mt-0.5">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                      s.rule_type === 'deny' ? 'bg-[#ff4d6a]/15 text-[#ff4d6a]' :
                      s.rule_type === 'rate_limit' ? 'bg-[#f59e0b]/15 text-[#f59e0b]' :
                      'bg-[#00e5c8]/15 text-[#00e5c8]'
                    }`}>
                      <Icon name={s.rule_type === 'deny' ? 'x' : s.rule_type === 'rate_limit' ? 'activity' : 'shield'} size={14} />
                    </div>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-semibold text-[#f0f4fc]">{s.agent}</span>
                      <span className="text-[#5a6a8a] text-xs">→</span>
                      <span className="text-xs font-mono text-[#8b9bc0]">{s.tool}</span>
                      <span className={`px-1.5 py-0.5 text-[10px] font-medium rounded ${
                        s.rule_type === 'deny' ? 'bg-[#ff4d6a]/10 text-[#ff4d6a]' :
                        s.rule_type === 'rate_limit' ? 'bg-[#f59e0b]/10 text-[#f59e0b]' :
                        'bg-[#00e5c8]/10 text-[#00e5c8]'
                      }`}>
                        {s.rule_type.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-[#8b9bc0] leading-relaxed">{s.description}</p>
                    <div className="flex items-center gap-3 mt-2">
                      <span className="text-[10px] text-[#5a6a8a]">
                        Confidence: <span className={s.confidence >= 0.9 ? 'text-[#34d399]' : s.confidence >= 0.7 ? 'text-[#f59e0b]' : 'text-[#8b9bc0]'}>
                          {Math.round(s.confidence * 100)}%
                        </span>
                      </span>
                      <span className="text-[10px] text-[#5a6a8a]">Source: {s.source}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      onClick={() => handleSuggestionAction(s.id, 'approve')}
                      disabled={actingOn === s.id}
                      className="px-2.5 py-1.5 text-xs bg-[#34d399]/15 text-[#34d399] border border-[#34d399]/30 rounded-lg hover:bg-[#34d399]/25 disabled:opacity-40 transition-colors min-h-[36px]"
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => handleSuggestionAction(s.id, 'reject')}
                      disabled={actingOn === s.id}
                      className="px-2.5 py-1.5 text-xs bg-[#ff4d6a]/10 text-[#ff4d6a] border border-[#ff4d6a]/30 rounded-lg hover:bg-[#ff4d6a]/20 disabled:opacity-40 transition-colors min-h-[36px]"
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )
        )}

        {autoGenYaml && (
          <div className="mt-4 space-y-2 animate-fadeIn">
            <div className="flex items-center justify-between">
              <p className="text-xs text-[#5a6a8a]">Auto-generated policy from observed baselines</p>
              <button
                onClick={() => { navigator.clipboard.writeText(autoGenYaml); }}
                className="px-2 py-1 text-xs text-[#8b9bc0] hover:text-[#f0f4fc] border border-[#2a3650] rounded hover:border-[#5a6a8a] flex items-center gap-1 transition-colors"
              >
                <Icon name="terminal" size={12} /> Copy
              </button>
            </div>
            <pre className="bg-[#0d1117] border border-[#2a3650] rounded-[12px] p-4 text-sm text-[#f0f4fc] font-mono overflow-x-auto max-h-60 overflow-y-auto whitespace-pre-wrap">
              {autoGenYaml}
            </pre>
          </div>
        )}
      </div>

      {/* AI Policy Generator */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
          <Icon name="sparkles" size={16} className="text-violet-400" />
          Generate Policy with AI
        </h3>
        {!canUseLLM ? (
          <UpgradePrompt feature="AI Policy Generator" compact />
        ) : (
        <div className="space-y-3">
          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Describe your security policy</label>
            <textarea
              value={genDescription}
              onChange={e => setGenDescription(e.target.value)}
              className="w-full h-24 bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] placeholder:text-[#5a6a8a] focus:border-[#00e5c8] focus:outline-none resize-none transition-colors"
              placeholder="e.g., Allow data-reader to read logs only. Deny write/delete for all agents except admin-bot. Rate limit 60 req/hr."
            />
            {genDescription.trim() && genDescription.trim().split(/\s+/).length < 5 && (
              <p className="text-xs text-[#f59e0b] mt-1 flex items-center gap-1">
                <Icon name="warning" size={11} />
                Vague descriptions produce weak policies. Be specific about agents, tools, and permissions.
              </p>
            )}
          </div>
          <button
            onClick={() => {
              if (!genDescription.trim()) return
              setGenerating(true)
              setGenError(null)
              genStream.start({
                endpoint: '/llm/generate-policy',
                body: { description: genDescription },
                onDone: (res) => { setGeneratedYaml(res.yaml); setGeneratedPolicy(res.policy as Record<string, unknown>); setGenerating(false) },
                onError: (msg) => { setGenError({ message: msg, type: 'unknown' }); setGenerating(false) },
              })
            }}
            disabled={!genDescription.trim() || genStream.streaming}
            className="px-4 py-2.5 bg-violet-600 text-white rounded-lg text-sm font-medium hover:bg-violet-500 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
          >
            <Icon name="sparkles" size={14} className={genStream.streaming && !generatedYaml ? 'animate-spin' : ''} />
            {genStream.streaming && !generatedYaml ? 'Generating...' : 'Generate Policy'}
          </button>
          {/* Streaming text preview */}
          {genStream.streaming && genStream.text && !generatedYaml && (
            <pre className="mt-2 text-xs text-[#8b9bc0] whitespace-pre-wrap font-mono bg-[#0d1117] rounded-lg p-3 max-h-32 overflow-y-auto">
              {genStream.text}
              <span className="animate-pulse text-violet-400">|</span>
            </pre>
          )}
        </div>
        )}

        {(genError || genStream.error) && (
          <div className="mt-3">
            <LLMErrorCard
              message={(genError?.message || genStream.error)!}
              errorType={(genError?.type || 'unknown') as any}
              onRetry={() => {
                if (!genDescription.trim()) return
                setGenerating(true)
                setGenError(null)
                genStream.start({
                  endpoint: '/llm/generate-policy',
                  body: { description: genDescription },
                  onDone: (res) => { setGeneratedYaml(res.yaml); setGeneratedPolicy(res.policy as Record<string, unknown>); setGenerating(false) },
                  onError: (msg) => { setGenError({ message: msg, type: 'unknown' }); setGenerating(false) },
                })
              }}
            />
          </div>
        )}

        {generatedYaml && (
          <div className="mt-4 space-y-3 animate-fadeIn">
            <div className="flex items-center justify-between">
              <p className="text-xs text-[#5a6a8a]">Generated YAML</p>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(generatedYaml)
                  setCopied(true)
                  setTimeout(() => setCopied(false), 2000)
                }}
                className="px-2 py-1 text-xs text-[#8b9bc0] hover:text-[#f0f4fc] border border-[#2a3650] rounded hover:border-[#5a6a8a] flex items-center gap-1 transition-colors"
              >
                <Icon name={copied ? 'check' : 'terminal'} size={12} />
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <pre className={`bg-[#0d1117] border border-[#2a3650] rounded-[12px] p-4 text-sm text-[#f0f4fc] font-mono overflow-x-auto max-h-80 overflow-y-auto whitespace-pre-wrap transition-opacity ${generating || refineStream.streaming ? 'opacity-30' : ''}`}>
              {generatedYaml}
            </pre>
            <div className="flex gap-2">
              <input
                value={refineInput}
                onChange={e => setRefineInput(e.target.value)}
                className="flex-1 bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
                placeholder="Refine: e.g., Add a rate limit of 50/hr for deploy-agent"
              />
              <button
                onClick={() => {
                  if (!refineInput.trim() || !generatedPolicy) return
                  setRefining(true)
                  setGenError(null)
                  const hasPolicy = generatedPolicy && Object.keys(generatedPolicy).length > 0
                  const instruction = hasPolicy
                    ? refineInput
                    : `${genDescription}\n\nAdditional requirement: ${refineInput}`
                  refineStream.start({
                    endpoint: '/llm/refine-policy',
                    body: { existing_policy: generatedPolicy || {}, instruction },
                    onDone: (res) => { setGeneratedYaml(res.yaml); setGeneratedPolicy(res.policy as Record<string, unknown>); setRefineInput(''); setRefining(false) },
                    onError: (msg) => { setGenError({ message: msg, type: 'unknown' }); setRefining(false) },
                  })
                }}
                disabled={!refineInput.trim() || refineStream.streaming}
                className="px-4 py-2 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5"
              >
                <Icon name="sparkles" size={13} className={refineStream.streaming ? 'animate-spin' : ''} />
                Refine
              </button>
            </div>
          </div>
        )}
      </div>

      {error && <p className="text-[#ff4d6a] text-sm">{error}</p>}
    </div>
  )
}

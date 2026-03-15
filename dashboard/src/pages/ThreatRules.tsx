import { useEffect, useState } from 'react'
import {
  cloudApi,
  mockData,
  type ThreatRule,
  type OrgProfile,
  type OrgTier,
} from '../cloudApi'
import PageHeader from '../components/PageHeader'
import SeverityBadge from '../components/SeverityBadge'
import Icon from '../components/Icon'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const ACTIONS = ['alert', 'block'] as const

// Tiers that can access custom rules
const RULE_TIERS: OrgTier[] = ['team', 'enterprise']

export default function ThreatRules() {
  const [org, setOrg] = useState<OrgProfile | null>(null)
  const [rules, setRules] = useState<ThreatRule[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState<string | null>(null)
  const [actionMsg, setActionMsg] = useState<{ ok: boolean; msg: string } | null>(null)

  // Create form
  const [name, setName] = useState('')
  const [pattern, setPattern] = useState('')
  const [severity, setSeverity] = useState('HIGH')
  const [action, setAction] = useState<'alert' | 'block'>('alert')
  const [creating, setCreating] = useState(false)

  // Test panel
  const [testSample, setTestSample] = useState('')
  const [testResult, setTestResult] = useState<{ matched: boolean; matches: string[] } | null>(null)
  const [testingRule, setTestingRule] = useState(false)

  const [deleting, setDeleting] = useState<string | null>(null)

  const canAccessRules = org ? RULE_TIERS.includes(org.tier) : false

  const fetchData = () => {
    setLoading(true)
    Promise.all([
      cloudApi.getOrgProfile().catch(() => mockData.orgProfile),
      cloudApi.listThreatRules().catch(() => mockData.threatRules),
    ]).then(([profile, rulesList]) => {
      setOrg(profile)
      setRules(rulesList)
    }).finally(() => setLoading(false))
  }

  useEffect(() => { fetchData() }, [])

  const handleCreate = async () => {
    if (!name.trim() || !pattern.trim()) return
    setCreating(true)
    setActionMsg(null)
    try {
      await cloudApi.createThreatRule({ name: name.trim(), pattern: pattern.trim(), severity, action })
      setActionMsg({ ok: true, msg: `Rule "${name}" created successfully.` })
      setName('')
      setPattern('')
      setSeverity('HIGH')
      setAction('alert')
      setShowCreate(false)
      fetchData()
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setCreating(false)
    }
  }

  const handleToggleEnabled = async (rule: ThreatRule) => {
    try {
      await cloudApi.updateThreatRule(rule.id, { enabled: !rule.enabled })
      setRules(prev => prev.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r))
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    }
  }

  const handleDelete = async (id: string) => {
    setDeleting(id)
    setActionMsg(null)
    try {
      await cloudApi.deleteThreatRule(id)
      setActionMsg({ ok: true, msg: 'Rule deleted.' })
      setRules(prev => prev.filter(r => r.id !== id))
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setDeleting(null)
    }
  }

  const handleTestRule = async () => {
    if (!pattern.trim() || !testSample.trim()) return
    setTestingRule(true)
    setTestResult(null)
    try {
      const res = await cloudApi.testThreatRule(pattern.trim(), testSample.trim())
      setTestResult(res)
    } catch {
      // Local regex test as fallback
      try {
        const re = new RegExp(pattern.trim(), 'gi')
        const matches = testSample.trim().match(re)
        setTestResult({
          matched: !!matches,
          matches: matches || [],
        })
      } catch (regexErr) {
        setActionMsg({ ok: false, msg: `Invalid regex: ${regexErr instanceof Error ? regexErr.message : String(regexErr)}` })
      }
    } finally {
      setTestingRule(false)
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Threat Rules" subtitle="Custom detection rules" />
        <div className="skeleton h-24 rounded-xl" />
        <div className="skeleton h-64 rounded-xl" />
      </div>
    )
  }

  // Upgrade prompt for Community/Pro users
  if (!canAccessRules) {
    return (
      <div className="space-y-6">
        <PageHeader title="Threat Rules" subtitle="Custom detection rules" />
        <div className="max-w-lg mx-auto mt-8 text-center animate-fadeIn">
          <div className="glass-card p-8">
            <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-[#fbbf24]/10 border border-[#fbbf24]/20 flex items-center justify-center">
              <Icon name="lock" size={24} className="text-[#fbbf24]" />
            </div>
            <h2 className="text-lg font-bold text-[#f0f4fc] mb-2">Custom Threat Rules</h2>
            <p className="text-sm text-[#8b9bc0] mb-2">
              Create custom detection rules with regex patterns, severity levels, and automated actions.
            </p>
            <p className="text-sm text-[#8b9bc0] mb-6">
              Available on <span className="text-[#00e5c8] font-semibold">Team</span> and <span className="text-[#00e5c8] font-semibold">Enterprise</span> plans.
            </p>
            <div className="space-y-3 text-left mb-6">
              {[
                'Define regex patterns to catch specific threats',
                'Set severity levels and automated actions (alert or block)',
                'Test rules against sample data before deploying',
                'Enable/disable rules without deleting them',
              ].map(feat => (
                <div key={feat} className="flex items-center gap-2 text-sm text-[#8b9bc0]">
                  <Icon name="check" size={14} className="text-[#00e5c8] shrink-0" />
                  {feat}
                </div>
              ))}
            </div>
            <a
              href="/billing"
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 transition-all duration-200"
            >
              <Icon name="arrow-up" size={14} />
              Upgrade to Team
            </a>
            <p className="text-[10px] text-[#5a6a8a] mt-4">
              Current plan: <span className="uppercase font-semibold">{org?.tier || 'community'}</span>
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Threat Rules" subtitle={`${rules.length} custom rule${rules.length !== 1 ? 's' : ''}`}>
        <button
          onClick={() => { setShowCreate(!showCreate); setActionMsg(null); setTestResult(null) }}
          className="px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 flex items-center gap-2 transition-all duration-200"
        >
          <Icon name="shield" size={14} />
          {showCreate ? 'Cancel' : 'New Rule'}
        </button>
      </PageHeader>

      {/* Create Form */}
      {showCreate && (
        <div className="glass-card p-6 animate-slideUp opacity-0 stagger-1">
          <h3 className="text-sm font-semibold text-[#f0f4fc] mb-5 flex items-center gap-2">
            <Icon name="code" size={16} className="text-violet-400" />
            Create Rule
          </h3>
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Rule Name</label>
                <input
                  value={name}
                  onChange={e => setName(e.target.value)}
                  className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
                  placeholder="e.g., SQL Injection Detection"
                />
              </div>
              <div>
                <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Severity</label>
                <select
                  value={severity}
                  onChange={e => setSeverity(e.target.value)}
                  className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
                >
                  {SEVERITIES.map(s => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Pattern (regex)</label>
              <input
                value={pattern}
                onChange={e => setPattern(e.target.value)}
                className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none font-mono transition-colors"
                placeholder="(?i)(union\s+select|drop\s+table)"
              />
              <p className="text-xs text-[#5a6a8a] mt-1">Standard regex syntax. Case-insensitive recommended with (?i) flag.</p>
            </div>

            <div>
              <label className="block text-xs text-[#5a6a8a] font-medium mb-2">Action</label>
              <div className="flex gap-3">
                {ACTIONS.map(a => (
                  <button
                    key={a}
                    onClick={() => setAction(a)}
                    className={`px-4 py-2 text-sm rounded-lg border font-medium transition-all duration-200 ${
                      action === a
                        ? a === 'block'
                          ? 'bg-[#ff4d6a]/15 border-[#ff4d6a]/40 text-[#ff4d6a]'
                          : 'bg-[#fbbf24]/15 border-[#fbbf24]/40 text-[#fbbf24]'
                        : 'bg-[#111827] border-[#2a3650] text-[#8b9bc0] hover:border-[#5a6a8a] hover:text-[#f0f4fc]'
                    }`}
                  >
                    <Icon name={a === 'block' ? 'shield' : 'alert'} size={14} className="inline mr-1.5" />
                    {a.charAt(0).toUpperCase() + a.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {/* Test area */}
            <div className="border-t border-[#2a3650] pt-4">
              <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Test Against Sample Data</label>
              <textarea
                value={testSample}
                onChange={e => setTestSample(e.target.value)}
                className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none font-mono transition-colors resize-none h-20"
                placeholder="Paste sample input to test the regex pattern..."
              />
              <div className="flex gap-3 mt-2">
                <button
                  onClick={handleTestRule}
                  disabled={!pattern.trim() || !testSample.trim() || testingRule}
                  className="px-3 py-1.5 text-xs bg-violet-500/15 text-violet-400 border border-violet-500/30 rounded-lg hover:bg-violet-500/25 flex items-center gap-1.5 disabled:opacity-50 transition-all duration-200"
                >
                  <Icon name="activity" size={12} className={testingRule ? 'animate-spin' : ''} />
                  {testingRule ? 'Testing...' : 'Test Pattern'}
                </button>
              </div>
              {testResult && (
                <div className={`mt-3 p-3 rounded-[12px] border animate-fadeIn ${
                  testResult.matched
                    ? 'bg-[#ff4d6a]/5 border-[#ff4d6a]/20'
                    : 'bg-[#34d399]/5 border-[#34d399]/20'
                }`}>
                  <p className={`text-sm flex items-center gap-2 ${testResult.matched ? 'text-[#ff4d6a]' : 'text-[#34d399]'}`}>
                    <Icon name={testResult.matched ? 'warning' : 'check'} size={14} />
                    {testResult.matched
                      ? `Pattern matched! ${testResult.matches.length} match${testResult.matches.length !== 1 ? 'es' : ''} found.`
                      : 'No matches. Sample data is clean.'}
                  </p>
                  {testResult.matched && testResult.matches.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {testResult.matches.map((m, i) => (
                        <code key={i} className="px-2 py-0.5 text-xs bg-[#0d1117] text-[#ff4d6a] border border-[#ff4d6a]/20 rounded font-mono">
                          {m}
                        </code>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Submit */}
            <div className="flex gap-3 pt-1">
              <button
                onClick={handleCreate}
                disabled={!name.trim() || !pattern.trim() || creating}
                className="px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
              >
                <Icon name="check" size={14} />
                {creating ? 'Creating...' : 'Create Rule'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Action messages */}
      {actionMsg && (
        <div className={`p-3 rounded-[12px] border animate-fadeIn ${
          actionMsg.ok ? 'bg-[#34d399]/5 border-[#34d399]/20' : 'bg-[#ff4d6a]/5 border-[#ff4d6a]/20'
        }`}>
          <p className={`text-sm flex items-center gap-2 ${actionMsg.ok ? 'text-[#34d399]' : 'text-[#ff4d6a]'}`}>
            <Icon name={actionMsg.ok ? 'check' : 'warning'} size={14} />
            {actionMsg.msg}
          </p>
        </div>
      )}

      {/* Rules List */}
      {rules.length === 0 ? (
        <div className="text-center py-16 animate-fadeIn">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[#00e5c8]/10 border border-[#00e5c8]/20 mb-4">
            <Icon name="code" size={32} className="text-[#00e5c8]" />
          </div>
          <p className="text-[#8b9bc0]">No custom rules yet.</p>
          <p className="text-xs text-[#5a6a8a] mt-1">Create a rule to add custom threat detection patterns.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map((rule, i) => (
            <div
              key={rule.id}
              className="glass-card overflow-hidden animate-slideUp opacity-0"
              style={{ animationDelay: `${i * 0.03}s` }}
            >
              <div
                onClick={() => setEditing(editing === rule.id ? null : rule.id)}
                className="flex items-center gap-4 px-4 py-3 cursor-pointer hover:bg-[#1f2a40] transition-colors duration-200"
              >
                {/* Enable/disable toggle */}
                <button
                  onClick={(e) => { e.stopPropagation(); handleToggleEnabled(rule) }}
                  className={`relative w-9 h-5 rounded-full transition-colors duration-200 shrink-0 ${
                    rule.enabled ? 'bg-[#00e5c8]' : 'bg-[#2a3650]'
                  }`}
                >
                  <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200 ${
                    rule.enabled ? 'translate-x-4' : 'translate-x-0'
                  }`} />
                </button>

                <SeverityBadge severity={rule.severity} />
                <span className="text-sm text-[#f0f4fc] font-medium flex-1">{rule.name}</span>
                <span className={`px-2 py-0.5 text-[10px] font-semibold rounded-full uppercase ${
                  rule.action === 'block'
                    ? 'bg-[#ff4d6a]/10 text-[#ff4d6a] border border-[#ff4d6a]/20'
                    : 'bg-[#fbbf24]/10 text-[#fbbf24] border border-[#fbbf24]/20'
                }`}>
                  {rule.action}
                </span>
                <span className="text-xs font-mono text-[#5a6a8a]">{rule.match_count} matches</span>
                <Icon
                  name="chevron-down"
                  size={16}
                  className={`text-[#5a6a8a] transition-transform duration-200 ${editing === rule.id ? 'rotate-0' : '-rotate-90'}`}
                />
              </div>

              {/* Expanded */}
              <div
                className={`overflow-hidden transition-all duration-300 ease-out ${
                  editing === rule.id ? 'max-h-64 opacity-100' : 'max-h-0 opacity-0'
                }`}
              >
                <div className="px-4 pb-4 pt-2 border-t border-[#2a3650] space-y-3">
                  <div>
                    <p className="text-xs text-[#5a6a8a] font-medium uppercase tracking-wider mb-1.5">Pattern</p>
                    <code className="block bg-[#0d1117] border border-[#2a3650] rounded-lg px-3 py-2 text-sm font-mono text-[#00e5c8]">
                      {rule.pattern}
                    </code>
                  </div>
                  <div className="flex gap-4 text-xs text-[#5a6a8a]">
                    <span>Created: {new Date(rule.created_at).toLocaleDateString()}</span>
                    <span>Matches: {rule.match_count}</span>
                    <span>Status: {rule.enabled ? 'Enabled' : 'Disabled'}</span>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={(e) => { e.stopPropagation(); handleDelete(rule.id) }}
                      disabled={deleting === rule.id}
                      className="px-3 py-1.5 text-xs bg-[#ff4d6a]/10 text-[#ff4d6a] border border-[#ff4d6a]/20 rounded-lg hover:bg-[#ff4d6a]/20 flex items-center gap-1.5 disabled:opacity-50 transition-all duration-200"
                    >
                      <Icon name="x" size={12} />
                      {deleting === rule.id ? 'Deleting...' : 'Delete Rule'}
                    </button>
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

import { useEffect, useState } from 'react'
import { api, Credential, CredentialChain, Agent } from '../api'
import PageHeader from '../components/PageHeader'
import StatusBadge from '../components/StatusBadge'
import RelativeTime from '../components/RelativeTime'
import Icon from '../components/Icon'
import { SkeletonTable } from '../components/Skeleton'
import ConnectionError from '../components/ConnectionError'

const TTL_OPTIONS = [
  { label: '1 hour', value: 3600 },
  { label: '8 hours', value: 28800 },
  { label: '24 hours', value: 86400 },
  { label: '7 days', value: 604800 },
]

// ── Delegation Chain Tree Visualization ──────────────────────

function DelegationChainTree({ chain, onClose }: { chain: CredentialChain; onClose: () => void }) {
  return (
    <div className="glass-card border-purple-500/30 p-5 animate-slideUp">
      <div className="flex items-start justify-between mb-4">
        <h3 className="text-sm font-medium text-purple-300 flex items-center gap-2">
          <Icon name="lock" size={16} />
          Delegation Chain
        </h3>
        <button onClick={onClose} className="text-[#5a6a8a] hover:text-[#f0f4fc]">
          <Icon name="x" size={14} />
        </button>
      </div>

      {/* Human identity at root */}
      {chain.human_context && (
        <div className="flex items-center gap-2 mb-3 pl-2">
          <div className="w-6 h-6 rounded-full bg-[#3b82f6]/20 border border-[#3b82f6]/40 flex items-center justify-center">
            <Icon name="users" size={12} className="text-[#3b82f6]" />
          </div>
          <div>
            <span className="text-xs text-[#3b82f6] font-medium">Human Identity</span>
            <div className="text-xs text-[#8b9bc0]">
              {chain.human_context.email}
              <span className="text-[#5a6a8a] ml-1">(sub: {chain.human_context.sub})</span>
            </div>
            {chain.human_context.roles.length > 0 && (
              <div className="flex gap-1 mt-0.5">
                {chain.human_context.roles.map(r => (
                  <span key={r} className="px-1.5 py-0.5 bg-[#3b82f6]/10 text-[#3b82f6]/70 border border-[#3b82f6]/20 rounded text-[10px]">
                    {r}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Chain nodes */}
      <div className="space-y-0">
        {chain.chain.map((node, i) => {
          const isLast = i === chain.chain.length - 1
          const isRevoked = node.status === 'REVOKED'
          return (
            <div key={node.token_id} className="flex items-stretch">
              {/* Connector line */}
              <div className="flex flex-col items-center w-8 flex-shrink-0">
                <div className={`w-px flex-1 ${isRevoked ? 'bg-[#ff4d6a]/40' : 'bg-purple-500/40'}`} />
                <div className={`w-3 h-3 rounded-full border-2 flex-shrink-0 ${
                  isRevoked
                    ? 'border-[#ff4d6a]/60 bg-[#ff4d6a]/20'
                    : isLast
                      ? 'border-[#00e5c8]/60 bg-[#00e5c8]/20'
                      : 'border-purple-500/60 bg-purple-500/20'
                }`} />
                {!isLast && <div className={`w-px flex-1 ${isRevoked ? 'bg-[#ff4d6a]/40' : 'bg-purple-500/40'}`} />}
              </div>

              {/* Node content */}
              <div className={`flex-1 py-2 pl-2 ${isRevoked ? 'opacity-60' : ''}`}>
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-medium ${isRevoked ? 'text-[#ff4d6a]' : 'text-[#f0f4fc]'}`}>
                    {node.agent_name}
                  </span>
                  <StatusBadge status={node.status} />
                  {isLast && (
                    <span className="px-1.5 py-0.5 bg-[#00e5c8]/15 text-[#00e5c8] rounded text-[10px] font-medium">
                      CURRENT
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="px-1.5 py-0.5 bg-[#111827] text-[#5a6a8a] rounded text-[10px] font-mono">
                    {node.scope || '(empty scope)'}
                  </span>
                  <span className="text-[10px] text-[#5a6a8a] font-mono">
                    {node.token_id.slice(0, 16)}...
                  </span>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      <div className="mt-3 pt-3 border-t border-[#2a3650]/40 text-xs text-[#5a6a8a]">
        Chain depth: {chain.chain_length} | Max further delegation: {chain.chain[chain.chain.length - 1]?.max_delegation_depth ?? 'N/A'}
      </div>
    </div>
  )
}

// ── Main Credentials Page ────────────────────────────────────

export default function Credentials() {
  const [credentials, setCredentials] = useState<Credential[]>([])
  const [agents, setAgents] = useState<Agent[]>([])
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState('')

  // Issue form
  const [agentName, setAgentName] = useState('')
  const [scope, setScope] = useState('read:tools')
  const [ttl, setTtl] = useState(3600)
  const [issuing, setIssuing] = useState(false)
  const [newToken, setNewToken] = useState('')
  const [copied, setCopied] = useState(false)

  // Delegation chain view
  const [selectedChain, setSelectedChain] = useState<CredentialChain | null>(null)
  const [loadingChain, setLoadingChain] = useState<string | null>(null)

  const load = () => {
    Promise.all([api.getCredentials(), api.getAgents()])
      .then(([creds, agts]) => { setCredentials(creds); setAgents(agts); setLoaded(true) })
      .catch(e => setError(e.message))
  }

  useEffect(load, [])

  const handleIssue = async () => {
    if (!agentName) return
    setIssuing(true)
    setError('')
    try {
      const result = await api.issueCredential(agentName, scope, ttl)
      setNewToken(result.token)
      load() // refresh list
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setIssuing(false)
    }
  }

  const handleRevoke = async (tokenId: string, cascade = false) => {
    try {
      await api.revokeCredential(tokenId, cascade)
      load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const handleViewChain = async (tokenId: string) => {
    setLoadingChain(tokenId)
    try {
      const chain = await api.getCredentialChain(tokenId)
      setSelectedChain(chain)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoadingChain(null)
    }
  }

  const copyToken = () => {
    navigator.clipboard.writeText(newToken)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (error && !loaded) return (
    <div className="space-y-6">
      <PageHeader title="Credentials" subtitle="Manage agent API tokens" />
      <ConnectionError onRetry={load} />
    </div>
  )

  return (
    <div className="space-y-6">
      <PageHeader title="Credentials" subtitle="Manage agent API tokens and delegation chains" />

      {/* Issue new credential */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
          <Icon name="key" size={16} className="text-[#00e5c8]" />
          Issue New Credential
        </h3>
        <div className="flex flex-wrap gap-3 items-end">
          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Agent</label>
            <select
              value={agentName}
              onChange={e => setAgentName(e.target.value)}
              className="bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
            >
              <option value="">Select agent...</option>
              {agents.map(a => <option key={a.name} value={a.name}>{a.name}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Scope</label>
            <input
              value={scope}
              onChange={e => setScope(e.target.value)}
              className="bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2 text-sm text-[#f0f4fc] font-mono focus:border-[#00e5c8] focus:outline-none w-48 transition-colors"
              placeholder="read:tools write:logs"
            />
          </div>
          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">TTL</label>
            <select
              value={ttl}
              onChange={e => setTtl(Number(e.target.value))}
              className="bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
            >
              {TTL_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          <button
            onClick={handleIssue}
            disabled={!agentName || issuing}
            className="px-4 py-2 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
          >
            <Icon name="key" size={14} />
            {issuing ? 'Issuing...' : 'Issue Token'}
          </button>
        </div>
      </div>

      {/* New token display */}
      {newToken && (
        <div className="glass-card border-[#34d399]/30 p-5 animate-slideUp">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-sm font-medium text-[#34d399] mb-2 flex items-center gap-2">
                <Icon name="check" size={16} /> Token issued successfully
              </p>
              <p className="text-xs text-[#5a6a8a] mb-2">Copy this token now — it won't be shown again.</p>
              <code className="block bg-[#111827] rounded-lg p-3 text-xs text-[#f0f4fc] font-mono break-all max-w-2xl">
                {newToken}
              </code>
            </div>
            <div className="flex gap-2">
              <button
                onClick={copyToken}
                className="px-3 py-1.5 bg-[#34d399]/15 text-[#34d399] border border-[#34d399]/30 rounded-lg text-xs hover:bg-[#34d399]/25 flex items-center gap-1"
              >
                <Icon name="check" size={12} />
                {copied ? 'Copied!' : 'Copy'}
              </button>
              <button
                onClick={() => setNewToken('')}
                className="px-2 py-1.5 text-[#5a6a8a] hover:text-[#f0f4fc]"
              >
                <Icon name="x" size={14} />
              </button>
            </div>
          </div>
        </div>
      )}

      {error && <p className="text-[#ff4d6a] text-sm">{error}</p>}

      {/* Delegation chain visualization */}
      {selectedChain && (
        <DelegationChainTree
          chain={selectedChain}
          onClose={() => setSelectedChain(null)}
        />
      )}

      {/* Credentials table */}
      {!loaded ? <SkeletonTable rows={5} cols={6} /> : (
        <div className="glass-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#2a3650] text-[#8b9bc0] text-left bg-[#111827]/60">
                <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Token ID</th>
                <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Agent</th>
                <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Scope</th>
                <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Identity</th>
                <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Issued</th>
                <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Expires</th>
                <th className="px-4 py-3 font-medium text-xs uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody>
              {credentials.map((c, i) => {
                const hasChain = (c.delegation_chain?.length ?? 0) > 0
                const hasHuman = !!c.human_context
                return (
                  <tr
                    key={c.token_id}
                    className={`border-b border-[#2a3650]/50 animate-fadeIn opacity-0 ${
                      c.status === 'REVOKED' ? 'opacity-50' : ''
                    }`}
                    style={{ animationDelay: `${i * 0.04}s` }}
                  >
                    <td className="px-4 py-3 font-mono text-xs text-[#8b9bc0]">{c.token_id.slice(0, 16)}...</td>
                    <td className="px-4 py-3 text-[#f0f4fc]">
                      {c.agent_name}
                      {c.delegated_by && (
                        <span className="block text-[10px] text-[#5a6a8a] mt-0.5">
                          via {c.delegated_by}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 bg-[#00e5c8]/10 text-[#00e5c8]/80 border border-[#00e5c8]/20 rounded-full text-xs">
                        {c.scope}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {hasHuman && (
                        <span className="px-2 py-0.5 bg-[#3b82f6]/10 text-[#3b82f6]/80 border border-[#3b82f6]/20 rounded-full text-xs" title={c.human_context?.email}>
                          {c.human_context?.email?.split('@')[0]}
                        </span>
                      )}
                      {hasChain && (
                        <span className="px-1.5 py-0.5 bg-purple-500/10 text-purple-300/80 border border-purple-500/20 rounded-full text-[10px] ml-1">
                          depth:{c.delegation_chain?.length}
                        </span>
                      )}
                      {!hasHuman && !hasChain && (
                        <span className="text-[#5a6a8a] text-xs">--</span>
                      )}
                    </td>
                    <td className="px-4 py-3"><StatusBadge status={c.status} /></td>
                    <td className="px-4 py-3"><RelativeTime timestamp={c.issued_at} className="text-[#8b9bc0] text-xs" /></td>
                    <td className="px-4 py-3"><RelativeTime timestamp={c.expires_at} className="text-[#8b9bc0] text-xs" /></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        {(hasChain || hasHuman) && (
                          <button
                            onClick={() => handleViewChain(c.token_id)}
                            disabled={loadingChain === c.token_id}
                            className="px-2 py-1 bg-purple-500/15 text-purple-400 border border-purple-500/30 rounded text-xs hover:bg-purple-500/25 flex items-center gap-1"
                            title="View delegation chain"
                          >
                            <Icon name="lock" size={12} />
                            {loadingChain === c.token_id ? '...' : 'Chain'}
                          </button>
                        )}
                        {c.status === 'ACTIVE' && (
                          <>
                            <button
                              onClick={() => handleRevoke(c.token_id)}
                              className="px-2 py-1 bg-[#ff4d6a]/15 text-[#ff4d6a] border border-[#ff4d6a]/30 rounded text-xs hover:bg-[#ff4d6a]/25 flex items-center gap-1"
                            >
                              <Icon name="x" size={12} /> Revoke
                            </button>
                            {hasChain && (
                              <button
                                onClick={() => handleRevoke(c.token_id, true)}
                                className="px-2 py-1 bg-[#ff4d6a]/15 text-[#ff4d6a] border border-[#ff4d6a]/30 rounded text-[10px] hover:bg-[#ff4d6a]/25"
                                title="Cascade revoke: revoke this credential and all descendants"
                              >
                                Cascade
                              </button>
                            )}
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

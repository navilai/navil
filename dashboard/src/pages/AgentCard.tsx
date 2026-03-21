import { useEffect, useState } from 'react'
import PageHeader from '../components/PageHeader'
import Icon from '../components/Icon'

const DEMO_AGENT_CARD = {
  name: 'navil-agent',
  description: 'An agent protected by Navil agent governance middleware',
  provider: { organization: '', url: '' },
  version: '1.0.0',
  capabilities: { streaming: true, pushNotifications: false, extendedAgentCard: true },
  skills: [{ id: 'mcp-tool-execution', name: 'MCP Tool Execution', description: 'Execute MCP server tools with governance and policy enforcement', tags: ['mcp', 'tools', 'governance'] }],
  securitySchemes: { navil_jwt: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } },
  security: [{ navil_jwt: [] }],
  interfaces: [{ protocol: 'jsonrpc', url: '/a2a', contentTypes: ['application/json'] }],
}

const ENDPOINTS = [
  { path: '/.well-known/agent.json', method: 'GET', description: 'Agent Card discovery' },
  { path: '/a2a', method: 'POST', description: 'Task dispatch (JSON-RPC)' },
  { path: '/mcp', method: 'POST', description: 'MCP tool execution' },
  { path: '/health', method: 'GET', description: 'Health check' },
]

export default function AgentCard() {
  const [agentCard, setAgentCard] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  // Config fields (read-only for now, sourced from env vars)
  const [agentName, setAgentName] = useState('')
  const [agentDescription, setAgentDescription] = useState('')
  const [providerOrg, setProviderOrg] = useState('')
  const [providerUrl, setProviderUrl] = useState('')

  useEffect(() => {
    async function fetchAgentCard() {
      try {
        const res = await fetch('/.well-known/agent.json', { signal: AbortSignal.timeout(5000) })
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        setAgentCard(data)
        // Populate config fields from live data
        setAgentName(data.name || '')
        setAgentDescription(data.description || '')
        setProviderOrg(data.provider?.organization || '')
        setProviderUrl(data.provider?.url || '')
      } catch {
        // Proxy not running — use demo data
        setError('Proxy not reachable — showing demo data')
        setAgentCard(DEMO_AGENT_CARD)
        setAgentName(DEMO_AGENT_CARD.name)
        setAgentDescription(DEMO_AGENT_CARD.description)
        setProviderOrg(DEMO_AGENT_CARD.provider.organization)
        setProviderUrl(DEMO_AGENT_CARD.provider.url)
      } finally {
        setLoading(false)
      }
    }
    fetchAgentCard()
  }, [])

  const cardJson = agentCard ? JSON.stringify(agentCard, null, 2) : ''

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(cardJson)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="A2A Agent Card" subtitle="Discoverable agent identity for agent-to-agent communication" />

      {/* Section 1: Current Agent Card */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-1">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
          <Icon name="code" size={16} className="text-[#00e5c8]" />
          Current Agent Card
        </h3>

        {/* Status indicator */}
        <div className={`mb-4 p-3 rounded-[12px] border flex items-center gap-3 ${
          error
            ? 'bg-[#fbbf24]/5 border-[#fbbf24]/20'
            : 'bg-[#34d399]/5 border-[#34d399]/20'
        }`}>
          <div className={`w-2 h-2 rounded-full shrink-0 ${error ? 'bg-[#fbbf24]' : 'bg-[#34d399]'}`} />
          <p className={`text-sm ${error ? 'text-[#fbbf24]' : 'text-[#34d399]'}`}>
            {error || 'Published at /.well-known/agent.json'}
          </p>
        </div>

        {loading ? (
          <div className="p-8 text-center">
            <Icon name="activity" size={20} className="text-[#5a6a8a] animate-spin mx-auto" />
            <p className="text-sm text-[#5a6a8a] mt-2">Fetching agent card...</p>
          </div>
        ) : (
          <>
            {/* Actions */}
            <div className="flex gap-2 mb-3">
              <button
                onClick={handleCopy}
                className="px-3 py-1.5 bg-[#1a2235] text-[#8b9bc0] border border-[#2a3650] rounded-lg text-xs font-medium hover:bg-[#1f2a40] hover:text-[#f0f4fc] hover:border-[#5a6a8a] flex items-center gap-1.5 transition-all duration-200"
              >
                <Icon name={copied ? 'check' : 'copy'} size={12} />
                {copied ? 'Copied!' : 'Copy'}
              </button>
              <a
                href="/.well-known/agent.json"
                target="_blank"
                rel="noopener noreferrer"
                className="px-3 py-1.5 bg-[#1a2235] text-[#8b9bc0] border border-[#2a3650] rounded-lg text-xs font-medium hover:bg-[#1f2a40] hover:text-[#f0f4fc] hover:border-[#5a6a8a] flex items-center gap-1.5 transition-all duration-200"
              >
                <Icon name="external-link" size={12} />
                Open in browser
              </a>
            </div>

            {/* JSON code block */}
            <div className="relative rounded-[12px] bg-[#0d1117] border border-[#2a3650] overflow-hidden">
              <div className="px-4 py-2 border-b border-[#2a3650] flex items-center gap-2">
                <span className="text-[10px] font-mono text-[#5a6a8a]">/.well-known/agent.json</span>
              </div>
              <pre className="p-4 overflow-x-auto text-xs font-mono leading-relaxed text-[#8b9bc0] max-h-[400px] overflow-y-auto">
                <code>{cardJson}</code>
              </pre>
            </div>
          </>
        )}
      </div>

      {/* Section 2: Configuration */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-2">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-5 flex items-center gap-2">
          <Icon name="settings" size={16} className="text-violet-400" />
          Configuration
        </h3>

        <div className="space-y-4">
          {/* Agent Name */}
          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Agent Name</label>
            <input
              value={agentName}
              onChange={e => setAgentName(e.target.value)}
              className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none font-mono transition-colors"
              placeholder="navil-agent"
            />
            <p className="text-xs text-[#5a6a8a] mt-1">
              Environment variable: <code className="font-mono text-[#5a6a8a]">NAVIL_AGENT_NAME</code>
            </p>
          </div>

          {/* Description */}
          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Description</label>
            <textarea
              value={agentDescription}
              onChange={e => setAgentDescription(e.target.value)}
              rows={2}
              className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors resize-none"
              placeholder="An agent protected by Navil agent governance middleware"
            />
            <p className="text-xs text-[#5a6a8a] mt-1">
              Environment variable: <code className="font-mono text-[#5a6a8a]">NAVIL_AGENT_DESCRIPTION</code>
            </p>
          </div>

          {/* Provider Organization */}
          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Provider Organization</label>
            <input
              value={providerOrg}
              onChange={e => setProviderOrg(e.target.value)}
              className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none font-mono transition-colors"
              placeholder="Your Organization"
            />
            <p className="text-xs text-[#5a6a8a] mt-1">
              Environment variable: <code className="font-mono text-[#5a6a8a]">NAVIL_PROVIDER_ORG</code>
            </p>
          </div>

          {/* Provider URL */}
          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Provider URL</label>
            <input
              value={providerUrl}
              onChange={e => setProviderUrl(e.target.value)}
              className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none font-mono transition-colors"
              placeholder="https://your-org.com"
            />
            <p className="text-xs text-[#5a6a8a] mt-1">
              Environment variable: <code className="font-mono text-[#5a6a8a]">NAVIL_PROVIDER_URL</code>
            </p>
          </div>

          {/* Save button — disabled with tooltip */}
          <div className="pt-1">
            <div className="relative group inline-block">
              <button
                disabled
                className="px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
              >
                <Icon name="check" size={14} />
                Save Configuration
              </button>
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-1.5 bg-[#1a2235] border border-[#2a3650] rounded-lg text-xs text-[#8b9bc0] whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
                Coming soon — set via environment variables
                <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-1 w-2 h-2 bg-[#1a2235] border-r border-b border-[#2a3650] rotate-45" />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Section 3: A2A Endpoints */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-3">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
          <Icon name="link" size={16} className="text-[#00e5c8]" />
          A2A Endpoints
        </h3>

        <div className="rounded-[12px] border border-[#2a3650] overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#2a3650] bg-[#0d1117]">
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-[#5a6a8a] uppercase tracking-wider">Endpoint</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-[#5a6a8a] uppercase tracking-wider">Method</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-[#5a6a8a] uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody>
              {ENDPOINTS.map((ep, i) => (
                <tr key={ep.path} className={`border-b border-[#2a3650] last:border-b-0 ${i % 2 === 0 ? 'bg-[#111827]' : 'bg-[#0d1117]'}`}>
                  <td className="px-4 py-2.5 font-mono text-xs text-[#00e5c8]">{ep.path}</td>
                  <td className="px-4 py-2.5">
                    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${
                      ep.method === 'GET'
                        ? 'bg-[#34d399]/10 text-[#34d399]'
                        : 'bg-[#60a5fa]/10 text-[#60a5fa]'
                    }`}>
                      {ep.method}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-[#8b9bc0]">{ep.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <p className="text-xs text-[#5a6a8a] mt-3 flex items-center gap-1.5">
          <Icon name="info" size={12} className="text-[#5a6a8a] shrink-0" />
          All endpoints are served by the Navil proxy. Start with: <code className="font-mono text-[#5a6a8a] ml-1">navil proxy start</code>
        </p>
      </div>
    </div>
  )
}

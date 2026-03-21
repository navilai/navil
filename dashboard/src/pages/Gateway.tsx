import { useEffect, useState, useCallback } from 'react'
import { api, ProxyStatus, TrafficEntry } from '../api'
import PageHeader from '../components/PageHeader'
import StatCard from '../components/StatCard'
import StatusBadge from '../components/StatusBadge'
import Icon from '../components/Icon'
import RelativeTime from '../components/RelativeTime'

interface CLIEvent {
  command: string
  subcommand: string
  agent: string
  decision: string
  duration: string
  timestamp: string
}

const DEMO_CLI_EVENTS: CLIEvent[] = [
  { command: 'gh', subcommand: 'pr list', agent: 'code-assistant', decision: 'ALLOW', duration: '120ms', timestamp: '2m ago' },
  { command: 'kubectl', subcommand: 'get pods', agent: 'deploy-agent', decision: 'ALLOW', duration: '340ms', timestamp: '5m ago' },
  { command: 'gh', subcommand: 'auth login', agent: 'code-assistant', decision: 'DENY', duration: '0ms', timestamp: '8m ago' },
  { command: 'aws', subcommand: 's3 ls', agent: 'data-reader', decision: 'ALLOW', duration: '890ms', timestamp: '12m ago' },
]

const POLL_INTERVAL = 2000

const decisionColors: Record<string, string> = {
  ALLOWED: 'text-[#34d399]',
  FORWARDED: 'text-[#34d399]',
  DENIED: 'text-[#ff4d6a]',
  AUTH_REQUIRED: 'text-[#ff4d6a]',
  ALERT: 'text-[#fbbf24]',
}

const decisionBg: Record<string, string> = {
  ALLOWED: 'bg-[#34d399]/10',
  FORWARDED: 'bg-[#34d399]/10',
  DENIED: 'bg-[#ff4d6a]/10',
  AUTH_REQUIRED: 'bg-[#ff4d6a]/10',
  ALERT: 'bg-[#fbbf24]/10',
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return `${h}h ${m}m`
}

export default function Gateway() {
  const [status, setStatus] = useState<ProxyStatus | null>(null)
  const [traffic, setTraffic] = useState<TrafficEntry[]>([])
  const [agentFilter, setAgentFilter] = useState('')
  const [blockedOnly, setBlockedOnly] = useState(false)

  const [fetchError, setFetchError] = useState('')

  // Start proxy form state
  const [targetUrl, setTargetUrl] = useState('http://localhost:3000')
  const [proxyPort, setProxyPort] = useState('9090')
  const [requireAuth, setRequireAuth] = useState(true)
  const [starting, setStarting] = useState(false)
  const [startError, setStartError] = useState('')

  const handleStartProxy = async () => {
    if (!targetUrl.trim()) return
    setStarting(true)
    setStartError('')
    try {
      await api.proxyStart(targetUrl.trim(), Number(proxyPort) || 9090, requireAuth)
      fetchData()
    } catch (e: unknown) {
      setStartError(e instanceof Error ? e.message : String(e))
    } finally {
      setStarting(false)
    }
  }

  const fetchData = useCallback(() => {
    api.proxyStatus().then(s => { setStatus(s); setFetchError('') }).catch(e => setFetchError(e.message))
    api.proxyTraffic(agentFilter || undefined, blockedOnly)
      .then(setTraffic)
      .catch(() => {})
  }, [agentFilter, blockedOnly])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, POLL_INTERVAL)
    return () => clearInterval(interval)
  }, [fetchData])

  // Unique agents from traffic for filter dropdown
  const agents = [...new Set(traffic.map(t => t.agent))].sort()

  const running = status?.running ?? false

  return (
    <div>
      <PageHeader
        title="Gateway"
        subtitle="MCP Security Proxy — real-time traffic monitoring"
      >
        <div className="flex items-center gap-3">
          {running ? (
            <span className="flex items-center gap-2 px-3 py-1.5 bg-[#34d399]/10 border border-[#34d399]/20 rounded-lg text-[#34d399] text-sm font-medium">
              <span className="w-2 h-2 rounded-full bg-[#34d399] animate-pulse" />
              Running
            </span>
          ) : (
            <span className="flex items-center gap-2 px-3 py-1.5 bg-[#5a6a8a]/10 border border-[#5a6a8a]/20 rounded-lg text-[#8b9bc0] text-sm font-medium">
              <span className="w-2 h-2 rounded-full bg-[#5a6a8a]" />
              Stopped
            </span>
          )}
          {running && status?.target_url && (
            <span className="text-xs text-[#5a6a8a] font-mono">
              {status.target_url}
            </span>
          )}
        </div>
      </PageHeader>

      {!running ? (
        /* Start proxy form */
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="w-16 h-16 rounded-2xl bg-[#00e5c8]/10 border border-[#00e5c8]/20 flex items-center justify-center mb-6">
            <Icon name="gateway" size={32} className="text-[#00e5c8]" />
          </div>
          <h3 className="text-xl font-bold mb-2 text-[#f0f4fc]">Start MCP Security Proxy</h3>
          <p className="text-[#8b9bc0] max-w-md mb-6 leading-relaxed">
            Intercept and monitor agent-to-tool traffic in real time.
            The proxy enforces policies, detects anomalies, and blocks threats.
          </p>

          <div className="bg-[#1a2235] border border-[#2a3650] rounded-[12px] p-6 max-w-lg w-full text-left space-y-4">
            <div>
              <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Target MCP Server URL</label>
              <input
                type="text"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="http://localhost:3000"
                className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] font-mono focus:border-[#00e5c8] focus:outline-none transition-colors"
              />
            </div>

            <div className="flex gap-4">
              <div className="flex-1">
                <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Proxy Port</label>
                <input
                  type="number"
                  value={proxyPort}
                  onChange={e => setProxyPort(e.target.value)}
                  placeholder="9090"
                  className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] font-mono focus:border-[#00e5c8] focus:outline-none transition-colors"
                />
              </div>
              <div className="flex-1 flex items-end pb-1">
                <label className="flex items-center gap-2 text-sm text-[#8b9bc0] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={requireAuth}
                    onChange={e => setRequireAuth(e.target.checked)}
                    className="rounded border-[#2a3650] bg-[#111827] text-[#00e5c8] focus:ring-[#00e5c8]/30"
                  />
                  Require auth tokens
                </label>
              </div>
            </div>

            {startError && (
              <p className="text-xs text-[#ff4d6a] flex items-center gap-1">
                <Icon name="warning" size={11} />
                {startError}
              </p>
            )}

            <button
              onClick={handleStartProxy}
              disabled={!targetUrl.trim() || starting}
              className="w-full px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-all duration-200"
            >
              <Icon name="gateway" size={14} className={starting ? 'animate-spin' : ''} />
              {starting ? 'Starting...' : 'Start Proxy'}
            </button>

            <p className="text-xs text-[#5a6a8a] text-center">
              Agents connect to <span className="text-[#8b9bc0] font-mono">http://localhost:{proxyPort || '9090'}/mcp</span> instead of the MCP server directly.
            </p>
          </div>
        </div>
      ) : (
        <>
          {/* Stats bar */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <StatCard
              label="Total Requests"
              value={status?.stats.total_requests ?? 0}
              icon="activity"
              accent="cyan"
              index={0}
            />
            <StatCard
              label="Blocked"
              value={status?.stats.blocked ?? 0}
              icon="shield"
              accent="red"
              index={1}
            />
            <StatCard
              label="Alerts Generated"
              value={status?.stats.alerts_generated ?? 0}
              icon="alert"
              accent="amber"
              index={2}
            />
            <StatCard
              label="Uptime"
              value={formatUptime(status?.uptime_seconds ?? 0)}
              icon="clock"
              accent="emerald"
              index={3}
            />
          </div>

          {/* Filter controls */}
          <div className="flex items-center gap-4 mb-4">
            <select
              value={agentFilter}
              onChange={e => setAgentFilter(e.target.value)}
              className="bg-[#1a2235] border border-[#2a3650] rounded-lg px-3 py-2 text-sm text-[#f0f4fc] focus:outline-none focus:border-[#00e5c8]/50 transition-colors"
            >
              <option value="">All agents</option>
              {agents.map(a => (
                <option key={a} value={a}>{a}</option>
              ))}
            </select>

            <label className="flex items-center gap-2 text-sm text-[#8b9bc0] cursor-pointer">
              <input
                type="checkbox"
                checked={blockedOnly}
                onChange={e => setBlockedOnly(e.target.checked)}
                className="rounded border-[#2a3650] bg-[#111827] text-[#00e5c8] focus:ring-[#00e5c8]/30"
              />
              Blocked only
            </label>

            <span className="text-xs text-[#5a6a8a] ml-auto font-medium">
              Auto-refreshing every 2s
            </span>
          </div>

          {/* Traffic table */}
          <div className="glass-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#2a3650] bg-[#111827]/60">
                    <th className="text-left px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Time</th>
                    <th className="text-left px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Agent</th>
                    <th className="text-left px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Method</th>
                    <th className="text-left px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Tool</th>
                    <th className="text-left px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Decision</th>
                    <th className="text-right px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Duration</th>
                    <th className="text-right px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Data</th>
                  </tr>
                </thead>
                <tbody>
                  {traffic.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-4 py-12 text-center text-[#5a6a8a]">
                        {blockedOnly
                          ? 'No blocked requests'
                          : 'No traffic yet — send a JSON-RPC request to the proxy'}
                      </td>
                    </tr>
                  ) : (
                    traffic.map((entry) => (
                      <tr
                        key={entry.timestamp + entry.agent + entry.tool}
                        className={`border-b border-[#2a3650]/50 ${decisionBg[entry.decision] || ''} hover:bg-[#1f2a40] transition-colors duration-200`}
                      >
                        <td className="px-4 py-2.5 text-[#5a6a8a] font-mono text-xs whitespace-nowrap">
                          <RelativeTime timestamp={entry.timestamp} />
                        </td>
                        <td className="px-4 py-2.5 text-[#f0f4fc] font-semibold">
                          {entry.agent}
                        </td>
                        <td className="px-4 py-2.5 text-[#8b9bc0] font-mono text-xs">
                          {entry.method}
                        </td>
                        <td className="px-4 py-2.5 text-[#f0f4fc]">
                          {entry.tool || '-'}
                        </td>
                        <td className={`px-4 py-2.5 font-semibold ${decisionColors[entry.decision] || 'text-[#8b9bc0]'}`}>
                          {entry.decision}
                        </td>
                        <td className="px-4 py-2.5 text-[#5a6a8a] text-right font-mono text-xs">
                          {entry.duration_ms}ms
                        </td>
                        <td className="px-4 py-2.5 text-[#5a6a8a] text-right font-mono text-xs">
                          {entry.data_bytes > 1024
                            ? `${(entry.data_bytes / 1024).toFixed(1)}KB`
                            : `${entry.data_bytes}B`}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* CLI Tool Calls */}
          <div className="mt-6">
            <h3 className="text-sm font-semibold text-[#f0f4fc] mb-3 flex items-center gap-2">
              <Icon name="terminal" size={16} className="text-[#00e5c8]" />
              CLI Tool Calls
            </h3>

            <div className="glass-card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#2a3650] bg-[#111827]/60">
                      <th className="text-left px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Command</th>
                      <th className="text-left px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Subcommand</th>
                      <th className="text-left px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Agent</th>
                      <th className="text-left px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Decision</th>
                      <th className="text-right px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Duration</th>
                      <th className="text-right px-4 py-3 text-[#8b9bc0] font-medium text-xs uppercase tracking-wider">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {DEMO_CLI_EVENTS.map((evt, i) => (
                      <tr
                        key={`${evt.command}-${evt.subcommand}-${evt.timestamp}`}
                        className="border-b border-[#2a3650]/50 hover:bg-[#1f2a40] transition-colors duration-200 animate-fadeIn opacity-0"
                        style={{ animationDelay: `${i * 0.03}s` }}
                      >
                        <td className="px-4 py-2.5 text-[#f0f4fc] font-mono font-semibold text-xs">
                          {evt.command}
                        </td>
                        <td className="px-4 py-2.5 text-[#8b9bc0] font-mono text-xs">
                          {evt.subcommand}
                        </td>
                        <td className="px-4 py-2.5 text-[#f0f4fc] text-xs">
                          {evt.agent}
                        </td>
                        <td className="px-4 py-2.5">
                          <StatusBadge status={evt.decision} />
                        </td>
                        <td className="px-4 py-2.5 text-[#5a6a8a] text-right font-mono text-xs">
                          {evt.duration}
                        </td>
                        <td className="px-4 py-2.5 text-[#5a6a8a] text-right text-xs">
                          {evt.timestamp}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

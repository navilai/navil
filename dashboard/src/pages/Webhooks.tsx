import { useEffect, useState, useCallback } from 'react'
import {
  WEBHOOK_EVENTS,
  type WebhookEndpoint,
  type WebhookDelivery,
} from '../cloudApi'
import useCloudApi from '../hooks/useCloudApi'
import PageHeader from '../components/PageHeader'
import StatusBadge from '../components/StatusBadge'
import CloudError from '../components/CloudError'
import Icon from '../components/Icon'

export default function Webhooks() {
  const cloud = useCloudApi()
  const [webhooks, setWebhooks] = useState<WebhookEndpoint[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [deliveries, setDeliveries] = useState<Record<string, WebhookDelivery[]>>({})
  const [testing, setTesting] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)
  const [actionMsg, setActionMsg] = useState<{ ok: boolean; msg: string } | null>(null)

  // Create form
  const [newUrl, setNewUrl] = useState('')
  const [newEvents, setNewEvents] = useState<string[]>([])
  const [creating, setCreating] = useState(false)
  const [createdSecret, setCreatedSecret] = useState<string | null>(null)

  const fetchWebhooks = useCallback(() => {
    setLoading(true)
    setError('')
    cloud.listWebhooks()
      .then(setWebhooks)
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : 'Failed to load webhooks.')
      })
      .finally(() => setLoading(false))
  }, [cloud])

  useEffect(() => { fetchWebhooks() }, [fetchWebhooks])

  const fetchDeliveries = (webhookId: string) => {
    cloud.listDeliveries(webhookId)
      .then(d => setDeliveries(prev => ({ ...prev, [webhookId]: d })))
      .catch((e: unknown) => {
        setActionMsg({ ok: false, msg: e instanceof Error ? e.message : 'Failed to load deliveries.' })
      })
  }

  const handleExpand = (id: string) => {
    if (expandedId === id) {
      setExpandedId(null)
    } else {
      setExpandedId(id)
      if (!deliveries[id]) fetchDeliveries(id)
    }
  }

  const handleCreate = async () => {
    if (!newUrl.trim() || newEvents.length === 0) return
    setCreating(true)
    setActionMsg(null)
    try {
      const res = await cloud.createWebhook({ url: newUrl.trim(), events: newEvents })
      setCreatedSecret(res.secret)
      setActionMsg({ ok: true, msg: 'Webhook created. Copy the signing secret below — it will not be shown again.' })
      setNewUrl('')
      setNewEvents([])
      fetchWebhooks()
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setCreating(false)
    }
  }

  const handleToggleActive = async (wh: WebhookEndpoint) => {
    try {
      await cloud.updateWebhook(wh.id, { is_active: !wh.is_active })
      fetchWebhooks()
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    }
  }

  const handleTest = async (id: string) => {
    setTesting(id)
    setActionMsg(null)
    try {
      const res = await cloud.testWebhook(id)
      if (res.success) {
        setActionMsg({ ok: true, msg: `Test delivery successful (${res.http_status}, ${res.latency_ms}ms)` })
      } else {
        setActionMsg({ ok: false, msg: `Test delivery failed: ${res.error || `HTTP ${res.http_status}`}` })
      }
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setTesting(null)
    }
  }

  const handleDelete = async (id: string) => {
    setDeleting(id)
    setActionMsg(null)
    try {
      await cloud.deleteWebhook(id)
      setActionMsg({ ok: true, msg: 'Webhook deleted.' })
      if (expandedId === id) setExpandedId(null)
      fetchWebhooks()
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setDeleting(null)
    }
  }

  const toggleEvent = (event: string) => {
    setNewEvents(prev =>
      prev.includes(event) ? prev.filter(e => e !== event) : [...prev, event]
    )
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Webhooks" subtitle="Manage webhook integrations" />
        {[0, 1, 2].map(i => (
          <div key={i} className="skeleton h-20 rounded-xl" style={{ animationDelay: `${i * 0.1}s` }} />
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Webhooks" subtitle="Manage webhook integrations" />
        <CloudError message={error} onRetry={fetchWebhooks} />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Webhooks" subtitle={`${webhooks.length} webhook${webhooks.length !== 1 ? 's' : ''} configured`}>
        <button
          onClick={() => { setShowCreate(!showCreate); setCreatedSecret(null); setActionMsg(null) }}
          className="px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 flex items-center gap-2 transition-all duration-200"
        >
          <Icon name="activity" size={14} />
          {showCreate ? 'Cancel' : 'New Webhook'}
        </button>
      </PageHeader>

      {/* Create Form */}
      {showCreate && (
        <div className="glass-card p-6 animate-slideUp opacity-0 stagger-1">
          <h3 className="text-sm font-semibold text-[#f0f4fc] mb-5 flex items-center gap-2">
            <Icon name="globe" size={16} className="text-[#00e5c8]" />
            Create Webhook
          </h3>
          <div className="space-y-4">
            <div>
              <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Endpoint URL</label>
              <input
                value={newUrl}
                onChange={e => setNewUrl(e.target.value)}
                className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none font-mono transition-colors"
                placeholder="https://hooks.example.com/navil"
              />
              <p className="text-xs text-[#5a6a8a] mt-1">Must use HTTPS. No private/internal addresses.</p>
            </div>

            <div>
              <label className="block text-xs text-[#5a6a8a] font-medium mb-2">Events to subscribe</label>
              <div className="flex flex-wrap gap-2">
                {WEBHOOK_EVENTS.map(event => (
                  <button
                    key={event}
                    onClick={() => toggleEvent(event)}
                    className={`px-3 py-1.5 text-xs rounded-lg border font-medium transition-all duration-200 ${
                      newEvents.includes(event)
                        ? 'bg-[#00e5c8]/15 border-[#00e5c8]/40 text-[#00e5c8]'
                        : 'bg-[#111827] border-[#2a3650] text-[#8b9bc0] hover:border-[#5a6a8a] hover:text-[#f0f4fc]'
                    }`}
                  >
                    {event}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex gap-3 pt-1">
              <button
                onClick={handleCreate}
                disabled={!newUrl.trim() || newEvents.length === 0 || creating}
                className="px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
              >
                <Icon name="check" size={14} />
                {creating ? 'Creating...' : 'Create Webhook'}
              </button>
            </div>

            {/* Created secret display */}
            {createdSecret && (
              <div className="p-3 rounded-[12px] border bg-[#fbbf24]/5 border-[#fbbf24]/20 animate-fadeIn">
                <p className="text-xs text-[#fbbf24] font-medium mb-2 flex items-center gap-1.5">
                  <Icon name="warning" size={12} />
                  Signing Secret (copy now — shown only once)
                </p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-[#0d1117] border border-[#2a3650] rounded-lg px-3 py-2 text-sm font-mono text-[#f0f4fc] select-all">
                    {createdSecret}
                  </code>
                  <button
                    onClick={() => navigator.clipboard.writeText(createdSecret)}
                    className="px-3 py-2 bg-[#1a2235] border border-[#2a3650] rounded-lg text-[#8b9bc0] hover:text-[#f0f4fc] hover:border-[#5a6a8a] transition-all duration-200"
                  >
                    <Icon name="copy" size={14} />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Action messages */}
      {actionMsg && !showCreate && (
        <div className={`p-3 rounded-[12px] border animate-fadeIn ${
          actionMsg.ok ? 'bg-[#34d399]/5 border-[#34d399]/20' : 'bg-[#ff4d6a]/5 border-[#ff4d6a]/20'
        }`}>
          <p className={`text-sm flex items-center gap-2 ${actionMsg.ok ? 'text-[#34d399]' : 'text-[#ff4d6a]'}`}>
            <Icon name={actionMsg.ok ? 'check' : 'warning'} size={14} />
            {actionMsg.msg}
          </p>
        </div>
      )}

      {/* Webhook List */}
      {webhooks.length === 0 ? (
        <div className="text-center py-16 animate-fadeIn">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[#00e5c8]/10 border border-[#00e5c8]/20 mb-4">
            <Icon name="globe" size={32} className="text-[#00e5c8]" />
          </div>
          <p className="text-[#8b9bc0]">No webhooks configured yet.</p>
          <p className="text-xs text-[#5a6a8a] mt-1">Create one to receive real-time event notifications.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {webhooks.map((wh, i) => (
            <div
              key={wh.id}
              className="glass-card overflow-hidden animate-slideUp opacity-0"
              style={{ animationDelay: `${i * 0.03}s` }}
            >
              {/* Header row */}
              <div
                onClick={() => handleExpand(wh.id)}
                className="flex items-center gap-4 px-4 py-3 cursor-pointer hover:bg-[#1f2a40] transition-colors duration-200"
              >
                <StatusBadge status={wh.is_active ? 'ACTIVE' : wh.status === 'failed' ? 'REVOKED' : 'INACTIVE'} />
                <span className="text-sm text-[#f0f4fc] font-mono truncate flex-1">{wh.url}</span>
                <span className="text-xs text-[#5a6a8a]">
                  {wh.events.length} event{wh.events.length !== 1 ? 's' : ''}
                </span>
                {wh.success_rate !== null && (
                  <span className={`text-xs font-mono ${
                    wh.success_rate >= 0.95 ? 'text-[#34d399]' : wh.success_rate >= 0.8 ? 'text-[#fbbf24]' : 'text-[#ff4d6a]'
                  }`}>
                    {(wh.success_rate * 100).toFixed(0)}%
                  </span>
                )}
                <Icon
                  name="chevron-down"
                  size={16}
                  className={`text-[#5a6a8a] transition-transform duration-200 ${expandedId === wh.id ? 'rotate-0' : '-rotate-90'}`}
                />
              </div>

              {/* Expanded details */}
              <div
                className={`overflow-hidden transition-all duration-300 ease-out ${
                  expandedId === wh.id ? 'max-h-[600px] opacity-100' : 'max-h-0 opacity-0'
                }`}
              >
                <div className="px-4 pb-4 pt-2 border-t border-[#2a3650] space-y-4">
                  {/* Subscribed events */}
                  <div>
                    <p className="text-xs text-[#5a6a8a] font-medium uppercase tracking-wider mb-2">Subscribed Events</p>
                    <div className="flex flex-wrap gap-1.5">
                      {wh.events.map(ev => (
                        <span key={ev} className="px-2 py-0.5 text-[11px] font-mono bg-[#111827] text-[#8b9bc0] border border-[#2a3650] rounded">
                          {ev}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex gap-2">
                    <button
                      onClick={(e) => { e.stopPropagation(); handleToggleActive(wh) }}
                      className="px-3 py-1.5 text-xs bg-[#1a2235] text-[#8b9bc0] border border-[#2a3650] rounded-lg hover:border-[#5a6a8a] hover:text-[#f0f4fc] flex items-center gap-1.5 transition-all duration-200"
                    >
                      <Icon name={wh.is_active ? 'eye' : 'unlock'} size={12} />
                      {wh.is_active ? 'Pause' : 'Activate'}
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleTest(wh.id) }}
                      disabled={testing === wh.id}
                      className="px-3 py-1.5 text-xs bg-[#1a2235] text-[#8b9bc0] border border-[#2a3650] rounded-lg hover:border-[#5a6a8a] hover:text-[#f0f4fc] flex items-center gap-1.5 disabled:opacity-50 transition-all duration-200"
                    >
                      <Icon name="activity" size={12} className={testing === wh.id ? 'animate-spin' : ''} />
                      {testing === wh.id ? 'Testing...' : 'Test'}
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleDelete(wh.id) }}
                      disabled={deleting === wh.id}
                      className="px-3 py-1.5 text-xs bg-[#ff4d6a]/10 text-[#ff4d6a] border border-[#ff4d6a]/20 rounded-lg hover:bg-[#ff4d6a]/20 flex items-center gap-1.5 disabled:opacity-50 transition-all duration-200"
                    >
                      <Icon name="x" size={12} />
                      {deleting === wh.id ? 'Deleting...' : 'Delete'}
                    </button>
                  </div>

                  {/* Delivery log */}
                  <div>
                    <p className="text-xs text-[#5a6a8a] font-medium uppercase tracking-wider mb-2">Recent Deliveries</p>
                    {deliveries[wh.id] ? (
                      deliveries[wh.id].length === 0 ? (
                        <p className="text-xs text-[#5a6a8a]">No deliveries yet.</p>
                      ) : (
                        <div className="bg-[#111827] rounded-lg border border-[#2a3650] overflow-hidden">
                          <table className="w-full text-xs">
                            <thead>
                              <tr className="border-b border-[#2a3650] text-[#5a6a8a]">
                                <th className="text-left px-3 py-2 font-medium">Event</th>
                                <th className="text-left px-3 py-2 font-medium">Status</th>
                                <th className="text-left px-3 py-2 font-medium">HTTP</th>
                                <th className="text-left px-3 py-2 font-medium">Latency</th>
                                <th className="text-left px-3 py-2 font-medium">Time</th>
                              </tr>
                            </thead>
                            <tbody>
                              {deliveries[wh.id].slice(0, 10).map(d => (
                                <tr key={d.id} className="border-b border-[#2a3650]/50 hover:bg-[#1a2235] transition-colors">
                                  <td className="px-3 py-2 font-mono text-[#8b9bc0]">{d.event_type}</td>
                                  <td className="px-3 py-2">
                                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                                      d.status === 'delivered'
                                        ? 'bg-[#34d399]/15 text-[#34d399]'
                                        : 'bg-[#ff4d6a]/15 text-[#ff4d6a]'
                                    }`}>
                                      {d.status}
                                    </span>
                                  </td>
                                  <td className="px-3 py-2 font-mono text-[#8b9bc0]">{d.http_status || '\u2014'}</td>
                                  <td className="px-3 py-2 font-mono text-[#8b9bc0]">{d.latency_ms ? `${d.latency_ms}ms` : '\u2014'}</td>
                                  <td className="px-3 py-2 text-[#5a6a8a]">
                                    {new Date(d.created_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )
                    ) : (
                      <div className="skeleton h-16 rounded-lg" />
                    )}
                  </div>

                  {/* Metadata */}
                  <div className="flex gap-4 text-xs text-[#5a6a8a]">
                    <span>Created: {new Date(wh.created_at).toLocaleDateString()}</span>
                    <span>Updated: {new Date(wh.updated_at).toLocaleDateString()}</span>
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

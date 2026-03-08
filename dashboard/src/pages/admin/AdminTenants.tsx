import { useCallback, useEffect, useState } from 'react'
import { api, AdminTenant } from '../../api'
import PageHeader from '../../components/PageHeader'
import Icon from '../../components/Icon'
import RelativeTime from '../../components/RelativeTime'
import { SkeletonTable } from '../../components/Skeleton'

const planBadge: Record<string, string> = {
  free: 'text-gray-400 bg-gray-400/10',
  lite: 'text-blue-400 bg-blue-400/10',
  elite: 'text-purple-400 bg-purple-400/10',
}

const proxyStatusColor: Record<string, string> = {
  connected: 'bg-emerald-500',
  stale: 'bg-yellow-500',
  disconnected: 'bg-gray-600',
}

export default function AdminTenants() {
  const [tenants, setTenants] = useState<AdminTenant[]>([])
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const limit = 25

  const fetchTenants = useCallback(() => {
    setError('')
    setLoading(true)
    api.adminTenants(limit, page * limit, search)
      .then(res => {
        setTenants(res.tenants)
        setTotal(res.total)
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [page, search])

  useEffect(() => { fetchTenants() }, [fetchTenants])

  const openDetail = (userId: string) => {
    setSelected(userId)
    setDetail(null)
    api.adminTenantDetail(userId)
      .then(setDetail)
      .catch(e => setError(e.message))
  }

  return (
    <div>
      <PageHeader
        title="Tenants"
        subtitle={`${total} registered tenants`}
      />

      {/* Search */}
      <div className="mb-6">
        <div className="relative max-w-md">
          <Icon name="scan" size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0) }}
            placeholder="Search by user ID..."
            className="w-full pl-10 pr-4 py-2.5 bg-gray-900/40 border border-gray-800/60 rounded-lg text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50"
          />
        </div>
      </div>

      {error && (
        <div className="glass-card p-4 mb-6 border-red-500/20">
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {loading && !tenants.length ? (
        <SkeletonTable rows={8} />
      ) : (
        <>
          {/* Table */}
          <div className="glass-card overflow-hidden mb-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800/60">
                  <th className="text-left px-4 py-3 text-gray-500 font-medium">User ID</th>
                  <th className="text-left px-4 py-3 text-gray-500 font-medium">Plan</th>
                  <th className="text-right px-4 py-3 text-gray-500 font-medium">Events</th>
                  <th className="text-right px-4 py-3 text-gray-500 font-medium">Alerts</th>
                  <th className="text-right px-4 py-3 text-gray-500 font-medium">Keys</th>
                  <th className="text-center px-4 py-3 text-gray-500 font-medium">Proxy</th>
                  <th className="text-right px-4 py-3 text-gray-500 font-medium">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {tenants.map((t, i) => (
                  <tr
                    key={t.user_id}
                    className={`border-b border-gray-800/30 hover:bg-gray-800/20 cursor-pointer transition-colors ${
                      selected === t.user_id ? 'bg-cyan-500/5' : ''
                    }`}
                    style={{ animationDelay: `${i * 30}ms` }}
                    onClick={() => openDetail(t.user_id)}
                  >
                    <td className="px-4 py-3">
                      <span className="text-gray-200 font-mono text-xs">
                        {t.user_id.length > 24 ? t.user_id.slice(0, 24) + '...' : t.user_id}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded capitalize ${planBadge[t.plan] || planBadge.free}`}>
                        {t.plan}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right text-gray-300">{t.event_count.toLocaleString()}</td>
                    <td className="px-4 py-3 text-right text-gray-300">{t.alert_count.toLocaleString()}</td>
                    <td className="px-4 py-3 text-right text-gray-300">{t.api_key_count}</td>
                    <td className="px-4 py-3 text-center">
                      <div className="flex items-center justify-center gap-1.5">
                        <div className={`w-2 h-2 rounded-full ${proxyStatusColor[t.proxy_status]}`} />
                        <span className="text-xs text-gray-500 capitalize">{t.proxy_status}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right text-gray-500 text-xs">
                      {t.last_seen ? <RelativeTime timestamp={t.last_seen} /> : '\u2014'}
                    </td>
                  </tr>
                ))}
                {tenants.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-gray-500">
                      {search ? 'No tenants match your search' : 'No tenants registered yet'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {total > limit && (
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-500">
                Showing {page * limit + 1}\u2013{Math.min((page + 1) * limit, total)} of {total}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="px-3 py-1.5 text-sm bg-gray-800/60 rounded-lg text-gray-400 hover:text-gray-200 disabled:opacity-30"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage(p => p + 1)}
                  disabled={(page + 1) * limit >= total}
                  className="px-3 py-1.5 text-sm bg-gray-800/60 rounded-lg text-gray-400 hover:text-gray-200 disabled:opacity-30"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Tenant Detail Drawer */}
      {selected && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="absolute inset-0 bg-black/50" onClick={() => setSelected(null)} />
          <div className="relative w-full max-w-lg bg-gray-900/95 backdrop-blur-xl border-l border-gray-800/60 overflow-y-auto">
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold text-gray-200">Tenant Detail</h3>
                <button
                  onClick={() => setSelected(null)}
                  className="p-1.5 text-gray-500 hover:text-gray-300 rounded-lg hover:bg-gray-800/60"
                >
                  <Icon name="shield" size={18} />
                </button>
              </div>

              <div className="text-xs font-mono text-cyan-400 bg-cyan-400/10 px-3 py-1.5 rounded mb-6 break-all">
                {selected}
              </div>

              {!detail ? (
                <div className="space-y-3">
                  {[...Array(4)].map((_, i) => (
                    <div key={i} className="h-16 bg-gray-800/40 rounded-lg animate-pulse" />
                  ))}
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Recent Events */}
                  <DetailSection title="Recent Events" count={(detail.events as Array<Record<string, unknown>>)?.length || 0}>
                    {(detail.events as Array<Record<string, unknown>>)?.slice(0, 10).map((e, i) => (
                      <div key={i} className="flex justify-between text-xs py-1.5 border-b border-gray-800/30">
                        <span className="text-gray-300">{String(e.agent_name)} \u2192 {String(e.tool_name)}</span>
                        <span className="text-gray-500">{String(e.duration_ms)}ms</span>
                      </div>
                    ))}
                  </DetailSection>

                  {/* Recent Alerts */}
                  <DetailSection title="Recent Alerts" count={(detail.alerts as Array<Record<string, unknown>>)?.length || 0}>
                    {(detail.alerts as Array<Record<string, unknown>>)?.slice(0, 10).map((a, i) => (
                      <div key={i} className="flex justify-between text-xs py-1.5 border-b border-gray-800/30">
                        <span className="text-gray-300">{String(a.anomaly_type)}</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                          a.severity === 'CRITICAL' ? 'text-red-400 bg-red-400/10' :
                          a.severity === 'HIGH' ? 'text-orange-400 bg-orange-400/10' :
                          'text-yellow-400 bg-yellow-400/10'
                        }`}>
                          {String(a.severity)}
                        </span>
                      </div>
                    ))}
                  </DetailSection>

                  {/* API Keys */}
                  <DetailSection title="API Keys" count={(detail.api_keys as Array<Record<string, unknown>>)?.length || 0}>
                    {(detail.api_keys as Array<Record<string, unknown>>)?.map((k, i) => (
                      <div key={i} className="flex justify-between text-xs py-1.5 border-b border-gray-800/30">
                        <div>
                          <span className="text-gray-300 font-mono">{String(k.key_prefix)}...</span>
                          <span className="text-gray-500 ml-2">{String(k.name)}</span>
                        </div>
                        {Boolean(k.revoked) && <span className="text-red-400 text-[10px]">Revoked</span>}
                      </div>
                    ))}
                  </DetailSection>

                  {/* Heartbeats */}
                  <DetailSection title="Proxy Heartbeats" count={(detail.heartbeats as Array<Record<string, unknown>>)?.length || 0}>
                    {(detail.heartbeats as Array<Record<string, unknown>>)?.map((h, i) => (
                      <div key={i} className="flex justify-between text-xs py-1.5 border-b border-gray-800/30">
                        <span className="text-gray-300">v{String(h.proxy_version)}</span>
                        <span className="text-gray-500">
                          {h.last_seen_at ? <RelativeTime timestamp={String(h.last_seen_at)} /> : '\u2014'}
                        </span>
                      </div>
                    ))}
                  </DetailSection>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function DetailSection({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="text-sm font-medium text-gray-400 mb-2 flex items-center justify-between">
        {title}
        <span className="text-xs text-gray-600">{count} total</span>
      </h4>
      <div className="bg-gray-800/30 rounded-lg p-3">
        {count > 0 ? children : (
          <p className="text-xs text-gray-600 text-center py-2">None</p>
        )}
      </div>
    </div>
  )
}

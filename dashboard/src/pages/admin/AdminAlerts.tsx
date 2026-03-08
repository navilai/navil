import { useCallback, useEffect, useState } from 'react'
import { api, AdminAlert } from '../../api'
import PageHeader from '../../components/PageHeader'
import SeverityBadge from '../../components/SeverityBadge'
import RelativeTime from '../../components/RelativeTime'
import Icon from '../../components/Icon'
import { SkeletonTable } from '../../components/Skeleton'

const severityOptions = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function AdminAlerts() {
  const [alerts, setAlerts] = useState<AdminAlert[]>([])
  const [total, setTotal] = useState(0)
  const [severity, setSeverity] = useState('ALL')
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const limit = 50

  const fetchAlerts = useCallback(() => {
    setError('')
    setLoading(true)
    api.adminAlerts(severity === 'ALL' ? undefined : severity, limit, page * limit)
      .then(res => {
        setAlerts(res.alerts)
        setTotal(res.total)
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [severity, page])

  useEffect(() => { fetchAlerts() }, [fetchAlerts])

  return (
    <div>
      <PageHeader
        title="Global Alerts"
        subtitle={`${total.toLocaleString()} alerts across all tenants`}
      />

      {/* Severity filter */}
      <div className="flex gap-2 mb-6">
        {severityOptions.map(sev => (
          <button
            key={sev}
            onClick={() => { setSeverity(sev); setPage(0) }}
            className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
              severity === sev
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'bg-gray-800/40 text-gray-500 border border-gray-800/60 hover:text-gray-300'
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {error && (
        <div className="glass-card p-4 mb-6 border-red-500/20">
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {loading && !alerts.length ? (
        <SkeletonTable rows={10} />
      ) : (
        <>
          <div className="glass-card overflow-hidden mb-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800/60">
                  <th className="text-left px-4 py-3 text-gray-500 font-medium">Severity</th>
                  <th className="text-left px-4 py-3 text-gray-500 font-medium">Tenant</th>
                  <th className="text-left px-4 py-3 text-gray-500 font-medium">Agent</th>
                  <th className="text-left px-4 py-3 text-gray-500 font-medium">Type</th>
                  <th className="text-right px-4 py-3 text-gray-500 font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a, i) => (
                  <tr
                    key={a.id}
                    className="border-b border-gray-800/30 hover:bg-gray-800/20 transition-colors"
                    style={{ animationDelay: `${i * 20}ms` }}
                  >
                    <td className="px-4 py-3">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-gray-400 font-mono text-xs">
                        {a.user_id.length > 16 ? a.user_id.slice(0, 16) + '...' : a.user_id}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-300">{a.agent_name}</td>
                    <td className="px-4 py-3">
                      <span className="text-xs text-gray-400 bg-gray-800/40 px-2 py-0.5 rounded">
                        {a.anomaly_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right text-gray-500 text-xs">
                      {a.created_at ? <RelativeTime timestamp={a.created_at} /> : '\u2014'}
                    </td>
                  </tr>
                ))}
                {alerts.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-12 text-center text-gray-500">
                      No alerts found
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
    </div>
  )
}

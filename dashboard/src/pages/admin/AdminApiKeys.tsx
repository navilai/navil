import { useCallback, useEffect, useState } from 'react'
import { api, AdminApiKey } from '../../api'
import PageHeader from '../../components/PageHeader'
import Icon from '../../components/Icon'
import RelativeTime from '../../components/RelativeTime'
import { SkeletonTable } from '../../components/Skeleton'

export default function AdminApiKeys() {
  const [keys, setKeys] = useState<AdminApiKey[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const limit = 50

  const fetchKeys = useCallback(() => {
    setError('')
    setLoading(true)
    api.adminApiKeys(limit, page * limit)
      .then(res => {
        setKeys(res.keys)
        setTotal(res.total)
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [page])

  useEffect(() => { fetchKeys() }, [fetchKeys])

  const handleRevoke = (keyId: number) => {
    if (!confirm('Revoke this API key? The tenant will lose access.')) return
    api.adminRevokeApiKey(keyId)
      .then(() => fetchKeys())
      .catch(e => setError(e.message))
  }

  return (
    <div>
      <PageHeader
        title="API Keys"
        subtitle={`${total} keys across all tenants`}
      />

      {error && (
        <div className="glass-card p-4 mb-6 border-red-500/20">
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {loading && !keys.length ? (
        <SkeletonTable rows={10} />
      ) : (
        <>
          <div className="glass-card overflow-hidden mb-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800/60">
                  <th className="text-left px-4 py-3 text-gray-500 font-medium">Key</th>
                  <th className="text-left px-4 py-3 text-gray-500 font-medium">Tenant</th>
                  <th className="text-left px-4 py-3 text-gray-500 font-medium">Name</th>
                  <th className="text-center px-4 py-3 text-gray-500 font-medium">Status</th>
                  <th className="text-right px-4 py-3 text-gray-500 font-medium">Last Used</th>
                  <th className="text-right px-4 py-3 text-gray-500 font-medium">Created</th>
                  <th className="text-right px-4 py-3 text-gray-500 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k, i) => (
                  <tr
                    key={k.id}
                    className={`border-b border-gray-800/30 hover:bg-gray-800/20 transition-colors ${
                      k.revoked ? 'opacity-50' : ''
                    }`}
                    style={{ animationDelay: `${i * 20}ms` }}
                  >
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-cyan-400">{k.key_prefix}...</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-gray-400 font-mono text-xs">
                        {k.user_id.length > 16 ? k.user_id.slice(0, 16) + '...' : k.user_id}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-300">{k.name}</td>
                    <td className="px-4 py-3 text-center">
                      {k.revoked ? (
                        <span className="text-xs text-red-400 bg-red-400/10 px-2 py-0.5 rounded">Revoked</span>
                      ) : (
                        <span className="text-xs text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded">Active</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right text-gray-500 text-xs">
                      {k.last_used_at ? <RelativeTime timestamp={k.last_used_at} /> : 'Never'}
                    </td>
                    <td className="px-4 py-3 text-right text-gray-500 text-xs">
                      {k.created_at ? <RelativeTime timestamp={k.created_at} /> : '\u2014'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {!k.revoked && (
                        <button
                          onClick={() => handleRevoke(k.id)}
                          className="text-xs text-red-400 hover:text-red-300 px-2 py-1 rounded hover:bg-red-400/10 transition-colors"
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {keys.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-gray-500">
                      No API keys found
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

import { useCallback, useEffect, useState } from 'react'
import { api, AdminSystem as AdminSystemType } from '../../api'
import PageHeader from '../../components/PageHeader'
import Icon from '../../components/Icon'
import { SkeletonCard } from '../../components/Skeleton'

export default function AdminSystem() {
  const [data, setData] = useState<AdminSystemType | null>(null)
  const [error, setError] = useState('')

  const fetchData = useCallback(() => {
    setError('')
    api.adminSystem()
      .then(setData)
      .catch(e => setError(e.message))
  }, [])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 15_000)
    return () => clearInterval(id)
  }, [fetchData])

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="glass-card p-6 text-center max-w-md">
          <Icon name="alert" size={32} className="text-red-400 mx-auto mb-3" />
          <p className="text-red-400 mb-3">{error}</p>
          <button onClick={fetchData} className="btn-primary text-sm">Retry</button>
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div>
        <PageHeader title="System Health" subtitle="Infrastructure monitoring" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {[...Array(4)].map((_, i) => <SkeletonCard key={i} />)}
        </div>
      </div>
    )
  }

  return (
    <div>
      <PageHeader title="System Health" subtitle="Infrastructure monitoring" />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Database */}
        <ServiceCard
          title="Database"
          icon="chart"
          status={data.database.status === 'connected' ? 'healthy' : 'error'}
          items={[
            { label: 'Status', value: data.database.status },
            { label: 'URL', value: data.database.url || 'N/A' },
            ...(data.database.error ? [{ label: 'Error', value: data.database.error, isError: true }] : []),
          ]}
        />

        {/* Redis */}
        <ServiceCard
          title="Redis"
          icon="activity"
          status={data.redis.status === 'connected' ? 'healthy' : data.redis.status === 'not_configured' ? 'warning' : 'error'}
          items={[
            { label: 'Status', value: data.redis.status },
            ...(data.redis.url ? [{ label: 'URL', value: data.redis.url }] : []),
            ...(data.redis.used_memory_mb != null ? [{ label: 'Memory', value: `${data.redis.used_memory_mb} MB` }] : []),
            ...(data.redis.error ? [{ label: 'Error', value: data.redis.error, isError: true }] : []),
          ]}
        />

        {/* Scheduler */}
        <ServiceCard
          title="Background Scheduler"
          icon="settings"
          status={data.scheduler.status === 'running' ? 'healthy' : 'error'}
          items={[
            { label: 'Status', value: data.scheduler.status },
            { label: 'Jobs', value: 'Metrics (5m), Trends (1h), Eviction (10m), Digest (1h)' },
          ]}
        />

        {/* LLM */}
        <ServiceCard
          title="LLM Engine"
          icon="sparkles"
          status={data.llm.available && data.llm.api_key_set ? 'healthy' : data.llm.available ? 'warning' : 'error'}
          items={[
            { label: 'Available', value: data.llm.available ? 'Yes' : 'No (install navil[llm])' },
            { label: 'Provider', value: data.llm.provider || 'None' },
            { label: 'Model', value: data.llm.model || 'None' },
            { label: 'API Key', value: data.llm.api_key_set ? 'Configured' : 'Not set' },
            ...(data.llm.base_url ? [{ label: 'Base URL', value: data.llm.base_url }] : []),
          ]}
        />
      </div>

      {/* Tenant Detectors */}
      <div className="glass-card p-6 mb-6">
        <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
          <Icon name="bot" size={16} className="text-gray-500" />
          Tenant Detector Cache
        </h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-xs text-gray-500 mb-1">Active Detectors</p>
            <p className="text-2xl font-bold text-cyan-400">{data.tenant_detectors.active}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 mb-1">Max Capacity</p>
            <p className="text-2xl font-bold text-gray-400">{data.tenant_detectors.max_size.toLocaleString()}</p>
          </div>
        </div>
        <div className="mt-3">
          <div className="h-2 bg-gray-800/60 rounded-full overflow-hidden">
            <div
              className="h-full bg-cyan-500/60 rounded-full transition-all duration-500"
              style={{ width: `${Math.min(100, (data.tenant_detectors.active / data.tenant_detectors.max_size) * 100)}%` }}
            />
          </div>
          <p className="text-xs text-gray-600 mt-1">
            {((data.tenant_detectors.active / data.tenant_detectors.max_size) * 100).toFixed(1)}% utilized
          </p>
        </div>
      </div>

      {/* Environment Configuration */}
      <div className="glass-card p-6">
        <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
          <Icon name="key" size={16} className="text-gray-500" />
          Environment Configuration
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <EnvRow label="Clerk Auth" configured={data.environment.clerk_configured} />
          <EnvRow label="Stripe Billing" configured={data.environment.stripe_configured} />
          <EnvRow label="Resend Email" configured={data.environment.resend_configured} />
          <EnvRow label="Admin IDs" configured={data.environment.admin_ids_set} />
          <EnvRow label="Proxy" configured={data.proxy_running} detail={data.proxy_running ? 'Running' : 'Not started'} />
          <EnvRow label="Stripe Billing" configured={data.stripe_enabled} detail={data.stripe_enabled ? 'Active' : 'Disabled'} />
        </div>
      </div>
    </div>
  )
}

function ServiceCard({
  title,
  icon,
  status,
  items,
}: {
  title: string
  icon: string
  status: 'healthy' | 'warning' | 'error'
  items: { label: string; value: string; isError?: boolean }[]
}) {
  const statusColor = status === 'healthy' ? 'bg-emerald-500' : status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
  const borderColor = status === 'healthy' ? 'border-emerald-500/20' : status === 'warning' ? 'border-yellow-500/20' : 'border-red-500/20'

  return (
    <div className={`glass-card p-6 border ${borderColor}`}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium text-gray-300 flex items-center gap-2">
          <Icon name={icon as any} size={16} className="text-gray-500" />
          {title}
        </h3>
        <div className={`w-2.5 h-2.5 rounded-full ${statusColor}`} />
      </div>
      <div className="space-y-2">
        {items.map(({ label, value, isError }) => (
          <div key={label} className="flex justify-between text-sm">
            <span className="text-gray-500">{label}</span>
            <span className={`${isError ? 'text-red-400' : 'text-gray-300'} text-xs max-w-[200px] truncate`}>
              {value}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function EnvRow({ label, configured, detail }: { label: string; configured: boolean; detail?: string }) {
  return (
    <div className="flex items-center justify-between bg-gray-800/30 rounded-lg px-3 py-2.5">
      <span className="text-sm text-gray-300">{label}</span>
      <div className="flex items-center gap-2">
        {detail && <span className="text-xs text-gray-500">{detail}</span>}
        <div className={`w-2 h-2 rounded-full ${configured ? 'bg-emerald-500' : 'bg-gray-600'}`} />
      </div>
    </div>
  )
}

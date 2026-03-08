import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, AdminOverview as AdminOverviewType, AdminThroughput, AdminBilling } from '../../api'
import StatCard from '../../components/StatCard'
import PageHeader from '../../components/PageHeader'
import Icon from '../../components/Icon'
import { SkeletonCard } from '../../components/Skeleton'

const planColors: Record<string, string> = {
  free: 'text-gray-400',
  lite: 'text-blue-400',
  elite: 'text-purple-400',
}

export default function AdminOverview() {
  const [data, setData] = useState<AdminOverviewType | null>(null)
  const [throughput, setThroughput] = useState<AdminThroughput | null>(null)
  const [billing, setBilling] = useState<AdminBilling | null>(null)
  const [error, setError] = useState('')

  const fetchData = useCallback(() => {
    setError('')
    Promise.all([
      api.adminOverview(),
      api.adminThroughput(24),
      api.adminBilling(),
    ])
      .then(([overview, tp, bill]) => {
        setData(overview)
        setThroughput(tp)
        setBilling(bill)
      })
      .catch(e => setError(e.message))
  }, [])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 30_000)
    return () => clearInterval(id)
  }, [fetchData])

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="glass-card p-6 text-center max-w-md">
          <Icon name="alert" size={32} className="text-red-400 mx-auto mb-3" />
          <p className="text-red-400 mb-3">{error}</p>
          <button onClick={fetchData} className="btn-primary text-sm">
            Retry
          </button>
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div>
        <PageHeader
          title="Admin Overview"
          subtitle="Navil Cloud operator dashboard"
        />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {[...Array(8)].map((_, i) => <SkeletonCard key={i} />)}
        </div>
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        title="Admin Overview"
        subtitle="Navil Cloud operator dashboard"
      />

      {/* KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Total Tenants"
          value={data.total_tenants}
          icon="bot"
          accent="cyan"
        />
        <StatCard
          label="Connected Proxies"
          value={data.connected_proxies}
          icon="gateway"
          accent="emerald"
        />
        <StatCard
          label="Events (1h)"
          value={data.events_last_hour}
          icon="activity"
          accent="blue"
        />
        <StatCard
          label="Alerts (1h)"
          value={data.alerts_last_hour}
          icon="alert"
          accent="amber"
        />
        <StatCard
          label="Total Events"
          value={data.total_events}
          icon="chart"
          accent="blue"
        />
        <StatCard
          label="Total Alerts"
          value={data.total_alerts}
          icon="alert"
          accent="orange"
        />
        <StatCard
          label="Critical (24h)"
          value={data.critical_alerts_24h}
          icon="alert"
          accent="red"
        />
        <StatCard
          label="Active API Keys"
          value={data.total_api_keys}
          icon="key"
          accent="purple"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* System Status */}
        <div className="glass-card p-6">
          <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
            <Icon name="settings" size={16} className="text-gray-500" />
            System Status
          </h3>
          <div className="space-y-3">
            <StatusRow
              label="Database"
              status={data.total_events >= 0}
              detail={`${data.total_events.toLocaleString()} events stored`}
            />
            <StatusRow
              label="Redis"
              status={data.redis_configured}
              detail={data.redis_configured ? 'Connected' : 'In-memory fallback'}
            />
            <StatusRow
              label="Scheduler"
              status={data.scheduler_running}
              detail={data.scheduler_running ? 'Running' : 'Stopped'}
            />
            <StatusRow
              label="LLM"
              status={data.llm_available}
              detail={data.llm_available ? `${data.llm_provider} / ${data.llm_model}` : 'Not configured'}
            />
            <StatusRow
              label="Stripe"
              status={data.stripe_enabled}
              detail={data.stripe_enabled ? 'Active' : 'Not configured'}
            />
            <StatusRow
              label="Tenant Detectors"
              status={true}
              detail={`${data.tenant_detectors_active} active`}
            />
          </div>
          <div className="mt-4 pt-4 border-t border-gray-800/60">
            <Link
              to="/admin/system"
              className="text-sm text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              View system details <Icon name="chart" size={14} />
            </Link>
          </div>
        </div>

        {/* Plan Distribution */}
        {billing && (
          <div className="glass-card p-6">
            <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
              <Icon name="chart" size={16} className="text-gray-500" />
              Plan Distribution
            </h3>
            <div className="space-y-4">
              {Object.entries(billing.plan_distribution).map(([plan, count]) => {
                const pct = billing.total_users > 0
                  ? Math.round((count / billing.total_users) * 100)
                  : 0
                return (
                  <div key={plan}>
                    <div className="flex justify-between text-sm mb-1">
                      <span className={`font-medium capitalize ${planColors[plan] || 'text-gray-400'}`}>
                        {plan}
                      </span>
                      <span className="text-gray-500">{count} users ({pct}%)</span>
                    </div>
                    <div className="h-2 bg-gray-800/60 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          plan === 'elite' ? 'bg-purple-500' :
                          plan === 'lite' ? 'bg-blue-500' : 'bg-gray-600'
                        }`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
            <div className="mt-4 pt-4 border-t border-gray-800/60 flex justify-between text-sm">
              <span className="text-gray-500">Total users</span>
              <span className="text-gray-300 font-medium">{billing.total_users}</span>
            </div>
          </div>
        )}
      </div>

      {/* Throughput Chart (simple bar representation) */}
      {throughput && throughput.events.length > 0 && (
        <div className="glass-card p-6">
          <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
            <Icon name="activity" size={16} className="text-gray-500" />
            Ingestion Throughput (24h)
          </h3>
          <div className="flex items-end gap-1 h-32">
            {throughput.events.map((pt, i) => {
              const max = Math.max(...throughput.events.map(p => p.count), 1)
              const h = Math.max(4, (pt.count / max) * 100)
              const hour = pt.hour.split(' ')[1] || pt.hour
              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1" title={`${pt.hour}: ${pt.count} events`}>
                  <div
                    className="w-full bg-cyan-500/60 rounded-t hover:bg-cyan-400/80 transition-colors"
                    style={{ height: `${h}%` }}
                  />
                  {i % 4 === 0 && (
                    <span className="text-[10px] text-gray-600">{hour}</span>
                  )}
                </div>
              )
            })}
          </div>
          <div className="flex justify-between mt-3 text-xs text-gray-500">
            <span>Total: {throughput.events.reduce((s, p) => s + p.count, 0).toLocaleString()} events</span>
            <span>{throughput.alerts.reduce((s, p) => s + p.count, 0).toLocaleString()} alerts</span>
          </div>
        </div>
      )}
    </div>
  )
}

function StatusRow({ label, status, detail }: { label: string; status: boolean; detail: string }) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full ${status ? 'bg-emerald-500' : 'bg-gray-600'}`} />
        <span className="text-sm text-gray-300">{label}</span>
      </div>
      <span className="text-xs text-gray-500">{detail}</span>
    </div>
  )
}

import { useEffect, useState, useCallback } from 'react'
import { type OrgProfile, PLANS } from '../cloudApi'
import useCloudApi from '../hooks/useCloudApi'
import PageHeader from '../components/PageHeader'
import StatCard from '../components/StatCard'
import CloudError from '../components/CloudError'
import Icon from '../components/Icon'

export default function Billing() {
  const cloud = useCloudApi()
  const [org, setOrg] = useState<OrgProfile | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [upgrading, setUpgrading] = useState<string | null>(null)
  const [portalLoading, setPortalLoading] = useState(false)
  const [interval, setInterval] = useState<'monthly' | 'annual'>('monthly')
  const [actionMsg, setActionMsg] = useState<{ ok: boolean; msg: string } | null>(null)

  const fetchOrg = useCallback(() => {
    setLoading(true)
    setError('')
    cloud.getOrgProfile()
      .then(setOrg)
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : 'Failed to load billing data.')
      })
      .finally(() => setLoading(false))
  }, [cloud])

  useEffect(() => { fetchOrg() }, [fetchOrg])

  const handleUpgrade = async (tier: string) => {
    setUpgrading(tier)
    setActionMsg(null)
    try {
      const res = await cloud.createCheckout(tier, interval)
      if (res.upgraded) {
        setActionMsg({ ok: true, msg: `Successfully upgraded to ${tier}!` })
        fetchOrg()
      } else if (res.url) {
        window.open(res.url, '_blank')
      }
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setUpgrading(null)
    }
  }

  const handleManageBilling = async () => {
    setPortalLoading(true)
    setActionMsg(null)
    try {
      const res = await cloud.createPortal()
      window.open(res.url, '_blank')
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setPortalLoading(false)
    }
  }

  const currentTierIndex = PLANS.findIndex(p => p.tier === org?.tier)

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Billing" subtitle="Manage your subscription" />
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[0, 1, 2].map(i => (
            <div key={i} className="skeleton h-24 rounded-xl" style={{ animationDelay: `${i * 0.1}s` }} />
          ))}
        </div>
        <div className="skeleton h-64 rounded-xl" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Billing" subtitle="Manage your subscription" />
        <CloudError message={error} onRetry={fetchOrg} />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Billing" subtitle="Manage your subscription">
        {org?.tier !== 'community' && (
          <button
            onClick={handleManageBilling}
            disabled={portalLoading}
            className="px-4 py-2.5 bg-surface text-ink border border-rule rounded-lg text-sm font-medium hover:bg-surface-elevated hover:border-ink-muted hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
          >
            <Icon name="external-link" size={14} />
            {portalLoading ? 'Opening...' : 'Manage Billing'}
          </button>
        )}
      </PageHeader>

      {/* Current Plan */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-1">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-sm font-semibold text-ink flex items-center gap-2">
            <Icon name="star" size={16} className="text-signal-amber" />
            Current Plan
          </h3>
          <span className="px-3 py-1 text-xs font-semibold rounded-full bg-signal-cyan/10 text-signal-cyan border border-signal-cyan/20 uppercase tracking-wider">
            {org?.tier || 'community'}
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <StatCard label="Active Agents" value={org?.api_key_count || 0} icon="bot" accent="cyan" index={0} />
          <StatCard label="Team Members" value={org?.user_count || 0} icon="users" accent="emerald" index={1} />
          <StatCard label="Plan" value={PLANS.find(p => p.tier === org?.tier)?.name || 'Community'} icon="shield" accent="amber" index={2} />
        </div>
      </div>

      {/* Interval Toggle */}
      <div className="flex items-center justify-center gap-3 animate-slideUp opacity-0 stagger-2">
        <span className={`text-sm ${interval === 'monthly' ? 'text-ink font-semibold' : 'text-ink-muted'}`}>Monthly</span>
        <button
          onClick={() => setInterval(i => i === 'monthly' ? 'annual' : 'monthly')}
          className={`relative w-11 h-6 rounded-full transition-colors duration-200 ${
            interval === 'annual' ? 'bg-signal-cyan' : 'bg-rule'
          }`}
        >
          <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform duration-200 ${
            interval === 'annual' ? 'translate-x-5' : 'translate-x-0'
          }`} />
        </button>
        <span className={`text-sm ${interval === 'annual' ? 'text-ink font-semibold' : 'text-ink-muted'}`}>
          Annual
          <span className="ml-1.5 px-1.5 py-0.5 text-[10px] font-semibold rounded bg-signal-green/10 text-signal-green border border-signal-green/20">
            Save 17%
          </span>
        </span>
      </div>

      {/* Plan Comparison */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 animate-slideUp opacity-0 stagger-3">
        {PLANS.map((plan, i) => {
          const isCurrent = plan.tier === org?.tier
          const isDowngrade = i < currentTierIndex
          return (
            <div
              key={plan.tier}
              className={`glass-card p-5 flex flex-col transition-all duration-200 hover:-translate-y-0.5 ${
                plan.highlighted ? 'border-signal-cyan/40 ring-1 ring-signal-cyan/20' : ''
              } ${isCurrent ? 'border-signal-cyan/60' : ''}`}
            >
              {plan.highlighted && (
                <div className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-signal-cyan/10 text-signal-cyan border border-signal-cyan/20 self-start mb-3 uppercase tracking-wider">
                  Most Popular
                </div>
              )}
              <h4 className="text-lg font-bold text-ink">{plan.name}</h4>
              <p className="text-2xl font-extrabold text-ink mt-2">
                {interval === 'monthly' ? plan.price : plan.annualPrice}
              </p>
              <div className="mt-4 space-y-2 text-sm flex-1">
                <div className="flex justify-between text-ink-secondary">
                  <span>Agents</span>
                  <span className="font-mono text-ink">{plan.agents}</span>
                </div>
                <div className="flex justify-between text-ink-secondary">
                  <span>Requests</span>
                  <span className="font-mono text-ink">{plan.requests}</span>
                </div>
                <div className="border-t border-rule pt-2 mt-3">
                  {plan.features.map(f => (
                    <p key={f} className="text-ink-secondary flex items-center gap-2 py-0.5">
                      <Icon name="check" size={12} className="text-signal-green shrink-0" />
                      {f}
                    </p>
                  ))}
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-rule">
                {isCurrent ? (
                  <div className="px-4 py-2.5 text-center text-sm font-semibold text-signal-cyan bg-signal-cyan/10 rounded-lg border border-signal-cyan/20">
                    Current Plan
                  </div>
                ) : plan.tier === 'enterprise' ? (
                  <a
                    href="mailto:sales@navil.ai"
                    className="block px-4 py-2.5 text-center text-sm font-semibold text-ink bg-surface border border-rule rounded-lg hover:bg-surface-elevated hover:border-ink-muted transition-all duration-200"
                  >
                    Contact Sales
                  </a>
                ) : isDowngrade ? (
                  <button
                    disabled
                    className="w-full px-4 py-2.5 text-sm font-medium text-ink-muted bg-surface rounded-lg border border-rule cursor-not-allowed"
                  >
                    Downgrade
                  </button>
                ) : (
                  <button
                    onClick={() => handleUpgrade(plan.tier)}
                    disabled={upgrading === plan.tier}
                    className="w-full px-4 py-2.5 bg-signal-cyan text-bg rounded-lg text-sm font-semibold hover:bg-signal-cyan hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-all duration-200"
                  >
                    {upgrading === plan.tier ? (
                      <>
                        <Icon name="activity" size={14} className="animate-spin" />
                        Processing...
                      </>
                    ) : (
                      <>
                        <Icon name="arrow-up" size={14} />
                        Upgrade
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Action messages */}
      {actionMsg && (
        <div className={`p-3 rounded-[12px] border animate-fadeIn ${
          actionMsg.ok ? 'bg-signal-green/5 border-signal-green/20' : 'bg-signal-red/5 border-signal-red/20'
        }`}>
          <p className={`text-sm flex items-center gap-2 ${actionMsg.ok ? 'text-signal-green' : 'text-signal-red'}`}>
            <Icon name={actionMsg.ok ? 'check' : 'warning'} size={14} />
            {actionMsg.msg}
          </p>
        </div>
      )}

      {/* Usage note */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-4">
        <h3 className="text-sm font-semibold text-ink mb-3 flex items-center gap-2">
          <Icon name="info" size={16} className="text-ink-secondary" />
          Billing Details
        </h3>
        <div className="space-y-2 text-sm">
          <p className="text-ink-secondary">
            Your subscription is managed through Stripe. Click "Manage Billing" to view invoices,
            update payment methods, or cancel your subscription.
          </p>
          <p className="text-ink-muted text-xs flex items-center gap-1.5">
            <Icon name="lock" size={10} className="text-ink-muted" />
            Payment data is handled securely by Stripe. Navil never stores your card details.
          </p>
        </div>
      </div>
    </div>
  )
}

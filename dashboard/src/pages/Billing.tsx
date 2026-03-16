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
            className="px-4 py-2.5 bg-[#1a2235] text-[#f0f4fc] border border-[#2a3650] rounded-lg text-sm font-medium hover:bg-[#1f2a40] hover:border-[#5a6a8a] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
          >
            <Icon name="external-link" size={14} />
            {portalLoading ? 'Opening...' : 'Manage Billing'}
          </button>
        )}
      </PageHeader>

      {/* Current Plan */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-1">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-sm font-semibold text-[#f0f4fc] flex items-center gap-2">
            <Icon name="star" size={16} className="text-[#fbbf24]" />
            Current Plan
          </h3>
          <span className="px-3 py-1 text-xs font-semibold rounded-full bg-[#00e5c8]/10 text-[#00e5c8] border border-[#00e5c8]/20 uppercase tracking-wider">
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
        <span className={`text-sm ${interval === 'monthly' ? 'text-[#f0f4fc] font-semibold' : 'text-[#5a6a8a]'}`}>Monthly</span>
        <button
          onClick={() => setInterval(i => i === 'monthly' ? 'annual' : 'monthly')}
          className={`relative w-11 h-6 rounded-full transition-colors duration-200 ${
            interval === 'annual' ? 'bg-[#00e5c8]' : 'bg-[#2a3650]'
          }`}
        >
          <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform duration-200 ${
            interval === 'annual' ? 'translate-x-5' : 'translate-x-0'
          }`} />
        </button>
        <span className={`text-sm ${interval === 'annual' ? 'text-[#f0f4fc] font-semibold' : 'text-[#5a6a8a]'}`}>
          Annual
          <span className="ml-1.5 px-1.5 py-0.5 text-[10px] font-semibold rounded bg-[#34d399]/10 text-[#34d399] border border-[#34d399]/20">
            Save 17%
          </span>
        </span>
      </div>

      {/* Plan Comparison */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 animate-slideUp opacity-0 stagger-3">
        {PLANS.map((plan, i) => {
          const isCurrent = plan.tier === org?.tier
          const isDowngrade = i < currentTierIndex
          return (
            <div
              key={plan.tier}
              className={`glass-card p-5 flex flex-col transition-all duration-200 hover:-translate-y-0.5 ${
                plan.highlighted ? 'border-[#00e5c8]/40 ring-1 ring-[#00e5c8]/20' : ''
              } ${isCurrent ? 'border-[#00e5c8]/60' : ''}`}
            >
              {plan.highlighted && (
                <div className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-[#00e5c8]/10 text-[#00e5c8] border border-[#00e5c8]/20 self-start mb-3 uppercase tracking-wider">
                  Most Popular
                </div>
              )}
              <h4 className="text-lg font-bold text-[#f0f4fc]">{plan.name}</h4>
              <p className="text-2xl font-extrabold text-[#f0f4fc] mt-2">
                {interval === 'monthly' ? plan.price : plan.annualPrice}
              </p>
              <div className="mt-4 space-y-2 text-sm flex-1">
                <div className="flex justify-between text-[#8b9bc0]">
                  <span>Agents</span>
                  <span className="font-mono text-[#f0f4fc]">{plan.agents}</span>
                </div>
                <div className="flex justify-between text-[#8b9bc0]">
                  <span>Requests</span>
                  <span className="font-mono text-[#f0f4fc]">{plan.requests}</span>
                </div>
                <div className="border-t border-[#2a3650] pt-2 mt-3">
                  {plan.features.map(f => (
                    <p key={f} className="text-[#8b9bc0] flex items-center gap-2 py-0.5">
                      <Icon name="check" size={12} className="text-[#34d399] shrink-0" />
                      {f}
                    </p>
                  ))}
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-[#2a3650]">
                {isCurrent ? (
                  <div className="px-4 py-2.5 text-center text-sm font-semibold text-[#00e5c8] bg-[#00e5c8]/10 rounded-lg border border-[#00e5c8]/20">
                    Current Plan
                  </div>
                ) : plan.tier === 'enterprise' ? (
                  <a
                    href="mailto:sales@navil.ai"
                    className="block px-4 py-2.5 text-center text-sm font-semibold text-[#f0f4fc] bg-[#1a2235] border border-[#2a3650] rounded-lg hover:bg-[#1f2a40] hover:border-[#5a6a8a] transition-all duration-200"
                  >
                    Contact Sales
                  </a>
                ) : isDowngrade ? (
                  <button
                    disabled
                    className="w-full px-4 py-2.5 text-sm font-medium text-[#5a6a8a] bg-[#111827] rounded-lg border border-[#2a3650] cursor-not-allowed"
                  >
                    Downgrade
                  </button>
                ) : (
                  <button
                    onClick={() => handleUpgrade(plan.tier)}
                    disabled={upgrading === plan.tier}
                    className="w-full px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-all duration-200"
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
          actionMsg.ok ? 'bg-[#34d399]/5 border-[#34d399]/20' : 'bg-[#ff4d6a]/5 border-[#ff4d6a]/20'
        }`}>
          <p className={`text-sm flex items-center gap-2 ${actionMsg.ok ? 'text-[#34d399]' : 'text-[#ff4d6a]'}`}>
            <Icon name={actionMsg.ok ? 'check' : 'warning'} size={14} />
            {actionMsg.msg}
          </p>
        </div>
      )}

      {/* Usage note */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-4">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-3 flex items-center gap-2">
          <Icon name="info" size={16} className="text-[#8b9bc0]" />
          Billing Details
        </h3>
        <div className="space-y-2 text-sm">
          <p className="text-[#8b9bc0]">
            Your subscription is managed through Stripe. Click "Manage Billing" to view invoices,
            update payment methods, or cancel your subscription.
          </p>
          <p className="text-[#5a6a8a] text-xs flex items-center gap-1.5">
            <Icon name="lock" size={10} className="text-[#5a6a8a]" />
            Payment data is handled securely by Stripe. Navil never stores your card details.
          </p>
        </div>
      </div>
    </div>
  )
}

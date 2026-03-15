/**
 * Navil Cloud API client.
 * Points at the cloud backend (/api/v1) vs the local backend (/api/local).
 * Falls back to demo/mock data when the backend is unreachable.
 */

const CLOUD_BASE = '/api/v1'
const FETCH_TIMEOUT_MS = 15_000

// ── Error parsing ─────────────────────────────────────────

async function parseError(res: Response, method: string, path: string): Promise<never> {
  let body: Record<string, unknown> | null = null
  try {
    body = await res.json()
  } catch {
    // not JSON
  }
  if (body?.detail) {
    if (typeof body.detail === 'string') throw new Error(body.detail)
    const detail = body.detail as Record<string, unknown>
    if (typeof detail === 'object' && detail?.message) {
      throw new Error(detail.message as string)
    }
  }
  if (res.status === 500 || res.status === 502 || res.status === 503) {
    throw new Error('Cloud backend not reachable.')
  }
  throw new Error(`${method} ${path} failed: ${res.status}`)
}

function withTimeout(ms: number): { signal: AbortSignal; clear: () => void } {
  const controller = new AbortController()
  const id = setTimeout(() => controller.abort(), ms)
  return { signal: controller.signal, clear: () => clearTimeout(id) }
}

async function get<T>(path: string): Promise<T> {
  const { signal, clear } = withTimeout(FETCH_TIMEOUT_MS)
  try {
    const res = await fetch(`${CLOUD_BASE}${path}`, { signal })
    if (!res.ok) return parseError(res, 'GET', path)
    return await res.json()
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw new Error(`GET ${path} timed out`)
    }
    throw e
  } finally {
    clear()
  }
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const { signal, clear } = withTimeout(FETCH_TIMEOUT_MS)
  try {
    const res = await fetch(`${CLOUD_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal,
    })
    if (!res.ok) return parseError(res, 'POST', path)
    return await res.json()
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw new Error(`POST ${path} timed out`)
    }
    throw e
  } finally {
    clear()
  }
}

async function patch<T>(path: string, body: unknown): Promise<T> {
  const { signal, clear } = withTimeout(FETCH_TIMEOUT_MS)
  try {
    const res = await fetch(`${CLOUD_BASE}${path}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal,
    })
    if (!res.ok) return parseError(res, 'PATCH', path)
    return await res.json()
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw new Error(`PATCH ${path} timed out`)
    }
    throw e
  } finally {
    clear()
  }
}

async function del(path: string): Promise<void> {
  const { signal, clear } = withTimeout(FETCH_TIMEOUT_MS)
  try {
    const res = await fetch(`${CLOUD_BASE}${path}`, { method: 'DELETE', signal })
    if (!res.ok && res.status !== 204) return parseError(res, 'DELETE', path)
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw new Error(`DELETE ${path} timed out`)
    }
    throw e
  } finally {
    clear()
  }
}

// ── Types ──────────────────────────────────────────────────

export type OrgTier = 'community' | 'pro' | 'growth' | 'team' | 'enterprise'

// Billing
export interface CheckoutRequest {
  tier: string
  interval: 'monthly' | 'annual'
}

export interface CheckoutResponse {
  url: string | null
  upgraded: boolean
}

export interface PortalResponse {
  url: string
}

// Webhooks
export interface WebhookEndpoint {
  id: string
  url: string
  events: string[]
  secret: string
  status: string
  is_active: boolean
  success_rate: number | null
  created_at: string
  updated_at: string
}

export interface CreateWebhookRequest {
  url: string
  events: string[]
}

export interface CreateWebhookResponse {
  id: string
  url: string
  events: string[]
  secret: string
  status: string
  is_active: boolean
  created_at: string
}

export interface UpdateWebhookRequest {
  url?: string
  events?: string[]
  is_active?: boolean
}

export interface WebhookDelivery {
  id: string
  webhook_id: string
  event_type: string
  status: string
  http_status: number | null
  latency_ms: number | null
  attempt: number
  next_retry_at: string | null
  created_at: string
}

export interface TestDeliveryResponse {
  success: boolean
  http_status: number | null
  latency_ms: number | null
  error: string | null
}

// Analytics
export interface TimeseriesPoint {
  date: string
  count: number
}

export interface TimeseriesResponse {
  days: number
  data: TimeseriesPoint[]
}

export interface ThreatCount {
  event_type: string
  count: number
}

export interface TopThreatsResponse {
  days: number
  data: ThreatCount[]
}

// Threat Rules (custom patterns)
export interface ThreatRule {
  id: string
  name: string
  pattern: string
  severity: string
  action: 'alert' | 'block'
  enabled: boolean
  created_at: string
  match_count: number
}

export interface CreateThreatRuleRequest {
  name: string
  pattern: string
  severity: string
  action: 'alert' | 'block'
}

export interface TestRuleResult {
  matched: boolean
  matches: string[]
}

// Org profile (for tier info)
export interface OrgProfile {
  id: string
  name: string
  tier: OrgTier
  created_at: string
  api_key_count: number
  user_count: number
}

// ── Allowed webhook events ────────────────────────────────

export const WEBHOOK_EVENTS = [
  'threat.detected',
  'agent.blocked',
  'agent.connected',
  'agent.disconnected',
  'policy.violated',
  'key.created',
  'key.revoked',
] as const

// ── Plan tiers ────────────────────────────────────────────

export interface PlanInfo {
  name: string
  tier: OrgTier
  price: string
  annualPrice: string
  agents: string
  requests: string
  features: string[]
  highlighted?: boolean
}

export const PLANS: PlanInfo[] = [
  {
    name: 'Community',
    tier: 'community',
    price: 'Free',
    annualPrice: 'Free',
    agents: '3',
    requests: '1K/mo',
    features: ['Community threat feed', 'Basic alerting', 'OSS scanner'],
  },
  {
    name: 'Pro',
    tier: 'pro',
    price: '$29/mo',
    annualPrice: '$290/yr',
    agents: '10',
    requests: '50K/mo',
    features: ['Priority alerts', 'Webhook integrations', 'Email support'],
  },
  {
    name: 'Team',
    tier: 'team',
    price: '$99/mo',
    annualPrice: '$990/yr',
    agents: '50',
    requests: '500K/mo',
    features: ['Custom threat rules', 'Team management', 'SSO', 'Dedicated support'],
    highlighted: true,
  },
  {
    name: 'Enterprise',
    tier: 'enterprise',
    price: 'Custom',
    annualPrice: 'Custom',
    agents: 'Unlimited',
    requests: 'Unlimited',
    features: ['On-prem deploy', 'SLA guarantee', 'Custom integrations', 'Dedicated CSM'],
  },
]

// ── API calls ─────────────────────────────────────────────

export const cloudApi = {
  // Org profile
  getOrgProfile: () => get<OrgProfile>('/org/profile'),

  // Billing
  createCheckout: (tier: string, interval: 'monthly' | 'annual' = 'monthly') =>
    post<CheckoutResponse>('/billing/checkout', { tier, interval }),
  createPortal: () =>
    post<PortalResponse>('/billing/portal', {}),

  // Webhooks
  listWebhooks: () => get<WebhookEndpoint[]>('/org/webhooks'),
  createWebhook: (data: CreateWebhookRequest) =>
    post<CreateWebhookResponse>('/org/webhooks', data),
  updateWebhook: (id: string, data: UpdateWebhookRequest) =>
    patch<WebhookEndpoint>(`/org/webhooks/${id}`, data),
  deleteWebhook: (id: string) => del(`/org/webhooks/${id}`),
  testWebhook: (id: string) =>
    post<TestDeliveryResponse>(`/org/webhooks/${id}/test`, {}),
  listDeliveries: (webhookId: string) =>
    get<WebhookDelivery[]>(`/org/webhooks/${webhookId}/deliveries`),

  // Analytics
  getTimeseries: (days = 7) =>
    get<TimeseriesResponse>(`/org/analytics/timeseries?days=${days}`),
  getTopThreats: (days = 7) =>
    get<TopThreatsResponse>(`/org/analytics/top-threats?days=${days}`),

  // Threat rules (custom patterns — Team+ only)
  listThreatRules: () => get<ThreatRule[]>('/org/threat-rules'),
  createThreatRule: (data: CreateThreatRuleRequest) =>
    post<ThreatRule>('/org/threat-rules', data),
  updateThreatRule: (id: string, data: Partial<ThreatRule>) =>
    patch<ThreatRule>(`/org/threat-rules/${id}`, data),
  deleteThreatRule: (id: string) => del(`/org/threat-rules/${id}`),
  testThreatRule: (pattern: string, sample: string) =>
    post<TestRuleResult>('/org/threat-rules/test', { pattern, sample }),
}

// ── Mock data for demo mode ────────────────────────────────

export const mockData = {
  orgProfile: {
    id: 'demo-org-001',
    name: 'Demo Organization',
    tier: 'pro' as OrgTier,
    created_at: '2025-01-15T00:00:00Z',
    api_key_count: 3,
    user_count: 5,
  },

  webhooks: [
    {
      id: 'wh-001',
      url: 'https://hooks.slack.com/services/T00/B00/xxx',
      events: ['threat.detected', 'agent.blocked'],
      secret: 'whsec_****',
      status: 'active',
      is_active: true,
      success_rate: 0.98,
      created_at: '2025-12-01T10:00:00Z',
      updated_at: '2026-03-10T14:30:00Z',
    },
    {
      id: 'wh-002',
      url: 'https://api.pagerduty.com/webhooks/v3',
      events: ['threat.detected', 'policy.violated'],
      secret: 'whsec_****',
      status: 'active',
      is_active: true,
      success_rate: 1.0,
      created_at: '2026-01-20T08:00:00Z',
      updated_at: '2026-03-15T09:00:00Z',
    },
    {
      id: 'wh-003',
      url: 'https://old-service.example.com/hook',
      events: ['agent.connected'],
      secret: 'whsec_****',
      status: 'failed',
      is_active: false,
      success_rate: 0.12,
      created_at: '2025-06-01T12:00:00Z',
      updated_at: '2026-02-28T16:00:00Z',
    },
  ] as WebhookEndpoint[],

  deliveries: [
    {
      id: 'del-001',
      webhook_id: 'wh-001',
      event_type: 'threat.detected',
      status: 'delivered',
      http_status: 200,
      latency_ms: 142,
      attempt: 1,
      next_retry_at: null,
      created_at: '2026-03-16T08:30:00Z',
    },
    {
      id: 'del-002',
      webhook_id: 'wh-001',
      event_type: 'agent.blocked',
      status: 'delivered',
      http_status: 200,
      latency_ms: 89,
      attempt: 1,
      next_retry_at: null,
      created_at: '2026-03-16T07:15:00Z',
    },
    {
      id: 'del-003',
      webhook_id: 'wh-001',
      event_type: 'threat.detected',
      status: 'failed',
      http_status: 500,
      latency_ms: 2034,
      attempt: 3,
      next_retry_at: '2026-03-16T12:00:00Z',
      created_at: '2026-03-15T22:00:00Z',
    },
    {
      id: 'del-004',
      webhook_id: 'wh-001',
      event_type: 'policy.violated',
      status: 'delivered',
      http_status: 200,
      latency_ms: 210,
      attempt: 1,
      next_retry_at: null,
      created_at: '2026-03-15T18:45:00Z',
    },
  ] as WebhookDelivery[],

  timeseries: (days: number): TimeseriesResponse => {
    const data: TimeseriesPoint[] = []
    const now = new Date()
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(now)
      d.setDate(d.getDate() - i)
      data.push({
        date: d.toISOString().slice(0, 10),
        count: Math.floor(Math.random() * 40) + 5,
      })
    }
    return { days, data }
  },

  topThreats: {
    days: 7,
    data: [
      { event_type: 'prompt_injection', count: 47 },
      { event_type: 'data_exfiltration', count: 32 },
      { event_type: 'privilege_escalation', count: 28 },
      { event_type: 'tool_misuse', count: 19 },
      { event_type: 'unusual_data_volume', count: 14 },
      { event_type: 'credential_abuse', count: 11 },
      { event_type: 'policy_violation', count: 8 },
      { event_type: 'lateral_movement', count: 5 },
    ],
  } as TopThreatsResponse,

  threatRules: [
    {
      id: 'rule-001',
      name: 'SQL Injection Pattern',
      pattern: '(?i)(union\\s+select|drop\\s+table|;\\s*delete)',
      severity: 'CRITICAL',
      action: 'block' as const,
      enabled: true,
      created_at: '2026-01-10T00:00:00Z',
      match_count: 156,
    },
    {
      id: 'rule-002',
      name: 'Sensitive File Access',
      pattern: '(?i)(/etc/passwd|/etc/shadow|\\.env|credentials\\.json)',
      severity: 'HIGH',
      action: 'alert' as const,
      enabled: true,
      created_at: '2026-02-05T00:00:00Z',
      match_count: 89,
    },
    {
      id: 'rule-003',
      name: 'Base64 Encoded Payload',
      pattern: '[A-Za-z0-9+/]{50,}={0,2}',
      severity: 'MEDIUM',
      action: 'alert' as const,
      enabled: false,
      created_at: '2026-02-20T00:00:00Z',
      match_count: 342,
    },
  ] as ThreatRule[],
}

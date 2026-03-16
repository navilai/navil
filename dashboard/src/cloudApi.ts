/**
 * Navil Cloud API client.
 * Points at the cloud backend (/api/v1) vs the local backend (/api/local).
 * Requires Clerk authentication — all requests include Bearer tokens.
 *
 * The API base URL is configured per environment via VITE_API_BASE_URL:
 *   Production:  https://api.navil.ai
 *   Preview:     https://api.navil.ai  (can be changed to a staging backend)
 *   Local dev:   http://localhost:8484  (proxied via Vite dev server)
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL as string | undefined
const CLOUD_BASE = API_BASE_URL ? `${API_BASE_URL.replace(/\/+$/, '')}/api/v1` : '/api/v1'
const FETCH_TIMEOUT_MS = 15_000

// ── Auth helper ──────────────────────────────────────────

/**
 * Retrieve a Clerk session token.
 * Uses the global Clerk instance attached to `window` by ClerkProvider.
 * Returns null if no session is available (user not signed in).
 */
async function getSessionToken(): Promise<string | null> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const clerk = (window as any).Clerk
    if (clerk?.session) {
      const token = await clerk.session.getToken()
      return token
    }
  } catch {
    // Clerk not loaded yet or no session
  }
  return null
}

/**
 * Build headers for an authenticated cloud API request.
 * If an explicit token is provided, it takes precedence.
 * Otherwise, attempts to retrieve the token from the Clerk session.
 */
async function buildHeaders(
  token?: string | null,
  extra?: Record<string, string>,
): Promise<Record<string, string>> {
  const headers: Record<string, string> = { ...extra }
  const t = token ?? (await getSessionToken())
  if (t) {
    headers['Authorization'] = `Bearer ${t}`
  }
  return headers
}

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
  if (res.status === 401) {
    throw new Error('Authentication required. Please sign in.')
  }
  if (res.status === 403) {
    throw new Error('Access denied. You do not have permission for this action.')
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

async function get<T>(path: string, token?: string | null): Promise<T> {
  const { signal, clear } = withTimeout(FETCH_TIMEOUT_MS)
  try {
    const headers = await buildHeaders(token)
    const res = await fetch(`${CLOUD_BASE}${path}`, { signal, headers })
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

async function post<T>(path: string, body: unknown, token?: string | null): Promise<T> {
  const { signal, clear } = withTimeout(FETCH_TIMEOUT_MS)
  try {
    const headers = await buildHeaders(token, { 'Content-Type': 'application/json' })
    const res = await fetch(`${CLOUD_BASE}${path}`, {
      method: 'POST',
      headers,
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

async function patch<T>(path: string, body: unknown, token?: string | null): Promise<T> {
  const { signal, clear } = withTimeout(FETCH_TIMEOUT_MS)
  try {
    const headers = await buildHeaders(token, { 'Content-Type': 'application/json' })
    const res = await fetch(`${CLOUD_BASE}${path}`, {
      method: 'PATCH',
      headers,
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

async function del(path: string, token?: string | null): Promise<void> {
  const { signal, clear } = withTimeout(FETCH_TIMEOUT_MS)
  try {
    const headers = await buildHeaders(token)
    const res = await fetch(`${CLOUD_BASE}${path}`, { method: 'DELETE', signal, headers })
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

// API Keys
export interface ApiKey {
  id: string
  key_prefix: string
  label: string
  created_at: string
  last_used_at: string | null
}

export interface CreateApiKeyResponse {
  id: string
  raw_key: string
  key_prefix: string
  label: string
  created_at: string
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
  getOrgProfile: (token?: string | null) => get<OrgProfile>('/org/me', token),

  // Billing
  createCheckout: (tier: string, interval: 'monthly' | 'annual' = 'monthly', token?: string | null) =>
    post<CheckoutResponse>('/billing/checkout', { tier, interval }, token),
  createPortal: (token?: string | null) =>
    post<PortalResponse>('/billing/portal', {}, token),

  // Webhooks
  listWebhooks: (token?: string | null) => get<WebhookEndpoint[]>('/org/webhooks', token),
  createWebhook: (data: CreateWebhookRequest, token?: string | null) =>
    post<CreateWebhookResponse>('/org/webhooks', data, token),
  updateWebhook: (id: string, data: UpdateWebhookRequest, token?: string | null) =>
    patch<WebhookEndpoint>(`/org/webhooks/${id}`, data, token),
  deleteWebhook: (id: string, token?: string | null) => del(`/org/webhooks/${id}`, token),
  testWebhook: (id: string, token?: string | null) =>
    post<TestDeliveryResponse>(`/org/webhooks/${id}/test`, {}, token),
  listDeliveries: (webhookId: string, token?: string | null) =>
    get<WebhookDelivery[]>(`/org/webhooks/${webhookId}/deliveries`, token),

  // Analytics
  getTimeseries: (days = 7, token?: string | null) =>
    get<TimeseriesResponse>(`/org/analytics/timeseries?days=${days}`, token),
  getTopThreats: (days = 7, token?: string | null) =>
    get<TopThreatsResponse>(`/org/analytics/top-threats?days=${days}`, token),

  // Threat rules (custom patterns — Team+ only)
  listThreatRules: (token?: string | null) => get<ThreatRule[]>('/org/threat-rules', token),
  createThreatRule: (data: CreateThreatRuleRequest, token?: string | null) =>
    post<ThreatRule>('/org/threat-rules', data, token),
  updateThreatRule: (id: string, data: Partial<ThreatRule>, token?: string | null) =>
    patch<ThreatRule>(`/org/threat-rules/${id}`, data, token),
  deleteThreatRule: (id: string, token?: string | null) => del(`/org/threat-rules/${id}`, token),
  testThreatRule: (pattern: string, sample: string, token?: string | null) =>
    post<TestRuleResult>('/org/threat-rules/test', { pattern, sample }, token),

  // API Keys
  listApiKeys: (token?: string | null) => get<ApiKey[]>('/org/keys', token),
  createApiKey: (label: string, token?: string | null) =>
    post<CreateApiKeyResponse>('/org/keys', { label }, token),
  revokeApiKey: (id: string, token?: string | null) => del(`/org/keys/${id}`, token),
}
